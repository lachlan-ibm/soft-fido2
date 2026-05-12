# Copyright IBM 2025

import logging
from contextlib import contextmanager
from enum import Enum
from typing import Any, Callable, Optional, Tuple, cast

# Module-level imports for optional D-Bus dependencies
_dbus_module: Any = None
_dbus_mainloop_class: Any = None
_glib_module: Any = None

try:
    import dbus
    from dbus.mainloop.glib import DBusGMainLoop
    from gi.repository import GLib  # type: ignore[import-untyped]

    _dbus_module = dbus
    _dbus_mainloop_class = DBusGMainLoop
    _glib_module = GLib
except ImportError:
    pass


class BiometricResult(Enum):
    SUCCESS = "verify-match"
    NO_MATCH = "verify-no-match"
    RETRY = "verify-retry-scan"
    DISCONNECTED = "verify-disconnected"
    UNKNOWN_ERROR = "verify-unknown-error"
    NOT_AVAILABLE = "not-available"
    TIMEOUT = "timeout"


class FprintDevice:
    """Fingerprint authentication via fprintd D-Bus service.

    Correct fprintd verification flow:
    1. Claim() - claim the device for exclusive use
    2. VerifyStart('any') - start verification
    3. VerifyFingerSelected signal - tells which finger to scan (NOW prompt user)
    4. User places finger on scanner
    5. VerifyStatus signal - verification result
    6. VerifyStop() - stop verification
    7. Release() - release device
    """

    FPRINTD_BUS_NAME = 'net.reactivated.Fprint'
    FPRINTD_MANAGER_PATH = '/net/reactivated/Fprint/Manager'
    FPRINTD_MANAGER_IFACE = 'net.reactivated.Fprint.Manager'
    FPRINTD_DEVICE_IFACE = 'net.reactivated.Fprint.Device'

    def __init__(self):
        self._bus: Any = None
        self._device_iface: Any = None
        self._available = False
        self._mainloop: Any = None
        self._verify_result: Optional[str] = None
        self._on_finger_needed_callback: Optional[Callable[[str], None]] = None

        if _dbus_module:
            self._initialize_dbus()

    def _initialize_dbus(self):
        """Initialize D-Bus connection and check fprintd availability."""
        try:
            if _dbus_mainloop_class is None or _dbus_module is None:
                self._available = False
                return

            _dbus_mainloop_class(set_as_default=True)
            self._bus = _dbus_module.SystemBus()

            manager = self._bus.get_object(self.FPRINTD_BUS_NAME, self.FPRINTD_MANAGER_PATH)
            manager_iface = _dbus_module.Interface(manager, self.FPRINTD_MANAGER_IFACE)

            device_path = manager_iface.GetDefaultDevice()
            device = self._bus.get_object(self.FPRINTD_BUS_NAME, device_path)
            self._device_iface = _dbus_module.Interface(device, self.FPRINTD_DEVICE_IFACE)

            self._available = True
            logging.info("Biometric authentication available via D-Bus")

        except Exception as e:
            logging.info(f"fprintd not available: {e}")
            self._available = False

    def is_available(self) -> bool:
        """Check if biometric authentication is available."""
        return self._available

    @contextmanager
    def _claimed_device(self, username: str):
        """Context manager for device claim/release lifecycle.
        
        Guarantees VerifyStop() and Release() are called even on exceptions.
        """
        try:
            self._device_iface.Claim(username)
            logging.info(f"Device claimed for user: {username or 'current'}")
            yield
        finally:
            try:
                self._device_iface.VerifyStop()
            except Exception:
                pass
            try:
                self._device_iface.Release()
            except Exception:
                pass

    def _process_verify_result(self, result: Optional[str]) -> Tuple[BiometricResult, str]:
        """Process verification result and return appropriate status."""
        if result is None:
            return (BiometricResult.TIMEOUT, "Verification timed out")
        
        result_map = {
            'verify-match': (BiometricResult.SUCCESS, "Fingerprint verified"),
            'verify-no-match': (BiometricResult.NO_MATCH, "Fingerprint does not match"),
            'verify-retry-scan': (BiometricResult.RETRY, "Retry fingerprint scan"),
            'verify-disconnected': (BiometricResult.DISCONNECTED, "Device disconnected"),
        }
        return result_map.get(result, (BiometricResult.UNKNOWN_ERROR, f"Unknown result: {result}"))

    def _verify_finger_selected_handler(self, finger_name: str) -> None:
        """Handle VerifyFingerSelected signal from fprintd.
        
        This signal indicates which finger should be scanned.
        Calls the user-provided callback if available.
        """
        logging.info(f"Finger selected: {finger_name}")
        if self._on_finger_needed_callback:
            self._on_finger_needed_callback(finger_name)

    def _verify_status_handler(self, result_code: str, done: bool) -> None:
        """Handle VerifyStatus signal from fprintd.
        
        This signal provides the verification result and completion status.
        Quits the mainloop when verification is complete.
        """
        self._verify_result = result_code
        logging.info(f"Verify status: {result_code}, done: {done}")
        if done and self._mainloop:
            self._mainloop.quit()

    @contextmanager
    def _run_mainloop_with_timeout(self, timeout: float):
        """Context manager for running GLib mainloop with timeout.
        
        Guarantees timeout source removal to prevent resource leaks.
        
        Args:
            timeout: Maximum time to run mainloop in seconds
            
        Yields:
            None
        """
        if _glib_module is None:
            raise RuntimeError("GLib main loop unavailable")
        
        self._mainloop = _glib_module.MainLoop()
        timeout_id = None
        try:
            timeout_id = _glib_module.timeout_add_seconds(
                int(timeout),
                lambda: cast(Any, self._mainloop).quit()
            )
            yield
            self._mainloop.run()
        finally:
            # Always remove timeout source to prevent resource leak
            if timeout_id is not None:
                _glib_module.source_remove(timeout_id)
            self._mainloop = None

    def _connect_verify_signals(self) -> None:
        """Connect D-Bus signal handlers for fingerprint verification.
        
        Sets up handlers for:
        - VerifyFingerSelected: Indicates which finger to scan
        - VerifyStatus: Provides verification result
        """
        self._device_iface.connect_to_signal(
            'VerifyFingerSelected',
            self._verify_finger_selected_handler
        )
        self._device_iface.connect_to_signal(
            'VerifyStatus',
            self._verify_status_handler
        )

    def verify(self, username: Optional[str] = None,
               on_finger_needed: Optional[Callable[[str], None]] = None,
               timeout: float = 15.0) -> Tuple[BiometricResult, str]:
        """
        Verify fingerprint with proper fprintd flow.

        Args:
            username: Username to verify (empty string = current user)
            on_finger_needed: Callback when VerifyFingerSelected signal received
                             This is when you should prompt the user to place finger
            timeout: Maximum wait time in seconds

        Returns:
            (BiometricResult, message)
        """
        # Early validation checks
        if not self._available:
            return (BiometricResult.NOT_AVAILABLE, "Biometric not available")

        if _glib_module is None:
            return (BiometricResult.UNKNOWN_ERROR, "GLib main loop unavailable")

        # Initialize result tracking
        self._verify_result = None
        self._on_finger_needed_callback = on_finger_needed

        try:
            with self._claimed_device(username or ""):
                # Set up signal handlers BEFORE starting verification
                self._connect_verify_signals()

                # Start verification
                self._device_iface.VerifyStart('any')
                logging.info("Fingerprint verification started")

                # Run mainloop with timeout
                with self._run_mainloop_with_timeout(timeout):
                    pass  # Mainloop runs until timeout or completion

            # Process result (device cleanup handled by context manager)
            return self._process_verify_result(self._verify_result)

        except Exception as e:
            logging.error(f"Verification error: {e}")
            return (BiometricResult.UNKNOWN_ERROR, f"Error: {str(e)}")
        finally:
            # Clean up callback reference
            self._on_finger_needed_callback = None

    def verify_with_retries(self, username: Optional[str] = None,
                            on_finger_needed: Optional[Callable[[str], None]] = None,
                            max_retries: int = 3, timeout: float = 15.0) -> Tuple[BiometricResult, str]:
        """Verify fingerprint with automatic retries."""
        for attempt in range(max_retries):
            result, message = self.verify(username, on_finger_needed, timeout)

            if result == BiometricResult.SUCCESS:
                return (result, message)
            elif result == BiometricResult.RETRY:
                logging.info(f"Retry {attempt + 1}/{max_retries}")
                continue
            else:
                return (result, message)

        return (BiometricResult.NO_MATCH, f"Failed after {max_retries} attempts")


_fprint_device_instance: Optional[FprintDevice] = None


def get_fprint_device() -> FprintDevice:
    """Get singleton FprintDevice instance."""
    global _fprint_device_instance
    if _fprint_device_instance is None:
        _fprint_device_instance = FprintDevice()
    return _fprint_device_instance

# Made with Bob

