# Copyright IBM 2025

import logging
import time
from contextlib import contextmanager
from enum import Enum
from typing import Any, Callable, Optional, Tuple

from jeepney import DBusAddress, HeaderFields, MatchRule, MessageType, new_method_call
from jeepney.io.blocking import open_dbus_connection
from jeepney.wrappers import new_method_call as wrappers_new_method_call


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
        self._connection = None
        self._device_path: Optional[str] = None
        self._available = False
        self._verify_result: Optional[str] = None
        self._on_finger_needed_callback: Optional[Callable[[str], None]] = None

        self._manager = DBusAddress(
            self.FPRINTD_MANAGER_PATH,
            bus_name=self.FPRINTD_BUS_NAME,
            interface=self.FPRINTD_MANAGER_IFACE
        )

        self._initialize_dbus()

    def _initialize_dbus(self):
        """Initialize D-Bus connection and check fprintd availability."""
        try:
            self._connection = open_dbus_connection(bus='SYSTEM')
            self._device_path = self._get_default_device_path()
            self._available = self._device_path is not None
            if self._available:
                logging.info("Biometric authentication available via D-Bus")
        except Exception as e:
            logging.info(f"fprintd not available: {e}")
            self._available = False
            self._connection = None
            self._device_path = None

    def _get_default_device_path(self) -> Optional[str]:
        """Get the default fprintd device path."""
        if self._connection is None:
            return None

        msg = new_method_call(self._manager, 'GetDefaultDevice')
        reply = self._connection.send_and_get_reply(msg)
        return str(reply.body[0])

    def _get_device_address(self, device_path: Optional[str] = None) -> DBusAddress:
        """Build a D-Bus address for the fingerprint device."""
        return DBusAddress(
            device_path or self._device_path or '',
            bus_name=self.FPRINTD_BUS_NAME,
            interface=self.FPRINTD_DEVICE_IFACE
        )

    def is_available(self) -> bool:
        """Check if biometric authentication is available."""
        return self._available

    @contextmanager
    def _claimed_device(self, device: DBusAddress, username: str):
        """Context manager for device claim/release lifecycle.

        Guarantees VerifyStop() and Release() are called even on exceptions.
        """
        if self._connection is None:
            raise RuntimeError("D-Bus connection unavailable")

        try:
            self._connection.send_and_get_reply(new_method_call(device, 'Claim', 's', (username,)))
            logging.info(f"Device claimed for user: {username or 'current'}")
            yield
        finally:
            try:
                self._connection.send(new_method_call(device, 'VerifyStop'))
            except Exception:
                pass
            try:
                self._connection.send(new_method_call(device, 'Release'))
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

    def _install_signal_matches(self, device: DBusAddress) -> None:
        """Subscribe to fingerprint verification signals."""
        if self._connection is None:
            raise RuntimeError("D-Bus connection unavailable")

        device_path = self._device_path or self.FPRINTD_MANAGER_PATH
        for member in ('VerifyFingerSelected', 'VerifyStatus'):
            rule = MatchRule(
                type='signal',
                sender=self.FPRINTD_BUS_NAME,
                interface=self.FPRINTD_DEVICE_IFACE,
                member=member,
                path=device_path
            )
            msg = wrappers_new_method_call(
                DBusAddress(
                    '/org/freedesktop/DBus',
                    bus_name='org.freedesktop.DBus',
                    interface='org.freedesktop.DBus'
                ),
                'AddMatch',
                signature='s',
                body=(rule.serialise(),)
            )
            self._connection.send_and_get_reply(msg)

    def _poll_for_verify_result(self, timeout: float) -> None:
        """Poll D-Bus for verification signals until completion or timeout."""
        if self._connection is None:
            raise RuntimeError("D-Bus connection unavailable")

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = max(0.0, min(0.1, deadline - time.monotonic()))
            try:
                msg = self._connection.receive(timeout=remaining)
            except TimeoutError:
                continue

            if msg is None or msg.header.message_type != MessageType.signal:
                continue

            member = msg.header.fields.get(HeaderFields.member)
            if member == 'VerifyFingerSelected':
                finger_name = str(msg.body[0])
                logging.info(f"Finger selected: {finger_name}")
                if self._on_finger_needed_callback:
                    self._on_finger_needed_callback(finger_name)
            elif member == 'VerifyStatus':
                result_code, done = msg.body
                self._verify_result = str(result_code)
                logging.info(f"Verify status: {result_code}, done: {done}")
                if bool(done):
                    return

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
        if not self._available or self._connection is None:
            return (BiometricResult.NOT_AVAILABLE, "Biometric not available")

        self._verify_result = None
        self._on_finger_needed_callback = on_finger_needed

        try:
            device_path = self._get_default_device_path()
            if not device_path:
                return (BiometricResult.NOT_AVAILABLE, "Biometric not available")

            self._device_path = device_path
            device = self._get_device_address(device_path)

            self._install_signal_matches(device)

            with self._claimed_device(device, username or ""):
                self._connection.send_and_get_reply(new_method_call(device, 'VerifyStart', 's', ('any',)))
                logging.info("Fingerprint verification started")
                self._poll_for_verify_result(timeout)

            return self._process_verify_result(self._verify_result)

        except Exception as e:
            logging.error(f"Verification error: {e}")
            return (BiometricResult.UNKNOWN_ERROR, f"Error: {str(e)}")
        finally:
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
