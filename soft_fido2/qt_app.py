# Copyright IBM 2022, 2025
# IBM Confidential

"""Main Qt application controller for system tray authentication.

This module provides the main application controller that:
- Manages application state (locked/unlocked)
- Processes message queues
- Handles signal processing
- Coordinates between UI and services

UI presentation is delegated to qt_ux modules.
Business logic is delegated to service modules.
"""

import os, time, sys, threading, logging, signal

from enum import Enum

from PyQt6.QtWidgets import QApplication, QDialog, QMessageBox
from PyQt6.QtCore import QThreadPool, QTimer
try:
    from soft_fido2.message_queues import QueueMessageType, MessageQueue, PlatformKeyRequest, PlatformKeyResponse
    from soft_fido2.qt_ux.config import PlatformConfig
    from soft_fido2.qt_ux.workers import Worker
    from soft_fido2.qt_ux.settings_dialog import SettingsDialog
    from soft_fido2.qt_ux.main_window import SysTrayMainWindow
    from soft_fido2.qt_svc.platform_key_service import PlatformKeyService
except:
    from message_queues import QueueMessageType, MessageQueue, PlatformKeyRequest, PlatformKeyResponse
    from qt_ux.config import PlatformConfig
    from qt_ux.workers import Worker
    from qt_ux.settings_dialog import SettingsDialog
    from qt_ux.main_window import SysTrayMainWindow
    from qt_svc.platform_key_service import PlatformKeyService


class SysTrayApp(QDialog):
    """Main application controller - handles state and events only.
    
    This is the main Qt application controller that:
    - Manages application state
    - Processes message queues
    - Handles signal processing
    - Coordinates between UI and services
    
    UI presentation is delegated to qt_ux modules.
    App logic is delegated to qt_svc modules.
    """
    
    # === Nested Classes ===
    
    class AppState(Enum):
        """Application state enumeration."""
        LOCKED = "locked"
        UNLOCKED = "unlocked"
    
    # Global flag for signal handling
    _received_signal = False
    _signal_num = 0
    
    def __init__(self, device_manager=None):
        """Initialize application with device manager.
        
        Args:
            device_manager: Optional device manager instance
        """
        self.app = QApplication(sys.argv)
        self.device_manager = device_manager
        super().__init__()
        
        # === State Variables ===
        self._current_state = self.AppState.LOCKED
        self._platform_key = None  # Can be KeyPair or TPMKeyPair
        self.fido_home = os.environ.get('FIDO_HOME', os.path.expanduser('~/.fido'))
        self.plat_cfg = PlatformConfig(self.fido_home)
        
        # === Service Layer ===
        self.platform_key_service = PlatformKeyService(self.fido_home)
        
        # === UI Components ===
        self.main_window = SysTrayMainWindow(self)
        
        # === Worker Setup ===
        self.threadPool = self._threadpool_setup()
        self.worker = self._worker_setup()
        self.quit = False
        
        # Track active dialog to prevent multiple dialogs
        self._active_dialog = None
        
        # === Signal Handling ===
        self._setup_signal_handling()
        
        # Hide the dialog window by default
        self.hide()
        
        # === Platform Key Auto-Load ===
        self._auto_load_platform_key()
        
        # === Finalize ===
        self._finalise()
    
    # ============================================================================
    # STATE MANAGEMENT
    # ============================================================================
    
    def _check_platform_key_exists(self):
        """Check if platform.key exists in FIDO_HOME.
        
        Returns:
            bool: True if platform.key exists, False otherwise
        """
        return self.platform_key_service.check_key_exists('file')
    
    def _set_state(self, state):
        """Set the application state and update icon.
        
        Args:
            state: New application state (AppState enum)
        """
        self._current_state = state
        self.main_window._update_icon_for_state()
    
    def _is_locked(self) -> bool:
        """Check if the application is locked.
        
        Returns:
            bool: True if locked, False if unlocked
        """
        return self._current_state == self.AppState.LOCKED
    
    # ============================================================================
    # PLATFORM KEY LOADING
    # ============================================================================
    
    def _auto_load_platform_key(self):
        """Attempt to load platform key on startup based on user's preference.
        
        Uses the PlatformKeyService to handle all key loading logic.
        Priority order:
        1. If platform.cfg exists: use configured preference
        2. If no config: try TPM first (if available), then file without password
        3. Stay locked and wait for user action
        
        State transitions:
        - UNLOCKED: Key loaded successfully (no password or already unlocked)
        - LOCKED: Key exists but requires password
        """
        preferred_key_type = self.plat_cfg.key_type
        success, key_pair, message = self.platform_key_service.auto_load_key(preferred_key_type)
        
        if success:
            self._platform_key = key_pair
            self._set_state(self.AppState.UNLOCKED)
            logging.info(message)
        else:
            # Key exists but locked (password-protected)
            self._set_state(self.AppState.LOCKED)
            logging.info(message)
    
    # ============================================================================
    # SIGNAL HANDLING
    # ============================================================================
    
    def _setup_signal_handling(self):
        """Set up signal handling for graceful shutdown."""
        # Set up the signal handlers
        signal.signal(signal.SIGINT, SysTrayApp._signal_handler)
        signal.signal(signal.SIGTERM, SysTrayApp._signal_handler)
        
        # Create a timer to check for signals
        self._signal_timer = QTimer(self)
        self._signal_timer.timeout.connect(self._check_signal)
        self._signal_timer.start(100)  # Check every 100ms
    
    @staticmethod
    def _signal_handler(sig, frame):
        """Signal handler that sets the global flag.
        
        Args:
            sig: Signal number
            frame: Current stack frame
        """
        logging.info(f"Received signal {sig}, setting flag for Qt event loop")
        try:
            SysTrayApp._received_signal = True
            SysTrayApp._signal_num = sig
        except Exception as e:
            logging.error(f"Error in signal handler: {e}")
    
    def _check_signal(self):
        """Check if a signal has been received and handle it."""
        if SysTrayApp._received_signal:
            sig_name = "SIGINT" if SysTrayApp._signal_num == signal.SIGINT else "SIGTERM"
            logging.info(f"Qt event loop detected {sig_name}, shutting down gracefully")
            # Stop the timer first to prevent re-entry
            self._signal_timer.stop()
            self._exit()
    
    # ============================================================================
    # EVENT HANDLERS
    # ============================================================================
    
    def __open_settings(self):
        """Open the settings dialog.
        
        Prevents multiple dialogs from being opened simultaneously.
        """
        # Check if another dialog is already active
        if self._active_dialog is not None:
            QMessageBox.information(
                self,
                "Operation in Progress",
                "Please complete the current operation before starting a new one."
            )
            return
            
        dialog = SettingsDialog(self, device_manager=self.device_manager)
        dialog.finished.connect(lambda: self.__handle_dialog_closed(dialog))
        
        # Set as active dialog
        self._active_dialog = dialog
        dialog.exec()
        # Clean up after dialog closes
        self.__handle_dialog_closed(dialog)
        
    def __handle_dialog_closed(self, dialog):
        """Handle dialog closed event.
        
        Common handler for when any dialog is closed or rejected.
        Clears the active dialog reference and performs cleanup.
        
        Args:
            dialog: The dialog that was closed
        """
        self._active_dialog = None
        dialog.deleteLater()
        
        # Check if platform key was created and update state accordingly
        if self._check_platform_key_exists() and self._is_locked():
            # Platform key now exists, try to auto-load it
            self._auto_load_platform_key()
    
    def on_message_clicked(self):
        """Handle notification message clicked event.
        
        Delegates to main window for handling.
        """
        self.main_window.on_message_clicked()
    
    # ============================================================================
    # MESSAGE QUEUE PROCESSING
    # ============================================================================
    
    def _threadpool_setup(self):
        """Set up the thread pool for background workers.
        
        Returns:
            QThreadPool: Configured thread pool
        """
        threadpool = QThreadPool()
        threadpool.maxThreadCount()
        return threadpool

    def _worker_setup(self):
        """Set up the message queue worker.
        
        Returns:
            Worker: Configured worker instance
        """
        return Worker(self._msg_queue_handler)

    def _msg_queue_handler(self):
        """Handle message queue processing.
        
        Main worker loop that processes:
        - Platform key requests
        - User notification requests
        - Authentication responses
        """
        notif_threads = []
        while not self.quit:
            time.sleep(0.001)
            
            # Handle platform key requests
            if MessageQueue.platform_key_requests.qsize() > 0:
                request = MessageQueue.platform_key_requests.get()
                self._handle_platform_key_request(request)
            
            if MessageQueue.notify_sysapp.qsize() > 0:
                msg = MessageQueue.notify_sysapp.get()
                logging.debug(f"Got a message: {msg}")
                if msg == QueueMessageType.USER_REQUEST or msg == QueueMessageType.USER_REQUEST_FPRINT:
                    t = threading.Thread(target=self.main_window.prompt_notification,
                            kwargs={'fprint_pending': msg == QueueMessageType.USER_REQUEST_FPRINT})
                    t.start()
                    notif_threads.append(t)
                    self.main_window.set_auth_icon()
                    self.main_window.start_icon_reset_timer()
                elif msg == QueueMessageType.AUTH_RESPONSE:
                    self.main_window.cancel_notification()
                    self.main_window._reset_icon()
                    # Stop the timer if it's running
                    if self.main_window.icon_reset_timer.isActive():
                        self.main_window.icon_reset_timer.stop()

            tempThreadList = []
            for t in notif_threads:
                if not t.is_alive():
                    t.join()
                    tempThreadList.append(t)
            for t in tempThreadList:
                notif_threads.remove(t)
    
    def _handle_platform_key_request(self, request: PlatformKeyRequest):
        """Handle platform key request from passkey_device.
        
        Args:
            request: Platform key request object
        """
        if self._is_locked():
            response = PlatformKeyResponse(
                request.request_id,
                key_pair=None,
                error="Platform key is locked"
            )
        else:
            # Return the platform key
            response = PlatformKeyResponse(
                request.request_id,
                key_pair=self._platform_key,
                error=None
            )
        
        MessageQueue.platform_key_responses.put(response)
    
    # ============================================================================
    # LIFECYCLE
    # ============================================================================
    
    def _exit(self):
        """Exit the application gracefully."""
        logging.info("Sysapp Exiting")
        MessageQueue.notify_udev.put(QueueMessageType.QUIT)
        self.main_window.cancel_notification()
        self.quit = True
        self.app.quit()

    def closeEvent(self, a0):
        """Handle close event.
        
        Override closeEvent to hide the window instead of closing the application.
        
        Args:
            a0: Close event object
        """
        # Override closeEvent to hide the window instead of closing the application
        if self.main_window.is_visible():
            self.hide()
            if a0:
                a0.ignore()
            else: #panic!
                self._exit()
        else:
            self._exit()

    def _finalise(self):
        """Finalize application setup and start event loop."""
        self.threadPool.start(self.worker)
        self.main_window.launch_notification()
        self.app.exec()

