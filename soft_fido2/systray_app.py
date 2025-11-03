# Copyrite IBM 2022, 2025
# IBM Confidential

import os, time, sys, subprocess, traceback, shutil, threading, logging, signal
from PyQt6.QtGui import QIcon, QAction
from PyQt6.QtWidgets import (QApplication, QDialog, QDialogButtonBox, QHBoxLayout,
                QLabel, QLineEdit, QListWidget, QMessageBox, QPushButton, QSystemTrayIcon, 
                QMenu, QVBoxLayout, QComboBox)
from PyQt6.QtCore import (QObject, QRunnable, QThreadPool, pyqtSignal, pyqtSlot, 
                        QTimer, Qt, QMetaObject)
try:
    from soft_fido2.message_queues import QueueMessageType, MessageQueue
    from soft_fido2.key_pair import KeyUtils
except:
    from message_queues import QueueMessageType, MessageQueue
    from key_pair import KeyUtils

class WorkerSignals(QObject):
    # Define signals as class attributes here
    error = pyqtSignal(tuple)

class Worker(QRunnable):
    def __init__(self, handle, *args, **kwargs):
        super().__init__()
        self.handle = handle
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

    @pyqtSlot()
    def run(self):
        try:
            self.handle(*self.args, **self.kwargs)
        except Exception:
            traceback.print_exc()
            exctype, value = sys.exc_info()[:2]
            self.signals.error.emit((exctype, value, traceback.format_exc()))


class ManageCredentialsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Manage Credentials")
        
        # Initialize instance variables
        self.fido_home = os.environ.get('FIDO_HOME', os.path.expanduser('~/.fido'))
        self.credentials = []
        
        # Create main layout
        layout = QVBoxLayout()
        
        # Add UI components to layout
        layout.addLayout(self._create_pin_input_section())
        layout.addLayout(self._create_passkey_selection_section())
        layout.addWidget(QLabel("Credentials:"))
        layout.addWidget(self._create_credentials_list())
        layout.addLayout(self._create_action_buttons())
        layout.addWidget(self._create_close_button())
        
        self.setLayout(layout)

    def _get_passkey_files(self):
        """
        Returns a list of .passkey files in the specified directory.
        
        Args:
            directory: The directory to search for .passkey files
            
        Returns:
            A list of full paths to .passkey files
        """
        passkey_files = []
        for filename in os.listdir(self.fido_home):
            if filename.endswith('.passkey'):
                passkey_files.append(os.path.join(self.fido_home, filename))
        return passkey_files

    def _create_pin_input_section(self):
        """Create the PIN input section with label and password field."""
        layout = QHBoxLayout()
        layout.addWidget(QLabel("PIN:"))
        self.pin_input = QLineEdit()
        self.pin_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.pin_input)
        return layout
    
    def _create_passkey_selection_section(self):
        """Create the passkey selection section with label and dropdown."""
        layout = QHBoxLayout()
        layout.addWidget(QLabel("Passkey:"))
        self.name_input = QComboBox()
        
        # Populate dropdown with passkey files
        self._load_passkey_files()
        
        layout.addWidget(self.name_input)
        return layout
    
    def _create_credentials_list(self):
        """Create the credentials list widget."""
        self.creds_list = QListWidget()
        return self.creds_list
    
    def _create_action_buttons(self):
        """Create the Load and Delete buttons."""
        layout = QHBoxLayout()
        
        self.load_button = QPushButton("(re)Load Credentials (and Cache pin)")
        self.load_button.clicked.connect(self.load_credentials)
        
        self.delete_button = QPushButton("Delete Resident Credential")
        self.delete_button.clicked.connect(self.delete_credential)
        
        layout.addWidget(self.load_button)
        layout.addWidget(self.delete_button)
        return layout
    
    def _create_close_button(self):
        """Create the Close button."""
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.reject)
        return close_button
    
    def _load_passkey_files(self):
        """Load passkey files and populate the dropdown."""
        if os.path.exists(self.fido_home):
            passkey_files = self._get_passkey_files()
            for passkey_file in passkey_files:
                # Add just the basename to the dropdown
                self.name_input.addItem(os.path.basename(passkey_file))

    def _try_cache_pin(self, nonce, passkey_path):
        """ Load then Save passkey. This will update the cached upper pin hash
        with the provided secret if it successfully unpacks the passkey file. """
        self.passkey = KeyUtils._load_passkey(nonce, passkey_path)
        self.credentials = self.passkey['res.creds']
        KeyUtils._save_passkey(
            self.passkey['key'],
            self.passkey['x5c'],
            self.passkey['res.creds'],
            self.passkey['pin.hash'],
            passkey_path
        )

    def load_credentials(self):
        try:
            # Get PIN hash
            pin = self.pin_input.text()
            nonce = KeyUtils.get_pin_hash(pin)
            # Get the selected passkey filename
            passkey_name = self.name_input.currentText()
            passkey_path = os.path.join(self.fido_home, passkey_name)
            
            self._try_cache_pin(nonce, passkey_path)
            # Success
            # Clear the list widget
            self.creds_list.clear()
            
            # Add credentials to the list widget showing only rp.id and user.id
            for cred in self.credentials:
                # Convert rp.id and user.id to UTF-8 if they are bytestrings
                rp_id_value = cred.get('rp.id', 'cred.parsing.error')
                user_id_value = cred.get('user.id', 'cred.parsing.error')
                
                # Check if values are bytestrings before decoding
                rp_id = rp_id_value.decode('utf-8') if isinstance(rp_id_value, bytes) else str(rp_id_value)
                user_id = user_id_value.decode('utf-8') if isinstance(user_id_value, bytes) else str(user_id_value)
                # Add to list widget
                item_text = f"uri: {rp_id} | user id: {user_id}"
                self.creds_list.addItem(item_text)
                
            
        except Exception as e:
            logging.exception(f"failed to load the credentials from {self.name_input.currentText()} : {e}")
            self.creds_list.clear()
            self.passkey = None
            self.credentials = []
            self.pin_input.clear()
            self.pin_input.setFocus()
        
    def delete_credential(self):
        # Get selected items
        selected_items = self.creds_list.selectedItems()
        if not selected_items:
            return
        
        # Confirm deletion
        confirm = QMessageBox.question(
            self,
            "Confirm Deletion",
            f"Are you sure you want to delete {len(selected_items)} selected credential(s)?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if confirm != QMessageBox.StandardButton.Yes:
            return
        
        # Get indices of selected items
        selected_indices = [self.creds_list.row(item) for item in selected_items]
        
        # Remove credentials from the list (in reverse order to avoid index shifting)
        for index in sorted(selected_indices, reverse=True):
            if 0 <= index < len(self.credentials):
                del self.credentials[index]
        self.write_passkey()

    def write_passkey(self): 
        if not self.passkey:
            return
        # Update the passkey and save it back to disk
        self.passkey['res.creds'] = self.credentials
        try:
            # Use the same passkey path that was used for loading
            passkey_path = os.path.join(self.fido_home, self.name_input.currentText())
            
            KeyUtils._save_passkey(
                self.passkey['key'],
                self.passkey['x5c'],
                self.credentials,
                self.passkey['pin.hash'],
                passkey_path
            )
            
            # Reload the credentials list to reflect changes
            self.load_credentials()
            
            QMessageBox.information(
                self,
                "Success",
                "Selected credentials have been deleted successfully."
            )
        except Exception as e:
            logging.exception(f"Failed to save updated passkey: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to delete credentials: {str(e)}"
            )

class CollectPlatformSecretDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Collect Platform Secret")

        layout = QVBoxLayout()
        
        # Pin
        pin_layout = QHBoxLayout()
        pin_layout.addWidget(QLabel("Passphrase: "))
        self.pin_input = QLineEdit()
        self.pin_input.setEchoMode(QLineEdit.EchoMode.Password)
        pin_layout.addWidget(self.pin_input)
        layout.addLayout(pin_layout)
        
        # Filename
        filename_layout = QHBoxLayout()
        filename_layout.addWidget(QLabel("Filename: "))
        self.filename_input = QLineEdit()
        self.filename_input.setText("platform.key")
        filename_layout.addWidget(self.filename_input)
        layout.addLayout(filename_layout)

        # Buttons
        button_box = QDialogButtonBox(
                QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        self.setLayout(layout)
    
    def get_pin(self):
        return self.pin_input.text()
    
    def get_filename(self):
        return self.filename_input.text()

    def reject(self):
        super().reject()

class GeneratePasskeyDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Generate New Passkey")
        layout = QVBoxLayout()
        
        # PIN input with password masking
        pin_layout = QHBoxLayout()
        pin_layout.addWidget(QLabel("PIN:"))
        self.pin_input = QLineEdit()
        self.pin_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pin_input.setPlaceholderText("Default: 00000000")
        pin_layout.addWidget(self.pin_input)
        layout.addLayout(pin_layout)
        
        # Passkey filename input
        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel("Passkey name:"))
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Default: default")
        name_layout.addWidget(self.name_input)
        layout.addLayout(name_layout)
        
        # Buttons
        button_box = QDialogButtonBox(
                QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        self.setLayout(layout)
    
    def get_values(self):
        pin = self.pin_input.text() or "00000000"
        passkey_name = self.name_input.text() or "default"
        return pin, passkey_name

class SysTrayApp(QDialog):
    class NotificationFramework:
        NOTIFY_SEND = 0
        QT = 1
    
    # Global flag for signal handling
    _received_signal = False
    _signal_num = 0
    
    def __init__(self):
        self.app = QApplication(sys.argv)
        super().__init__()
        
        self.main_icon = self._generate_icon('../icons/main_icon.png',
                                            QIcon.ThemeIcon.DialogPassword)
        self.auth_icon = self._generate_icon('../icons/auth_request.png',
                                            QIcon.ThemeIcon.DialogWarning)
        
        # Create the tray icon as a member variable
        self._tray_icon = QSystemTrayIcon(self.main_icon, self)
        self._tray_icon.setToolTip('EyeBeeKey')
        
        self.menu = self._menu_setup()
        self.notification_fw = self._setup_notifications()
        self.threadPool = self._threadpool_setup()
        self.worker = self._worker_setup()
        self.quit = False
        
        # Track active dialog to prevent multiple dialogs
        self._active_dialog = None
        
        # Create a timer to reset the icon after a period of time
        self.icon_reset_timer = QTimer(self)
        self.icon_reset_timer.setSingleShot(True)
        self.icon_reset_timer.timeout.connect(self._reset_icon)
        
        # Set up signal handling with Qt
        self._setup_signal_handling()
        
        # Hide the dialog window by default
        self.hide()
        
        self._finalise()
    
    def _setup_signal_handling(self):
        """Set up signal handling"""
        # Set up the signal handlers
        signal.signal(signal.SIGINT, SysTrayApp._signal_handler)
        signal.signal(signal.SIGTERM, SysTrayApp._signal_handler)
        
        # Create a timer to check for signals
        self._signal_timer = QTimer(self)
        self._signal_timer.timeout.connect(self._check_signal)
        self._signal_timer.start(100)  # Check every 100ms
    
    @staticmethod
    def _signal_handler(sig, frame):
        """Signal handler that sets the global flag"""
        logging.info(f"Received signal {sig}, setting flag for Qt event loop")
        try:
            SysTrayApp._received_signal = True
            SysTrayApp._signal_num = sig
        except Exception as e:
            logging.error(f"Error in signal handler: {e}")
    
    def _check_signal(self):
        """Check if a signal has been received"""
        if SysTrayApp._received_signal:
            sig_name = "SIGINT" if SysTrayApp._signal_num == signal.SIGINT else "SIGTERM"
            logging.info(f"Qt event loop detected {sig_name}, shutting down gracefully")
            SysTrayApp._received_signal = False
            self._exit()

    def _setup_notifications(self):
        if shutil.which('notify-send'):
            return self.NotificationFramework.NOTIFY_SEND
        else:
            self._tray_icon.messageClicked.connect(self.on_message_clicked)
            return self.NotificationFramework.QT

    def launch_notification(self):
        return {
            self.NotificationFramework.NOTIFY_SEND: NotifySend.launch_notification,
            self.NotificationFramework.QT: self._launch_notification_fallback
            }.get(self.notification_fw, self._launch_notification_fallback)()

    def prompt_notification(self):
        return {
            self.NotificationFramework.NOTIFY_SEND: NotifySend.prompt_notification,
            self.NotificationFramework.QT: self._prompt_notification_fallback
            }.get(self.notification_fw, self._prompt_notification_fallback)()

    def cancel_notification(self):
        NotifySend.cancel_notification()

    def _launch_notification_fallback(self):
        self._tray_icon.showMessage("EyeBeeKey",
                         "Use the Generate Cache Key option to get started",
                         QSystemTrayIcon.MessageIcon.Information, 3000)

    def _prompt_notification_fallback(self):
        self._tray_icon.showMessage("EyeBeeKey",
                         "Pirate key recieved a webauthn ceremony, should I respond?",
                         QSystemTrayIcon.MessageIcon.Critical, 15000)

    def on_message_clicked(self):
        MessageQueue.notify_auth.put(QueueMessageType.USER_RESPONSE_ACCEPT)

    def _menu_setup(self):
        menu = QMenu()
        action_setup = [
                        self.__generate_platform_key_action_setup,
                        self.__generate_passkey_action_setup,
                        self.__manage_credentials_action_setup,
                        self.__exit_action_setup]
        for action in action_setup:
            menu.addAction(action())
        return menu

    def _generate_icon(self, path, fallback):
        icon = None
        icon_path = os.path.join(os.getcwd(), path)
        if os.path.exists(icon_path):
            icon = QIcon(icon_path)
        else:
            icon = QIcon.fromTheme(fallback)
        return icon

    def __generate_platform_key_action_setup(self):
        action = QAction('Generate Cache Key', self.app)
        action.triggered.connect(self.__generate_platform_key)
        return action

    def __generate_passkey_action_setup(self):
        action = QAction('Generate Passkey', self.app)
        action.triggered.connect(self.__generate_passkey)
        return action

    def __manage_credentials_action_setup(self):
        action = QAction('Manage Credentials', self.app)
        action.triggered.connect(self.__manage_credentials)
        return action

    def __exit_action_setup(self):
        action = QAction('Exit', self.app)
        action.triggered.connect(self._exit)
        return action

    def __generate_platform_key(self):
        '''
        Generate a new platform key in the specified file with the optional given secret.
        '''
        # Check if another dialog is already active
        if self._active_dialog is not None:
            QMessageBox.information(
                self,
                "Operation in Progress",
                "Please complete the current operation before starting a new one."
            )
            return
            
        dialog = CollectPlatformSecretDialog(self)
        # Connect to the dialog's signals
        dialog.accepted.connect(lambda: self.__handle_platform_key_dialog(dialog))
        dialog.rejected.connect(lambda: self.__handle_dialog_closed(dialog))
        
        # Set as active dialog
        self._active_dialog = dialog
        dialog.show()
            
    def __validate_filename_input(self, filename):
        # Ensure filename has .key extension
        if not filename.endswith('.key'):
            filename += '.key'
        
        fido_home = os.environ.get('FIDO_HOME', os.path.expanduser('~/.fido'))
        os.makedirs(fido_home, exist_ok=True)
        return os.path.join(fido_home, filename)


    def __handle_platform_key_dialog(self, dialog):
        '''
        Handle the platform key dialog's accepted signal.
        '''
        # Clear active dialog reference
        self._active_dialog = None
        try:
            pin = dialog.get_pin()
            filename = dialog.get_filename()
            
            platform_key_path = self.__validate_filename_input(filename)
            # Check if file already exists            
            if os.path.exists(platform_key_path):
                # Ask for confirmation before overwriting
                confirm = QMessageBox.question(
                    self,
                    "Confirm Overwrite",
                    f"File {filename} already exists. Overwrite?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )
                if confirm != QMessageBox.StandardButton.Yes:
                    return
            
            # Create the platform key
            nonce = pin if pin and len(pin) > 0 else None
            KeyUtils.create_platform_key(secret=nonce, filename=filename)
            
            QMessageBox.information(
                self,
                "Success",
                f"Platform key created successfully as {filename}"
            )
            
        except Exception as e:
            logging.error(f"Error processing platform key: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to create platform key: {str(e)}"
            )

    def __generate_passkey(self):
        # Check if another dialog is already active
        if self._active_dialog is not None:
            QMessageBox.information(
                self,
                "Operation in Progress",
                "Please complete the current operation before starting a new one."
            )
            return
            
        dialog = GeneratePasskeyDialog(self)
        # Connect to the dialog's signals
        dialog.accepted.connect(lambda: self.__handle_generate_passkey_dialog(dialog))
        dialog.rejected.connect(lambda: self.__handle_dialog_closed(dialog))
        
        # Set as active dialog
        self._active_dialog = dialog
        dialog.show()
        
    def __handle_generate_passkey_dialog(self, dialog):
        # Clear active dialog reference
        self._active_dialog = None
        pin, passkey_name = dialog.get_values()
        try:
            passkey_data = KeyUtils.generate_passkey()
            pin_hash = KeyUtils.get_pin_hash(pin)
            # Save passkey
            fido_home = os.environ.get("FIDO_HOME", None)
            if not fido_home:
                self._tray_icon.showMessage("EyeBeeKey",
                     "FIDO_HOME property not set, restart passkey process",
                     QSystemTrayIcon.MessageIcon.Critical, 7500)
                return
            os.makedirs(fido_home, exist_ok=True)
            passkey_path = os.path.join(fido_home, f"{passkey_name}.passkey")
            KeyUtils._save_passkey(
                passkey_data['key'],
                passkey_data['x5c'],
                [],  # No resident credentials initially
                pin_hash,
                passkey_path
            )
            QMessageBox.information(None,
                                    "Success",
                                    f"Passkey {passkey_name}.passkey created in {fido_home}")
    
        except Exception as e:
            QMessageBox.critical(None,
                                 "Error",
                                 f"Failed to generate passkey: {str(e)}")
            self._exit()

    def __manage_credentials(self):
        # Check if another dialog is already active
        if self._active_dialog is not None:
            QMessageBox.information(
                self,
                "Operation in Progress",
                "Please complete the current operation before starting a new one."
            )
            return
            
        dialog = ManageCredentialsDialog(self)
        # No special handling needed for this dialog's result
        # but we should still clean up when it's closed
        dialog.finished.connect(lambda: self.__handle_dialog_closed(dialog))
        
        # Set as active dialog
        self._active_dialog = dialog
        dialog.show()
        
    def __handle_dialog_closed(self, dialog):
        """
        Common handler for when any dialog is closed or rejected.
        Clears the active dialog reference and performs cleanup.
        """
        self._active_dialog = None
        dialog.deleteLater()

    def _threadpool_setup(self):
        threadpool = QThreadPool()
        threadpool.maxThreadCount()
        return threadpool

    def _worker_setup(self):
        return Worker(self._msg_queue_handler)

    def _msg_queue_handler(self):
        notif_threads = []
        while not self.quit:
            time.sleep(0.001)
            if MessageQueue.notify_sysapp.qsize() > 0:
                msg = MessageQueue.notify_sysapp.get()
                logging.debug(f"Got a message: {msg}")
                if msg == QueueMessageType.USER_REQUEST:
                    t = threading.Thread(target=self.prompt_notification)
                    t.start()
                    notif_threads.append(t)
                    self._tray_icon.setIcon(self.auth_icon)
                    self._tray_icon.setToolTip('Requesting Authentication...')
                    # Use QMetaObject.invokeMethod to safely call a method in the main thread
                    QMetaObject.invokeMethod(self, "start_icon_reset_timer",
                                           Qt.ConnectionType.QueuedConnection)
                elif msg == QueueMessageType.AUTH_RESPONSE:
                    self.cancel_notification()
                    self._reset_icon()
                    # Stop the timer if it's running
                    if self.icon_reset_timer.isActive():
                        self.icon_reset_timer.stop()

            tempThreadList = []
            for t in notif_threads:
                if not t.is_alive():
                    t.join()
                    tempThreadList.append(t)
            for t in tempThreadList:
                notif_threads.remove(t)

    def _exit(self):
        logging.info("Sysapp Exiting")
        MessageQueue.notify_udev.put(QueueMessageType.QUIT)
        if self.notification_fw == self.NotificationFramework.NOTIFY_SEND:
            NotifySend.cancel_notification()
        self.quit = True
        self.app.quit()

    def closeEvent(self, a0):
        # Override closeEvent to hide the window instead of closing the application
        if self._tray_icon.isVisible():
            self.hide()
            if a0:
                a0.ignore()
            else: #panic!
                self._exit()
        else:
            self._exit()
            
    @pyqtSlot()
    def start_icon_reset_timer(self):
        """Start the icon reset timer from the main thread"""
        # Start the timer to reset the icon after 15 seconds (15000 ms)
        self.icon_reset_timer.start(15000)
        
    def _reset_icon(self):
        """Reset the tray icon to the main icon and update the tooltip."""
        self._tray_icon.setIcon(self.main_icon)
        self._tray_icon.setToolTip('EyeBeePasskey')

    def _finalise(self):
        self._tray_icon.setContextMenu(self.menu)
        self._tray_icon.show()
        self.threadPool.start(self.worker)
        self.launch_notification()
        self.app.exec()


class NotifySend:
    ACCEPT = 0
    DECLINE = 1
    EXPIRE = 2

    proc = None

    @classmethod
    def prompt_notification(cls):
        timeout = 15000  # Expire notification in a minute
        cmd = ['notify-send',
            '--action=accept=Accept',
            '--action=decline=Decline',
            '--action=default=default',
            '--expire-time={}'.format(timeout),
            '--icon=info',
            '--app-name=EyeBeeKey',
            'I challenge thee',
            'Pirate key recieved a webauthn ceremony, should I respond?']
        cls.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        while cls.proc.poll() is None:
            time.sleep(0.002)
        outMsg, errMsg = cls.proc.communicate()
        outMsg, errMsg = outMsg.decode('utf-8'), errMsg.decode('utf-8')

        if outMsg == 'accept\n' or outMsg == 'default\n':
            MessageQueue.notify_auth.put(QueueMessageType.USER_RESPONSE_ACCEPT)
        else:
            MessageQueue.notify_auth.put(QueueMessageType.USER_RESPONSE_REJECT)

    @classmethod
    def cancel_notification(cls):
        if cls.proc:
            cls.proc.terminate()

    @classmethod
    def launch_notification(cls):
        cmd = ['notify-send',
            '--app-name=EyeBeeKey',
            '--icon=info', 'EyeBeeKey',
            'Starting the Pirate Passkey UHID Service']
        subprocess.Popen(cmd).communicate()

# Made with Bob
