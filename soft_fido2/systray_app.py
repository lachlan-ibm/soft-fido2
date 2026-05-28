# Copyrite IBM 2022, 2025
# IBM Confidential

import os, time, sys, traceback, threading, logging, signal
from enum import Enum
from typing import Optional, TYPE_CHECKING, cast
from PyQt6.QtGui import QIcon, QAction
from PyQt6.QtWidgets import (QApplication, QDialog, QDialogButtonBox, QHBoxLayout,
                QLabel, QLineEdit, QListWidget, QMessageBox, QPushButton, QSystemTrayIcon,
                QMenu, QVBoxLayout, QComboBox, QRadioButton, QButtonGroup, QGroupBox)
from PyQt6.QtCore import (QObject, QRunnable, QThreadPool, pyqtSignal, pyqtSlot,
                        QTimer, Qt, QMetaObject)
try:
    from soft_fido2.message_queues import QueueMessageType, MessageQueue, PlatformKeyRequest, PlatformKeyResponse
    from soft_fido2.key_pair import KeyUtils, KeyPair
except:
    from message_queues import QueueMessageType, MessageQueue, PlatformKeyRequest, PlatformKeyResponse
    from key_pair import KeyUtils, KeyPair
try:
    from soft_fido2.dbus_notify import DBusNotifier, DBusNotificationListener
except ImportError:
    # D-Bus not available, will use Qt fallback
    DBusNotifier = None
    DBusNotificationListener = None


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


class SettingsDialog(QDialog):
    # UI Text Constants
    TITLE = "AyeBeKey Settings"
    CACHE_GROUP_TITLE = "Platform Key Configuration:"
    PASSKEY_GROUP_TITLE = "Passkey Wallet Generation:"
    CRED_GROUP_TITLE = "Resident Credential Management:"
    TPM_RADIO_TEXT = "TPM-based Platform Key"
    FILE_RADIO_TEXT = "File-based Platform Key"
    CREATE_CACHE_BTN_TEXT = "Create/Update Platform Key"
    GENERATE_PASSKEY_BTN_TEXT = "Generate Passkey Wallet"
    LOAD_CREDS_BTN_TEXT = "(re)Load Credentials"
    DELETE_CRED_BTN_TEXT = "Delete Credential"
    CLOSE_BTN_TEXT = "Close"
    PIN_LABEL = "PIN:"
    PASSKEY_NAME_LABEL = "Passkey wallet name:"
    PASSKEY_LABEL = "Passkey wallet:"
    PIN_PLACEHOLDER = "Default: 00000000"
    PASSKEY_NAME_PLACEHOLDER = "Default: default"
    CREDS_LIST_HEADER = "User ID                           |  Relying Party ID"
    
    # Tooltip Help Text
    CACHE_GROUP_TOOLTIP = (
        "Platform Key Configuration\n\n"
        "What: The platform key is used to encrypt part of the passkey wallet secret.\n\n"
        "Why: During the pin auth ceremony the client (browser) will only send half of the secret entered by the user. This key allows EyeBeKey to securely store and decrypt the other half of the secret to unlock a passkey wallet.\n\n"
        "How: Choose TPM (hardware-based, more secure) or File-based storage, then click 'Create/Update Platform Key'."
    )
    PASSKEY_GROUP_TOOLTIP = (
        "Passkey Wallet Generation\n\n"
        "What: A passkey wallet is an encrypted container that stores your FIDO2 credentials.\n\n"
        "Why: Required to hold your authentication credentials for websites and services.\n\n"
        "How: Enter a PIN (default: 00000000), optionally name your wallet (default: 'default'), then click 'Generate Passkey Wallet'."
    )
    CRED_GROUP_TOOLTIP = (
        "Resident Credential Management\n\n"
        "What: View and manage FIDO2 resident credentials stored in your passkey wallet.\n\n"
        "Why: Allows you to see which resident credentials are stored and delete ones you no longer need. This action also updates the encrypted half of the secret that is stored in the wallet for the pin auth ceremony.\n\n"
        "How: Enter your PIN, select a passkey wallet, click 'Load Credentials' to view, then select and delete unwanted credentials."
    )
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(self.TITLE)
        
        # Set window icon to vanilla icon from parent if available
        if parent and hasattr(parent, 'vanilla_icon'):
            self.setWindowIcon(parent.vanilla_icon)
        
        self.fido_home = os.environ.get('FIDO_HOME', os.path.expanduser('~/.fido'))
        
        # Initialize state
        self.credentials = []
        self.passkey = None
        self.tpm_available = self._check_tpm_available()
        
        # Build UI
        main_layout = QVBoxLayout()
        main_layout.addWidget(self._create_cache_group())
        main_layout.addWidget(self._create_passkey_group())
        main_layout.addWidget(self._create_credentials_group())
        main_layout.addWidget(self._create_close_button())

        self.setLayout(main_layout)
        
        # Set initial focus based on current state after dialog is fully shown
        QTimer.singleShot(0, self._set_initial_focus)
    
    def _create_labeled_input(self, label_text, placeholder="", password=False):
        """Create a horizontal layout with label and input field."""
        layout = QHBoxLayout()
        layout.addWidget(QLabel(label_text))
        input_field = QLineEdit()
        if password:
            input_field.setEchoMode(QLineEdit.EchoMode.Password)
        if placeholder:
            input_field.setPlaceholderText(placeholder)
        layout.addWidget(input_field)
        return layout, input_field
    
    def _create_button(self, text, handler):
        """Create a button with connected handler."""
        button = QPushButton(text)
        button.clicked.connect(handler)
        # Prevent button from being triggered by Enter key when it doesn't have focus
        button.setAutoDefault(False)
        return button
    
    def _create_cache_group(self):
        """Create platform key configuration section."""
        group = QGroupBox(self.CACHE_GROUP_TITLE)
        group.setToolTip(self.CACHE_GROUP_TOOLTIP)
        layout = QVBoxLayout()
        
        # Radio buttons
        layout.addLayout(self._create_cache_radio_buttons())
        
        # Status label
        self.status_label = QLabel()
        self._update_cache_status()
        layout.addWidget(self.status_label)
        
        # Create button - store reference for focus management
        self.create_cache_key_button = self._create_button(
            self.CREATE_CACHE_BTN_TEXT,
            self._handle_create_cache_key
        )
        layout.addWidget(self.create_cache_key_button)
        
        group.setLayout(layout)
        return group
    
    def _create_cache_radio_buttons(self):
        """Create radio button layout for cache type selection."""
        layout = QHBoxLayout()
        self.cache_type_group = QButtonGroup(self)
        
        self.tpm_radio = QRadioButton(self.TPM_RADIO_TEXT)
        self.file_radio = QRadioButton(self.FILE_RADIO_TEXT)
        
        self.cache_type_group.addButton(self.tpm_radio, 0)
        self.cache_type_group.addButton(self.file_radio, 1)
        
        self.tpm_radio.setEnabled(self.tpm_available)
        
        # Set initial selection based on which key is actually loaded
        self._set_radiobtn_from_loaded_key()
        
        self.cache_type_group.buttonClicked.connect(self._update_cache_status)
        
        layout.addWidget(self.tpm_radio)
        layout.addWidget(self.file_radio)
        return layout
    
    def _set_radiobtn_from_loaded_key(self):
        """Set radio button selection based ONLY on user's saved preference in platform.cfg."""
        # Check if parent has a saved preference from platform.cfg
        parent = self.parent()
        if parent and hasattr(parent, '_preferred_key_type'):
            preferred_type = getattr(parent, '_preferred_key_type', None)
            if preferred_type is not None:
                if preferred_type == 'tpm':
                    self.tpm_radio.setChecked(True)
                    self.file_radio.setChecked(False)
                    return
                elif preferred_type == 'file':
                    self.tpm_radio.setChecked(False)
                    self.file_radio.setChecked(True)
                    return
        
        # No preference saved - default based on TPM availability
        self.tpm_radio.setChecked(self.tpm_available)
        self.file_radio.setChecked(not self.tpm_available)
    
    def _create_passkey_group(self):
        """Create passkey generation section."""
        group = QGroupBox(self.PASSKEY_GROUP_TITLE)
        group.setToolTip(self.PASSKEY_GROUP_TOOLTIP)
        layout = QVBoxLayout()
        
        # PIN input - store reference for focus management
        pin_layout, self.passkey_pin_input = self._create_labeled_input(
            self.PIN_LABEL,
            placeholder=self.PIN_PLACEHOLDER,
            password=True
        )
        layout.addLayout(pin_layout)
        
        # Name input
        name_layout, self.passkey_name_input = self._create_labeled_input(
            self.PASSKEY_NAME_LABEL,
            placeholder=self.PASSKEY_NAME_PLACEHOLDER
        )
        layout.addLayout(name_layout)
        
        # Generate button - store reference for focus management
        self.generate_passkey_button = self._create_button(
            self.GENERATE_PASSKEY_BTN_TEXT,
            self._handle_generate_passkey
        )
        layout.addWidget(self.generate_passkey_button)
        
        # Connect Enter key to trigger generate passkey
        self.passkey_pin_input.returnPressed.connect(self._handle_generate_passkey)
        
        group.setLayout(layout)
        return group
    
    def _create_credentials_group(self):
        """Create resident credential management section."""
        group = QGroupBox(self.CRED_GROUP_TITLE)
        group.setToolTip(self.CRED_GROUP_TOOLTIP)
        layout = QVBoxLayout()
        
        # PIN input - store reference for focus management
        cred_pin_layout, self.cred_pin_input = self._create_labeled_input(
            self.PIN_LABEL,
            password=True
        )
        layout.addLayout(cred_pin_layout)
        
        # Passkey selection
        layout.addLayout(self._create_passkey_selector())
        
        # Credentials list
        layout.addWidget(QLabel(self.CREDS_LIST_HEADER))
        self.creds_list = QListWidget()
        layout.addWidget(self.creds_list)
        
        # Action buttons
        layout.addLayout(self._create_credential_buttons())
        
        # Connect Enter key to trigger reload credentials
        self.cred_pin_input.returnPressed.connect(self._handle_reload_credentials)
        
        group.setLayout(layout)
        return group
    
    def _create_passkey_selector(self):
        """Create passkey dropdown selector."""
        layout = QHBoxLayout()
        layout.addWidget(QLabel(self.PASSKEY_LABEL))
        self.cred_passkey_input = QComboBox()
        self._load_passkey_files()
        layout.addWidget(self.cred_passkey_input)
        return layout
    
    def _create_credential_buttons(self):
        """Create credential action buttons."""
        layout = QHBoxLayout()
        
        # Store reference for focus management
        self.reload_creds_button = self._create_button(
            self.LOAD_CREDS_BTN_TEXT,
            self._load_credentials
        )
        layout.addWidget(self.reload_creds_button)
        
        layout.addWidget(self._create_button(
            self.DELETE_CRED_BTN_TEXT,
            self._delete_credential
        ))
        return layout
    
    def _create_close_button(self):
        """Create dialog close button."""
        return self._create_button(self.CLOSE_BTN_TEXT, self.accept)
    
    def _check_tpm_available(self):
        try:
            from soft_fido2.tpm_device import TPMDevice
            return TPMDevice.is_available()
        except:
            return False
    
    def _check_cache_key_status(self, use_tpm):
        if use_tpm:
            try:
                from soft_fido2.tpm_device import TPMDevice
                tpm = TPMDevice()
                tpm.get_key()
                return True
            except:
                return False
        else:
            platform_key_path = os.path.join(self.fido_home, 'platform.key')
            return os.path.exists(platform_key_path)
    
    def _update_cache_status(self):
        use_tpm = self.tpm_radio.isChecked()
        has_key = self._check_cache_key_status(use_tpm)
        
        if has_key:
            key_type = "TPM" if use_tpm else "File-based"
            self.status_label.setText(f"✓ Valid {key_type} platform key exists")
            self.status_label.setStyleSheet("color: green; font-weight: bold;")
        else:
            key_type = "TPM" if use_tpm else "File-based"
            self.status_label.setText(f"⚠ No valid {key_type} platform key found")
            self.status_label.setStyleSheet("color: orange; font-weight: bold;")
    
    def _determine_initial_focus_state(self):
        """
        Determine which UI element should receive initial focus based on app state.
        
        Returns:
            str: One of 'platform_key', 'passkey_generation', 'credential_management'
        """
        # Check if platform key exists (check both TPM and file-based)
        has_tpm_key = self._check_cache_key_status(use_tpm=True)
        has_file_key = self._check_cache_key_status(use_tpm=False)
        has_platform_key = has_tpm_key or has_file_key
        
        if not has_platform_key:
            return 'platform_key'
        
        # Check if any passkeys exist
        passkey_files = self._get_passkey_files()
        has_passkeys = len(passkey_files) > 0
        
        if not has_passkeys:
            return 'passkey_generation'
        
        return 'credential_management'
    
    def _set_initial_focus(self):
        """Set initial focus based on application state."""
        focus_state = self._determine_initial_focus_state()
        
        if focus_state == 'platform_key':
            self.create_cache_key_button.setFocus()
        elif focus_state == 'passkey_generation':
            self.passkey_pin_input.setFocus()
        elif focus_state == 'credential_management':
            self.cred_pin_input.setFocus()
    
    def _handle_reload_credentials(self):
        """Handle Enter key press in credential management PIN field."""
        # Trigger the reload credentials button action
        self._load_credentials()
    
    def _handle_create_cache_key(self):
        use_tpm = self.tpm_radio.isChecked()
        
        if use_tpm:
            self._create_tpm_cache_key()
        else:
            self._create_file_cache_key()
    
    def _create_tpm_cache_key(self):
        try:
            from soft_fido2.tpm_device import TPMDevice
            tpm = TPMDevice()
            tpm.create_key()
            
            # Save preference to parent app
            parent = self.parent()
            if parent and hasattr(parent, '_save_preferred_key_type'):
                cast('SysTrayApp', parent)._save_preferred_key_type('tpm')
            
            QMessageBox.information(
                self,
                "Success",
                "TPM Platform key created successfully"
            )
            self._update_cache_status()
            # Update focus after platform key creation
            self._set_initial_focus()
            
        except Exception as e:
            logging.exception(f"Failed to create TPM Platform key: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to create TPM Platform key: {str(e)}"
            )
    
    def _save_platform_key(self, passphrase, filename):
        try:
            if not filename.endswith('.key'):
                filename += '.key'

            os.makedirs(self.fido_home, exist_ok=True)
            platform_key_path = os.path.join(self.fido_home, filename)
            
            if os.path.exists(platform_key_path):
                confirm = QMessageBox.question(
                    self,
                    "Confirm Overwrite",
                    f"File {filename} already exists. Overwrite? Any existing platform credentials may be lost",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )
                if confirm != QMessageBox.StandardButton.Yes:
                    return
            
            nonce = passphrase.encode('utf-8') if passphrase and len(passphrase) > 0 else None
            KeyUtils.create_platform_key(secret=nonce, filename=filename)
            
            # Save preference to parent app
            parent = self.parent()
            if parent and hasattr(parent, '_save_preferred_key_type'):
                cast('SysTrayApp', parent)._save_preferred_key_type('file')
            
            QMessageBox.information(
                self,
                "Success",
                f"File-based platform key created successfully as {filename}"
            )
            self._update_cache_status()
            # Update focus after platform key creation
            self._set_initial_focus()
            
        except Exception as e:
            logging.exception(f"Failed to create file-based platform key: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to create file-based platform key: {str(e)}"
            )

    def _create_file_cache_key(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Create File-based Platform Key")
        layout = QVBoxLayout()
        
        # Passphrase input
        passphrase_layout = QHBoxLayout()
        passphrase_layout.addWidget(QLabel("Passphrase:"))
        passphrase_input = QLineEdit()
        passphrase_input.setEchoMode(QLineEdit.EchoMode.Password)
        passphrase_layout.addWidget(passphrase_input)
        layout.addLayout(passphrase_layout)
        
        # Filename input
        filename_layout = QHBoxLayout()
        filename_layout.addWidget(QLabel("Filename:"))
        filename_input = QLineEdit()
        filename_input.setText("platform.key")
        filename_layout.addWidget(filename_input)
        layout.addLayout(filename_layout)
        
        # Buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)
        layout.addWidget(button_box)
        
        dialog.setLayout(layout)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._save_platform_key(passphrase_input.text(), 
                                    filename_input.text())
    
    def _get_passkey_files(self):
        """
        Returns a list of .passkey files in the specified directory.
        Checks for corresponding .stash files and logs warnings if missing.
        
        Returns:
            A list of full paths to .passkey files
        """
        passkey_files = []
        if os.path.exists(self.fido_home):
            for filename in os.listdir(self.fido_home):
                if filename.endswith('.passkey'):
                    passkey_path = os.path.join(self.fido_home, filename)
                    
                    # Check for corresponding .stash file
                    base_name = filename[:-8]  # Remove .passkey
                    stash_path = os.path.join(self.fido_home, base_name + '.stash')
                    
                    if os.path.exists(stash_path):
                        passkey_files.append(passkey_path)
                    else:
                        # Log warning but don't include file
                        logging.warning(f"Found {filename} without corresponding .stash file.")
        return passkey_files
    
    def _load_passkey_files(self):
        """Load passkey files and populate the dropdown."""
        passkey_files = self._get_passkey_files()
        for passkey_file in passkey_files:
            self.cred_passkey_input.addItem(os.path.basename(passkey_file))
    
    def _try_cache_pin(self, nonce, passkey_path):
        """Load then Save passkey. This will update the cached upper pin hash
        with the provided secret if it successfully unpacks the passkey file."""
        self.passkey = KeyUtils._load_passkey(nonce, passkey_path)
        self.credentials = self.passkey['res.creds']
        KeyUtils._save_passkey(
            self.passkey['key'],
            self.passkey['x5c'],
            self.passkey['res.creds'],
            self.passkey['pin.hash'],
            passkey_path
        )
    
    def _load_credentials(self):
        try:
            pin = self.cred_pin_input.text()
            nonce = KeyUtils.get_pin_hash(pin)
            passkey_name = self.cred_passkey_input.currentText()
            passkey_path = os.path.join(self.fido_home, passkey_name)
            
            self._try_cache_pin(nonce, passkey_path)
            
            self.creds_list.clear()
            
            for cred in self.credentials:
                rp_id_bytes = cred.get('rp.id', 'cred.parsing.error')
                user_id_bytes = cred.get('user.id', 'cred.parsing.error')
                
                rp_id = rp_id_bytes.decode('utf-8') if isinstance(rp_id_bytes, bytes) \
                                else str(rp_id_bytes)
                user_id_value = user_id_bytes.hex().upper() if isinstance(user_id_bytes, bytes) \
                                else str(user_id_bytes)
                user_id = user_id_value[:15]
                if len(user_id_value) > 15:
                    user_id += '...'
                else:
                    user_id += ' ' * (18 - len(user_id_value))
                
                item_text = f"{user_id} | {rp_id}"
                self.creds_list.addItem(item_text)
            
            # Show success message
            QMessageBox.information(
                self,
                "Success",
                f"Successfully loaded {len(self.credentials)} credential(s) and cached PIN for {passkey_name}"
            )
                
        except Exception as e:
            logging.exception(f"failed to load the credentials from {self.cred_passkey_input.currentText()} : {e}")
            self.creds_list.clear()
            self.passkey = None
            self.credentials = []
            self.cred_pin_input.clear()
            self.cred_pin_input.setFocus()
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to unlock passkey. Please check your PIN and try again.\n\nError: {str(e)}"
            )
    
    def _delete_credential(self):
        selected_items = self.creds_list.selectedItems()
        if not selected_items:
            return
        
        confirm = QMessageBox.question(
            self,
            "Confirm Deletion",
            f"Are you sure you want to delete {len(selected_items)} selected credential(s)?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if confirm != QMessageBox.StandardButton.Yes:
            return
        
        selected_indices = [self.creds_list.row(item) for item in selected_items]
        
        for index in sorted(selected_indices, reverse=True):
            if 0 <= index < len(self.credentials):
                del self.credentials[index]
        self._write_passkey()
    
    def _write_passkey(self):
        if not self.passkey:
            return
        
        self.passkey['res.creds'] = self.credentials
        try:
            passkey_path = os.path.join(self.fido_home, self.cred_passkey_input.currentText())
            
            KeyUtils._save_passkey(
                self.passkey['key'],
                self.passkey['x5c'],
                self.credentials,
                self.passkey['pin.hash'],
                passkey_path
            )
            
            self._load_credentials()
            
            QMessageBox.information(
                self,
                "Success",
                "Selected credentials have been deleted successfully."
            )
            
            # Update focus after credential deletion (check if passkeys still exist)
            self._set_initial_focus()
            
        except Exception as e:
            logging.exception(f"Failed to save updated passkey: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to delete credentials: {str(e)}"
            )
    
    def _handle_generate_passkey(self):
        pin = self.passkey_pin_input.text() or "00000000"
        passkey_name = self.passkey_name_input.text() or "default"
        
        try:
            passkey_data = KeyUtils.generate_passkey()
            pin_hash = KeyUtils.get_pin_hash(pin)
            
            os.makedirs(self.fido_home, exist_ok=True)
            passkey_path = os.path.join(self.fido_home, f"{passkey_name}.passkey")
            
            KeyUtils._save_passkey(
                passkey_data['key'],
                passkey_data['x5c'],
                [],
                pin_hash,
                passkey_path
            )
            
            QMessageBox.information(
                self,
                "Success",
                f"Passkey {passkey_name}.passkey created in {self.fido_home}"
            )
            
            self.passkey_pin_input.clear()
            self.passkey_name_input.clear()
            
            # Refresh the passkey dropdown in the credential management section
            self.cred_passkey_input.clear()
            self._load_passkey_files()
            
            # Update focus after passkey generation
            self._set_initial_focus()
            
        except Exception as e:
            logging.exception(f"Failed to generate passkey: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to generate passkey: {str(e)}"
            )

class SysTrayApp(QDialog):
    class NotificationFramework:
        DBUS = 0           # Direct D-Bus (primary)
        QT = 1             # Qt system tray (fallback only)
    
    class AppState(Enum):
        LOCKED = "locked"
        UNLOCKED = "unlocked"
    
    # Global flag for signal handling
    _received_signal = False
    _signal_num = 0
    
    def __init__(self):
        self.app = QApplication(sys.argv)
        super().__init__()
        
        # Initialize state to LOCKED
        self._current_state = self.AppState.LOCKED
        self._platform_key = None  # Can be KeyPair or TPMKeyPair
        self._preferred_key_type = self._load_preferred_key_type()  # Load preference early
        
        # Load all icon variants
        self.vanilla_icon = self._generate_icon('main_icon.svg', QIcon.ThemeIcon.DialogPassword)
        self.locked_icon = self._generate_icon('main_icon_locked.svg', QIcon.ThemeIcon.DialogPassword)
        self.unlocked_icon = self._generate_icon('main_icon_unlocked.svg', QIcon.ThemeIcon.DialogPassword)
        self.main_icon = self.locked_icon  # Start locked
        self.auth_icon = self._generate_icon('auth_request.png',
                                            QIcon.ThemeIcon.DialogWarning)
        
        # Create the tray icon as a member variable
        self._tray_icon = QSystemTrayIcon(self.main_icon, self)
        self._tray_icon.setToolTip('AyeBeeKey')

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
        
        # Attempt auto-load before finalizing
        self._auto_load_platform_key()
        
        self._finalise()
    
    def _get_config_path(self):
        """Get path to platform configuration file"""
        fido_home = os.environ.get('FIDO_HOME', os.path.expanduser('~/.fido'))
        return os.path.join(fido_home, 'platform.cfg')
    
    def _load_preferred_key_type(self):
        """Load user's preferred platform key type from config file.
        
        Returns:
            str: 'tpm' or 'file', or None if no preference saved
        """
        config_path = self._get_config_path()
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    key_type = f.read().strip()
                    if key_type in ('tpm', 'file'):
                        logging.info(f"Loaded preferred key type: {key_type}")
                        return key_type
            except Exception as e:
                logging.warning(f"Failed to load key type preference: {e}")
        return None
    
    def _save_preferred_key_type(self, key_type):
        """Save user's preferred platform key type to config file.
        
        Args:
            key_type: 'tpm' or 'file'
        """
        if key_type not in ('tpm', 'file'):
            logging.error(f"Invalid key type: {key_type}")
            return
        
        config_path = self._get_config_path()
        try:
            with open(config_path, 'w') as f:
                f.write(key_type)
            logging.info(f"Saved preferred key type: {key_type}")
            # Update the in-memory preference so it's immediately available
            self._preferred_key_type = key_type
        except Exception as e:
            logging.error(f"Failed to save key type preference: {e}")
    
    def _check_platform_key_exists(self):
        """Check if platform.key exists in FIDO_HOME"""
        fido_home = os.environ.get('FIDO_HOME', os.path.expanduser('~/.fido'))
        platform_key_path = os.path.join(fido_home, 'platform.key')
        return os.path.exists(platform_key_path)
    
    def _set_state(self, state):
        """Set the application state and update icon"""
        self._current_state = state
        self._update_icon_for_state()
    
    def _is_locked(self) -> bool:
        """Check if the application is locked"""
        return self._current_state == self.AppState.LOCKED
    
    def _update_icon_for_state(self):
        """Update the tray icon based on current state"""
        if self._current_state == self.AppState.LOCKED:
            self._tray_icon.setIcon(self.locked_icon)
            self._tray_icon.setToolTip('AyeBeKey - Locked')
        else:
            self._tray_icon.setIcon(self.unlocked_icon)
            self._tray_icon.setToolTip('AyeBeKey - Unlocked')
    
    def _auto_load_platform_key(self):
        """Attempt to load platform key on startup based on user's preference.
        
        Priority order:
        1. If platform.cfg exists: use configured preference
        2. If no config: try TPM first (if available), then file without password
        3. Stay locked and wait for user action
        """
        if self._preferred_key_type is not None:
            # User has a saved preference
            if self._preferred_key_type == 'tpm':
                if self._try_load_tpm_key():
                    return
                logging.info("TPM key not available, staying locked")
                return
            elif self._preferred_key_type == 'file':
                if self._try_load_filesystem_key(password=None):
                    return
                logging.info("File key requires password or doesn't exist, staying locked")
                return
        
        # No preference set - try fallbacks
        if self._try_load_tpm_key():
            return
        # Fallback to file without password
        if self._try_load_filesystem_key(password=None):
            return
        logging.info("Platform key requires password or doesn't exist")
    
    def _try_load_tpm_key(self) -> bool:
        """Try to load platform key from TPM"""
        try:
            from soft_fido2.tpm_device import TPMDevice
            tpm = TPMDevice()
            handle, public_key = tpm.get_key()
            # Convert TPM key to KeyPair format
            self._platform_key = self._convert_tpm_to_keypair(handle, public_key)
            self._set_state(self.AppState.UNLOCKED)
            logging.info("Platform key loaded from TPM")
            return True
        except Exception as e:
            logging.debug(f"TPM key not available: {e}")
            return False
    
    def _convert_tpm_to_keypair(self, handle, public_key):
        """Convert TPM key to KeyPair-compatible wrapper"""
        from soft_fido2.tpm_device import TPMDevice

        class TPMKeyPair:
            def __init__(self, handle, public_key):
                self.handle = handle
                self.public_key = public_key
                self.is_tpm = True
                self.tpm_device = TPMDevice()
            
            def get_private(self):
                return self.handle
            
            def get_public(self):
                return self.public_key

            def tpm_encrypt(self, plaintext, public_key):
                return self.tpm_device.ecdh_encrypt(
                    plaintext, public_key, persistent_handle=self.handle
                )

            def tpm_decrypt(self, encrypted):
                return self.tpm_device.ecdh_decrypt(
                    encrypted, persistent_handle=self.handle
                )
        
        return TPMKeyPair(handle, public_key)
    
    def _try_load_filesystem_key(self, password: Optional[bytes]) -> bool:
        """Try to load platform key from filesystem"""
        try:
            platform_key_path = os.path.join(
                os.environ.get('FIDO_HOME', os.path.expanduser('~/.fido')),
                'platform.key'
            )
            if not os.path.exists(platform_key_path):
                return False
            
            with open(platform_key_path, 'rb') as f:
                key_pem = f.read()
            
            self._platform_key = KeyPair.load_key_pair(key_pem, password)
            self._set_state(self.AppState.UNLOCKED)
            logging.info("Platform key loaded from filesystem")
            return True
        except Exception as e:
            if password is None:
                logging.debug(f"Platform key requires password: {e}")
            else:
                logging.error(f"Failed to load platform key: {e}")
            return False

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
            # Stop the timer first to prevent re-entry
            self._signal_timer.stop()
            self._exit()

    def _setup_notifications(self):
        """Determine which notification framework to use - D-Bus first, Qt fallback"""
        # Initialize instance variables for D-Bus notification tracking
        self._current_notification_id = None
        self._dbus_notifier = None
        self._dbus_listener = None
        
        # Try D-Bus notification service (primary method with full interactivity)
        if DBusNotifier is not None and DBusNotificationListener is not None:
            self._dbus_notifier = DBusNotifier()
            if self._dbus_notifier.is_available():
                # Initialize D-Bus listener for interactive notifications
                self._dbus_listener = DBusNotificationListener(
                    on_action_callback=self._handle_notification_action,
                    on_closed_callback=self._handle_notification_closed
                )
                if self._dbus_listener.is_available():
                    logging.info("Using D-Bus notifications with interactive support")
                    return self.NotificationFramework.DBUS
                else:
                    logging.warning("D-Bus listener unavailable, falling back to Qt")
            else:
                logging.warning("D-Bus notifier unavailable, falling back to Qt")
        else:
            logging.info("D-Bus module not available, using Qt fallback")
        
        # Fallback to Qt system tray notifications (limited functionality)
        self._tray_icon.messageClicked.connect(self.on_message_clicked)
        logging.info("Using Qt system tray notifications (no interactive buttons)")
        return self.NotificationFramework.QT

    def launch_notification(self):
        """
        Smart startup notification - only show if user action needed:
        - If locked: Show "get started" message (needs platform key setup)
        - If unlocked: No notification (app in good state)
        """
        if self._current_state == self.AppState.LOCKED:
            self._show_notification(
                title="AyeBeKey",
                message="Use the Generate Cache Key option to get started",
                urgency="normal",
                timeout=3000
            )
        # else: No notification when app is in good state

    def prompt_notification(self, fprint_pending=False):
        """Show authentication request notification"""
        self._show_notification(
            title="Aye.Be.Key UV",
            message="User Verification: accept" + ("? or scan fingerprint" if fprint_pending else "?"),
            urgency="critical",
            timeout=15000,
            actions=[('accept', 'Accept'), ('decline', 'Decline')] if self.notification_fw == self.NotificationFramework.DBUS else None
        )

    def cancel_notification(self):
        """Cancel active notification"""
        if self.notification_fw == self.NotificationFramework.DBUS:
            self._cancel_notification_dbus()
        # Qt notifications don't need explicit cancellation

    def _show_notification(self, title, message, urgency="normal", timeout=3000, actions=None):
        """
        Unified notification display - routes to Qt or D-Bus based on framework
        
        Args:
            title: Notification title
            message: Notification message
            urgency: "low", "normal", or "critical"
            timeout: Display duration in milliseconds
            actions: List of (action_key, button_label) tuples for D-Bus only
        """
        if self.notification_fw == self.NotificationFramework.DBUS:
            self._show_notification_dbus(title, message, urgency, timeout, actions)
        else:
            self._show_notification_qt(title, message, urgency, timeout)

    def _show_notification_qt(self, title, message, urgency, timeout):
        """Display notification using Qt system tray"""
        icon_map = {
            "low": QSystemTrayIcon.MessageIcon.Information,
            "normal": QSystemTrayIcon.MessageIcon.Information,
            "critical": QSystemTrayIcon.MessageIcon.Critical
        }
        self._tray_icon.showMessage(title, message, icon_map.get(urgency, QSystemTrayIcon.MessageIcon.Information), timeout)

    def _show_notification_dbus(self, title, message, urgency, timeout, actions=None):
        """Display notification using D-Bus"""
        if not self._dbus_notifier:
            return
        
        urgency_map = {
            "low": self._dbus_notifier.URGENCY_LOW,
            "normal": self._dbus_notifier.URGENCY_NORMAL,
            "critical": self._dbus_notifier.URGENCY_CRITICAL
        }
        
        # Set ceremony icon for authentication requests
        if urgency == "critical" and actions:
            self._set_ceremony_icon()
            icon_path = os.path.abspath(os.path.join(
                os.path.dirname(__file__), 'icons', 'main_icon.svg'
            ))
        else:
            icon_path = 'dialog-password'
        
        self._current_notification_id = self._dbus_notifier.send_notification(
            title=title,
            message=message,
            urgency=urgency_map.get(urgency, self._dbus_notifier.URGENCY_NORMAL),
            timeout=timeout,
            actions=actions or [],
            hints={'category': 'device'} if actions else {},
            icon=icon_path
        )

    def _cancel_notification_dbus(self):
        """Cancel active notification"""
        if self._dbus_notifier and self._current_notification_id is not None:
            self._dbus_notifier.close_notification(self._current_notification_id)
            self._current_notification_id = None

    def _handle_notification_action(self, notification_id, action_key):
        """Handle D-Bus notification action callback"""
        logging.info(f"Notification action: {action_key}")
        
        if action_key == 'accept':
            # User clicked Accept button (authentication)
            MessageQueue.notify_auth.put(QueueMessageType.USER_RESPONSE_ACCEPT)
            # Restore status icon after user response
            self._restore_status_icon()
        elif action_key == 'decline':
            # User clicked Decline button (authentication)
            MessageQueue.notify_auth.put(QueueMessageType.USER_RESPONSE_REJECT)
            # Restore status icon after user response
            self._restore_status_icon()
        elif action_key == 'unlock':
            # User clicked Unlock button (platform key)
            self.__open_settings()
        elif action_key == 'later':
            # User clicked Later button (platform key)
            logging.info("User chose to unlock platform key later")

    def _handle_notification_closed(self, notification_id, reason):
        """Handle notification closed event"""
        reason_map = {1: 'expired', 2: 'dismissed', 3: 'closed by app', 4: 'undefined'}
        reason_str = reason_map.get(reason, f'unknown({reason})')
        logging.info(f"Notification closed: {reason_str}")
        
        # Restore status icon when notification expires or is dismissed
        if reason in (1, 2):  # 1=expired, 2=dismissed by user
            self._restore_status_icon()
            if reason == 1:  # Expired - treat as rejection
                MessageQueue.notify_auth.put(QueueMessageType.USER_RESPONSE_REJECT)

    def _set_ceremony_icon(self):
        """Set tray icon to main_icon.svg during authentication ceremony"""
        icon_path = os.path.join(os.path.dirname(__file__), 'icons', 'main_icon.svg')
        if os.path.exists(icon_path):
            self._tray_icon.setIcon(QIcon(icon_path))
            logging.info("Set ceremony icon: main_icon.svg")

    def _restore_status_icon(self):
        """Restore tray icon to locked/unlocked status after ceremony"""
        self._update_icon_for_state()
        logging.info("Restored status icon")


    def on_message_clicked(self):
        MessageQueue.notify_auth.put(QueueMessageType.USER_RESPONSE_ACCEPT)

    def _menu_setup(self):
        menu = QMenu()
        action_setup = [
                        self.__settings_action_setup,
                        self.__exit_action_setup]
        for action in action_setup:
            menu.addAction(action())
        return menu

    def _generate_icon(self, path, fallback):
        icon = None
        # Try to find icon relative to the module directory
        module_dir = os.path.dirname(os.path.abspath(__file__))
        icon_path = os.path.join(module_dir, 'icons', path)
        if os.path.exists(icon_path):
            icon = QIcon(icon_path)
        else:
            # Fallback to theme icon
            icon = QIcon.fromTheme(fallback)
        return icon

    def __settings_action_setup(self):
        action = QAction('Settings', self.app)
        action.triggered.connect(self.__open_settings)
        return action

    def __exit_action_setup(self):
        action = QAction('Exit', self.app)
        action.triggered.connect(self._exit)
        return action

    def __open_settings(self):
        # Check if another dialog is already active
        if self._active_dialog is not None:
            QMessageBox.information(
                self,
                "Operation in Progress",
                "Please complete the current operation before starting a new one."
            )
            return
            
        dialog = SettingsDialog(self)
        dialog.finished.connect(lambda: self.__handle_dialog_closed(dialog))
        
        # Set as active dialog
        self._active_dialog = dialog
        dialog.exec()
        # Clean up after dialog closes
        self.__handle_dialog_closed(dialog)
        
    def __handle_dialog_closed(self, dialog):
        """
        Common handler for when any dialog is closed or rejected.
        Clears the active dialog reference and performs cleanup.
        """
        self._active_dialog = None
        dialog.deleteLater()
        
        # Check if platform key was created and update state accordingly
        if self._check_platform_key_exists() and self._is_locked():
            # Platform key now exists, try to auto-load it
            self._auto_load_platform_key()

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
            
            # Handle platform key requests
            if MessageQueue.platform_key_requests.qsize() > 0:
                request = MessageQueue.platform_key_requests.get()
                self._handle_platform_key_request(request)
            
            if MessageQueue.notify_sysapp.qsize() > 0:
                msg = MessageQueue.notify_sysapp.get()
                logging.debug(f"Got a message: {msg}")
                if msg == QueueMessageType.USER_REQUEST or msg == QueueMessageType.USER_REQUEST_FPRINT:
                    t = threading.Thread(target=self.prompt_notification,
                            kwargs={'fprint_pending': msg == QueueMessageType.USER_REQUEST_FPRINT})
                    t.start()
                    notif_threads.append(t)
                    self._tray_icon.setIcon(self.auth_icon)
                    self._tray_icon.setToolTip('Aye.Be.Key UV')
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
    
    def _handle_platform_key_request(self, request: PlatformKeyRequest):
        """Handle platform key request from passkey_device"""
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

    def _exit(self):
        logging.info("Sysapp Exiting")
        MessageQueue.notify_udev.put(QueueMessageType.QUIT)
        if self.notification_fw == self.NotificationFramework.DBUS:
            self._cancel_notification_dbus()
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
        """Reset the tray icon to the state-appropriate icon and update the tooltip."""
        self._update_icon_for_state()

    def _finalise(self):
        self._tray_icon.setContextMenu(self.menu)
        self._tray_icon.show()
        self.threadPool.start(self.worker)
        self.launch_notification()
        self.app.exec()


# Made with Bob
