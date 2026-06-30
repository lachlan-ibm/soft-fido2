"""Settings Dialog for FIDO2 Authenticator Configuration.

This module provides the main settings dialog UI for managing platform keys,
passkey wallets, and credentials. Business logic is delegated to service classes
in the qt_svc package.

Key Features:
    - Platform key configuration (TPM or file-based)
    - Passkey wallet generation and selection
    - Credential management (load, view, delete)
    - Advanced configuration access

Example:
    dialog = SettingsDialog(parent=main_window, device_manager=device_mgr)
    dialog.exec()
"""

# Copyrite IBM 2022, 2025
# IBM Confidential

import os
import logging
from typing import cast, Any

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QRadioButton, QButtonGroup, QGroupBox, QComboBox, QListWidget,
    QMessageBox
)
from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QIcon

try:
    from soft_fido2.qt.svc.platform_key_service import PlatformKeyService
    from soft_fido2.qt.svc.passkey_service import PasskeyService
    from soft_fido2.qt.svc.credential_service import CredentialService
    from soft_fido2.qt.ux.advanced_dialog import AdvancedConfigDialog
    from soft_fido2.qt.ux.config import PlatformConfig
except ImportError:
    from qt.svc.platform_key_service import PlatformKeyService
    from qt.svc.passkey_service import PasskeyService
    from qt.svc.credential_service import CredentialService
    from qt.ux.advanced_dialog import AdvancedConfigDialog
    from qt.ux.config import PlatformConfig

            
class SettingsDialog(QDialog):
    """Main settings dialog for platform key and credential management.
    
    This dialog provides UI for:
    - Platform key configuration (TPM or file)
    - Passkey wallet generation
    - Credential management
    
    Business logic is delegated to service classes.
    
    Attributes:
        device_manager: Reference to the device manager for advanced operations
        fido_home: Path to FIDO home directory
        platform_key_service: Service for platform key operations
        passkey_service: Service for passkey wallet operations
        credential_service: Service for credential operations
    """
    
    # UI Text Constants
    TITLE = "Aye.Be.Key"
    CACHE_GROUP_TITLE = "Platform Key Configuration"
    CACHE_GROUP_TOOLTIP = "Configure your platform authentication key"
    TPM_RADIO_TEXT = "Trusted Platform Module (TPM)"
    FILE_RADIO_TEXT = "File"
    PASSKEY_GROUP_TITLE = "Passkey Wallet"
    CREDENTIALS_GROUP_TITLE = "Resident Credentials"
    
    def __init__(self, parent=None, device_manager=None):
        """Initialize settings dialog.
        
        Args:
            parent: Parent widget
            device_manager: Device manager instance for advanced operations
        """
        super().__init__(parent)
        self.setWindowTitle(self.TITLE + " Settings")
        self.setMinimumWidth(350)
        self.setMinimumHeight(500)
        
        # Set window icon
        icon_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'icons')
        main_icon_path = os.path.join(icon_dir, 'main_icon.svg')
        if os.path.exists(main_icon_path):
            self.setWindowIcon(QIcon(main_icon_path))
        
        # Store device manager reference
        self.device_manager = device_manager
        
        # Get FIDO home directory from SysTrayApp
        self.fido_home = parent.fido_home if parent and hasattr(parent, 'fido_home') else os.path.expanduser('~/.fido')
        
        
        # Initialize configuration
        self.plat_cfg = PlatformConfig(self.fido_home)
        
        # Initialize services
        self.platform_key_service = PlatformKeyService(self.fido_home)
        self.passkey_service = PasskeyService(self.fido_home)
        self.credential_service = CredentialService(self.fido_home)
        
        # Initialize logger
        self.logger = logging.getLogger(__name__)
        
        # Initialize state
        self.credentials = []
        self.passkey = None
        self.tpm_available = self._check_tpm_available()
        
        # Check if platform key is already unlocked in parent app
        self.platform_key_unlocked = self._check_parent_platform_key_unlocked()
        
        # Widget references (initialized in _create_cache_group)
        self.create_key_btn: QPushButton
        self.secret_input: QLineEdit
        self.unlock_btn: QPushButton
        self.advanced_btn: QPushButton
        self.status_label: QLabel
        self.cache_type_group: QButtonGroup
        self.tpm_radio: QRadioButton
        self.file_radio: QRadioButton
        
        # Widget references (initialized in _create_passkey_group)
        self.passkey_selector: QComboBox
        self.pin_input: QLineEdit
        self.wallet_name_input: QLineEdit
        self.generate_btn: QPushButton
        
        # Widget references (initialized in _create_credentials_group)
        self.credentials_pin_input: QLineEdit  # PIN input for unlocking existing wallets
        self.credentials_list: QListWidget
        self.reload_btn: QPushButton
        self.delete_btn: QPushButton
        
        # Build UI
        main_layout = QVBoxLayout()
        main_layout.addWidget(self._create_cache_group())
        main_layout.addWidget(self._create_passkey_group())
        main_layout.addWidget(self._create_credentials_group())
        
        # Credential action buttons
        buttons_layout = QHBoxLayout()
        self.reload_btn = self._create_button("Reload Credentials", self._handle_reload_credentials)
        self.delete_btn = self._create_button("Delete Selected", self._handle_delete_credential)
        self.delete_btn.setEnabled(False)
        buttons_layout.addWidget(self.reload_btn)
        buttons_layout.addWidget(self.delete_btn)
        main_layout.addLayout(buttons_layout)
        
        main_layout.addWidget(self._create_close_button())

        self.setLayout(main_layout)
        
        # Connect selection change for delete button
        self.credentials_list.itemSelectionChanged.connect(
            lambda: self.delete_btn.setEnabled(len(self.credentials_list.selectedItems()) > 0)
        )
        
        # Connect credentials PIN input to reload credentials on Enter
        self.credentials_pin_input.returnPressed.connect(self._handle_reload_credentials)
        
        # Set initial focus based on current state after dialog is fully shown
        QTimer.singleShot(0, self._set_initial_focus)
    
    # === UI Creation Methods ===
    
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
        
        self.status_label = QLabel()
        layout.addWidget(self.status_label)
        
        # Platform key controls (left to right: create, secret input, unlock, advanced)
        controls_layout = QHBoxLayout()
        
        # Get icon directory path
        icon_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'icons')
        
        # Create Platform Key Button
        self.create_key_btn = QPushButton()
        plus_icon_path = os.path.join(icon_dir, 'plus_icon.svg')
        if os.path.exists(plus_icon_path):
            self.create_key_btn.setIcon(QIcon(plus_icon_path))
        self.create_key_btn.setToolTip("Create a new platform key")
        self.create_key_btn.setFixedSize(32, 32)
        self.create_key_btn.setAutoDefault(False)
        self.create_key_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.create_key_btn.clicked.connect(self._handle_create_cache_key)
        controls_layout.addWidget(self.create_key_btn)
        
        # Platform Key Secret Text Input
        self.secret_input = QLineEdit()
        self.secret_input.setPlaceholderText("Enter password to unlock platform key")
        self.secret_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.secret_input.setToolTip("Enter password to unlock platform key")
        self.secret_input.setEnabled(False)  # Initially disabled
        controls_layout.addWidget(self.secret_input)
        
        # Unlock Button
        self.unlock_btn = QPushButton()
        unlock_icon_path = os.path.join(icon_dir, 'unlocked_padlock.svg')
        if os.path.exists(unlock_icon_path):
            self.unlock_btn.setIcon(QIcon(unlock_icon_path))
        self.unlock_btn.setToolTip("Unlock platform key with password")
        self.unlock_btn.setFixedSize(32, 32)
        self.unlock_btn.setAutoDefault(False)
        self.unlock_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.unlock_btn.setEnabled(False)  # Initially disabled
        self.unlock_btn.clicked.connect(self._handle_unlock_platform_key)
        controls_layout.addWidget(self.unlock_btn)
        
        # Connect secret input signals
        self.secret_input.returnPressed.connect(self._handle_unlock_platform_key)
        self.secret_input.textChanged.connect(self._update_platform_key_controls_state)
        
        # Advanced Config Button
        self.advanced_btn = QPushButton()
        settings_icon_path = os.path.join(icon_dir, 'settings_cog.svg')
        if os.path.exists(settings_icon_path):
            self.advanced_btn.setIcon(QIcon(settings_icon_path))
        self.advanced_btn.setToolTip("Advanced Configuration")
        self.advanced_btn.setFixedSize(32, 32)
        self.advanced_btn.clicked.connect(self._open_advanced_config)
        self.advanced_btn.setAutoDefault(False)
        self.advanced_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        controls_layout.addWidget(self.advanced_btn)
        
        layout.addLayout(controls_layout)
        
        group.setLayout(layout)
        
        # Update status and controls after all widgets are created
        self._update_cache_status()
        self._update_platform_key_controls_state()
        
        return group
    
    def _open_advanced_config(self):
        """Open advanced configuration dialog."""
            
        dialog = AdvancedConfigDialog(self, device_manager=self.device_manager)
        dialog.exec()
        # Clear focus from the advanced button after dialog closes
        self.advanced_btn.clearFocus()
        # Optionally restore focus to appropriate widget based on state
        QTimer.singleShot(0, self._set_initial_focus)
    
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
        
        self.cache_type_group.buttonClicked.connect(self._on_cache_type_changed)
        
        layout.addWidget(self.tpm_radio)
        layout.addWidget(self.file_radio)
        return layout
    
    def _set_radiobtn_from_loaded_key(self):
        """Set radio button selection based on saved configuration preference."""
        # First, check if there's a saved preference in platform.cfg
        saved_key_type = self.plat_cfg.key_type
        
        if saved_key_type == 'tpm':
            self.tpm_radio.setChecked(True)
        elif saved_key_type == 'file':
            self.file_radio.setChecked(True)
        else:
            # No saved preference, check which key actually exists
            key_type = self.platform_key_service.get_key_type()
            
            if key_type == 'tpm':
                self.tpm_radio.setChecked(True)
            elif key_type == 'file':
                self.file_radio.setChecked(True)
            else:
                # No key exists, default to file-based
                self.file_radio.setChecked(True)
    
    def _create_passkey_group(self):
        """Create passkey wallet section."""
        group = QGroupBox(self.PASSKEY_GROUP_TITLE)
        layout = QVBoxLayout()
        
        pin_layout, self.pin_input = self._create_labeled_input(
            "PIN:", placeholder="Enter wallet secret", password=True
        )
        layout.addLayout(pin_layout)
        
        # Wallet name input
        name_layout, self.wallet_name_input = self._create_labeled_input(
            "Wallet Name:", placeholder="Enter wallet name (Default: default.passkey)"
        )
        layout.addLayout(name_layout)
        
        # Generate button
        self.generate_btn = self._create_button("Generate New Wallet", self._handle_generate_passkey)
        layout.addWidget(self.generate_btn)
        
        group.setLayout(layout)
        
        return group
    
    def _create_credentials_group(self):
        """Create credentials management section."""
        group = QGroupBox(self.CREDENTIALS_GROUP_TITLE)
        layout = QVBoxLayout()
        
        # Passkey selector for loading credentials
        selector_layout = QHBoxLayout()
        selector_layout.addWidget(QLabel("Select Passkey:"))
        self.passkey_selector = QComboBox()
        self.passkey_selector.setMinimumWidth(200)
        selector_layout.addWidget(self.passkey_selector)
        layout.addLayout(selector_layout)
        
        # PIN input for unlocking existing wallet
        pin_layout, self.credentials_pin_input = self._create_labeled_input(
            "PIN:", placeholder="Enter PIN to unlock wallet", password=True
        )
        layout.addLayout(pin_layout)
        
        # Column headers for credentials table
        headers_layout = QHBoxLayout()
        user_id_header = QLabel("User ID")
        rp_id_header = QLabel("Relying Party ID")
        # Set fixed width for User ID column to match the formatted output (18 chars + separator)
        user_id_header.setMinimumWidth(150)
        headers_layout.addWidget(user_id_header)
        headers_layout.addWidget(rp_id_header)
        headers_layout.addStretch()
        layout.addLayout(headers_layout)
        
        # Credentials list
        self.credentials_list = QListWidget()
        self.credentials_list.setMinimumHeight(150)
        layout.addWidget(self.credentials_list)
        
        # Load available passkeys
        self._load_passkey_files()
        
        group.setLayout(layout)
        return group
    
    def _create_passkey_selector(self):
        """Create passkey selector combo box."""
        self.passkey_selector = QComboBox()
        self.passkey_selector.setMinimumWidth(200)
        return self.passkey_selector
    
    def _create_credential_buttons(self):
        """Create credential management buttons."""
        layout = QHBoxLayout()
        
        self.reload_btn = self._create_button("[re]Load Credentials", self._handle_reload_credentials)
        self.delete_btn = self._create_button("Delete Selected", self._handle_delete_credential)
        self.delete_btn.setEnabled(False)
        
        layout.addWidget(self.reload_btn)
        layout.addWidget(self.delete_btn)
        
        return layout
    
    def _create_close_button(self):
        """Create close button."""
        close_btn = self._create_button("Close", self.accept)
        return close_btn
    
    # === State Management Methods ===
    
    def _check_parent_platform_key_unlocked(self):
        """Check if the parent application has already unlocked the platform key.
        
        Returns:
            bool: True if parent has unlocked platform key, False otherwise
        """
        parent = self.parent()
        if parent and hasattr(parent, '_platform_key') and hasattr(parent, '_current_state'):
            # Check if platform key exists and app is in unlocked state
            try:
                from soft_fido2.qt_app import SysTrayApp
                app = cast(Any, parent)
                return (app._platform_key is not None and
                        app._current_state == SysTrayApp.AppState.UNLOCKED)
            except ImportError:
                from qt_app import SysTrayApp
                app = cast(Any, parent)
                return (app._platform_key is not None and
                        app._current_state == SysTrayApp.AppState.UNLOCKED)
        return False
    
    def _check_tpm_available(self):
        """Check if TPM is available on the system."""
        try:
            from soft_fido2.platform.tpm_device import TPMDevice
            tpm = TPMDevice()
            # Try to get key to verify TPM is actually functional
            try:
                tpm.get_key()
                return True
            except:
                # TPM exists but no key yet, still available
                return True
        except Exception as e:
            self.logger.debug(f"TPM not available: {e}")
            return False
    
    def _check_cache_key_status(self):
        """Check the status of platform keys."""
        tpm_exists = self.platform_key_service.check_key_exists('tpm')
        file_exists = self.platform_key_service.check_key_exists('file')
        return tpm_exists, file_exists
    
    def _on_cache_type_changed(self):
        """Handle radio button change - save preference and update UI."""
        selected_tpm = self.tpm_radio.isChecked()
        
        # Reset unlock state when switching key types
        self.platform_key_unlocked = False
        
        # Save the user's preference to platform.cfg
        if selected_tpm:
            self.plat_cfg.key_type = 'tpm'
        else:
            self.plat_cfg.key_type = 'file'
        
        # Update the UI
        self._update_cache_status()
    
    def _update_cache_status(self):
        """Update the platform key status label."""
        tpm_exists, file_exists = self._check_cache_key_status()
        selected_tpm = self.tpm_radio.isChecked()
        
        if selected_tpm:
            if tpm_exists:
                if self.platform_key_service.is_tpm_password_protected():
                    self.status_label.setText(" TPM platform key exists (password-protected)")
                else:
                    self.status_label.setText(" TPM platform key exists")
                self.status_label.setStyleSheet("color: green;")
            else:
                self.status_label.setText(" No TPM platform key found")
                self.status_label.setStyleSheet("color: red;")
        else:
            if file_exists:
                if self.platform_key_service.is_password_protected():
                    self.status_label.setText(" Platform key file exists (password-protected)")
                else:
                    self.status_label.setText(" Platform key file exists")
                self.status_label.setStyleSheet("color: green;")
            else:
                self.status_label.setText(" No platform key file found")
                self.status_label.setStyleSheet("color: red;")
        
        self._update_platform_key_controls_state()
    
    def _is_key_password_protected(self):
        """Check if the file-based platform key is password-protected."""
        return self.platform_key_service.is_password_protected()
    
    def _update_unlock_button_style(self):
        """Update unlock button appearance based on unlock state."""
        if self.platform_key_unlocked:
            # Green border with subtle green background when unlocked
            self.unlock_btn.setStyleSheet("""
                QPushButton {
                    background-color: rgba(76, 175, 80, 0.15);
                    border: 2px solid #4CAF50;
                }
                QPushButton:hover {
                    background-color: rgba(76, 175, 80, 0.25);
                }
            """)
        else:
            # Reset to default style when locked
            self.unlock_btn.setStyleSheet("")
    
    def _update_platform_key_controls_state(self):
        """Update the enabled/disabled state of platform key controls."""
        tpm_exists, file_exists = self._check_cache_key_status()
        selected_tpm = self.tpm_radio.isChecked()
        
        # Determine if a key exists for the selected type
        key_exists = tpm_exists if selected_tpm else file_exists
        
        # Create button: enabled if no key exists for selected type
        self.create_key_btn.setEnabled(not key_exists)
        
        # Enable secret input for both TPM and file keys if password-protected
        if selected_tpm and tpm_exists:
            is_protected = self.platform_key_service.is_tpm_password_protected()
            self.secret_input.setEnabled(is_protected)
            
            if is_protected:
                has_password = len(self.secret_input.text()) > 0
                self.unlock_btn.setEnabled(has_password)
                self._update_unlock_button_style()
            else:
                self.unlock_btn.setEnabled(False)
                self.platform_key_unlocked = False
                self.unlock_btn.setStyleSheet("")
        elif not selected_tpm and file_exists:
            is_protected = self._is_key_password_protected()
            self.secret_input.setEnabled(is_protected)
            
            if is_protected:
                has_password = len(self.secret_input.text()) > 0
                self.unlock_btn.setEnabled(has_password)
                self._update_unlock_button_style()
            else:
                self.unlock_btn.setEnabled(False)
                self.platform_key_unlocked = False
                self.unlock_btn.setStyleSheet("")
        else:
            self.secret_input.setEnabled(False)
            self.unlock_btn.setEnabled(False)
            self.platform_key_unlocked = False
            self.unlock_btn.setStyleSheet("")
    
    def _determine_initial_focus_state(self):
        """Determine which widget should receive initial focus.
        
        Priority:
        1. Platform key password input if file-based key needs unlocking
        2. Passkey Wallet PIN input if no wallets exist (for creating new wallet)
        3. Credentials PIN input if wallets exist (for unlocking existing wallet)
        """
        tpm_exists, file_exists = self._check_cache_key_status()
        selected_tpm = self.tpm_radio.isChecked()

        # Priority 1: If the selected key is password-protected and not yet
        # unlocked, focus the password input so the user knows what to do.
        if not self.platform_key_unlocked:
            if selected_tpm and tpm_exists and self.platform_key_service.is_tpm_password_protected():
                return 'secret_input'
            if not selected_tpm and file_exists and self._is_key_password_protected():
                return 'secret_input'
        
        # Priority 2: If no platform key exists, focus on create button
        if not tpm_exists and not file_exists:
            return 'create_key'
        
        # Priority 3: Check if any passkey wallets exist
        passkey_files = self._get_passkey_files()
        has_wallets = len(passkey_files) > 0
        
        # Priority 4: If platform key exists (and unlocked if needed)
        if (selected_tpm and tpm_exists) or (not selected_tpm and file_exists):
            if has_wallets:
                # Focus on credentials PIN input for unlocking existing wallet
                return 'credentials_pin_input'
            else:
                # Focus on passkey wallet PIN input for creating new wallet
                return 'pin_input'
        
        # Default: focus on create button
        return 'create_key'
    
    def _set_initial_focus(self):
        """Set initial focus to the appropriate widget."""
        focus_target = self._determine_initial_focus_state()
        
        if focus_target == 'create_key':
            self.create_key_btn.setFocus()
        elif focus_target == 'secret_input':
            self.secret_input.setFocus()
        elif focus_target == 'pin_input':
            self.pin_input.setFocus()
        elif focus_target == 'credentials_pin_input':
            self.credentials_pin_input.setFocus()
    
    # === Event Handlers (delegate to services) ===
    
    def _handle_reload_credentials(self):
        """Reload credentials from selected passkey."""
        passkey_file = self.passkey_selector.currentText()
        if not passkey_file:
            QMessageBox.warning(self, "No Passkey", "Please select a passkey wallet first.")
            return
        
        pin = self.credentials_pin_input.text()
        if not pin:
            QMessageBox.warning(self, "No PIN", "Please enter your PIN in the Credentials section.")
            return
        
        # Use credential service to load credentials
        success, credentials, message = self.credential_service.load_credentials(passkey_file, pin)
        
        if success:
            self.credentials = credentials
            self._display_credentials()
            QMessageBox.information(self, "Success", message)
        else:
            QMessageBox.warning(self, "Error", message)
    
    def _display_credentials(self):
        """Display loaded credentials in the list widget."""
        self.credentials_list.clear()
        for cred in self.credentials:
            display_text = self.credential_service.format_credential_for_display(cred)
            self.credentials_list.addItem(display_text)
    
    def _handle_create_cache_key(self):
        """Handle platform key creation."""
        selected_tpm = self.tpm_radio.isChecked()
        
        if selected_tpm:
            self._create_tpm_cache_key()
        else:
            self._create_file_cache_key()
    
    def _handle_unlock_platform_key(self):
        """Handle unlocking password-protected platform key."""
        password = self.secret_input.text()
        
        if not password:
            QMessageBox.warning(self, "No Password", "Please enter the platform key password.")
            return
        
        selected_tpm = self.tpm_radio.isChecked()
        
        # Use appropriate unlock method based on key type
        if selected_tpm:
            success, key_pair, message = self.platform_key_service.unlock_tpm_key(password)
        else:
            success, key_pair, message = self.platform_key_service.unlock_key(password)
        
        if success:
            # Mark as unlocked and update UI
            self.platform_key_unlocked = True
            self._update_unlock_button_style()
            
            # Update the main application's platform key and state
            parent = self.parent()
            if parent and hasattr(parent, '_platform_key'):
                app = cast(Any, parent)
                app._platform_key = key_pair
                app._set_state(app.AppState.UNLOCKED)
                self.logger.info("Platform key unlocked and main application state updated")
            
            QMessageBox.information(self, "Success", message)
            self.secret_input.clear()
            self._update_platform_key_controls_state()
            # Set focus based on priority algorithm
            QTimer.singleShot(0, self._set_initial_focus)
        else:
            # Unlocked state is false on failure
            self.platform_key_unlocked = False
            self._update_unlock_button_style()
            QMessageBox.warning(self, "Error", message)
    
    def _create_tpm_cache_key(self):
        """Create TPM-based platform key using service."""
        reply = QMessageBox.question(
            self, "Create TPM Key",
            "Do you want to password-protect the TPM key? (you should)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel
        )
        
        if reply == QMessageBox.StandardButton.Cancel:
            return
        
        password = ""
        if reply == QMessageBox.StandardButton.Yes:
            # Get password from user
            from PyQt6.QtWidgets import QInputDialog
            password, ok = QInputDialog.getText(
                self, "Set Password",
                "Enter password for TPM key:",
                QLineEdit.EchoMode.Password
            )
            
            if ok and password:
                # Confirm password
                password2, ok2 = QInputDialog.getText(
                    self, "Confirm Password",
                    "Confirm password:",
                    QLineEdit.EchoMode.Password
                )
                
                if ok2:
                    if password != password2:
                        QMessageBox.warning(self, "Error", "Passwords do not match.")
                        return
                else:
                    return
            else:
                return
        
        success, message = self.platform_key_service.create_tpm_key(password)
        
        if success:
            # Save the key type preference
            self.plat_cfg.key_type = 'tpm'
            QMessageBox.information(self, "Success", message)
            self._update_cache_status()
            
            # Focus appropriately based on whether password was set
            if password:
                self.secret_input.setFocus()
            else:
                self.pin_input.setFocus()
        else:
            QMessageBox.warning(self, "Error", message)
    
    def _save_platform_key(self, passphrase: str = ""):
        """Save file-based platform key using service."""
        success, message = self.platform_key_service.create_file_key(passphrase)
        
        if success:
            # Save the key type preference
            self.plat_cfg.key_type = 'file'
            QMessageBox.information(self, "Success", message)
            self._update_cache_status()
            return True
        else:
            QMessageBox.warning(self, "Error", message)
            return False
    
    def _create_file_cache_key(self):
        """Create file-based platform key."""
        reply = QMessageBox.question(
            self, "Create File Key",
            "Do you want to password-protect the platform key?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel
        )
        
        if reply == QMessageBox.StandardButton.Cancel:
            return
        
        if reply == QMessageBox.StandardButton.Yes:
            # Get password from user
            from PyQt6.QtWidgets import QInputDialog
            password, ok = QInputDialog.getText(
                self, "Set Password",
                "Enter password for platform key:",
                QLineEdit.EchoMode.Password
            )
            
            if ok and password:
                # Confirm password
                password2, ok2 = QInputDialog.getText(
                    self, "Confirm Password",
                    "Confirm password:",
                    QLineEdit.EchoMode.Password
                )
                
                if ok2:
                    if password == password2:
                        if self._save_platform_key(password):
                            # Focus on password input after creation
                            self.secret_input.setFocus()
                    else:
                        QMessageBox.warning(self, "Error", "Passwords do not match.")
        else:
            # Create unprotected key
            if self._save_platform_key(""):
                # Focus on PIN input after successful creation
                self.pin_input.setFocus()
    
    def _get_passkey_files(self):
        """Get list of available passkey files using service."""
        return self.passkey_service.list_passkey_files()
    
    def _load_passkey_files(self):
        """Load available passkey files into selector."""
        passkey_files = self._get_passkey_files()
        self.passkey_selector.clear()
        self.passkey_selector.addItems(passkey_files)
    
    def _try_cache_pin(self, pin: str):
        """Try to cache PIN by loading passkey (legacy method for compatibility)."""
        passkey_file = self.passkey_selector.currentText()
        if passkey_file:
            # This will cache the PIN as a side effect
            self.passkey_service.load_passkey(passkey_file, pin)
    
    def _load_credentials(self):
        """Load credentials from selected passkey (legacy method)."""
        self._handle_reload_credentials()
    
    def _delete_credential(self):
        """Delete selected credential (legacy method)."""
        self._handle_delete_credential()
    
    def _handle_delete_credential(self):
        """Handle credential deletion."""
        selected_items = self.credentials_list.selectedItems()
        if not selected_items:
            return
        
        passkey_file = self.passkey_selector.currentText()
        if not passkey_file:
            QMessageBox.warning(self, "No Passkey", "No passkey wallet selected.")
            return
        
        pin = self.credentials_pin_input.text()
        if not pin:
            QMessageBox.warning(self, "No PIN", "Please enter your PIN in the Credentials section.")
            return
        
        # Get selected credential index
        credential_index = self.credentials_list.currentRow()
        
        reply = QMessageBox.question(
            self, "Delete Credential",
            f"Are you sure you want to delete this credential?\n\n{selected_items[0].text()}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            # Use credential service to delete
            success, message = self.credential_service.delete_credential(
                passkey_file, pin, credential_index
            )
            
            if success:
                # Reload credentials to refresh the list
                self._handle_reload_credentials()
                QMessageBox.information(self, "Success", message)
            else:
                QMessageBox.warning(self, "Error", message)
    
    def _write_passkey(self, pin: str, name: str):
        """Write new passkey using service."""
        success, message = self.passkey_service.generate_passkey(pin, name)
        
        if success:
            QMessageBox.information(self, "Success", message)
            self._load_passkey_files()
            # Select the newly created passkey
            index = self.passkey_selector.findText(f"{name}.passkey")
            if index >= 0:
                self.passkey_selector.setCurrentIndex(index)
        else:
            QMessageBox.warning(self, "Error", message)
    
    def _handle_generate_passkey(self):
        """Handle passkey generation."""
        pin = self.pin_input.text()
        
        if not pin:
            QMessageBox.warning(self, "No PIN", "Please enter a PIN (8+ digits).")
            return
        
        if len(pin) > 8:
            QMessageBox.warning(self, "Invalid PIN", "PIN must be 8+ digits.")
            return
        
        # Get wallet name (optional)
        wallet_name = self.wallet_name_input.text().strip()
        if not wallet_name:
            wallet_name = "default"
        
        # Validate wallet name (alphanumeric and underscores only)
        if not wallet_name.replace('_', '').isalnum():
            QMessageBox.warning(
                self, "Invalid Name",
                "Wallet name must contain only letters, numbers, and underscores."
            )
            return
        
        reply = QMessageBox.question(
            self, "Generate Passkey",
            f"Generate new passkey wallet '{wallet_name}' with PIN?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self._write_passkey(pin, wallet_name)
