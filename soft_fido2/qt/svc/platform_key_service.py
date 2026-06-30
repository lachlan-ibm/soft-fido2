"""Platform Key Service for managing platform authentication keys.

This service encapsulates all business logic for platform key operations,
including TPM-based and file-based key management. It provides a clean
interface for creating, unlocking, and validating platform keys without
coupling to UI components.

Features:
    - TPM key creation and validation
    - File-based key creation with optional password protection
    - Password-protected key unlocking
    - Key existence and type detection
    - Password protection status checking

Example:
    service = PlatformKeyService(fido_home="/path/to/.fido")
    
    # Create a TPM key
    success, message = service.create_tpm_key()
    
    # Create a file-based key with password
    success, message = service.create_file_key("my_password", "platform.key")
    
    # Unlock a password-protected key
    success, key_pair, message = service.unlock_key("my_password")
"""

import os
import logging
from typing import Optional, Tuple, Any

try:
    from soft_fido2.key_pair import KeyUtils, KeyPair
except ImportError:
    from key_pair import KeyUtils, KeyPair


class PlatformKeyService:
    """Service for managing platform authentication keys.
    
    This service handles all platform key operations including creation,
    unlocking, and validation for both TPM-based and file-based keys.
    
    Attributes:
        fido_home: Path to the FIDO home directory where keys are stored
    """
    
    def __init__(self, fido_home: str):
        """Initialize the platform key service.
        
        Args:
            fido_home: Path to the FIDO home directory (e.g., ~/.fido)
        """
        self.fido_home = fido_home
        self.logger = logging.getLogger(__name__)
    
    def _get_tpm_password_file(self) -> str:
        """Get path to TPM password configuration file."""
        return os.path.join(self.fido_home, '.tpm_password_protected')
    
    def is_tpm_password_protected(self) -> bool:
        """Check if TPM key is password-protected."""
        return os.path.exists(self._get_tpm_password_file())
    
    def _save_tpm_password_flag(self):
        """Mark TPM key as password-protected."""
        os.makedirs(self.fido_home, exist_ok=True)
        with open(self._get_tpm_password_file(), 'w') as f:
            f.write('1')
    
    def _remove_tpm_password_flag(self):
        """Remove password-protected flag."""
        path = self._get_tpm_password_file()
        if os.path.exists(path):
            os.remove(path)
    
    def create_tpm_key(self, password: str = "") -> Tuple[bool, str]:
        """Create a TPM-based platform key.
        
        Creates a new platform key using the Trusted Platform Module (TPM).
        The key is stored securely in the TPM and can only be accessed on
        the same hardware.
        
        Args:
            password: Optional password to protect the key
        
        Returns:
            Tuple containing:
                - success (bool): True if key was created successfully
                - message (str): Success or error message
        
        Example:
            success, message = service.create_tpm_key()
            if success:
                print(f"TPM key created: {message}")
            else:
                print(f"Failed: {message}")
        """
        try:
            from soft_fido2.platform.tpm_device import TPMDevice
            
            tpm = TPMDevice()
            
            # Convert password to bytes
            pwd_bytes = password.encode('utf-8') if password else b""
            tpm.create_key(password=pwd_bytes)
            
            # Mark as password-protected if password provided
            if password:
                self._save_tpm_password_flag()
            else:
                self._remove_tpm_password_flag()
            
            self.logger.info("TPM platform key created successfully")
            return True, "TPM platform key created successfully"
            
        except ImportError as e:
            error_msg = "TPM support not available - tpm_device module not found"
            self.logger.error(f"{error_msg}: {e}")
            return False, error_msg
            
        except Exception as e:
            error_msg = f"Failed to create TPM platform key: {str(e)}"
            self.logger.exception(error_msg)
            return False, error_msg
    
    def create_file_key(self, passphrase: str = "", filename: str = "platform.key") -> Tuple[bool, str]:
        """Create a file-based platform key.
        
        Creates a new platform key stored as a file in the FIDO home directory.
        The key can optionally be password-protected.
        
        Args:
            passphrase: Password to protect the key (empty string for no password)
            filename: Name of the key file (will add .key extension if missing)
        
        Returns:
            Tuple containing:
                - success (bool): True if key was created successfully
                - message (str): Success or error message
        
        Example:
            # Create unprotected key
            success, msg = service.create_file_key("", "platform.key")
            
            # Create password-protected key
            success, msg = service.create_file_key("my_password", "platform.key")
        """
        try:
            # Ensure filename has .key extension
            if not filename.endswith('.key'):
                filename += '.key'
            
            # Ensure FIDO home directory exists
            os.makedirs(self.fido_home, exist_ok=True)
            platform_key_path = os.path.join(self.fido_home, filename)
            
            # Check if file already exists
            if os.path.exists(platform_key_path):
                return False, f"File {filename} already exists. Please delete it first or choose a different name."
            
            # Create the key
            nonce = passphrase.encode('utf-8') if passphrase and len(passphrase) > 0 else None
            KeyUtils.create_platform_key(secret=nonce, filename=filename)
            
            protection_status = "password-protected" if nonce else "unprotected"
            success_msg = f"File-based platform key created successfully as {filename} ({protection_status})"
            self.logger.info(success_msg)
            return True, success_msg
            
        except Exception as e:
            error_msg = f"Failed to create file-based platform key: {str(e)}"
            self.logger.exception(error_msg)
            return False, error_msg
    
    def unlock_key(self, password: str) -> Tuple[bool, Optional[KeyPair], str]:
        """Unlock a password-protected file-based platform key.
        
        Attempts to load and decrypt a password-protected platform key file.
        
        Args:
            password: Password to unlock the key
        
        Returns:
            Tuple containing:
                - success (bool): True if key was unlocked successfully
                - key_pair (Optional[KeyPair]): The unlocked key pair, or None on failure
                - message (str): Success or error message
        
        Example:
            success, key_pair, msg = service.unlock_key("my_password")
            if success:
                print(f"Key unlocked: {msg}")
                # Use key_pair for authentication
            else:
                print(f"Failed: {msg}")
        """
        try:
            platform_key_path = os.path.join(self.fido_home, 'platform.key')
            
            if not os.path.exists(platform_key_path):
                return False, None, "Platform key file not found"
            
            # Convert password to bytes
            password_bytes = password.encode('utf-8') if password else None
            
            # Attempt to load the key with the password
            with open(platform_key_path, 'rb') as f:
                key_pem = f.read()
            
            key_pair = KeyPair.load_key_pair(key_pem, password=password_bytes)
            
            self.logger.info("Platform key unlocked successfully")
            return True, key_pair, "Platform key unlocked successfully"
            
        except Exception as e:
            error_msg = f"Failed to unlock platform key: {str(e)}"
            self.logger.warning(error_msg)
            return False, None, "Invalid password or corrupted key file"
    
    def unlock_tpm_key(self, password: str) -> Tuple[bool, Any, str]:
        """Unlock a password-protected TPM key.

        Performs a proof-of-knowledge round-trip (ecdh_encrypt + ecdh_decrypt)
        before reporting success.

        Args:
            password: Password to unlock the key

        Returns:
            Tuple of (success, key_pair, message)
        """
        try:
            from soft_fido2.platform.tpm_device import TPMDevice

            tpm = TPMDevice()
            pwd_bytes = password.encode('utf-8')

            handle, public_key_tpm = tpm.get_key()
            key_pair = self._convert_tpm_to_keypair(handle, public_key_tpm, pwd_bytes)

            # Verify the password is correct before reporting success.
            # ecdh_zgen requires auth in both directions — pass password to both.
            _probe = os.urandom(32)
            _blob = tpm.ecdh_encrypt(_probe, key_pair.public, handle, password=pwd_bytes)
            tpm.ecdh_decrypt(_blob, handle, password=pwd_bytes)

            return True, key_pair, "TPM key unlocked successfully"
        except Exception as e:
            error_msg = f"Failed to unlock TPM key: {str(e)}"
            self.logger.error(error_msg)
            return False, None, "Invalid password"
    
    def load_tpm_key(self, password: Optional[str] = None) -> Tuple[bool, Optional[Any], str]:
        """Load TPM-based platform key.
        
        Args:
            password: Optional password if key is password-protected
        """
        try:
            from soft_fido2.platform.tpm_device import TPMDevice
            
            tpm = TPMDevice()
            
            # Check if password-protected
            if self.is_tpm_password_protected():
                if not password:
                    return False, None, "TPM key requires password"
                pwd_bytes = password.encode('utf-8')
            else:
                pwd_bytes = b""
            
            handle, public_key_tpm = tpm.get_key()
            
            # Convert TPM key to KeyPair-compatible wrapper
            tpm_key_pair = self._convert_tpm_to_keypair(handle, public_key_tpm, pwd_bytes)
            
            return True, tpm_key_pair, "TPM key loaded successfully"
        except Exception as e:
            error_msg = f"Failed to load TPM key: {str(e)}"
            self.logger.error(error_msg)
            return False, None, error_msg
    
    def check_key_exists(self, key_type: str) -> bool:
        """Check if a platform key of the specified type exists.
        
        Args:
            key_type: Type of key to check ('tpm' or 'file')
        
        Returns:
            bool: True if the specified key type exists and is valid
        
        Example:
            if service.check_key_exists('tpm'):
                print("TPM key is available")
            elif service.check_key_exists('file'):
                print("File-based key is available")
        """
        if key_type == 'tpm':
            try:
                from soft_fido2.platform import TPMBackend as TPMDevice
                tpm = TPMDevice()
                tpm.get_key()
                return True
            except Exception:
                return False
        elif key_type == 'file':
            platform_key_path = os.path.join(self.fido_home, 'platform.key')
            return os.path.exists(platform_key_path)
        else:
            self.logger.warning(f"Unknown key type: {key_type}")
            return False
    
    def is_password_protected(self) -> bool:
        """Check if the file-based platform key is password-protected.
        
        Attempts to load the key without a password. If this fails, the key
        is considered password-protected.
        
        Returns:
            bool: True if the file key exists and is password-protected,
                  False if it doesn't exist or is not password-protected
        
        Example:
            if service.is_password_protected():
                password = get_password_from_user()
                success, key, msg = service.unlock_key(password)
            else:
                # Key can be loaded without password
                pass
        """
        platform_key_path = os.path.join(self.fido_home, 'platform.key')
        
        if not os.path.exists(platform_key_path):
            return False
        
        try:
            with open(platform_key_path, 'rb') as f:
                key_pem = f.read()
            # Try to load without password
            KeyPair.load_key_pair(key_pem, password=None)
            # If successful, key is not password-protected
            return False
        except Exception:
            # If loading without password fails, it's password-protected
            return True
    
    def get_key_type(self) -> Optional[str]:
        """Determine the type of existing platform key.
        
        Checks for both TPM and file-based keys and returns the type of
        the first one found. TPM keys are checked first.
        
        Returns:
            Optional[str]: 'tpm' if TPM key exists, 'file' if file key exists,
                          None if no key exists
        
        Example:
            key_type = service.get_key_type()
            if key_type == 'tpm':
                print("Using TPM-based authentication")
            elif key_type == 'file':
                print("Using file-based authentication")
            else:
                print("No platform key configured")
        """
        if self.check_key_exists('tpm'):
            return 'tpm'
        elif self.check_key_exists('file'):
            return 'file'
        else:
            return None
    
    def delete_file_key(self, filename: str = "platform.key") -> Tuple[bool, str]:
        """Delete a file-based platform key.
        
        Args:
            filename: Name of the key file to delete
        
        Returns:
            Tuple containing:
                - success (bool): True if key was deleted successfully
                - message (str): Success or error message
        
        Example:
            success, msg = service.delete_file_key("platform.key")
            if success:
                print(f"Key deleted: {msg}")
        """
        try:
            if not filename.endswith('.key'):
                filename += '.key'
            
            platform_key_path = os.path.join(self.fido_home, filename)
            
            if not os.path.exists(platform_key_path):
                return False, f"Key file {filename} does not exist"
            
            os.remove(platform_key_path)
            success_msg = f"Platform key {filename} deleted successfully"
            self.logger.info(success_msg)
            return True, success_msg
            
        except Exception as e:
            error_msg = f"Failed to delete platform key: {str(e)}"
            self.logger.exception(error_msg)
            return False, error_msg

    
    def _convert_tpm_to_keypair(self, handle, public_key_tpm, tpm_password: bytes = b"") -> Any:
        """Convert TPM key to KeyPair-compatible wrapper.
        
        Creates a TPMKeyPair wrapper that provides a KeyPair-compatible interface
        for TPM-based keys, allowing them to be used interchangeably with
        file-based keys.
        
        Args:
            handle: TPM key handle
            public_key_tpm: TPM2B_PUBLIC object
            tpm_password: Password bytes for the TPM key
        
        Returns:
            TPMKeyPair: Wrapper object with KeyPair-compatible interface
        """
        from soft_fido2.platform.tpm_device import TPMKeyPair
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend
        
        # Convert TPM public key to cryptography public key
        x = int.from_bytes(bytes(public_key_tpm.publicArea.unique.ecc.x), 'big')
        y = int.from_bytes(bytes(public_key_tpm.publicArea.unique.ecc.y), 'big')
        public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
        public_key = public_numbers.public_key(default_backend())
        
        return TPMKeyPair(handle, public_key, tpm_password=tpm_password)
    
    def load_file_key(self, password: Optional[bytes] = None) -> Tuple[bool, Optional[KeyPair], str]:
        """Load platform key from filesystem.
        
        Attempts to load a file-based platform key, optionally using a password
        for decryption.
        
        Args:
            password: Optional password bytes for encrypted keys
        
        Returns:
            Tuple containing:
                - success (bool): True if key was loaded successfully
                - key_pair (Optional[KeyPair]): The loaded key pair, or None on failure
                - message (str): Success or error message
        
        Example:
            # Load unprotected key
            success, key_pair, msg = service.load_file_key()
            
            # Load password-protected key
            password = "my_password".encode('utf-8')
            success, key_pair, msg = service.load_file_key(password)
        """
        try:
            platform_key_path = os.path.join(self.fido_home, 'platform.key')
            if not os.path.exists(platform_key_path):
                return False, None, "Platform key file not found"
            
            with open(platform_key_path, 'rb') as f:
                key_pem = f.read()
            
            key_pair = KeyPair.load_key_pair(key_pem, password)
            self.logger.info("Platform key loaded from filesystem")
            return True, key_pair, "Platform key loaded from filesystem"
        except Exception as e:
            if password is None:
                error_msg = f"Platform key requires password: {e}"
                self.logger.debug(error_msg)
            else:
                error_msg = f"Failed to load platform key: {e}"
                self.logger.error(error_msg)
            return False, None, error_msg
    
    def auto_load_key(self, preferred_key_type: Optional[str] = None) -> Tuple[bool, Optional[Any], str]:
        """Attempt to load platform key on startup based on user's preference.
        
        Priority order:
        1. If preferred_key_type is specified: use that preference
        2. If no preference: try TPM first (if available), then file without password
        3. Return failure if no key can be loaded
        
        Args:
            preferred_key_type: Optional preferred key type ('tpm' or 'file')
        
        Returns:
            Tuple containing:
                - success (bool): True if key was loaded successfully
                - key_pair: The loaded key pair (TPMKeyPair or KeyPair), or None on failure
                - message (str): Success or error message
        
        Example:
            # Auto-load with preference
            success, key, msg = service.auto_load_key('tpm')
            
            # Auto-load with fallback logic
            success, key, msg = service.auto_load_key()
        """
        if preferred_key_type is not None:
            # User has a saved preference
            if preferred_key_type == 'tpm':
                success, key_pair, message = self.load_tpm_key(password=None)
                if success:
                    return True, key_pair, message
                # Check if it's password-protected
                if self.is_tpm_password_protected():
                    self.logger.info("TPM key requires password, staying locked")
                    return False, None, "TPM key requires password"
                self.logger.info("TPM key not available, staying locked")
                return False, None, "TPM key not available"
            elif preferred_key_type == 'file':
                success, key_pair, message = self.load_file_key(password=None)
                if success:
                    return True, key_pair, message
                self.logger.info("File key requires password or doesn't exist, staying locked")
                return False, None, "File key requires password or doesn't exist"
        
        # No preference set - try fallbacks
        success, key_pair, message = self.load_tpm_key(password=None)
        if success:
            return True, key_pair, message
        
        # Fallback to file without password
        success, key_pair, message = self.load_file_key(password=None)
        if success:
            return True, key_pair, message
        
        self.logger.info("Platform key requires password or doesn't exist")
        return False, None, "Platform key requires password or doesn't exist"