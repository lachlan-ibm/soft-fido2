"""Passkey Service for managing FIDO2 passkey wallets.

This service encapsulates all business logic for passkey wallet operations,
including generation, listing, validation, and loading of passkey files.
It provides a clean interface for passkey management without coupling to
UI components.

Key Features:
    - Generate new passkey wallets with PIN protection
    - List available passkey files with validation
    - Validate passkey file integrity (checks for .stash files)
    - Load passkey wallets with PIN verification
    - Manage passkey file lifecycle

Example:
    service = PasskeyService(fido_home="/path/to/.fido")
    
    # Generate a new passkey
    success, message = service.generate_passkey("1234", "my_wallet")
    
    # List available passkeys
    passkeys = service.list_passkey_files()
    
    # Load a passkey
    success, passkey_data, message = service.load_passkey("my_wallet.passkey", "1234")
"""

import os
import logging
from typing import Optional, Tuple, List, Dict, Any

try:
    from soft_fido2.key_pair import KeyUtils
except ImportError:
    from key_pair import KeyUtils


class PasskeyService:
    """Service for managing FIDO2 passkey wallets.
    
    This service handles all passkey wallet operations including creation,
    listing, validation, and loading of passkey files.
    
    Attributes:
        fido_home: Path to the FIDO home directory where passkeys are stored
    """
    
    def __init__(self, fido_home: str):
        """Initialize the passkey service.
        
        Args:
            fido_home: Path to the FIDO home directory (e.g., ~/.fido)
        """
        self.fido_home = fido_home
        self.logger = logging.getLogger(__name__)
    
    def generate_passkey(self, pin: str = "00000000", name: str = "default") -> Tuple[bool, str]:
        """Generate a new passkey wallet.
        
        Creates a new passkey wallet file protected by a PIN. The wallet
        includes a key pair and certificate chain, and is stored with an
        empty credential list.
        
        Args:
            pin: PIN to protect the wallet (default: "00000000")
            name: Name of the wallet file (without .passkey extension)
        
        Returns:
            Tuple containing:
                - success (bool): True if passkey was generated successfully
                - message (str): Success or error message
        
        Example:
            success, msg = service.generate_passkey("1234", "my_wallet")
            if success:
                print(f"Passkey created: {msg}")
        """
        try:
            # Ensure FIDO home directory exists
            os.makedirs(self.fido_home, exist_ok=True)
            
            # Generate passkey data
            passkey_data = KeyUtils.generate_passkey()
            pin_hash = KeyUtils.get_pin_hash(pin)
            
            # Construct passkey file path
            passkey_path = os.path.join(self.fido_home, f"{name}.passkey")
            
            # Check if file already exists
            if os.path.exists(passkey_path):
                return False, f"Passkey {name}.passkey already exists. Please choose a different name."
            
            # Save the passkey with empty credential list
            KeyUtils._save_passkey(
                passkey_data['key'],
                passkey_data['x5c'],
                [],  # Empty credential list
                pin_hash,
                passkey_path
            )
            
            success_msg = f"Passkey {name}.passkey created successfully in {self.fido_home}"
            self.logger.info(success_msg)
            return True, success_msg
            
        except Exception as e:
            error_msg = f"Failed to generate passkey: {str(e)}"
            self.logger.exception(error_msg)
            return False, error_msg
    
    def list_passkey_files(self) -> List[str]:
        """List all available passkey files.
        
        Returns a list of passkey filenames (without path) that have
        corresponding .stash files. Passkeys without .stash files are
        logged as warnings but not included in the list.
        
        Returns:
            List of passkey filenames (e.g., ["default.passkey", "work.passkey"])
        
        Example:
            passkeys = service.list_passkey_files()
            for passkey in passkeys:
                print(f"Available passkey: {passkey}")
        """
        passkey_files = []
        
        if not os.path.exists(self.fido_home):
            self.logger.warning(f"FIDO home directory does not exist: {self.fido_home}")
            return passkey_files
        
        try:
            for filename in os.listdir(self.fido_home):
                if filename.endswith('.passkey'):
                    # Check for corresponding .stash file
                    base_name = filename[:-8]  # Remove .passkey extension
                    stash_path = os.path.join(self.fido_home, base_name + '.stash')
                    
                    if os.path.exists(stash_path):
                        passkey_files.append(filename)
                    else:
                        # Log warning but don't include file
                        self.logger.warning(
                            f"Found {filename} without corresponding .stash file. "
                            "This passkey may be incomplete or corrupted."
                        )
        except Exception as e:
            self.logger.exception(f"Error listing passkey files: {e}")
        
        return sorted(passkey_files)
    
    def validate_passkey(self, filename: str) -> Tuple[bool, str]:
        """Validate a passkey file.
        
        Checks if the passkey file exists and has a corresponding .stash file.
        
        Args:
            filename: Name of the passkey file (with or without .passkey extension)
        
        Returns:
            Tuple containing:
                - valid (bool): True if passkey is valid
                - message (str): Validation result message
        
        Example:
            valid, msg = service.validate_passkey("my_wallet.passkey")
            if not valid:
                print(f"Invalid passkey: {msg}")
        """
        try:
            # Ensure filename has .passkey extension
            if not filename.endswith('.passkey'):
                filename += '.passkey'
            
            passkey_path = os.path.join(self.fido_home, filename)
            
            # Check if passkey file exists
            if not os.path.exists(passkey_path):
                return False, f"Passkey file {filename} does not exist"
            
            # Check for corresponding .stash file
            base_name = filename[:-8]  # Remove .passkey extension
            stash_path = os.path.join(self.fido_home, base_name + '.stash')
            
            if not os.path.exists(stash_path):
                return False, f"Passkey {filename} is missing corresponding .stash file"
            
            return True, f"Passkey {filename} is valid"
            
        except Exception as e:
            error_msg = f"Error validating passkey: {str(e)}"
            self.logger.exception(error_msg)
            return False, error_msg
    
    def load_passkey(self, filename: str, pin: str) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        """Load a passkey wallet.
        
        Attempts to load and decrypt a passkey wallet file using the provided PIN.
        
        Args:
            filename: Name of the passkey file (with or without .passkey extension)
            pin: PIN to unlock the wallet
        
        Returns:
            Tuple containing:
                - success (bool): True if passkey was loaded successfully
                - passkey_data (Optional[Dict]): The loaded passkey data, or None on failure
                - message (str): Success or error message
        
        The passkey_data dictionary contains:
            - 'key': The key pair
            - 'x5c': Certificate chain
            - 'res.creds': List of credentials
            - 'pin.hash': PIN hash
        
        Example:
            success, data, msg = service.load_passkey("my_wallet.passkey", "1234")
            if success:
                credentials = data['res.creds']
                print(f"Loaded {len(credentials)} credentials")
        """
        try:
            # Ensure filename has .passkey extension
            if not filename.endswith('.passkey'):
                filename += '.passkey'
            
            passkey_path = os.path.join(self.fido_home, filename)
            
            # Validate passkey first
            valid, validation_msg = self.validate_passkey(filename)
            if not valid:
                return False, None, validation_msg
            
            # Generate PIN hash
            nonce = KeyUtils.get_pin_hash(pin)
            
            # Load the passkey
            passkey_data = KeyUtils._load_passkey(nonce, passkey_path)
            
            # Cache the PIN by re-saving (updates cached upper pin hash)
            KeyUtils._save_passkey(
                passkey_data['key'],
                passkey_data['x5c'],
                passkey_data['res.creds'],
                passkey_data['pin.hash'],
                passkey_path
            )
            
            credential_count = len(passkey_data['res.creds'])
            success_msg = f"Successfully loaded {credential_count} credential(s) from {filename}"
            self.logger.info(success_msg)
            return True, passkey_data, success_msg
            
        except Exception as e:
            error_msg = f"Failed to load passkey: {str(e)}"
            self.logger.warning(error_msg)
            return False, None, "Failed to unlock passkey. Please check your PIN and try again."
    
    def delete_passkey(self, filename: str) -> Tuple[bool, str]:
        """Delete a passkey wallet and its associated files.
        
        Deletes both the .passkey file and its corresponding .stash file.
        
        Args:
            filename: Name of the passkey file (with or without .passkey extension)
        
        Returns:
            Tuple containing:
                - success (bool): True if passkey was deleted successfully
                - message (str): Success or error message
        
        Example:
            success, msg = service.delete_passkey("old_wallet.passkey")
            if success:
                print(f"Passkey deleted: {msg}")
        """
        try:
            # Ensure filename has .passkey extension
            if not filename.endswith('.passkey'):
                filename += '.passkey'
            
            passkey_path = os.path.join(self.fido_home, filename)
            base_name = filename[:-8]  # Remove .passkey extension
            stash_path = os.path.join(self.fido_home, base_name + '.stash')
            
            # Check if passkey file exists
            if not os.path.exists(passkey_path):
                return False, f"Passkey file {filename} does not exist"
            
            # Delete passkey file
            os.remove(passkey_path)
            
            # Delete stash file if it exists
            if os.path.exists(stash_path):
                os.remove(stash_path)
            
            success_msg = f"Passkey {filename} and associated files deleted successfully"
            self.logger.info(success_msg)
            return True, success_msg
            
        except Exception as e:
            error_msg = f"Failed to delete passkey: {str(e)}"
            self.logger.exception(error_msg)
            return False, error_msg
    
    def get_passkey_count(self) -> int:
        """Get the number of valid passkey files.
        
        Returns:
            int: Number of valid passkey files (with corresponding .stash files)
        
        Example:
            count = service.get_passkey_count()
            print(f"You have {count} passkey(s)")
        """
        return len(self.list_passkey_files())
