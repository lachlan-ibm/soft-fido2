"""Credential Service for managing FIDO2 credentials within passkey wallets.

This service encapsulates all business logic for credential management operations,
including loading, deleting, and querying credentials stored in passkey wallets.
It provides a clean interface for credential operations without coupling to
UI components.

Key Features:
    - Load credentials from passkey wallets
    - Delete credentials from passkey wallets
    - Get credential counts
    - Format credentials for display
    - Manage credential lifecycle

Example:
    service = CredentialService(fido_home="/path/to/.fido")
    
    # Load credentials
    success, creds, msg = service.load_credentials("wallet.passkey", "1234")
    
    # Delete a credential
    success, msg = service.delete_credential("wallet.passkey", "1234", 0)
    
    # Get credential count
    count = service.get_credential_count("wallet.passkey", "1234")
"""

import os
import logging
from typing import Optional, Tuple, List, Dict, Any

try:
    from soft_fido2.key_pair import KeyUtils
except ImportError:
    from key_pair import KeyUtils


class CredentialService:
    """Service for managing FIDO2 credentials within passkey wallets.
    
    This service handles all credential management operations including
    loading, deleting, and querying credentials stored in passkey files.
    
    Attributes:
        fido_home: Path to the FIDO home directory where passkeys are stored
    """
    
    def __init__(self, fido_home: str):
        """Initialize the credential service.
        
        Args:
            fido_home: Path to the FIDO home directory (e.g., ~/.fido)
        """
        self.fido_home = fido_home
        self.logger = logging.getLogger(__name__)
    
    def load_credentials(self, passkey_file: str, pin: str) -> Tuple[bool, List[Dict[str, Any]], str]:
        """Load credentials from a passkey wallet.
        
        Loads and decrypts a passkey wallet file, returning the list of
        stored credentials. Also caches the PIN for future operations.
        
        Args:
            passkey_file: Name of the passkey file (with or without .passkey extension)
            pin: PIN to unlock the wallet
        
        Returns:
            Tuple containing:
                - success (bool): True if credentials were loaded successfully
                - credentials (List[Dict]): List of credential dictionaries
                - message (str): Success or error message
        
        Each credential dictionary contains:
            - 'rp.id': Relying party identifier (bytes or str)
            - 'user.id': User identifier (bytes or str)
            - Other FIDO2 credential fields
        
        Example:
            success, creds, msg = service.load_credentials("wallet.passkey", "1234")
            if success:
                for cred in creds:
                    rp_id = cred.get('rp.id', 'unknown')
                    print(f"Credential for: {rp_id}")
        """
        try:
            # Ensure filename has .passkey extension
            if not passkey_file.endswith('.passkey'):
                passkey_file += '.passkey'
            
            passkey_path = os.path.join(self.fido_home, passkey_file)
            
            # Check if passkey file exists
            if not os.path.exists(passkey_path):
                return False, [], f"Passkey file {passkey_file} does not exist"
            
            # Generate PIN hash
            nonce = KeyUtils.get_pin_hash(pin)
            
            # Load the passkey
            passkey_data = KeyUtils._load_passkey(nonce, passkey_path)
            credentials = passkey_data['res.creds']
            
            # Cache the PIN by re-saving (updates cached upper pin hash)
            KeyUtils._save_passkey(
                passkey_data['key'],
                passkey_data['x5c'],
                credentials,
                passkey_data['pin.hash'],
                passkey_path
            )
            
            success_msg = f"Successfully loaded {len(credentials)} credential(s) from {passkey_file}"
            self.logger.info(success_msg)
            return True, credentials, success_msg
            
        except Exception as e:
            error_msg = f"Failed to load credentials: {str(e)}"
            self.logger.exception(error_msg)
            return False, [], "Failed to unlock passkey. Please check your PIN and try again."
    
    def delete_credential(self, passkey_file: str, pin: str, credential_index: int) -> Tuple[bool, str]:
        """Delete a credential from a passkey wallet.
        
        Removes a credential at the specified index from the passkey wallet
        and saves the updated wallet.
        
        Args:
            passkey_file: Name of the passkey file (with or without .passkey extension)
            pin: PIN to unlock the wallet
            credential_index: Index of the credential to delete (0-based)
        
        Returns:
            Tuple containing:
                - success (bool): True if credential was deleted successfully
                - message (str): Success or error message
        
        Example:
            # Delete the first credential
            success, msg = service.delete_credential("wallet.passkey", "1234", 0)
            if success:
                print(f"Credential deleted: {msg}")
        """
        try:
            # Load credentials first
            success, credentials, load_msg = self.load_credentials(passkey_file, pin)
            if not success:
                return False, load_msg
            
            # Validate credential index
            if credential_index < 0 or credential_index >= len(credentials):
                return False, f"Invalid credential index: {credential_index}"
            
            # Remove the credential
            del credentials[credential_index]
            
            # Ensure filename has .passkey extension
            if not passkey_file.endswith('.passkey'):
                passkey_file += '.passkey'
            
            passkey_path = os.path.join(self.fido_home, passkey_file)
            
            # Reload passkey to get key and x5c
            nonce = KeyUtils.get_pin_hash(pin)
            passkey_data = KeyUtils._load_passkey(nonce, passkey_path)
            
            # Save updated credentials
            KeyUtils._save_passkey(
                passkey_data['key'],
                passkey_data['x5c'],
                credentials,
                passkey_data['pin.hash'],
                passkey_path
            )
            
            success_msg = f"Credential deleted successfully. {len(credentials)} credential(s) remaining."
            self.logger.info(success_msg)
            return True, success_msg
            
        except Exception as e:
            error_msg = f"Failed to delete credential: {str(e)}"
            self.logger.exception(error_msg)
            return False, error_msg
    
    def delete_credentials(self, passkey_file: str, pin: str, credential_indices: List[int]) -> Tuple[bool, str]:
        """Delete multiple credentials from a passkey wallet.
        
        Removes credentials at the specified indices from the passkey wallet
        and saves the updated wallet. Indices are processed in reverse order
        to maintain correct positions during deletion.
        
        Args:
            passkey_file: Name of the passkey file (with or without .passkey extension)
            pin: PIN to unlock the wallet
            credential_indices: List of credential indices to delete (0-based)
        
        Returns:
            Tuple containing:
                - success (bool): True if credentials were deleted successfully
                - message (str): Success or error message
        
        Example:
            # Delete multiple credentials
            success, msg = service.delete_credentials("wallet.passkey", "1234", [0, 2, 5])
            if success:
                print(f"Credentials deleted: {msg}")
        """
        try:
            # Load credentials first
            success, credentials, load_msg = self.load_credentials(passkey_file, pin)
            if not success:
                return False, load_msg
            
            # Validate all indices
            for index in credential_indices:
                if index < 0 or index >= len(credentials):
                    return False, f"Invalid credential index: {index}"
            
            # Remove credentials in reverse order to maintain correct indices
            for index in sorted(credential_indices, reverse=True):
                del credentials[index]
            
            # Ensure filename has .passkey extension
            if not passkey_file.endswith('.passkey'):
                passkey_file += '.passkey'
            
            passkey_path = os.path.join(self.fido_home, passkey_file)
            
            # Reload passkey to get key and x5c
            nonce = KeyUtils.get_pin_hash(pin)
            passkey_data = KeyUtils._load_passkey(nonce, passkey_path)
            
            # Save updated credentials
            KeyUtils._save_passkey(
                passkey_data['key'],
                passkey_data['x5c'],
                credentials,
                passkey_data['pin.hash'],
                passkey_path
            )
            
            deleted_count = len(credential_indices)
            success_msg = f"{deleted_count} credential(s) deleted successfully. {len(credentials)} credential(s) remaining."
            self.logger.info(success_msg)
            return True, success_msg
            
        except Exception as e:
            error_msg = f"Failed to delete credentials: {str(e)}"
            self.logger.exception(error_msg)
            return False, error_msg
    
    def get_credential_count(self, passkey_file: str, pin: Optional[str] = None) -> int:
        """Get the number of credentials in a passkey wallet.
        
        If PIN is provided, loads the wallet and returns the actual count.
        If PIN is not provided, returns 0 (cannot determine count without unlocking).
        
        Args:
            passkey_file: Name of the passkey file (with or without .passkey extension)
            pin: Optional PIN to unlock the wallet
        
        Returns:
            int: Number of credentials (0 if file doesn't exist, error, or no PIN provided)
        
        Example:
            count = service.get_credential_count("wallet.passkey", "1234")
            print(f"Wallet contains {count} credential(s)")
        """
        if pin is None:
            self.logger.warning("Cannot get credential count without PIN")
            return 0
        
        try:
            success, credentials, _ = self.load_credentials(passkey_file, pin)
            if success:
                return len(credentials)
            else:
                return 0
        except Exception as e:
            self.logger.exception(f"Error getting credential count: {e}")
            return 0
    
    def format_credential_for_display(self, credential: Dict[str, Any]) -> str:
        """Format a credential for display in UI.
        
        Extracts and formats the relying party ID and user ID from a credential
        dictionary for display purposes.
        
        Args:
            credential: Credential dictionary containing 'rp.id' and 'user.id'
        
        Returns:
            str: Formatted string like "USER_ID_HEX... | rp.example.com"
        
        Example:
            for cred in credentials:
                display_text = service.format_credential_for_display(cred)
                print(display_text)
        """
        try:
            rp_id_bytes = credential.get('rp.id', 'cred.parsing.error')
            user_id_bytes = credential.get('user.id', 'cred.parsing.error')
            
            # Convert rp.id to string
            rp_id = rp_id_bytes.decode('utf-8') if isinstance(rp_id_bytes, bytes) \
                    else str(rp_id_bytes)
            
            # Convert user.id to hex string
            user_id_value = user_id_bytes.hex().upper() if isinstance(user_id_bytes, bytes) \
                            else str(user_id_bytes)
            
            # Truncate user ID if too long
            user_id = user_id_value[:15]
            if len(user_id_value) > 15:
                user_id += '...'
            else:
                user_id += ' ' * (18 - len(user_id_value))
            
            return f"{user_id} | {rp_id}"
            
        except Exception as e:
            self.logger.exception(f"Error formatting credential: {e}")
            return "Error formatting credential"
    
    def get_credential_details(self, credential: Dict[str, Any]) -> Dict[str, str]:
        """Get detailed information about a credential.
        
        Extracts and formats various fields from a credential for detailed display.
        
        Args:
            credential: Credential dictionary
        
        Returns:
            Dict containing formatted credential details:
                - 'rp_id': Relying party identifier
                - 'user_id': User identifier (hex)
                - 'user_id_full': Full user identifier (hex)
        
        Example:
            details = service.get_credential_details(credential)
            print(f"RP: {details['rp_id']}")
            print(f"User: {details['user_id']}")
        """
        try:
            rp_id_bytes = credential.get('rp.id', b'unknown')
            user_id_bytes = credential.get('user.id', b'unknown')
            
            # Convert rp.id to string
            rp_id = rp_id_bytes.decode('utf-8') if isinstance(rp_id_bytes, bytes) \
                    else str(rp_id_bytes)
            
            # Convert user.id to hex string
            user_id_full = user_id_bytes.hex().upper() if isinstance(user_id_bytes, bytes) \
                           else str(user_id_bytes)
            
            # Truncated version
            user_id = user_id_full[:15]
            if len(user_id_full) > 15:
                user_id += '...'
            
            return {
                'rp_id': rp_id,
                'user_id': user_id,
                'user_id_full': user_id_full
            }
            
        except Exception as e:
            self.logger.exception(f"Error getting credential details: {e}")
            return {
                'rp_id': 'error',
                'user_id': 'error',
                'user_id_full': 'error'
            }
