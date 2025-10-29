"""
Compatibility layer for decrypting credential IDs encrypted with either Fernet or SymmetricKey.

This module provides a class that can detect and decrypt credential IDs that were encrypted
with either the legacy Fernet encryption or the new SymmetricKey encryption.
"""

import base64
import logging
from typing import Optional, Union

from cryptography.fernet import Fernet
from soft_fido2.symmetric_key import SymmetricKey
from soft_fido2.key_pair import KeyPair

class CredentialIdMigrator:
    """
    A class that can decrypt credential IDs encrypted with either Fernet or SymmetricKey.
    
    This class provides backward compatibility for existing Fernet-encrypted credential IDs
    while supporting the new SymmetricKey encryption for new registrations.

    This prvodes a path forwards for legacy registrations which use a Fernet key.
    """
    
    @staticmethod
    def _urlb64_decode(b64_string: Union[str, bytes]) -> bytes:
        """
        Decode URL-safe base64 strings which may be missing trailing padding.

        Args:
            b64_string: URL-safe base64 encoded string to decode

        Returns:
            Decoded bytes
        """
        if isinstance(b64_string, str):
            b64_string = b64_string.encode('utf-8')
            
        # Add padding if needed
        pad = len(b64_string) % 4
        if pad:
            b64_string += b'=' * pad
            
        return base64.urlsafe_b64decode(b64_string)
    
    @classmethod
    def decrypt_credential_id(cls, cred_id: Union[str, bytes], seed: bytes) -> Optional[KeyPair]:
        """
        Try to decrypt a credential ID using either a Fernet or SymmetricKey.
        
        Args:
            cred_id: URL-safe base64 encoded credential ID
            seed: The seed used to encrypt the credential ID
            
        Returns:
            The decrypted KeyPair or None if decryption fails
        """
        if isinstance(cred_id, str): 
            cred_id = cls._urlb64_decode(cred_id)
        fKey = Fernet(base64.urlsafe_b64encode(seed))
        sKey = SymmetricKey(base64.urlsafe_b64encode(seed).decode())

        if len(cred_id) > 0:
            # Try SymmetricKey first
            try:
                key_bytes = sKey.decrypt(cred_id)
                return KeyPair.load_key_pair(key_bytes)
            except Exception as e:
                logging.warning(f"Failed to decrypt with SymmetricKey: {e}")
            
            # Try Fernet if SymmetricKey failed
            try:
                key_bytes = fKey.decrypt(cred_id)
                return KeyPair.load_key_pair(key_bytes)
            except Exception as e:
                logging.warning(f"Failed to decrypt with Fernet: {e}")
        
        return None
    
    @classmethod
    def migrate_credential_id(cls, cred_id: str, seed: bytes) -> Optional[str]:
        """
        Migrate a credential ID from Fernet encryption to SymmetricKey encryption.
        
        Args:
            cred_id: URL-safe base64 encoded credential ID
            seed: The seed used to generate the Fernet and Symmetric keys
            
        Returns:
            The re-encrypted credential ID or None if migration fails
        """
        # First decrypt the credential ID using the old key
        key_pair = cls.decrypt_credential_id(cred_id, seed)
        
        if key_pair is None:
            return None
        
        # Re-encrypt the private key using the new SymmetricKey
        new_cred_id_bytes = SymmetricKey(seed).encrypt(key_pair.get_private_bytes())
        
        # Return the base64-encoded credential ID
        return base64.urlsafe_b64encode(new_cred_id_bytes).decode('utf-8')

# Made with Bob
