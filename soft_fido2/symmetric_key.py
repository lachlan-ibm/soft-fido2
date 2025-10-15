"""
Custom implementation of symmetric encryption with AES-GCM.
This replaces the dependency on cryptography.fernet with a custom implementation.

This implementation provides authenticated encryption that guarantees a message
cannot be manipulated or read without the key.
"""

import base64
import os
import struct
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class SymmetricKey:
    """
    SymmetricKey implements symmetric encryption using AES-GCM.
    
    This class provides methods to generate keys, encrypt, and decrypt messages
    using AES-GCM for authenticated encryption.
    """
    
    # Version byte for our GCM-based tokens (different from standard Fernet)
    VERSION = b'\x81'  # Using 0x81 to distinguish from standard Fernet's 0x80
    
    # Minimum token size: Version (1) + Timestamp (8) + Nonce (12) + Tag (16) + min ciphertext (1)
    MIN_TOKEN_SIZE = 38
    
    def __init__(self, key):
        """
        Initialize with a symmetric key.
        
        Args:
            key (bytes or str): A 32-byte key or a URL-safe base64-encoded 32-byte key.
                Used for both encryption and authentication in GCM mode.
        """
        if isinstance(key, str):
            key = base64.urlsafe_b64decode(key.encode('utf-8'))
        
        if len(key) != 32:
            raise ValueError(
                "Symmetric key must be 32 bytes (URL-safe base64-encoded)."
            )
        
        self._key = key
        self._backend = default_backend()
    
    @classmethod
    def generate_key(cls):
        """
        Generates a new symmetric key.
        
        Returns:
            str: A URL-safe base64-encoded 32-byte key.
        """
        key = os.urandom(32)
        return base64.urlsafe_b64encode(key).decode('utf-8')
    
    def encrypt(self, data):
        """
        Encrypts data using AES-GCM.
        
        Args:
            data (bytes): The data to encrypt.
            
        Returns:
            bytes: The encrypted token.
        """
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes.")
        
        # Current time in seconds since the epoch, as a 64-bit integer
        current_time = int(time.time())
        
        # Generate a random 96-bit nonce (recommended size for GCM)
        nonce = os.urandom(12)
        
        # Encrypt the data with AES-GCM
        encryptor = Cipher(
            algorithms.AES(self._key),
            modes.GCM(nonce),
            backend=self._backend
        ).encryptor()
        
        # Include timestamp in the associated data for authentication
        associated_data = struct.pack('>Q', current_time)
        encryptor.authenticate_additional_data(associated_data)
        ciphertext = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag
        
        # Format: Version (0x81) || Timestamp (8 bytes) || Nonce (12 bytes) || Tag (16 bytes) || Ciphertext
        token = (
            self.VERSION +
            associated_data +  # Timestamp
            nonce +
            tag +
            ciphertext
        )
        
        # Return URL-safe base64 encoded token
        return base64.urlsafe_b64encode(token)
    
    def _parse_token(self, token_bytes):
        """
        Parse a token into its components.
        
        Args:
            token_bytes: Raw bytes of the token after base64 decoding
            
        Returns:
            tuple: (version, timestamp_bytes, nonce, tag, ciphertext)
            
        Raises:
            ValueError: If the token format is invalid
        """
        if len(token_bytes) < self.MIN_TOKEN_SIZE:
            raise ValueError(f"Token too short: {len(token_bytes)} bytes, minimum is {self.MIN_TOKEN_SIZE}")
        
        # Extract parts
        version = token_bytes[0:1]
        timestamp_bytes = token_bytes[1:9]
        nonce = token_bytes[9:21]
        tag = token_bytes[21:37]
        ciphertext = token_bytes[37:]
        
        # Verify version
        if version != self.VERSION:
            raise ValueError(f"Invalid token version: {version!r}, expected {self.VERSION!r}")
        
        return version, timestamp_bytes, nonce, tag, ciphertext
    
    def _verify_timestamp(self, timestamp_bytes, ttl):
        """
        Verify that a token's timestamp is within the TTL.
        
        Args:
            timestamp_bytes: 8-byte timestamp from the token
            ttl: Time-to-live in seconds
            
        Raises:
            ValueError: If the token has expired
        """
        if ttl is None:
            return
            
        timestamp = struct.unpack('>Q', timestamp_bytes)[0]
        current_time = int(time.time())
        
        if current_time - timestamp > ttl:
            age = current_time - timestamp
            raise ValueError(f"Token expired: token is {age} seconds old, but TTL is {ttl}")
    
    def decrypt(self, token, ttl=None):
        """
        Decrypts a token.
        
        Args:
            token (bytes or str): The token to decrypt.
            ttl (int, optional): Time-to-live in seconds. If the token is older
                than this, decryption will fail. If None, no TTL check is performed.
                    
        Returns:
            bytes: The decrypted data.
                
        Raises:
            ValueError: If the token is invalid, expired, or cannot be decrypted
            TypeError: If the token is not bytes or str
        """
        if isinstance(token, str):
            token = token.encode('utf-8')
        
        try:
            data = base64.urlsafe_b64decode(token)
        except (TypeError, ValueError) as e:
            raise ValueError(f"Invalid token: base64 decoding failed: {e}")
        
        # Parse the token into its components
        _, timestamp_bytes, nonce, tag, ciphertext = self._parse_token(data)
        
        # Verify timestamp if TTL is provided
        self._verify_timestamp(timestamp_bytes, ttl)
        
        # Decrypt the ciphertext with AES-GCM
        try:
            decryptor = Cipher(
                algorithms.AES(self._key),
                modes.GCM(nonce, tag),
                backend=self._backend
            ).decryptor()
            
            # Include timestamp in the associated data for authentication
            decryptor.authenticate_additional_data(timestamp_bytes)
            
            # Decrypt and verify the ciphertext
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext
        except Exception as e:
            # Catch any other exceptions, including cryptography.exceptions.InvalidTag
            # This is important for the test_invalid_token test case
            raise ValueError(f"Decryption failed: {str(e)}")

# Made with Bob
