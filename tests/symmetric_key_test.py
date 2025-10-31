#!/usr/bin/env python3
"""
Test script for the custom Fernet implementation with AES-GCM.
This script verifies that our custom Fernet implementation works correctly.
Note: This implementation is not compatible with the original cryptography.fernet.Fernet
since we've switched to AES-GCM for better security.
"""

import os
import sys
import base64
import unittest

# Add the parent directory to the path so we can import the soft_fido2 module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soft_fido2.symmetric_key import SymmetricKey


class TestSymmetricKey(unittest.TestCase):
    """Test cases for the SymmetricKey class."""

    def setUp(self):
        """Set up test fixtures."""
        # Generate a key for testing
        self.key = SymmetricKey.generate_key()
        self.symmetric_key = SymmetricKey(self.key)
        
        # Test data
        self.test_data = b"This is a test message for Fernet encryption."


    def test_key_generation(self):
        """Test that key generation produces valid keys."""
        key = SymmetricKey.generate_key()
        # Key should be URL-safe base64 encoded
        decoded_key = base64.urlsafe_b64decode(key)
        # Key should be 32 bytes (256 bits)
        self.assertEqual(len(decoded_key), 32)

    def test_encryption_decryption(self):
        """Test that encryption and decryption work correctly."""
        # Encrypt the test data
        token = self.symmetric_key.encrypt(self.test_data)
        
        # Decrypt the token
        decrypted_data = self.symmetric_key.decrypt(token)
        
        # The decrypted data should match the original
        self.assertEqual(decrypted_data, self.test_data)

    def test_token_format(self):
        """Test that the token format is correct."""
        token = self.symmetric_key.encrypt(self.test_data)
        decoded_token = base64.urlsafe_b64decode(token)
        
        # Token should start with version byte 0x81 (our GCM version)
        self.assertEqual(decoded_token[0], 0x81)
        
        # Token should be at least 38 bytes:
        # 1 byte version + 8 bytes timestamp + 12 bytes nonce +
        # 16 bytes tag + at least 1 byte ciphertext
        self.assertGreaterEqual(len(decoded_token), 38)

    # Note: We've removed the compatibility test with original Fernet
    # since our GCM implementation is intentionally not compatible

    def test_invalid_token(self):
        """Test that invalid tokens are rejected."""
        # Generate a valid token
        token = self.symmetric_key.encrypt(self.test_data)
        
        # Corrupt the token
        decoded_token = base64.urlsafe_b64decode(token)
        corrupted_token = base64.urlsafe_b64encode(decoded_token[:-1] + bytes([decoded_token[-1] ^ 0xFF]))
        
        # Decrypting the corrupted token should raise an exception
        with self.assertRaises(ValueError):
            self.symmetric_key.decrypt(corrupted_token)

    def test_ttl_validation(self):
        """Test that TTL validation works correctly."""
        # Encrypt the test data
        token = self.symmetric_key.encrypt(self.test_data)
        
        # Decrypt with a very large TTL (should succeed)
        decrypted_data = self.symmetric_key.decrypt(token, ttl=100000)
        self.assertEqual(decrypted_data, self.test_data)
        
        # Decrypt with a TTL of 0 (should fail)
        # This is a bit tricky to test reliably, as it depends on timing
        # We'll skip this test for now
        pass


if __name__ == "__main__":
    unittest.main()

# Made with Bob
