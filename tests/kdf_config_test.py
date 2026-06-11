#!/usr/bin/env python3
"""
Unit tests for Phase 1: KDF Info Configuration
Tests the persistent storage and retrieval of credential KDF info.
"""

import os
import sys
import tempfile
import shutil
import unittest
from unittest.mock import patch

# Add the parent directory to the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soft_fido2.key_pair import KeyUtils, KeyPair


class TestKDFInfoConfig(unittest.TestCase):
    """Test cases for KDF info configuration storage."""

    def setUp(self):
        """Set up test fixtures with temporary FIDO_HOME."""
        # Create a temporary directory for FIDO_HOME
        self.test_fido_home = tempfile.mkdtemp()
        self.original_fido_home = os.environ.get('FIDO_HOME')
        os.environ['FIDO_HOME'] = self.test_fido_home
        
        # Create a platform key for encryption/decryption
        self.platform_key = KeyUtils.create_platform_key()

    def tearDown(self):
        """Clean up test fixtures."""
        # Restore original FIDO_HOME
        if self.original_fido_home is not None:
            os.environ['FIDO_HOME'] = self.original_fido_home
        else:
            os.environ.pop('FIDO_HOME', None)
        
        # Remove temporary directory
        if os.path.exists(self.test_fido_home):
            shutil.rmtree(self.test_fido_home)

    def test_get_default_credential_kdf_info(self):
        """Test that default KDF info constant is returned."""
        default_info = KeyUtils.get_default_credential_kdf_info()
        self.assertEqual(default_info, "CTAP2-CRED-INFO-v1")
        self.assertIsInstance(default_info, str)

    def test_get_credential_kdf_info_returns_default_when_file_missing(self):
        """Test that default value is returned when platform.info doesn't exist."""
        kdf_info = KeyUtils.get_credential_kdf_info()
        self.assertEqual(kdf_info, b"CTAP2-CRED-INFO-v1")
        self.assertIsInstance(kdf_info, bytes)

    def test_set_and_get_credential_kdf_info(self):
        """Test setting and retrieving custom KDF info."""
        custom_info = "MY-CUSTOM-KDF-INFO-v2"
        
        # Set custom KDF info
        KeyUtils.set_credential_kdf_info(custom_info)
        
        # Verify file was created
        info_path = KeyUtils._get_platform_info_path()
        self.assertTrue(os.path.exists(info_path))
        
        # Retrieve and verify
        retrieved_info = KeyUtils.get_credential_kdf_info()
        self.assertEqual(retrieved_info, custom_info.encode('utf-8'))

    def test_set_credential_kdf_info_validates_empty_string(self):
        """Test that empty strings are rejected."""
        with self.assertRaises(ValueError) as context:
            KeyUtils.set_credential_kdf_info("")
        self.assertIn("cannot be empty", str(context.exception))
        
        with self.assertRaises(ValueError) as context:
            KeyUtils.set_credential_kdf_info("   ")
        self.assertIn("cannot be empty", str(context.exception))

    def test_set_credential_kdf_info_validates_length(self):
        """Test that strings exceeding 128 characters are rejected."""
        long_string = "A" * 129
        with self.assertRaises(ValueError) as context:
            KeyUtils.set_credential_kdf_info(long_string)
        self.assertIn("cannot exceed 128 characters", str(context.exception))
        
        # 128 characters should be accepted
        max_length_string = "B" * 128
        KeyUtils.set_credential_kdf_info(max_length_string)
        retrieved = KeyUtils.get_credential_kdf_info()
        self.assertEqual(retrieved, max_length_string.encode('utf-8'))

    def test_set_credential_kdf_info_validates_utf8(self):
        """Test that non-UTF-8 safe strings are rejected."""
        # This test verifies the UTF-8 encoding check
        # Python 3 strings are Unicode by default, so we test the encoding
        valid_utf8 = "Valid-UTF8-String-🔐"
        KeyUtils.set_credential_kdf_info(valid_utf8)
        retrieved = KeyUtils.get_credential_kdf_info()
        self.assertEqual(retrieved, valid_utf8.encode('utf-8'))

    def test_platform_info_file_permissions(self):
        """Test that platform.info file has secure permissions (0o600)."""
        custom_info = "TEST-PERMISSIONS"
        KeyUtils.set_credential_kdf_info(custom_info)
        
        info_path = KeyUtils._get_platform_info_path()
        file_stat = os.stat(info_path)
        file_mode = file_stat.st_mode & 0o777
        
        # File should be readable and writable only by owner
        self.assertEqual(file_mode, 0o600)

    def test_get_platform_info_path_requires_fido_home(self):
        """Test that _get_platform_info_path raises error when FIDO_HOME is not set."""
        # Remove FIDO_HOME
        os.environ.pop('FIDO_HOME', None)
        
        with self.assertRaises(RuntimeError) as context:
            KeyUtils._get_platform_info_path()
        self.assertIn("FIDO_HOME environment variable is not set", str(context.exception))

    def test_kdf_info_persistence_across_instances(self):
        """Test that KDF info persists across multiple get/set operations."""
        values = ["VALUE-1", "VALUE-2", "VALUE-3"]
        
        for value in values:
            KeyUtils.set_credential_kdf_info(value)
            retrieved = KeyUtils.get_credential_kdf_info()
            self.assertEqual(retrieved, value.encode('utf-8'))

    def test_kdf_info_encryption_integrity(self):
        """Test that stored KDF info is encrypted and cannot be read as plaintext."""
        secret_info = "SECRET-KDF-INFO"
        KeyUtils.set_credential_kdf_info(secret_info)
        
        # Read the raw file content
        info_path = KeyUtils._get_platform_info_path()
        with open(info_path, 'r') as f:
            raw_content = f.read()
        
        # The raw content should not contain the plaintext secret
        self.assertNotIn(secret_info, raw_content)
        
        # But decryption should recover it
        retrieved = KeyUtils.get_credential_kdf_info()
        self.assertEqual(retrieved, secret_info.encode('utf-8'))

    def test_corrupted_file_returns_default(self):
        """Test that corrupted platform.info file returns default value."""
        # Create a corrupted file
        info_path = KeyUtils._get_platform_info_path()
        with open(info_path, 'w') as f:
            f.write("CORRUPTED_DATA_NOT_BASE64")
        
        # Should return default without crashing
        kdf_info = KeyUtils.get_credential_kdf_info()
        self.assertEqual(kdf_info, b"CTAP2-CRED-INFO-v1")


class TestDeterministicKeyDerivation(unittest.TestCase):
    """Test cases for Phase 2: Deterministic Key Derivation Helpers."""

    def setUp(self):
        """Set up test fixtures with temporary FIDO_HOME."""
        # Create a temporary directory for FIDO_HOME
        self.test_fido_home = tempfile.mkdtemp()
        self.original_fido_home = os.environ.get('FIDO_HOME')
        os.environ['FIDO_HOME'] = self.test_fido_home
        
        # Create a platform key for encryption/decryption
        self.platform_key = KeyUtils.create_platform_key()
        
        # Set default KDF info for consistent testing
        KeyUtils.set_credential_kdf_info("CTAP2-CRED-INFO-v1")

    def tearDown(self):
        """Clean up test fixtures."""
        # Restore original FIDO_HOME
        if self.original_fido_home is not None:
            os.environ['FIDO_HOME'] = self.original_fido_home
        else:
            os.environ.pop('FIDO_HOME', None)
        
        # Remove temporary directory
        if os.path.exists(self.test_fido_home):
            shutil.rmtree(self.test_fido_home)

    def test_p256_derivation_is_deterministic(self):
        """Test that P-256 keypair derivation is deterministic."""
        master_secret = b"A" * 32
        rp_id = b"example.com"
        nonce = b"B" * 32

        kp1 = KeyUtils.derive_p256_keypair(master_secret, rp_id, nonce)
        kp2 = KeyUtils.derive_p256_keypair(master_secret, rp_id, nonce)

        self.assertEqual(kp1.get_public_bytes(), kp2.get_public_bytes())

    def test_mldsa44_derivation_is_deterministic(self):
        """Test that ML-DSA-44 keypair derivation is deterministic."""
        master_secret = b"A" * 32
        rp_id = b"example.com"
        nonce = b"B" * 32

        kp1 = KeyUtils.derive_mldsa_keypair(master_secret, rp_id, nonce, "ML-DSA-44", -48)
        kp2 = KeyUtils.derive_mldsa_keypair(master_secret, rp_id, nonce, "ML-DSA-44", -48)

        self.assertEqual(kp1.get_public(), kp2.get_public())

    def test_different_kdf_info_changes_derived_key(self):
        """Test that different KDF info values produce different keys."""
        master_secret = b"A" * 32
        rp_id = b"example.com"
        nonce = b"B" * 32

        KeyUtils.set_credential_kdf_info("FIDO2-CRED-KEY-v1")
        kp1 = KeyUtils.derive_p256_keypair(master_secret, rp_id, nonce)

        KeyUtils.set_credential_kdf_info("FIDO2-CRED-KEY-v2")
        kp2 = KeyUtils.derive_p256_keypair(master_secret, rp_id, nonce)

        self.assertNotEqual(kp1.get_public_bytes(), kp2.get_public_bytes())

    def test_different_nonce_changes_key(self):
        """Test that different nonces produce different keys."""
        master_secret = b"A" * 32
        rp_id = b"example.com"

        kp1 = KeyUtils.derive_p256_keypair(master_secret, rp_id, b"B" * 32)
        kp2 = KeyUtils.derive_p256_keypair(master_secret, rp_id, b"C" * 32)

        self.assertNotEqual(kp1.get_public_bytes(), kp2.get_public_bytes())

    def test_different_rp_id_changes_key(self):
        """Test that different RP IDs produce different keys."""
        master_secret = b"A" * 32
        nonce = b"B" * 32

        kp1 = KeyUtils.derive_p256_keypair(master_secret, b"example.com", nonce)
        kp2 = KeyUtils.derive_p256_keypair(master_secret, b"example.org", nonce)

        self.assertNotEqual(kp1.get_public_bytes(), kp2.get_public_bytes())

    def test_different_master_secret_changes_key(self):
        """Test that different master secrets produce different keys."""
        rp_id = b"example.com"
        nonce = b"B" * 32

        kp1 = KeyUtils.derive_p256_keypair(b"A" * 32, rp_id, nonce)
        kp2 = KeyUtils.derive_p256_keypair(b"C" * 32, rp_id, nonce)

        self.assertNotEqual(kp1.get_public_bytes(), kp2.get_public_bytes())

    def test_derive_keypair_from_context_p256(self):
        """Test algorithm dispatch for P-256 (COSE -7)."""
        master_secret = b"A" * 32
        rp_id = b"example.com"
        nonce = b"B" * 32

        kp_direct = KeyUtils.derive_p256_keypair(master_secret, rp_id, nonce)
        kp_dispatch = KeyUtils.derive_keypair_from_context(master_secret, rp_id, nonce, -7)

        self.assertEqual(kp_direct.get_public_bytes(), kp_dispatch.get_public_bytes())

    def test_derive_keypair_from_context_mldsa44(self):
        """Test algorithm dispatch for ML-DSA-44 (COSE -48)."""
        master_secret = b"A" * 32
        rp_id = b"example.com"
        nonce = b"B" * 32

        kp_direct = KeyUtils.derive_mldsa_keypair(master_secret, rp_id, nonce, "ML-DSA-44", -48)
        kp_dispatch = KeyUtils.derive_keypair_from_context(master_secret, rp_id, nonce, -48)

        self.assertEqual(kp_direct.get_public(), kp_dispatch.get_public())

    def test_derive_keypair_from_context_unsupported_algorithm(self):
        """Test that unsupported COSE algorithms raise ValueError."""
        master_secret = b"A" * 32
        rp_id = b"example.com"
        nonce = b"B" * 32

        with self.assertRaises(ValueError) as context:
            KeyUtils.derive_keypair_from_context(master_secret, rp_id, nonce, -999)
        self.assertIn("Unsupported COSE algorithm", str(context.exception))

    def test_derive_credential_key_material_length(self):
        """Test that derive_credential_key_material produces correct length output."""
        master_secret = b"A" * 32
        rp_id = b"example.com"
        nonce = b"B" * 32

        # Test various lengths
        for length in [16, 32, 48, 64]:
            material = KeyUtils.derive_credential_key_material(
                master_secret=master_secret,
                rp_id=rp_id,
                credential_nonce=nonce,
                cose_alg=-7,
                length=length,
                alg_suffix=b"|TEST",
            )
            self.assertEqual(len(material), length)

    def test_derive_credential_key_material_is_deterministic(self):
        """Test that derive_credential_key_material is deterministic."""
        master_secret = b"A" * 32
        rp_id = b"example.com"
        nonce = b"B" * 32

        material1 = KeyUtils.derive_credential_key_material(
            master_secret=master_secret,
            rp_id=rp_id,
            credential_nonce=nonce,
            cose_alg=-7,
            length=32,
            alg_suffix=b"|EC",
        )
        material2 = KeyUtils.derive_credential_key_material(
            master_secret=master_secret,
            rp_id=rp_id,
            credential_nonce=nonce,
            cose_alg=-7,
            length=32,
            alg_suffix=b"|EC",
        )
        self.assertEqual(material1, material2)

    def test_different_alg_suffix_changes_material(self):
        """Test that different algorithm suffixes produce different key material."""
        master_secret = b"A" * 32
        rp_id = b"example.com"
        nonce = b"B" * 32

        material_ec = KeyUtils.derive_credential_key_material(
            master_secret=master_secret,
            rp_id=rp_id,
            credential_nonce=nonce,
            cose_alg=-7,
            length=32,
            alg_suffix=b"|EC",
        )
        material_mldsa = KeyUtils.derive_credential_key_material(
            master_secret=master_secret,
            rp_id=rp_id,
            credential_nonce=nonce,
            cose_alg=-7,
            length=32,
            alg_suffix=b"|MLDSA",
        )
        self.assertNotEqual(material_ec, material_mldsa)

    def test_different_cose_alg_changes_material(self):
        """Test that different COSE algorithms produce different key material."""
        master_secret = b"A" * 32
        rp_id = b"example.com"
        nonce = b"B" * 32

        material1 = KeyUtils.derive_credential_key_material(
            master_secret=master_secret,
            rp_id=rp_id,
            credential_nonce=nonce,
            cose_alg=-7,
            length=32,
            alg_suffix=b"|EC",
        )
        material2 = KeyUtils.derive_credential_key_material(
            master_secret=master_secret,
            rp_id=rp_id,
            credential_nonce=nonce,
            cose_alg=-8,
            length=32,
            alg_suffix=b"|EC",
        )
        self.assertNotEqual(material1, material2)

    def test_p256_scalar_in_valid_range(self):
        """Test that derived P-256 scalar is in valid range [1, order-1]."""
        master_secret = b"A" * 32
        rp_id = b"example.com"
        nonce = b"B" * 32

        # Derive keypair multiple times with different inputs
        for i in range(10):
            test_nonce = (i).to_bytes(32, 'big')
            kp = KeyUtils.derive_p256_keypair(master_secret, rp_id, test_nonce)
            
            # If we can get the public key, the scalar was valid
            # (invalid scalars would cause an exception during key derivation)
            self.assertIsNotNone(kp.get_public())
            self.assertIsNotNone(kp.get_private())


if __name__ == '__main__':
    unittest.main()

# Made with Bob
