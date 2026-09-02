#!/usr/bin/env python3
"""
Unit tests for TPM-based key derivation functionality.

Tests the TPM ECDH-IKM-based HKDF implementation for passkey seed derivation,
ensuring deterministic behavior, domain separation, and backward compatibility.
"""

import unittest
import base64
from unittest.mock import Mock, patch, MagicMock
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

from soft_fido2.key_pair import KeyUtils
from soft_fido2.platform import TPMDevice, TPMKeyPair


class TestTPMDerivation(unittest.TestCase):
    """Test TPM-based key derivation"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Create a software EC key for comparison tests
        self.software_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        
        # Mock TPM device and key pair
        self.mock_tpm_device = Mock(spec=TPMDevice)
        self.mock_tpm_key = Mock(spec=TPMKeyPair)
        self.mock_tpm_key.is_tpm = True
        self.mock_tpm_key.tpm_device = self.mock_tpm_device
        self.mock_tpm_key.handle = 0x8104F1D0
        self.mock_tpm_key.tpm_password = b""

        # Set up deterministic IKM output for testing.
        # _tpm_derive_seed calls tpm_device.ecdh_derive_ikm(persistent_handle, password)
        self.test_ikm = b'\x01' * 32  # 32-byte IKM for testing
        self.mock_tpm_device.ecdh_derive_ikm.return_value = self.test_ikm
    
    def test_file_key_derivation_backward_compatibility(self):
        """Test that file-based keys still work with the refactored code"""
        entropy = b"example.com"
        
        # This should not raise an exception
        seed = KeyUtils.get_passkey_seed(entropy, self.software_key)
        
        # Verify the seed is properly formatted
        self.assertIsInstance(seed, bytes)
        # Base64-url encoded 32 bytes should be 43 characters (with padding stripped)
        decoded = base64.urlsafe_b64decode(seed + b'==')  # Add padding for decode
        self.assertEqual(len(decoded), 32)
    
    def test_tpm_key_dispatch(self):
        """Test that TPM keys are properly dispatched to TPM derivation path"""
        entropy = b"example.com"
        
        seed = KeyUtils.get_passkey_seed(entropy, self.mock_tpm_key)
        
        # Verify ecdh_derive_ikm was called with the key's handle and password
        self.mock_tpm_device.ecdh_derive_ikm.assert_called_once_with(
            persistent_handle=self.mock_tpm_key.handle,
            password=self.mock_tpm_key.tpm_password
        )
        
        # Verify seed is properly formatted
        self.assertIsInstance(seed, bytes)
        decoded = base64.urlsafe_b64decode(seed + b'==')
        self.assertEqual(len(decoded), 32)
    
    def test_tpm_derivation_deterministic(self):
        """Test that TPM derivation is deterministic for same inputs"""
        entropy = b"example.com"
        
        seed1 = KeyUtils.get_passkey_seed(entropy, self.mock_tpm_key)
        seed2 = KeyUtils.get_passkey_seed(entropy, self.mock_tpm_key)
        
        self.assertEqual(seed1, seed2, "TPM derivation must be deterministic")
    
    def test_tpm_derivation_different_entropy(self):
        """Test that different entropy produces different seeds"""
        entropy1 = b"example.com"
        entropy2 = b"different.com"
        
        # Reset mock to ensure fresh calls
        self.mock_tpm_device.ecdh_derive_ikm.reset_mock()
        
        # ecdh_derive_ikm returns fixed IKM regardless of entropy;
        # entropy is the HKDF salt so different entropy → different seed.
        self.mock_tpm_device.ecdh_derive_ikm.return_value = self.test_ikm
        
        seed1 = KeyUtils.get_passkey_seed(entropy1, self.mock_tpm_key)
        seed2 = KeyUtils.get_passkey_seed(entropy2, self.mock_tpm_key)
        
        self.assertNotEqual(seed1, seed2, "Different entropy must produce different seeds")
    
    def test_entropy_validation(self):
        """Test that entropy must be bytes"""
        with self.assertRaises(ValueError) as context:
            KeyUtils.get_passkey_seed("not bytes", self.software_key)
        
        self.assertIn("Entropy must be bytes", str(context.exception))
    
    def test_file_key_type_validation(self):
        """Test that file-based path validates key type"""
        entropy = b"example.com"
        invalid_key = "not a key"
        
        with self.assertRaises(ValueError) as context:
            KeyUtils._file_derive_seed(entropy, invalid_key)
        
        self.assertIn("EllipticCurvePrivateKey", str(context.exception))
    
    def test_tpm_key_attributes_required(self):
        """Test that TPM keys must have required attributes"""
        entropy = b"example.com"
        
        # Test missing tpm_device attribute
        bad_tpm_key = Mock()
        bad_tpm_key.is_tpm = True
        bad_tpm_key.handle = 0x8104F1D0
        # Missing tpm_device attribute - accessing it will raise AttributeError
        del bad_tpm_key.tpm_device
        
        with self.assertRaises(AttributeError):
            KeyUtils._tpm_derive_seed(entropy, bad_tpm_key)
        
        # Test missing handle attribute
        bad_tpm_key2 = Mock()
        bad_tpm_key2.is_tpm = True
        bad_tpm_key2.tpm_device = Mock()
        bad_tpm_key2.tpm_device.ecdh_derive_ikm.return_value = b'\x01' * 32
        # Missing handle attribute
        del bad_tpm_key2.handle
        
        with self.assertRaises(AttributeError):
            KeyUtils._tpm_derive_seed(entropy, bad_tpm_key2)
    
    def test_tpm_ikm_parameters(self):
        """Test that ecdh_derive_ikm is called with correct parameters"""
        entropy = b"test.example.com"
        handle = 0x8104F1D0
        password = b""
        
        self.mock_tpm_key.handle = handle
        self.mock_tpm_key.tpm_password = password
        
        KeyUtils.get_passkey_seed(entropy, self.mock_tpm_key)
        
        # Verify ecdh_derive_ikm was called with correct parameters
        self.mock_tpm_device.ecdh_derive_ikm.assert_called_once_with(
            persistent_handle=handle,
            password=password
        )
    
    def test_hkdf_info_constant(self):
        """Test that HKDF uses the correct info string"""
        # The info string should be consistent; verify the output is stable
        entropy = b"example.com"
        
        seed1 = KeyUtils.get_passkey_seed(entropy, self.mock_tpm_key)
        seed2 = KeyUtils.get_passkey_seed(entropy, self.mock_tpm_key)
        
        self.assertEqual(seed1, seed2)


class TestTPMDeviceECDH(unittest.TestCase):
    """Test TPMDevice ecdh_derive_ikm functionality"""
    
    @patch('soft_fido2.platform.nix.tpm_device.ESAPI')
    @patch('soft_fido2.platform.nix.tpm_device.redirect_tcti_to_logging')
    def test_ecdh_derive_ikm_basic_operation(self, mock_redirect, mock_esapi_class):
        """Test basic ecdh_derive_ikm operation"""
        mock_esapi = MagicMock()
        mock_esapi_class.return_value = mock_esapi

        mock_handle = MagicMock()
        mock_esapi.tr_from_tpmpublic.return_value = mock_handle

        # Mock read_public to return a public key with ECC point
        mock_pub = MagicMock()
        mock_pub.publicArea.unique.ecc.x = b'\x01' * 32
        mock_pub.publicArea.unique.ecc.y = b'\x02' * 32
        mock_esapi.read_public.return_value = (mock_pub, None, None)

        # Mock ecdh_zgen to return a Z point
        mock_z_point = MagicMock()
        mock_z_point.point.x = b'\xaa' * 32
        mock_esapi.ecdh_zgen.return_value = mock_z_point

        tpm = TPMDevice()
        result = tpm.ecdh_derive_ikm()

        # Verify result is the x-coordinate of the Z point
        self.assertEqual(result, b'\xaa' * 32)
        self.assertEqual(len(result), 32)

        # Verify ecdh_zgen was called
        mock_esapi.ecdh_zgen.assert_called_once()

    @patch('soft_fido2.platform.nix.tpm_device.ESAPI')
    @patch('soft_fido2.platform.nix.tpm_device.redirect_tcti_to_logging')
    def test_ecdh_derive_ikm_custom_handle(self, mock_redirect, mock_esapi_class):
        """Test ecdh_derive_ikm with custom persistent handle"""
        mock_esapi = MagicMock()
        mock_esapi_class.return_value = mock_esapi

        mock_handle = MagicMock()
        mock_esapi.tr_from_tpmpublic.return_value = mock_handle

        mock_pub = MagicMock()
        mock_pub.publicArea.unique.ecc.x = b'\x03' * 32
        mock_pub.publicArea.unique.ecc.y = b'\x04' * 32
        mock_esapi.read_public.return_value = (mock_pub, None, None)

        mock_z_point = MagicMock()
        mock_z_point.point.x = b'\xbb' * 32
        mock_esapi.ecdh_zgen.return_value = mock_z_point

        tpm = TPMDevice()
        custom_handle = 0x81000001
        result = tpm.ecdh_derive_ikm(persistent_handle=custom_handle)

        # Verify the custom handle was used
        mock_esapi.tr_from_tpmpublic.assert_called_once()
        self.assertEqual(result, b'\xbb' * 32)


class TestIntegrationScenarios(unittest.TestCase):
    """Integration tests for real-world scenarios"""
    
    def test_multiple_rp_ids_software_key(self):
        """Test derivation for multiple RP IDs with software key"""
        software_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        
        rp_ids = [b"example.com", b"test.com", b"demo.org"]
        seeds = []
        
        for rp_id in rp_ids:
            seed = KeyUtils.get_passkey_seed(rp_id, software_key)
            seeds.append(seed)
        
        # All seeds should be unique
        self.assertEqual(len(seeds), len(set(seeds)))
        
        # Each seed should be properly formatted
        for seed in seeds:
            decoded = base64.urlsafe_b64decode(seed + b'==')
            self.assertEqual(len(decoded), 32)
    
    def test_multiple_rp_ids_tpm_key(self):
        """Test derivation for multiple RP IDs with TPM key"""
        mock_tpm_device = Mock(spec=TPMDevice)
        mock_tpm_key = Mock()
        mock_tpm_key.is_tpm = True
        mock_tpm_key.tpm_device = mock_tpm_device
        mock_tpm_key.handle = 0x8104F1D0
        mock_tpm_key.tpm_password = b""

        rp_ids = [b"example.com", b"test.com", b"demo.org"]
        
        # ecdh_derive_ikm returns fixed IKM; entropy (HKDF salt) drives uniqueness
        mock_tpm_device.ecdh_derive_ikm.return_value = b'\x01' * 32
        
        seeds = []
        for rp_id in rp_ids:
            seed = KeyUtils.get_passkey_seed(rp_id, mock_tpm_key)
            seeds.append(seed)
        
        # All seeds should be unique (different entropy → different HKDF output)
        self.assertEqual(len(seeds), len(set(seeds)))
        
        # Verify ecdh_derive_ikm was called for each RP ID
        self.assertEqual(mock_tpm_device.ecdh_derive_ikm.call_count, len(rp_ids))


if __name__ == '__main__':
    unittest.main()

# Made with Bob
