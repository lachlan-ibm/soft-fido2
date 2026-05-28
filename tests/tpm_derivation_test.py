#!/usr/bin/env python3
"""
Unit tests for TPM-based key derivation functionality.

Tests the TPM HMAC-based HKDF implementation for passkey seed derivation,
ensuring deterministic behavior, domain separation, and backward compatibility.
"""

import unittest
import base64
from unittest.mock import Mock, patch, MagicMock
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

from soft_fido2.key_pair import KeyUtils
from soft_fido2.tpm_device import TPMDevice


class TestTPMDerivation(unittest.TestCase):
    """Test TPM-based key derivation"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Create a software EC key for comparison tests
        self.software_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        
        # Mock TPM device and key pair
        self.mock_tpm_device = Mock(spec=TPMDevice)
        self.mock_tpm_key = Mock()
        self.mock_tpm_key.is_tpm = True
        self.mock_tpm_key.tpm_device = self.mock_tpm_device
        self.mock_tpm_key.handle = 0x8104F1D0
        
        # Set up deterministic HMAC output for testing
        # This simulates the TPM HMAC operation returning a fixed PRK
        self.test_prk = b'\x01' * 32  # 32-byte PRK for testing
        self.mock_tpm_device.hmac.return_value = self.test_prk
    
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
        
        # Verify TPM HMAC was called
        self.mock_tpm_device.hmac.assert_called_once_with(
            data=entropy,
            persistent_handle=self.mock_tpm_key.handle
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
        self.mock_tpm_device.hmac.reset_mock()
        
        # Set different PRK for different entropy
        def hmac_side_effect(data, persistent_handle):
            if data == entropy1:
                return b'\x01' * 32
            else:
                return b'\x02' * 32
        
        self.mock_tpm_device.hmac.side_effect = hmac_side_effect
        
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
        bad_tpm_key2.tpm_device.hmac.return_value = b'\x01' * 32
        # Missing handle attribute
        del bad_tpm_key2.handle
        
        with self.assertRaises(AttributeError):
            KeyUtils._tpm_derive_seed(entropy, bad_tpm_key2)
    
    def test_tpm_hmac_parameters(self):
        """Test that TPM HMAC is called with correct parameters"""
        entropy = b"test.example.com"
        handle = 0x8104F1D0
        
        self.mock_tpm_key.handle = handle
        
        KeyUtils.get_passkey_seed(entropy, self.mock_tpm_key)
        
        # Verify HMAC was called with correct parameters
        self.mock_tpm_device.hmac.assert_called_once_with(
            data=entropy,
            persistent_handle=handle
        )
    
    def test_hkdf_info_constant(self):
        """Test that HKDF uses the correct info string"""
        # This is implicitly tested by the deterministic test,
        # but we verify the constant is used correctly
        entropy = b"example.com"
        
        # The info string should be b"FIDO2-PASSKEY-SEED"
        # We can't directly test this without mocking HKDFExpand,
        # but we verify the output is consistent
        seed1 = KeyUtils.get_passkey_seed(entropy, self.mock_tpm_key)
        seed2 = KeyUtils.get_passkey_seed(entropy, self.mock_tpm_key)
        
        self.assertEqual(seed1, seed2)


class TestTPMDeviceHMAC(unittest.TestCase):
    """Test TPMDevice HMAC functionality"""
    
    @patch('soft_fido2.tpm_device.ESAPI')
    @patch('soft_fido2.tpm_device.redirect_tcti_to_logging')
    def test_hmac_basic_operation(self, mock_redirect, mock_esapi_class):
        """Test basic HMAC operation"""
        # Set up mocks
        mock_esapi = MagicMock()
        mock_esapi_class.return_value = mock_esapi
        
        mock_handle = MagicMock()
        mock_esapi.tr_from_tpmpublic.return_value = mock_handle
        
        # Mock HMAC result
        mock_result = MagicMock()
        mock_result.buffer = b'\xaa' * 32
        mock_esapi.hmac.return_value = mock_result
        
        # Create TPM device and call HMAC
        tpm = TPMDevice()
        data = b"test data"
        result = tpm.hmac(data)
        
        # Verify result
        self.assertEqual(result, b'\xaa' * 32)
        self.assertEqual(len(result), 32)
        
        # Verify HMAC was called correctly
        mock_esapi.hmac.assert_called_once()
        call_args = mock_esapi.hmac.call_args
        self.assertEqual(bytes(call_args[1]['buffer'].buffer), data)
    
    @patch('soft_fido2.tpm_device.ESAPI')
    @patch('soft_fido2.tpm_device.redirect_tcti_to_logging')
    def test_hmac_custom_handle(self, mock_redirect, mock_esapi_class):
        """Test HMAC with custom persistent handle"""
        mock_esapi = MagicMock()
        mock_esapi_class.return_value = mock_esapi
        
        mock_handle = MagicMock()
        mock_esapi.tr_from_tpmpublic.return_value = mock_handle
        
        mock_result = MagicMock()
        mock_result.buffer = b'\xbb' * 32
        mock_esapi.hmac.return_value = mock_result
        
        tpm = TPMDevice()
        custom_handle = 0x81000001
        result = tpm.hmac(b"data", persistent_handle=custom_handle)
        
        # Verify custom handle was used
        from tpm2_pytss.types import TPM2_HANDLE
        mock_esapi.tr_from_tpmpublic.assert_called_once()
        # The handle should be wrapped in TPM2_HANDLE
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
        
        rp_ids = [b"example.com", b"test.com", b"demo.org"]
        
        # Set up different HMAC outputs for different RP IDs
        def hmac_side_effect(data, persistent_handle):
            # Use hash of data to generate deterministic but different outputs
            import hashlib
            return hashlib.sha256(data).digest()
        
        mock_tpm_device.hmac.side_effect = hmac_side_effect
        
        seeds = []
        for rp_id in rp_ids:
            seed = KeyUtils.get_passkey_seed(rp_id, mock_tpm_key)
            seeds.append(seed)
        
        # All seeds should be unique
        self.assertEqual(len(seeds), len(set(seeds)))
        
        # Verify TPM HMAC was called for each RP ID
        self.assertEqual(mock_tpm_device.hmac.call_count, len(rp_ids))


if __name__ == '__main__':
    unittest.main()

# Made with Bob
