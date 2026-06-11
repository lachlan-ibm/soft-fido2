#!/usr/bin/env python3
"""
Test to verify HKDF seed generation works correctly after migration.
"""

import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from soft_fido2.key_pair import KeyUtils, KeyPair


def test_hkdf_seed_generation():
    """Test that HKDF seed generation produces valid output."""
    # Generate a test EC key
    test_key = KeyPair.generate_ecdsa()
    
    # Test with different rp.id values
    rp_ids = [b"google.com", b"github.com", b"webauthn.dev"]
    
    seeds = {}
    for rp_id in rp_ids:
        seed = KeyUtils.get_passkey_seed(rp_id, test_key.get_private())
        seeds[rp_id] = seed
        
        # Verify seed is base64 URL-encoded
        decoded = base64.urlsafe_b64decode(seed)
        assert len(decoded) == 32, f"Seed should be 32 bytes, got {len(decoded)}"
    
    # Verify different rp.id values produce different seeds
    unique_seeds = set(seeds.values())
    assert len(unique_seeds) == len(rp_ids), "Different rp.id values should produce different seeds"
    
    # Verify deterministic: same inputs produce same output
    seed1 = KeyUtils.get_passkey_seed(b"test.com", test_key.get_private())
    seed2 = KeyUtils.get_passkey_seed(b"test.com", test_key.get_private())
    assert seed1 == seed2, "Same inputs should produce same seed (deterministic)"


def test_hkdf_seed_with_fernet():
    """Test that HKDF-generated seeds work correctly with Fernet encryption."""
    from cryptography.fernet import Fernet
    
    test_key = KeyPair.generate_ecdsa()
    seed = KeyUtils.get_passkey_seed(b"fernet-test.com", test_key.get_private())
    f = Fernet(seed)
    
    # Test encryption/decryption
    test_data = b"Hello, FIDO2!"
    encrypted = f.encrypt(test_data)
    decrypted = f.decrypt(encrypted)
    
    assert decrypted == test_data, "Fernet encryption/decryption failed"


def test_hkdf_seed_domain_separation():
    """Test that HKDF provides proper domain separation."""
    test_key = KeyPair.generate_ecdsa()
    
    # Same key, different domains should produce different seeds
    seed_google = KeyUtils.get_passkey_seed(b"google.com", test_key.get_private())
    seed_github = KeyUtils.get_passkey_seed(b"github.com", test_key.get_private())
    
    assert seed_google != seed_github, "Different domains should produce different seeds"


def test_hkdf_seed_key_isolation():
    """Test that different keys produce different seeds for the same domain."""
    key1 = KeyPair.generate_ecdsa()
    key2 = KeyPair.generate_ecdsa()
    
    rp_id = b"example.com"
    
    seed1 = KeyUtils.get_passkey_seed(rp_id, key1.get_private())
    seed2 = KeyUtils.get_passkey_seed(rp_id, key2.get_private())
    
    assert seed1 != seed2, "Different keys should produce different seeds"

# Made with Bob
