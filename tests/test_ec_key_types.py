#!/usr/bin/env python3
"""Test that all EC key types with different hash algorithms work correctly."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from soft_fido2.key_pair import KeyUtils, KeyPair


def test_ec_key_with_sha256():
    """Test EC key with SHA256 (ES256, alg_id=-7)"""
    # Generate P-256 key
    private_key = ec.generate_private_key(ec.SECP256R1())
    
    # Get config with SHA256
    config = KeyUtils._get_key_config(private_key, hashes.SHA256())
    assert config['alg_id'] == -7, f"Expected alg_id -7 for ES256, got {config['alg_id']}"
    
    # Extract key material
    key_material = config['extract_key'](private_key)
    assert len(key_material) == 32, f"Expected 32 bytes for P-256, got {len(key_material)}"
    
    print("✓ EC key with SHA256 (ES256) works correctly")


def test_ec_key_with_sha384():
    """Test EC key with SHA384 (ES384, alg_id=-35)"""
    # Generate P-384 key
    private_key = ec.generate_private_key(ec.SECP384R1())
    
    # Get config with SHA384
    config = KeyUtils._get_key_config(private_key, hashes.SHA384())
    assert config['alg_id'] == -35, f"Expected alg_id -35 for ES384, got {config['alg_id']}"
    
    # Extract key material
    key_material = config['extract_key'](private_key)
    assert len(key_material) == 48, f"Expected 48 bytes for P-384, got {len(key_material)}"
    
    print("✓ EC key with SHA384 (ES384) works correctly")


def test_ec_key_with_sha512():
    """Test EC key with SHA512 (ES512, alg_id=-36)"""
    # Generate P-521 key
    private_key = ec.generate_private_key(ec.SECP521R1())
    
    # Get config with SHA512
    config = KeyUtils._get_key_config(private_key, hashes.SHA512())
    assert config['alg_id'] == -36, f"Expected alg_id -36 for ES512, got {config['alg_id']}"
    
    # Extract key material
    key_material = config['extract_key'](private_key)
    assert len(key_material) == 66, f"Expected 66 bytes for P-521, got {len(key_material)}"
    
    print("✓ EC key with SHA512 (ES512) works correctly")


def test_ec_key_without_hash_raises_error():
    """Test that EC key without hash algorithm raises ValueError"""
    private_key = ec.generate_private_key(ec.SECP256R1())
    
    try:
        KeyUtils._get_key_config(private_key)
        assert False, "Expected ValueError when hash_alg is not provided for EC key"
    except ValueError as e:
        assert "Hash algorithm is required" in str(e)
        print("✓ EC key without hash algorithm correctly raises ValueError")


def test_all_ec_configs_are_unique():
    """Test that all EC key configurations have unique algorithm IDs"""
    ec_configs = [
        (ec.EllipticCurvePrivateKey, hashes.SHA256),
        (ec.EllipticCurvePrivateKey, hashes.SHA384),
        (ec.EllipticCurvePrivateKey, hashes.SHA512),
    ]
    
    alg_ids = []
    for key_type, hash_type in ec_configs:
        key = (key_type, hash_type)
        if key in KeyUtils._KEY_TYPE_CONFIG:
            alg_id = KeyUtils._KEY_TYPE_CONFIG[key]['alg_id']
            alg_ids.append(alg_id)
    
    assert len(alg_ids) == len(set(alg_ids)), f"Duplicate algorithm IDs found: {alg_ids}"
    assert -7 in alg_ids, "ES256 (alg_id=-7) not found"
    assert -35 in alg_ids, "ES384 (alg_id=-35) not found"
    assert -36 in alg_ids, "ES512 (alg_id=-36) not found"
    
    print(f"✓ All EC configurations are unique with alg_ids: {sorted(alg_ids)}")

