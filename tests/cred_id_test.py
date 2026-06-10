#!/bin/python3

from hmac import new
from soft_fido2 import Fido2Authenticator, KeyPair
from soft_fido2.credential_id_migrator import CredentialIdMigrator
from soft_fido2.key_pair import KeyUtils
import uuid
import base64
import secrets
from cryptography.fernet import Fernet

from soft_fido2.symmetric_key import SymmetricKey


def test_Cred_id_Consturctor():
    u = str(uuid.uuid4()).encode()
    kp = KeyPair.generate_rsa()
    authenticator = Fido2Authenticator(keyPair=kp, credId=u)
    # get_credential_id() returns base64-encoded version of cib
    # Since we passed raw bytes as credId, cib is those raw bytes
    # So get_credential_id() returns base64.urlsafe_b64encode(u).decode()
    assert authenticator.get_credential_id() == base64.urlsafe_b64encode(u).decode(), "Cred Id does not match original"


def test_Cred_Id_As_Encrypted_Key():
    """Test Prefix credential ID format with embedded key material"""
    # Setup
    skey = SymmetricKey(SymmetricKey.generate_key())
    
    # Generate keypair
    cose_alg = -7  # ES256
    kp = KeyPair.generate_ecdsa()
    
    # Create authenticator and generate credential ID
    authenticator = Fido2Authenticator(keyPair=kp, sKey=skey)
    credIdBytes = authenticator._get_credential_id_bytes(kp, alg_id=cose_alg)
    
    # Verify prefix
    assert credIdBytes[:len(Fido2Authenticator.CRED_PREFIX)] == Fido2Authenticator.CRED_PREFIX, "Missing CRED_PREFIX"
    
    # Decrypt metadata and extract key material
    b64CredId = base64.urlsafe_b64encode(credIdBytes)
    decrypted_cose_alg, key_material = Fido2Authenticator._decrypt_credential_context(b64CredId, skey)
    
    # Verify metadata matches
    assert decrypted_cose_alg == cose_alg, "COSE algorithm mismatch"
    assert len(key_material) == 32, "Key material should be 32 bytes"
    
    # Reconstruct keypair from credential ID (use raw bytes, not base64-encoded)
    rebuilt_kp = Fido2Authenticator._get_key_pair_from_credential_id(credIdBytes, skey)
    
    # Verify keys match
    assert kp.get_public_bytes() == rebuilt_kp.get_public_bytes(), "Reconstructed key does not match original"

def test_Cred_Id_As_Fernet_Encrypted_Key():
    """Test Prefix credential ID format with embedded key material"""
    # Setup
    fkey = Fernet(Fernet.generate_key())
    
    # Generate keypair
    cose_alg = -7  # ES256
    kp = KeyPair.generate_ecdsa()
    
    # Create authenticator and generate credential ID
    authenticator = Fido2Authenticator(keyPair=kp, fKey=fkey)
    credIdBytes = authenticator._get_credential_id_bytes(kp, alg_id=cose_alg)
    
    # Verify prefix
    assert credIdBytes[:len(Fido2Authenticator.CRED_PREFIX)] == Fido2Authenticator.CRED_PREFIX, "Missing CRED_PREFIX"
    
    # Decrypt metadata and extract key material
    b64CredId = base64.urlsafe_b64encode(credIdBytes)
    decrypted_cose_alg, key_material = Fido2Authenticator._decrypt_credential_context(b64CredId, fkey)
    
    # Verify metadata matches
    assert decrypted_cose_alg == cose_alg, "COSE algorithm mismatch"
    assert len(key_material) == 32, "Key material should be 32 bytes"
    
    # Reconstruct keypair from credential ID (use raw bytes, not base64-encoded)
    rebuilt_kp = Fido2Authenticator._get_key_pair_from_credential_id(credIdBytes, fkey)
    
    # Verify keys match
    assert kp.get_public_bytes() == rebuilt_kp.get_public_bytes(), "Reconstructed key does not match original"


def test_CredId_As_Symmetric_Key():
    """Test Prefix credential ID generation with symmetric key"""
    seed = SymmetricKey.generate_key()
    kp = KeyPair.generate_ecdsa()
    authenticator = Fido2Authenticator(keyPair=kp, sKey=SymmetricKey(seed))
    
    # Generate credential ID with F1D0 format
    cose_alg = -7
    credIdBytes = authenticator._get_credential_id_bytes(kp, alg_id=cose_alg)
    assert credIdBytes is not None, "Credential ID generation failed"
    assert len(credIdBytes) > 0, "Credential ID is empty"
    assert credIdBytes[:len(Fido2Authenticator.CRED_PREFIX)] == Fido2Authenticator.CRED_PREFIX, "Missing CRED_PREFIX"


def test_CredId_migrate_fernet_to_symkey():
    """Test Prefix format works with both Fernet and SymmetricKey"""
    seed = SymmetricKey.generate_key()
    sk = SymmetricKey(seed)
    fk = Fernet(seed)
    kp = KeyPair.generate_ecdsa()
    
    # Test with Fernet key
    auth_fernet = Fido2Authenticator(keyPair=kp, fKey=fk)
    assert auth_fernet.kp, "Authenticator Key Pair not found"
    
    cose_alg = -7
    cred_id_fernet = auth_fernet._get_credential_id_bytes(kp, alg_id=cose_alg)
    assert cred_id_fernet[:len(Fido2Authenticator.CRED_PREFIX)] == Fido2Authenticator.CRED_PREFIX
    
    # Test with SymmetricKey
    auth_symkey = Fido2Authenticator(keyPair=kp, sKey=sk)
    cred_id_symkey = auth_symkey._get_credential_id_bytes(kp, alg_id=cose_alg)
    assert cred_id_symkey[:len(Fido2Authenticator.CRED_PREFIX)] == Fido2Authenticator.CRED_PREFIX


def test_CredId_with_prefix():
    """Test Prefix credential ID format with CRED_PREFIX"""
    skey = SymmetricKey(SymmetricKey.generate_key())
    
    # Generate keypair
    cose_alg = -7  # ES256
    kp = KeyPair.generate_ecdsa()
    
    authenticator = Fido2Authenticator(keyPair=kp, sKey=skey)
    
    # Get credential ID (already includes prefix in F1D0 format)
    cred_id_bytes = authenticator._get_credential_id_bytes(kp, alg_id=cose_alg)
    
    # Verify prefix is already included
    assert cred_id_bytes[:len(Fido2Authenticator.CRED_PREFIX)] == Fido2Authenticator.CRED_PREFIX, "Missing CRED_PREFIX"
    
    # Verify size is within CTAP2 limit
    assert len(cred_id_bytes) < 1024, f"Credential ID ({len(cred_id_bytes)} bytes) exceeds 1024 byte limit"
    
    # Reconstruct keypair from credential ID (use raw bytes directly)
    reconstructed_kp = Fido2Authenticator._get_key_pair_from_credential_id(cred_id_bytes, skey)
    
    # Verify the reconstructed key matches the original
    assert kp.get_public_bytes() == reconstructed_kp.get_public_bytes(), "Reconstructed key does not match original"
    print(f"Prefix credential ID test passed (size: {len(cred_id_bytes)} bytes)")


def test_F1D0_round_trip_all_algorithms():
    """Test Prefix format round-trip for all supported algorithms"""
    skey = SymmetricKey(SymmetricKey.generate_key())
    
    # Test EC and ML-DSA algorithms
    test_cases = [
        (-7, "ES256", lambda: KeyPair.generate_ecdsa()),
        (-48, "ML-DSA-44", lambda: KeyPair.generate_mldsa("ML-DSA-44")),
        (-49, "ML-DSA-65", lambda: KeyPair.generate_mldsa("ML-DSA-65")),
        (-50, "ML-DSA-87", lambda: KeyPair.generate_mldsa("ML-DSA-87")),
    ]
    
    for alg_id, alg_name, gen_func in test_cases:
        kp = gen_func()
        authenticator = Fido2Authenticator(keyPair=kp, sKey=skey)
        
        # Generate credential ID
        cred_id_bytes = authenticator._get_credential_id_bytes(kp, alg_id=alg_id)
        assert cred_id_bytes[:len(Fido2Authenticator.CRED_PREFIX)] == Fido2Authenticator.CRED_PREFIX
        
        # Reconstruct (use raw bytes directly)
        reconstructed_kp = Fido2Authenticator._get_key_pair_from_credential_id(cred_id_bytes, skey)
        
        # Verify
        assert kp.get_public_bytes() == reconstructed_kp.get_public_bytes()
        print(f"✓ {alg_name} round-trip successful")

# Made with Bob
