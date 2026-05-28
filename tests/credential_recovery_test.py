#!/usr/bin/env python3
# Copyrite IBM 2025
# IBM Confidential

import os
import base64
import secrets
import pytest
from cryptography.fernet import Fernet

from soft_fido2.authenticator import Fido2Authenticator
from soft_fido2.key_pair import KeyPair, KeyUtils
from soft_fido2.symmetric_key import SymmetricKey


@pytest.fixture
def test_data():
    """Fixture providing test data for credential recovery tests."""
    # Test data
    rp_id = "example.com"
    user_id = "user123"
    challenge = os.urandom(32)
    
    # Create attestation options
    attestation_options = {
        "rp": {
            "id": rp_id,
            "name": "Example RP"
        },
        "user": {
            "id": base64.urlsafe_b64encode(user_id.encode()).decode('utf-8').rstrip('='),
            "name": "Test User",
            "displayName": "Test User"
        },
        "challenge": base64.urlsafe_b64encode(challenge).decode('utf-8').rstrip('='),
        "pubKeyCredParams": [
            {
                "type": "public-key",
                "alg": -7  # ES256
            }
        ]
    }
    
    # Create assertion options
    assertion_options = {
        "rpId": rp_id,
        "challenge": base64.urlsafe_b64encode(challenge).decode('utf-8').rstrip('='),
        "allowCredentials": []  # Will be filled after credential creation
    }
    
    return {
        "rp_id": rp_id,
        "user_id": user_id,
        "challenge": challenge,
        "attestation_options": attestation_options,
        "assertion_options": assertion_options
    }


def create_authenticator_with_key(rp_id, key_type="fernet"):
    """
    Create an authenticator with either a Fernet key or SymmetricKey using new prefix format.
    
    Args:
        rp_id (str): The Relying Party ID to use for seed generation
        key_type (str): Type of key to create - "fernet" or "symmetric"
        
    Returns:
        tuple: (authenticator, key, seed, ca_key_pair, cose_alg) where:
            - authenticator is the Fido2Authenticator instance
            - key is either the Fernet key or SymmetricKey
            - seed is the raw seed bytes
            - ca_key_pair is the CA key pair
            - cose_alg is the COSE algorithm identifier
    """
    # Generate a key pair for the authenticator
    ca_key_pair = KeyPair.generate_ecdsa()
    
    # Generate a seed from the RP ID
    if not rp_id:
        raise ValueError("RP ID is required")
        
    seed = KeyUtils.get_passkey_seed(rp_id.encode(), ca_key_pair.get_private())
    
    # Generate credential keypair
    cose_alg = -7  # ES256
    kp = KeyPair.generate_ecdsa()
    
    # Create the appropriate key type
    if key_type.lower() == "fernet":
        key = Fernet(seed)
        authenticator = Fido2Authenticator(keyPair=kp, fKey=key)
    elif key_type.lower() == "symmetric":
        key = SymmetricKey(seed.decode())
        authenticator = Fido2Authenticator(keyPair=kp, sKey=key)
    else:
        raise ValueError(f"Unsupported key type: {key_type}")
    
    # Generate credential ID with prefix format
    authenticator._get_credential_id_bytes(kp, alg_id=cose_alg)
    
    if authenticator.kp is None:
        raise ValueError("Failed to create authenticator: KeyPair missing")
        
    return authenticator, key, seed, ca_key_pair, cose_alg

def generate_credential(authenticator, attestation_options, assertion_options):
    """
    Generate a credential and update the assertion options.
    
    Args:
        authenticator (Fido2Authenticator): The authenticator to use
        attestation_options (dict): The attestation options
        assertion_options (dict): The assertion options to update
        
    Returns:
        str: The credential ID
    """
    if not attestation_options:
        raise ValueError("Attestation options are required")
        
    # Generate a credential (attestation)
    attestation_result = authenticator.credential_create(attestation_options)
    
    # Extract the credential ID
    cred_id = attestation_result['rawId']
    
    # Add the credential to allowed credentials for assertion
    if assertion_options is not None:
        assertion_options["allowCredentials"] = [
            {
                "type": "public-key",
                "id": cred_id
            }
        ]
    
    return cred_id

def verify_assertion_result(assertion_result, cred_id, original_authenticator, new_authenticator):
    """
    Verify the assertion result and that private keys match.
    
    Args:
        assertion_result (dict): The assertion result to verify
        cred_id (str): The credential ID to check against
        original_authenticator (Fido2Authenticator): The original authenticator
        new_authenticator (Fido2Authenticator): The new authenticator
        
    Returns:
        bool: True if verification passes
    """
    # Verify the assertion result
    assert assertion_result['type'] == 'public-key', "Assertion result type is not 'public-key'"
    assert assertion_result['id'] == cred_id, "Assertion result ID does not match credential ID"
    assert 'signature' in assertion_result['response'], "Signature missing from assertion result"
    
    # Verify the private keys match
    assert new_authenticator.kp is not None, "New authenticator key pair not set"
    assert new_authenticator.kp.get_private_bytes() == original_authenticator.kp.get_private_bytes(), "Private keys do not match"
    
    print("ASN1 bytes match")
    return True

def test_credential_recovery_with_fernet_key(test_data):
    """
    Test creating a credential with Fernet key and then recovering it for assertion using new prefix format.
    
    This test verifies the credential recovery flow using a Fernet key:
    1. Creating an authenticator with a Fernet key derived from a seed
    2. Generating a credential (attestation) with the authenticator
    3. Extracting the credential ID for later use
    4. Reconstructing the keypair directly from the credential ID
    5. Performing an assertion with the recovered authenticator
    6. Verifying the assertion result and that the private keys match
    """
    # Create authenticator with Fernet key
    authenticator, key, seed, ca_kp, cose_alg = create_authenticator_with_key(test_data["rp_id"], "fernet")
    
    # Ensure key is of the correct type
    assert isinstance(key, Fernet), "Key must be a Fernet instance"
    fkey = key  # Now we know it's a Fernet key
    
    # Generate credential and update assertion options
    cred_id = generate_credential(
        authenticator,
        test_data["attestation_options"],
        test_data["assertion_options"]
    )

    # Verify seed regeneration
    regen_seed = KeyUtils.get_passkey_seed(test_data["rp_id"].encode(), ca_kp.get_private())
    assert regen_seed == seed, f"registration seed {seed} != assertion seed {regen_seed}"

    # Reconstruct keypair directly from credential ID (new prefix format)
    # cred_id is a base64-encoded string, decode it to get raw bytes
    cred_id_bytes = base64.urlsafe_b64decode(cred_id + '==') if isinstance(cred_id, str) else cred_id
    recovered_kp = Fido2Authenticator._get_key_pair_from_credential_id(cred_id_bytes, Fernet(regen_seed))

    # Create a new authenticator instance for assertion
    # Pass the raw bytes (already decoded above), not re-encoded
    new_authenticator = Fido2Authenticator(keyPair=recovered_kp, credId=cred_id_bytes, fKey=Fernet(seed))
    
    # Perform an assertion with the recovered key
    assertion_result = new_authenticator.credential_request(test_data["assertion_options"])
    
    # Verify the assertion result
    verify_assertion_result(assertion_result, cred_id, authenticator, new_authenticator)

def test_credential_recovery_with_symmetric_key(test_data):
    """
    Test creating a credential with SymmetricKey and then recovering it for assertion using new prefix format.
    
    This test verifies the credential recovery flow using a SymmetricKey:
    1. Creating an authenticator with a SymmetricKey derived from a seed
    2. Generating a credential (attestation) with the authenticator
    3. Extracting the credential ID for later use
    4. Reconstructing the keypair directly from the credential ID
    5. Performing an assertion with the recovered authenticator
    6. Verifying the assertion result and that the private keys match
    
    This test is similar to test_credential_recovery_with_fernet_key but uses SymmetricKey instead of Fernet,
    which provides an alternative encryption mechanism for credential recovery.
    """
    # Create authenticator with SymmetricKey
    authenticator, key, seed, ca_kp, cose_alg = create_authenticator_with_key(test_data["rp_id"], "symmetric")

    # Verify seed regeneration
    regen_seed = KeyUtils.get_passkey_seed(test_data["rp_id"].encode(), ca_kp.get_private())
    assert regen_seed == seed, f"registration seed {seed} != assertion seed {regen_seed}"

    # Ensure key is of the correct type
    assert isinstance(key, SymmetricKey), "Key must be a SymmetricKey instance"
    skey = key  # Now we know it's a SymmetricKey
    
    # Generate credential and update assertion options
    cred_id = generate_credential(
        authenticator,
        test_data["attestation_options"],
        test_data["assertion_options"]
    )
    
    # Reconstruct keypair directly from credential ID (new prefix format)
    # cred_id is a base64-encoded string, decode it to get raw bytes
    cred_id_bytes = base64.urlsafe_b64decode(cred_id + '==') if isinstance(cred_id, str) else cred_id
    recovered_kp = Fido2Authenticator._get_key_pair_from_credential_id(cred_id_bytes, skey)

    # Create a new authenticator instance for assertion
    # Pass the raw bytes (already decoded above), not re-encoded
    new_authenticator = Fido2Authenticator(
        keyPair=recovered_kp,
        credId=cred_id_bytes,
        sKey=skey
    )
    
    # Perform an assertion with the recovered key
    assertion_result = new_authenticator.credential_request(test_data["assertion_options"])
    
    # Verify the assertion result
    verify_assertion_result(assertion_result, cred_id, authenticator, new_authenticator)
# Made with Bob
