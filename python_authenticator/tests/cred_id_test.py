#!/bin/python3

from soft_FIDO2 import Fido2Authenticator, KeyPair
import pytest
import uuid
from cryptography.fernet import Fernet


def test_Cred_id_Consturctor():
    u = str(uuid.uuid4())
    kp = KeyPair.generate_rsa()
    authenticator = Fido2Authenticator(keyPair=kp, credId=u)
    assert authenticator.get_credential_id() == u, "Cred Id does not match original"


def test_Cred_Id_As_Encrypted_Key():
    fk = Fernet(Fernet.generate_key())
    kp = KeyPair.generate_ecdsa()
    authenticator = Fido2Authenticator(keyPair=kp, fKey=fk)

    credIdBytes = authenticator._get_credential_id_bytes(kp)
    credId = authenticator.get_credential_id()
    new_authenticator = Fido2Authenticator(credId=credId, fKey=fk)

    original_key = kp.get_private_bytes()
    rebuilt_key = new_authenticator.kp.get_private_bytes()

    assert original_key == rebuilt_key, "Serialized keys are different"
    assert credIdBytes == new_authenticator._get_credential_id_bytes(new_authenticator.kp), "Cred Id bytes are different"
