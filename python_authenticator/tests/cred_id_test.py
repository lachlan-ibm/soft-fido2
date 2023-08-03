#!/bin/python3

from soft_FIDO2 import Fido2Authenticator, KeyPair
import pytest
import uuid
from cryptography.fernet import Fernet


def Cred_id_Consturctor_Test():
    u = str(uuid.uuid4())
    kp = KeyPair.generate_rsa()
    authenticator = Fido2Authenticator(keyPair=kp, credId=u)
    assert authenticator.get_credential_id() == u, "Cred Id does not match original"


def Cred_Id_As_Encrypted_Key_Test():
    fk = Fernet(Fernet.generate_key())
    kp = KeyPair.generate_ecdsa()
    authenticator = Fido2Authenticator(keyPair=kp, fKey=fk)

    credId = authenticator.get_credential_id()
    new_authenticator = Fido2Authenticator(credId=credId, fKey=fk)

    original_key = kp.get_private()
    rebuilt_key = new_authenticator.kp.get_private()

    assert original_key == rebuilt_key
    assert credId == new_authenticator.get_credential_id()
