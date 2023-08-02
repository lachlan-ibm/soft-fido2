#!/bin/python3

from soft_FIDO2 import Fido2Authenticator, KeyPair
import pytest
import uuid


def Cred_id_Consturctor_Test():
    u = str(uuid.uuid4())
    k = KeyPair.generate_rsa()
    authenticator = Fido2Authenticator(keyPair=kp, credId=u)
    assert authenticator.get_credential_id() == u, "Cred Id does not match original"
