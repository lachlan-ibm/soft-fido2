#!/bin/python3

from hmac import new
from soft_fido2 import Fido2Authenticator, KeyPair
from soft_fido2.credential_id_decryptor import CredentialIdMigrator
import uuid
import base64
from cryptography.fernet import Fernet

from soft_fido2.symmetric_key import SymmetricKey


def test_Cred_id_Consturctor():
    u = str(uuid.uuid4()).encode()
    kp = KeyPair.generate_rsa()
    authenticator = Fido2Authenticator(key_pair=kp, cred_id=u)
    assert authenticator.get_credential_id() == u.decode(), "Cred Id does not match original"


def test_Cred_Id_As_Encrypted_Key():
    fk = Fernet(Fernet.generate_key())
    kp = KeyPair.generate_ecdsa()
    authenticator = Fido2Authenticator(key_pair=kp, f_key=fk)

    credIdBytes = authenticator._get_credential_id_bytes(kp)
    credId = authenticator.get_credential_id().encode()
    new_authenticator = Fido2Authenticator(cred_id=credId, f_key=fk)

    original_key = kp.get_private_bytes()
    assert new_authenticator.kp, "Authenticator keypair is None"
    rebuilt_key = new_authenticator.kp.get_private_bytes()

    assert original_key == rebuilt_key, "Serialized keys are different"
    assert credIdBytes == new_authenticator._get_credential_id_bytes(new_authenticator.kp), "Cred Id bytes are different"

def test_CredId_As_Symmetric_Key():
    seed = SymmetricKey.generate_key()
    kp = KeyPair.generate_ecdsa()
    authenticator = Fido2Authenticator(key_pair=kp, s_key=SymmetricKey(seed))

def test_CredId_migrate_fernet_to_symkey():
    seed = SymmetricKey.generate_key()
    sk = SymmetricKey(seed)
    fk = Fernet(seed)
    kp = KeyPair.generate_ecdsa()
    authenticator = Fido2Authenticator(key_pair=kp, f_key=fk)
    assert authenticator.kp, "Authenticatior Key Pair not found"
    credId = authenticator.get_credential_id(kp)
    newCredId = CredentialIdMigrator.migrate_credential_id(credId, seed=base64.urlsafe_b64decode(seed))
    assert newCredId != None, "Migration failed"
    print("New cred id :: ", newCredId)
    
    new_kp = Fido2Authenticator._get_key_pair_from_credential_id(newCredId, sk)
    print("OLD :: ", authenticator.kp.get_private_bytes() )
    print("NEW :: ", new_kp.get_private_bytes())
    assert authenticator.kp.get_private_bytes() == new_kp.get_private_bytes(), "Private keys are different"

    new_authenticator = Fido2Authenticator(cred_id=newCredId.encode(), s_key=sk)
    assert new_authenticator.kp, "Authenticatior Key Pair not found"
    print("BLA :: ", new_authenticator.kp.get_private_bytes())
    assert new_authenticator.kp.get_private_bytes() == authenticator.kp.get_private_bytes(), "Authenticator key pairs are different"
