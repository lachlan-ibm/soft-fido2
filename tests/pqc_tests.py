from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.mldsa import (
    MLDSA44PublicKey,
    MLDSA65PublicKey,
    MLDSA87PublicKey
)
from soft_fido2 import Fido2Authenticator, KeyPair
import os, json, base64, uuid, struct, cbor2


def _parse_attested_credential_data(auth_data: bytes):
    rp_id_hash = auth_data[:32]
    flags = auth_data[32:33]
    assert len(flags) == 1, "flags incorrect length :: {}".format(hex(int.from_bytes(flags)))
    counter = auth_data[33:37]
    aaguid = auth_data[37:53]
    cred_id_len_bytes = auth_data[53:55]
    cred_id_len = struct.unpack(">H", bytes([cred_id_len_bytes[0], cred_id_len_bytes[1]]))[0]
    assert cred_id_len > 0, "cred_id_len must be greater than 0"
    cred_id = auth_data[55: 55 + cred_id_len]
    cred_pubkey_cbor = auth_data[55 + cred_id_len:]
    assert cred_pubkey_cbor, "Cred data must exist"
    assert cred_id_len == len(cred_id), "Cred data length mismatch :: {} {} {} ".format(
                                                cred_id_len_bytes, cred_id_len, len(cred_pubkey_cbor))
    cose = cbor2.loads(cred_pubkey_cbor)
    assert isinstance(cose, dict)
    return aaguid, rp_id_hash, flags, counter, cred_id, cose



def _do_the_thing(kp, cid):
    authenticator = Fido2Authenticator(keyPair=kp, credId=cid)
    challenge = base64.urlsafe_b64encode(os.urandom(64))
    create_credential_options = {
            "challenge": str(challenge),
            "rp": {
                "id": "example.com",
                "name": "Example Service"
            },
            "user": {
                "id": str(base64.urlsafe_b64encode(
                        str(uuid.uuid4()).replace('-', '').encode())), # Random 32-byte user ID
                "name": "user@example.com"
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -48},# ML-DSA-44
                {"type": "public-key", "alg": -49} # ML-DSA-65
            ]
    }

    r = authenticator.credential_create(create_credential_options, atteStmtFmt='packed-self')
    print(json.dumps(r, indent=4))
    response = r.get('response')
    assert isinstance(response, dict), "Response is not a dict"
    attObjB64 = response.get('attestationObject')
    assert attObjB64 is not None, "Attestation Object missing"
    attObjCbor = base64.urlsafe_b64decode(attObjB64)
    att_obj = cbor2.loads(attObjCbor)
    assert isinstance(att_obj, dict)
    auth_data = att_obj['authData']
    aaguid, rp_id_hash, flags, counter, cred_id, cose = _parse_attested_credential_data(
            auth_data=auth_data)
    hasher = hashes.Hash(hashes.SHA256())
    cdj = r['response']['clientDataJSON']
    hasher.update(json.dumps(cdj).encode())
    cdh = hasher.finalize()
    to_sign = bytes(auth_data + cdh)
    sig = att_obj['attStmt']['sig']
    return aaguid, rp_id_hash, flags, counter, cred_id, cose, to_sign, sig


def _verify_sig(msg, sig, public_key):
        """
        Verify ML-DSA signature using cryptography library v47+.
        
        Args:
            msg: Message that was signed
            sig: Signature bytes
            public_key: Public key
        """
        try:
            public_key.verify(sig, msg)
            return True
        except Exception as e:
            print(f"Exception :: {e}")
        return False


def test_ML_DSA_44_sign():
    cid = base64.urlsafe_b64encode(os.urandom(64))
    #authenticator = Fido2Authenticator(cred_id=cid)
    kp = KeyPair.generate_mldsa("ML-DSA-44")
    pubkey = kp.get_public()
    aaguid, rp_id_hash, flags, counter, cred_id, cose, to_sign, sig = _do_the_thing(kp, cid)
    assert aaguid == b'\x00' * 16, "AAGUID should be null"
    assert cred_id == cid, "Cred id not correct {} != {}".format(cred_id, cid)
    assert isinstance(cose, dict), "COSE key missing"
    assert counter == b'\x00' * 4, "Counter not correct"
    assert flags == int.to_bytes(0x01 | 0x40 | 0x04, 1, 'big'), "Flags not correct {} != {}".format(
                                                                        flags, int.to_bytes(0x01 | 0x40 | 0x04, 1, 'big'))
    assert cose[3] == -48, "ML-DSA-44 alg id"
    rhoTone = cose[-1]
    # Compare serialized public key bytes
    pubkey_bytes = pubkey.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    assert rhoTone == pubkey_bytes, "Public bytes not correct"
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(b"example.com")
    test_rp_hash = hasher.finalize()
    assert test_rp_hash == rp_id_hash, "returned hash does not match {} != {}".format(test_rp_hash, rp_id_hash)
    _verify_sig(to_sign, sig, pubkey)

def test_ML_DSA_67_sign():
    kp = KeyPair.generate_mldsa("ML-DSA-65")
    pubkey = kp.get_public()
    cid = base64.urlsafe_b64encode(os.urandom(64))
    #authenticator = Fido2Authenticator(cred_id=cid)
    aaguid, rp_id_hash, flags, counter, cred_id, cose, to_sign, sig = _do_the_thing(kp, cid)
    assert aaguid == b'\x00' * 16, "AAGUID should be null"
    assert cred_id == cid, "Cred id not correct {} != {}".format(cred_id, cid)
    assert isinstance(cose, dict), "COSE key missing"
    assert counter == b'\x00' * 4, "Counter not correct"
    assert flags == int.to_bytes(0x01 | 0x40 | 0x04, 1, 'big'), "Flags not correct {} != {}".format(
                                                                        flags, int.to_bytes(0x01 | 0x40 | 0x04, 1, 'big'))
    assert cose[3] == -49, "ML-DSA-65 alg id"
    rhoTone = cose[-1]
    # Compare serialized public key bytes
    pubkey_bytes = pubkey.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    assert rhoTone == pubkey_bytes, "Public bytes not correct"
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(b"example.com")
    test_rp_hash = hasher.finalize()
    assert test_rp_hash == rp_id_hash, "returned hash does not match {} != {}".format(test_rp_hash, rp_id_hash)
    _verify_sig(to_sign, sig, pubkey)

def test_ML_DSA_87_sign():
    kp = KeyPair.generate_mldsa("ML-DSA-87")
    pubkey = kp.get_public()
    cid = base64.urlsafe_b64encode(os.urandom(64))
    #authenticator = Fido2Authenticator(cred_id=cid)
    aaguid, rp_id_hash, flags, counter, cred_id, cose, to_sign, sig = _do_the_thing(kp, cid) 
    assert aaguid == b'\x00' * 16, "AAGUID should be null"
    assert cred_id == cid, "Cred id not correct {} != {}".format(cred_id, cid)
    assert isinstance(cose, dict), "COSE key missing"
    assert counter == b'\x00' * 4, "Counter not correct"
    assert flags == int.to_bytes(0x01 | 0x40 | 0x04, 1, 'big'), "Flags not correct {} != {}".format(
                                                                        flags, int.to_bytes(0x01 | 0x40 | 0x04, 1, 'big'))
    assert cose[3] == -50, "ML-DSA-87 alg id"
    rhoTone = cose[-1]
    pubkey_bytes = pubkey.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    assert rhoTone == pubkey_bytes, "Public bytes not correct"
    assert -3 not in cose, "Invalid key not present"
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(b"example.com")
    test_rp_hash = hasher.finalize()
    assert test_rp_hash == rp_id_hash, "returned hash does not match {} != {}".format(test_rp_hash, rp_id_hash)
    _verify_sig(to_sign, sig, pubkey)
    #assert False, "Capture output for isfs2 cross contamination"