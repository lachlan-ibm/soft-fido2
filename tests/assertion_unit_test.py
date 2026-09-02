#!/bin/python3

import base64
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from fido2.webauthn import AttestationObject, AttestedCredentialData, CollectedClientData
from fido2.attestation.packed import PackedAttestation

from soft_fido2 import Fido2Authenticator, KeyPair



def test_E2E(fido2_server, fido2_authenticator):
    attested_data = AttestedCredentialData( fido2_authenticator.process_attested_credential_data(
                                 fido2_authenticator.kp.get_public(),
                                 fido2_authenticator._get_credential_id_bytes(fido2_authenticator.kp) ))
    assertion_options, state = fido2_server.authenticate_begin(credentials=[attested_data])
    assertion_options = dict(assertion_options)['publicKey']
    #assertion_options['challenge'] = base64.urlsafe_b64encode(assertion_options['challenge']).decode('utf-8')
    print(assertion_options)
    assertion = fido2_authenticator.credential_request(assertion_options)
    print(assertion)
    
    # Create a response dictionary that matches what the server expects
    response = {
        'id': assertion['id'],
        'rawId': assertion['rawId'],
        'response': {
            'clientDataJSON': assertion['response']['clientDataJSON'],
            'authenticatorData': assertion['response']['authenticatorData'],
            'signature': assertion['response']['signature'],
            'userHandle': assertion['response'].get('userHandle')
        },
        'type': 'public-key'
    }
    
    fido2_server.authenticate_complete(state, [attested_data], response)


def _register(fido2_server, fido2_user, authenticator):
    attestation_options, state = fido2_server.register_begin(fido2_user)
    attestation_options = dict(attestation_options)['publicKey']
    #attestation_options['challenge'] = base64.urlsafe_b64encode(attestation_options['challenge']).decode('utf-8')
    #attestation_options['user']['id'] = base64.urlsafe_b64encode(attestation_options['user']['id']).decode('utf-8')
    attestation = authenticator.credential_create(attestation_options)
    serverAttestationObject = AttestationObject(authenticator._urlb64_decode(attestation.get('response', {}).get('attestationObject')))
    serverClientData = CollectedClientData(base64.urlsafe_b64decode(attestation["response"]["clientDataJSON"]))
    verifier = PackedAttestation()
    verifier.verify(serverAttestationObject.att_stmt,
            serverAttestationObject.auth_data, serverClientData.hash)


def test_Signing_RSA(fido2_server, fido2_user):
    kp = KeyPair.generate_rsa()
    authenticator = Fido2Authenticator(keyPair=kp)
    _register(fido2_server, fido2_user, authenticator)
    assert isinstance(authenticator.kp, KeyPair), "Authenticator has unexpected key material"
    attested_data = AttestedCredentialData(bytes(authenticator.process_attested_credential_data(
                                authenticator.kp.get_public(),
                                authenticator._get_credential_id_bytes(authenticator.kp))))
    assertion_options, _ = fido2_server.authenticate_begin(credentials=[attested_data])
    assertion_options = dict(assertion_options)['publicKey']
    assertion = authenticator.credential_request(assertion_options)
    rsp: str | dict[str, str] = assertion["response"]
    assert isinstance(rsp, dict)
    cdj = base64.urlsafe_b64decode(str(rsp["clientDataJSON"]))
    clientDataHash = hashlib.sha256(cdj).digest()
    authData = base64.urlsafe_b64decode(str(rsp["authenticatorData"]))
    #RSA key
    authenticator.kp.get_public().verify(base64.urlsafe_b64decode(rsp["signature"]), authData + clientDataHash, padding.PKCS1v15(), hashes.SHA256())


def test_Signing_EC(fido2_server, fido2_user):
    kp = KeyPair.generate_ecdsa()
    authenticator = Fido2Authenticator(keyPair=kp)
    _register(fido2_server, fido2_user, authenticator)
    assert isinstance(authenticator.kp, KeyPair), "Authenticator has unexpected key material"
    attested_data = AttestedCredentialData(bytes(authenticator.process_attested_credential_data(
                                authenticator.kp.get_public(),
                                authenticator._get_credential_id_bytes(authenticator.kp))))
    assertion_options, _ = fido2_server.authenticate_begin(credentials=[attested_data])
    assertion_options = dict(assertion_options)['publicKey']
    assertion = authenticator.credential_request(assertion_options)
    rsp: str | dict[str, str] = assertion["response"]
    assert isinstance(rsp, dict)
    cdj = base64.urlsafe_b64decode(str(rsp["clientDataJSON"]))
    clientDataHash = hashlib.sha256(cdj).digest()
    authData = base64.urlsafe_b64decode(str(rsp["authenticatorData"]))
    authenticator.kp.get_public().verify(base64.urlsafe_b64decode(rsp["signature"]), authData + clientDataHash, ec.ECDSA(hashes.SHA256()))

def test_Signing_ML(fido2_server, fido2_user):
    kp = KeyPair.generate_mldsa()
    authenticator = Fido2Authenticator(keyPair=kp)
    return True
    _register(fido2_server, fido2_user, authenticator)
    assert isinstance(authenticator.kp, KeyPair), "Authenticator has unexpected key material"
    attested_data = AttestedCredentialData(bytes(authenticator.process_attested_credential_data(
                                authenticator.kp.get_public(),
                                authenticator._get_credential_id_bytes(authenticator.kp))))
    assertion_options, _ = fido2_server.authenticate_begin(credentials=[attested_data])
    assertion_options = dict(assertion_options)['publicKey']
    assertion = authenticator.credential_request(assertion_options)
    cdj = base64.urlsafe_b64decode(str(assertion["response"]["clientDataJSON"]))
    clientDataHash = hashlib.sha256(cdj).digest()
    authData = base64.urlsafe_b64decode(str(assertion["response"]["authenticatorData"]))
    authenticator.kp.get_public().verify(base64.urlsafe_b64decode(assertion["response"]["signature"]), authData + clientDataHash)

def test_Client_Data_JSON(fido2_server, fido2_user):
    authenticator = Fido2Authenticator()
    assert isinstance(authenticator.kp, KeyPair)
    _register(fido2_server, fido2_user, authenticator)
    attested_data = AttestedCredentialData( authenticator.process_attested_credential_data(
                                 authenticator.kp.get_public(),
                                 authenticator._get_credential_id_bytes(authenticator.kp) ))
    assertion_options, state = fido2_server.authenticate_begin(credentials=[attested_data])
    assertion_options = dict(assertion_options)['publicKey']
    assertion = authenticator.credential_request(assertion_options)
    rsp = assertion['response']
    assert isinstance(rsp, dict)
    CollectedClientData(authenticator._urlb64_decode(rsp["clientDataJSON"]))


def test_Authenticator_Data(fido2_server, fido2_user):
    pass


def test_CredId_Key_Reconstruction(fido2_server, fido2_user):
    pass
