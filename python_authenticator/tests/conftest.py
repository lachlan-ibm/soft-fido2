import pytest
from fido2.webauthn import PublicKeyCredentialRpEntity, AttestedCredentialData, CollectedClientData, AuthenticatorData, AttestationObject
import base64
import cbor2 as cbor

import fido2.features

fido2.features.webauthn_json_mapping.enabled = True

user = {"id": b"example_user", "name": "Example User"}
rp = PublicKeyCredentialRpEntity("Fido2 Authenticator Test", "fido2.authenticator.test")

@pytest.fixture(scope='module', autouse=True)
def fido2_rp():
    return rp

@pytest.fixture(scope='module', autouse=True)
def fido2_user():
    return user

@pytest.fixture(scope='module', autouse=True)
def fido2_server():
    from fido2.server import Fido2Server
    return Fido2Server(rp)

@pytest.fixture(scope='module')
def fido2_authenticator(fido2_server, fido2_user):
    from soft_fido2 import Fido2Authenticator
    attestation_options, state = fido2_server.register_begin(fido2_user)
    attestation_options = dict(attestation_options)['publicKey']
    #attestation_options['challenge'] = base64.urlsafe_b64encode(attestation_options['challenge']).decode('utf-8')
    #attestation_options['user']['id'] = base64.urlsafe_b64encode(attestation_options['user']['id']).decode('utf-8')
    print(attestation_options)
    authenticator = Fido2Authenticator()
    attestation = authenticator.credential_create(attestation_options)
    client_data = CollectedClientData(authenticator._urlb64_decode(attestation['response']['clientDataJSON']))
    att_obj = AttestationObject(authenticator._urlb64_decode(attestation['response']['attestationObject']))
    fido2_server.register_complete(state, client_data, att_obj)
    yield authenticator
