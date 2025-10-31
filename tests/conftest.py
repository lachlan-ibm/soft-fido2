import pytest
from fido2.webauthn import PublicKeyCredentialRpEntity


user = {"id": b"example_user", "name": "Example User"}
rp = PublicKeyCredentialRpEntity(name="Fido2 Authenticator Test", id="fido2.authenticator.test")

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
    # Create a registration response object that the server expects
    # Create a response dictionary that matches what the server expects
    response = {
        'id': attestation['id'],
        'rawId': attestation['rawId'],
        'response': {
            'clientDataJSON': attestation['response']['clientDataJSON'],
            'attestationObject': attestation['response']['attestationObject']
        },
        'type': 'public-key'
    }
    
    fido2_server.register_complete(state, response)
    yield authenticator
