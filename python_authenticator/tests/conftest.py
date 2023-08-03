import pytest

rp = "https://fido2.authenticator.test"

user = 'example_user'

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
def fido2_autenticator(fido2_server, fido2_user):
    from soft_FIDO2 import Fido2Authenticator
    attestation_options = fido2_server().register_begin(fido2_user)
    authenticator = Fido2Authenticator()
    attestation = authenticator.credential_create(attestation_options)
    fido2_server.register_complete(attesation)

    yield authenticator
