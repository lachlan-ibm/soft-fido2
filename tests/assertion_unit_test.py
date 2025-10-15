#!/bin/python3

from soft_fido2 import Fido2Authenticator
import pytest
from fido2.server import Fido2Server
from fido2.webauthn import AttestedCredentialData, AuthenticationResponse, AuthenticatorAssertionResponse, AuthenticatorData, CollectedClientData
import base64

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
    idBytes = fido2_authenticator._urlb64_decode(assertion['id'].encode('utf-8'))
    client_data = CollectedClientData(fido2_authenticator._urlb64_decode(assertion['response']['clientDataJSON']))
    authData = AuthenticatorData(fido2_authenticator._urlb64_decode(assertion['response']["authenticatorData"]))
    sigBytes = fido2_authenticator._urlb64_decode(assertion['response']["signature"])
    response = AuthenticatorAssertionResponse(
                                                    client_data=client_data, authenticator_data=authData, signature=sigBytes)
    assertion_data = AuthenticationResponse(raw_id=idBytes, response=response)
    fido2_server.authenticate_complete(state, [attested_data], assertion_data)


def Signing_Test(fido2_server, fido2_authenticator):
    pass


def Client_Data_JSON_Test(fido2_sever, fido2_authenticator):
    pass


def Authenticator_Data_Test(fido2_server, fido2_authenticator):
    pass


def Attestation_Object_Test(fido2_server, fido2_authenticator):
    pass


def Key_Reconstruction_Test(fido2_server, fido2_authenticator):
    pass
