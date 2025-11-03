#!/bin/python3

from fido2.webauthn import AttestedCredentialData


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


def test_Signing(fido2_server, fido2_authenticator):
    pass


def test_Client_Data_JSON(fido2_server, fido2_authenticator):
    pass


def test_Authenticator_Data(fido2_server, fido2_authenticator):
    pass


def test_Attestation_Object(fido2_server, fido2_authenticator):
    pass


def test_Key_Reconstruction(fido2_server, fido2_authenticator):
    pass
