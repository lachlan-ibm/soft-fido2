#!/bin/python3

from soft_FIDO2 import Fido2Authenticator
import pytest
from fido2.server import Fido2Server


def E2E_Unit_Test(fido2_server, fido2_rp, fido2_user):
    attestation_options = fido2_server.register_begin(fido2_user)
    authenticator = Fido2Authenticator()
    attestation = authenticator.credential_create(attestation_options)
    fido2_server.register_complete(attesation)


def Authenticator_Data_Test(fido2_server, fido2_authenticator):
    attestation_options = fido2_server.register_begin(fido2_user)
    authenticator = Fido2Authenticator()
    attestation = authenticator.credential_create(attestation_options)
    from fido2.attestation import PackedAttestation
    verifier = PackedAttestation()
    serverAttestationObject = AttestationObject(
            base64.urlsafe_b64decode(attestaton.get('attestationObject')))
    from fido2.ctap2 import ClientData
    serverClientData = ClientData(base64.urlsafe_b64decode(attestation["clientDataJSON"]))
    #verifier.verify(fido2_server.rp.id_hash, serverAttestationObject.att_statement, 
    #        serverAttestationObject.auth_data, serverClientData.hash,


def Client_Data_JSON_Test(fido2_sever, fido2_authenticator):
    attestation_options = fido2_server.register_begin(fido2_user)
    authenticator = Fido2Authenticator()
    attestation = authenticator.credential_create(attestation_options)
    from fido2.ctap2 import ClientData
    serverClientData = ClientData(attestation["clientDataJSON"])


def Signing_Test(fido2_server, fido2_authenticator):
    attestation_options = fido2_server.register_begin(fido2_user)
    authenticator = Fido2Authenticator()
    attestation = authenticator.credential_create(attestation_options)
    cdj = base64.urlsafe_b64decode(attestation.get("clientDataJSON"))
    clientDataHash = hashlib.sha256( cdj.encode('utf-8') ).digest()
    attestationObject = cbor.loads(base64.urlsafe_b64decode(attestation.get("response").get("attestationObject")))
    authData = attestationObject.get("authData")
    attStmt = attestationObject.get("attStmt")
    from cryptography import x509
    cert = x509.load_der_x509_certificate(attStmt.get('x5c')[0], default_backend())
    pubKey = cert.public_key() 
    pubKey.verify(attStmt.get('sig'), authData + clientDataHash, padding.PKCS1v15(), hashes.SHA256())


def Attestation_Object_Test(fido2_server, fido2_authenticator):
    attestation_options = fido2_server.register_begin(fido2_user)
    authenticator = Fido2Authenticator()
    attestation = authenticator.credential_create(attestation_options)
    from fido2.ctap2 import AttestationObject
    #AttestationObject(base64.urlsafe_b64decode(attestation.get("response").get("attestationObject"))


#### Attestation format tests ####

def Packed_RSA_Attestation_Test(fido2_server, fido2_authenticator):
    pass


def Packed_EC_Attestation_Test(fido2_server, fido2_authenticator):
    pass


def TPM_Attestation_Test(fido2_server, fido2_authenticator):
    pass


def Android_Keystore_Attestation_Test(fido2_server, fido2_authenticator):
    pass


def Android_Safetynet_Attestation_Test(fido2_server, fido2_authenticator):
    pass


def None_Attestation_Test(fido2_server, fido2_authenticator):
    pass


def U2F_Attestation_Test(fido2_server, fido2_authenticator):
    pass
