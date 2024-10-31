#!/bin/python3

from soft_FIDO2 import Fido2Authenticator, KeyPair, CertUtils
import pytest
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, AttestedCredentialData, CollectedClientData, AuthenticatorData, AttestationObject
import base64
import hashlib
import cbor2 as cbor
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec



def test_E2E(fido2_server, fido2_rp, fido2_user):
    attestation_options, state = fido2_server.register_begin(fido2_user)
    attestation_options = dict(attestation_options)['publicKey']
    #attestation_options['challenge'] = base64.urlsafe_b64encode(attestation_options['challenge']).decode('utf-8')
    #attestation_options['user']['id'] = base64.urlsafe_b64encode(attestation_options['user']['id']).decode('utf-8')
    authenticator = Fido2Authenticator()
    attestation = authenticator.credential_create(attestation_options)
    client_data = CollectedClientData(authenticator._urlb64_decode(attestation['response']['clientDataJSON']))
    att_obj = AttestationObject(authenticator._urlb64_decode(attestation['response']['attestationObject']))
    fido2_server.register_complete(state, client_data, att_obj)



def test_Authenticator_Data(fido2_server, fido2_authenticator, fido2_user):
    attestation_options, state = fido2_server.register_begin(fido2_user)
    attestation_options = dict(attestation_options)['publicKey']
    #attestation_options['challenge'] = base64.urlsafe_b64encode(attestation_options['challenge']).decode('utf-8')
    #attestation_options['user']['id'] = base64.urlsafe_b64encode(attestation_options['user']['id']).decode('utf-8')
    authenticator = Fido2Authenticator()
    attestation = authenticator.credential_create(attestation_options)
    from fido2.attestation import PackedAttestation
    verifier = PackedAttestation()
    serverAttestationObject = AttestationObject(authenticator._urlb64_decode(attestation.get('response', {}).get('attestationObject')))
    serverClientData = CollectedClientData(base64.urlsafe_b64decode(attestation["response"]["clientDataJSON"]))
    verifier.verify(serverAttestationObject.att_stmt,
            serverAttestationObject.auth_data, serverClientData.hash)


def test_Client_Data_JSON(fido2_server, fido2_authenticator, fido2_user):
    attestation_options, state = fido2_server.register_begin(fido2_user)
    attestation_options = dict(attestation_options)['publicKey']
    #attestation_options['challenge'] = base64.urlsafe_b64encode(attestation_options['challenge']).decode('utf-8')
    #attestation_options['user']['id'] = base64.urlsafe_b64encode(attestation_options['user']['id']).decode('utf-8')
    authenticator = Fido2Authenticator()
    attestation = authenticator.credential_create(attestation_options)
    serverClientData = CollectedClientData(authenticator._urlb64_decode(attestation["response"]["clientDataJSON"]))


def test_Signing(fido2_server, fido2_authenticator, fido2_user):
    attestation_options, state = fido2_server.register_begin(fido2_user)
    attestation_options = dict(attestation_options)['publicKey']
    #attestation_options['challenge'] = base64.urlsafe_b64encode(attestation_options['challenge']).decode('utf-8')
    #attestation_options['user']['id'] = base64.urlsafe_b64encode(attestation_options['user']['id']).decode('utf-8')
    caKp = KeyPair.generate_rsa()
    subject = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'root'),
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME, u'Travis CI/CD')
    ])
    caCert = CertUtils.gen_ca_cert(subject=subject, keyPair=caKp)
    authenticator = Fido2Authenticator(keyPair=KeyPair.generate_rsa(), caKeyPair=caKp, caCert=caCert)
    attestation = authenticator.credential_create(attestation_options, atteStmtFmt='packed')
    cdj = base64.urlsafe_b64decode(attestation.get("response", {}).get("clientDataJSON"))
    clientDataHash = hashlib.sha256( cdj ).digest()
    attestationObject = cbor.loads(base64.urlsafe_b64decode(attestation.get("response").get("attestationObject")))
    authData = attestationObject.get("authData")
    attStmt = attestationObject.get("attStmt")
    cert = x509.load_der_x509_certificate(attStmt.get('x5c')[0], default_backend())
    pubKey = cert.public_key()
    #RSA key
    pubKey.verify(attStmt.get('sig'), authData + clientDataHash, padding.PKCS1v15(), hashes.SHA256())
    #EC Key
    #hasher = hashes.Hash(hashes.SHA256())
    #hasher.update(authData + clientDataHash)
    #pubKey.verify(attStmt.get('sig'), hasher.finalize(), ec.ECDSA(hashes.SHA256()))


def test_Attestation_Object(fido2_server, fido2_authenticator, fido2_user):
    attestation_options, state = fido2_server.register_begin(fido2_user)
    attestation_options = dict(attestation_options)['publicKey']
    #attestation_options['challenge'] = base64.urlsafe_b64encode(attestation_options['challenge']).decode('utf-8')
    #attestation_options['user']['id'] = base64.urlsafe_b64encode(attestation_options['user']['id']).decode('utf-8')
    authenticator = Fido2Authenticator()
    attestation = authenticator.credential_create(attestation_options)
    AttestationObject(base64.urlsafe_b64decode(attestation.get("response").get("attestationObject")))


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
