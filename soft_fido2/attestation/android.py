import base64
import hashlib
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
import jwt

from ..cert_utils import CertUtils
from ..key_pair import KeyUtils


def build_android_safetynet_attestation_statement(atteStmtFmt, clientDataHash, authData, credIdBytes,
                                                  keyPair, *, ca_certificate, ca_key_pair,
                                                  cts_profile_match, **_):
    """Create an attestation statement with the Android SafetyNet format.

    Args:
        atteStmtFmt (str): statement format
        clientDataHash (bytes): hash of the serialized client data
        authData (bytes): authenticator data
        credIdBytes (bytes): credential ID bytes
        keyPair (KeyPair): public/private key pair to sign with
        ca_certificate: CA certificate for the x5c chain
        ca_key_pair (KeyPair): CA key pair used to sign the leaf cert
        cts_profile_match (bool): value for the ctsProfileMatch claim

    Returns:
        dict: Android SafetyNet attestation statement
              https://www.w3.org/TR/webauthn/#android-safetynet-attestation
    """
    if isinstance(keyPair.get_public(), ec.EllipticCurvePublicKey):
        raise RuntimeError("Android safetynet Attestation requires a RSA key")
    if ca_certificate is None:
        raise RuntimeError("Android safetynet Attestation requires a CA certificate to be"
                           " set for the authenticator")
    leafSubj = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u'attest.android.com'),
        x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, u'Authenticator Attestation'),
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u'AU'),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u'IBM')
    ])
    leafCert = CertUtils.gen_aik_cert(subject=leafSubj,
                                      issuer=ca_certificate.subject,
                                      keyPair=keyPair,
                                      signKeyPair=ca_key_pair)
    nonceBytes = [*authData, *clientDataHash]
    nonceHash = hashlib.sha256(bytes(nonceBytes)).digest()
    claims = {
        u'timestampMs': round(time.time() * 1000),
        u'nonce': base64.b64encode(nonceHash).decode(),
        u'apkPackageName': u"com.package.name.of.requesting.app",
        u"apkCertificateDigestSha256": [u"b64 encoded sha256 of cert"],
        u"ctsProfileMatch": cts_profile_match,
        u"basicIntegrity": True
    }
    jwtResponse = jwt.encode(
        claims,
        keyPair.get_private_bytes(),
        algorithm="RS256",
        headers={"x5c": [CertUtils.get_bytes(leafCert).decode(),
                         CertUtils.get_bytes(ca_certificate).decode()]})
    return {u'ver': u'some version', u'response': jwtResponse.encode()}


def build_android_key_attestation_statement(atteStmtFmt, clientDataHash, authData, credIdBytes,
                                            keyPair, *, ca_certificate, ca_key_pair,
                                            hash_alg, **_):
    """Create an attestation statement with the Android Keystore format.

    Args:
        atteStmtFmt (str): statement format
        clientDataHash (bytes): hash of the serialized client data
        authData (bytes): authenticator data
        credIdBytes (bytes): credential ID bytes
        keyPair (KeyPair): public/private key pair to sign with
        ca_certificate: CA certificate for the x5c chain
        ca_key_pair (KeyPair): CA key pair used to sign the leaf cert
        hash_alg (hashes.HashAlgorithm): hashing algorithm for the alg field

    Returns:
        dict: Android Keystore attestation statement
              https://www.w3.org/TR/webauthn/#android-key-attestation
    """
    if not ca_certificate:
        raise RuntimeError("Android Key Attestation requires a CA certificate to be "
                           "present when the authenticator is created")

    # Build x5c chain
    leafSubj = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u'leaf'),
        x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, u'Authenticator Attestation'),
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u'AU'),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u'IBM')
    ])
    leafCert = CertUtils.gen_aik_cert(subject=leafSubj,
                                      issuer=ca_certificate.subject,
                                      keyPair=keyPair,
                                      signKeyPair=ca_key_pair,
                                      androidKeyNonce=bytes(clientDataHash))
    x5c = [CertUtils.get_encoded(leafCert), CertUtils.get_encoded(ca_certificate)]

    # Sign data
    toSign = [*authData, *clientDataHash]
    if isinstance(keyPair.get_public(), rsa.RSAPublicKey):
        sig = keyPair.get_private().sign(bytes(toSign), padding.PKCS1v15(), hashes.SHA256())
    else:  # Must be EC key
        digest = hashes.Hash(hashes.SHA256())
        digest.update(bytes(toSign))
        sig = keyPair.get_private().sign(digest.finalize(),
                                         ec.ECDSA(utils.Prehashed(hashes.SHA256())))

    return {
        u"x5c": x5c,
        u"sig": sig,
        u"alg": KeyUtils.get_alg_id_from_pubkey_and_hash(keyPair.get_public(), hash_alg)
    }
