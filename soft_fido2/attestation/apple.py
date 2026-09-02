import hashlib

from cryptography import x509

from ..cert_utils import CertUtils


def build_apple_attestation_statement(atteStmtFmt, clientDataHash, authData, credIdBytes, keyPair,
                                      *, ca_certificate, ca_key_pair, **_):
    """Create an attestation statement with the Apple Platform format.

    Args:
        atteStmtFmt (str): statement format ('apple')
        clientDataHash (bytes): hash of the serialized client data
        authData (bytes): authenticator data
        credIdBytes (bytes): credential ID bytes
        keyPair (KeyPair): public/private key pair
        ca_certificate: CA certificate for the x5c chain
        ca_key_pair (KeyPair): CA key pair used to sign the Apple cert

    Returns:
        dict: Apple platform attestation statement containing x5c certificate chain
    """
    if not ca_certificate:
        raise RuntimeError("Apple Attestation requires a CA certificate to be "
                           "present when the authenticator is created")
    nonceBytes = []
    nonceBytes += authData
    nonceBytes += clientDataHash
    nonceHash = hashlib.sha256(bytes(nonceBytes)).digest()
    leafSubj = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u'apple'),
        x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, u'Authenticator Attestation'),
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u'AU'),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u'IBM')
    ])
    appleCert = CertUtils.gen_apple_cert(subject=leafSubj,
                                         issuer=ca_certificate.subject,
                                         keyPair=keyPair,
                                         signKeyPair=ca_key_pair,
                                         nonce=nonceHash)
    return {'x5c': [CertUtils.get_encoded(appleCert), CertUtils.get_encoded(ca_certificate)]}
