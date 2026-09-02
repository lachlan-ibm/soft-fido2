from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa, padding, rsa, utils

from ..cert_utils import CertUtils
from ..key_pair import KeyUtils


def build_packed_attestation_statement(atteStmtFmt, clientDataHash, authData, credIdBytes, keyPair,
                                       *, hash_alg, salt_len,
                                       ca_certificate, ca_key_pair, aaguid, **_):
    """Create an attestation statement with the packed format.

    Args:
        atteStmtFmt (str): statement format, either 'packed' or 'packed-self'
        clientDataHash (bytes): hash of the serialized client data
        authData (bytes): authenticator data
        credIdBytes (bytes): credential ID bytes
        keyPair (KeyPair): public/private key pair to sign with
        hash_alg (hashes.HashAlgorithm): hashing algorithm
        salt_len (int | None): PSS salt length; truthy value selects PSS padding for RSA
        ca_certificate: CA certificate used for the x5c chain (full attestation only)
        ca_key_pair (KeyPair): CA key pair used to sign the leaf cert (full attestation only)
        aaguid (bytes): raw AAGUID bytes

    Returns:
        dict: packed attestation statement
              https://www.w3.org/TR/webauthn/#packed-attestation
    """
    result = {}  # Key order is important
    result[u"alg"] = KeyUtils.get_alg_id_from_pubkey_and_hash(
        keyPair.get_public(), hash_alg, pss=True if salt_len else False)
    toSign = bytes([*authData, *clientDataHash])
    sig = ""

    if isinstance(keyPair.get_public(), rsa.RSAPublicKey):
        sig = keyPair.get_private().sign(toSign, padding.PKCS1v15(), hash_alg)
    elif isinstance(keyPair.get_public(), ec.EllipticCurvePublicKey):
        digest = hashes.Hash(hash_alg)
        digest.update(b''.join([(x.encode() if isinstance(x, str) else bytes([x])) for x in toSign]))
        sig = keyPair.get_private().sign(digest.finalize(),
                                         ec.ECDSA(utils.Prehashed(hash_alg)))
    elif isinstance(keyPair.get_public(),
                    (mldsa.MLDSA44PublicKey, mldsa.MLDSA65PublicKey, mldsa.MLDSA87PublicKey,
                     ed25519.Ed25519PublicKey)):
        sig = keyPair.get_private().sign(toSign)  # Generic sign method
    else:
        raise RuntimeError("Unsupported key type")

    result[u"sig"] = sig

    # Maybe add x5c
    selfAttestation = 'self' in atteStmtFmt
    if not selfAttestation:
        if not ca_certificate:
            raise RuntimeError("Packed Attestation requires a CA certificate to be "
                               "present when the authenticator is created")
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
                                          aaguid=aaguid)
        result['x5c'] = [CertUtils.get_encoded(leafCert), CertUtils.get_encoded(ca_certificate)]
    return result
