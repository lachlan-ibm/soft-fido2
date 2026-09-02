from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from ..cert_utils import CertUtils
from ..key_pair import KeyUtils


def build_fido_u2f_attestation_statement(atteStmtFmt, clientDataHash, authData, credIdBytes, keyPair,
                                         **_):
    """Create an attestation statement with the U2F format.

    Args:
        atteStmtFmt (str): statement format
        clientDataHash (bytes): hash of the serialized client data
        authData (bytes): authenticator data
        credIdBytes (bytes): credential ID bytes
        keyPair (KeyPair): public/private key pair to sign with

    Returns:
        dict: u2f attestation statement
              https://www.w3.org/TR/webauthn/#fido-u2f-attestation
    """
    if not isinstance(keyPair.get_public(), ec.EllipticCurvePublicKey):
        raise Exception("FIDO U2F only supports ECDSA keys")

    pubKey = bytearray(b'\x04')
    pubKey.extend(KeyUtils._long_to_bytes(keyPair.get_public().public_numbers().x))
    pubKey.extend(KeyUtils._long_to_bytes(keyPair.get_public().public_numbers().y))

    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u'root'),
        x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, u'IBM Security')
    ])
    cert = CertUtils.gen_ca_cert(subject=subject, keyPair=keyPair)

    rpIdHash = authData[0:32]
    toSign = []
    toSign += ['\x00']
    toSign += rpIdHash
    toSign += clientDataHash
    toSign += credIdBytes
    toSign += pubKey
    digest = hashes.Hash(hashes.SHA256())
    digest.update(b''.join([(x.encode() if isinstance(x, str) else bytes([x])) for x in toSign]))
    sig = keyPair.get_private().sign(digest.finalize(), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    return {'sig': sig, 'x5c': [CertUtils.get_encoded(cert)]}
