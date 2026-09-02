import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from ..cert_utils import CertUtils
from ..key_pair import KeyUtils


def _build_rsa_public_area(keyPair):
    pubArea = []
    pubArea += [0, 1]    # TPM_ALG_ID = TPM_ALG_RSA
    pubArea += [0, 11]   # name_alg = TPM_ALG_SHA256
    pubArea += [0] * 4   # TPMA_OBJECT
    pubArea += [0] * 2   # authPolicy
    pubArea += [0, 0x10] # symmetric = TPM_ALG_NULL
    pubArea += [1, 4]    # scheme = TPM_ALG_RSASSA (PKCS1-v1.5)
    pubArea += list(struct.pack("!H", keyPair.get_public().key_size )) # keySize; eg 1024 = [4, 0]    
    pubArea += [0] * 4   # exponent
    unique = KeyUtils._long_to_bytes(keyPair.get_public().public_numbers().n)
    uniqueLength = struct.pack("!H", len(unique))
    pubArea += [uniqueLength[0], uniqueLength[1]]
    pubArea += unique
    return bytes(pubArea)


def _build_ec_public_area(keypair):
    pubArea = []
    pubArea += [0, 0x23] # TPM_ALG_ID = TPM_ALG_ECC
    pubArea += [0, 0x0B] # TPM_ALG_SHA256
    pubArea += [0] * 4   # TPMA_OBJECT
    pubArea += [0] * 2   # authPolicy
    pubArea += [0, 0x10] # symmetric = TPM_ALG_NULL
    pubArea += [0, 0x10] # scheme = TPM_ALG_NULL
    pubArea += [0, 0x03] # curve_id == TPM_ECC_NIST_P256
    pubArea += [0, 0x10] # kdf == TPM_ALG_NULL
    xBytes = KeyUtils._long_to_bytes(keypair.get_public().public_numbers().x)
    xByteLen = struct.pack("!H", len(xBytes))
    pubArea += [xByteLen[0], xByteLen[1]]
    pubArea += xBytes
    yBytes = KeyUtils._long_to_bytes(keypair.get_public().public_numbers().y)
    yByteLen = struct.pack("!H", len(yBytes))
    pubArea += [yByteLen[0], yByteLen[1]]
    pubArea += yBytes
    return bytes(pubArea)


def _build_cert_info(attsToSign, pubInfo):
    certInfo = [0xFF, 0x54, 0x43, 0x47] # TPM_GENERATED
    certInfo += [0x80, 0x17]             # TPM_ST_ATTEST_CERTIFY
    certInfo += [0] * 2                  # qualified signer length
    digest = hashes.Hash(hashes.SHA256())
    digest.update(attsToSign)
    sigHash = digest.finalize()
    sigHashLength = struct.pack("!H", len(sigHash))
    certInfo += [sigHashLength[0], sigHashLength[1]]
    certInfo += sigHash
    certInfo += [0] * 17  # clock info
    vendorId = struct.pack("!L", CertUtils.TPM_VENDOR_ID)
    certInfo += [0] * (8 - len(vendorId))
    certInfo += vendorId
    attestedName = [0x00, 0x0B]  # name_alg
    digest = hashes.Hash(hashes.SHA256())
    digest.update(pubInfo)
    attestedName += digest.finalize()
    attestedNameLength = struct.pack("!H", len(attestedName))
    certInfo += [attestedNameLength[0], attestedNameLength[1]]
    certInfo += attestedName
    certInfo += [0] * 2  # attested qualified name length
    return bytes(certInfo)


def build_tpm_attestation_statement(atteStmtFmt, clientDataHash, authData, credIdBytes, keyPair,
                                    *, ca_certificate, ca_key_pair, aaguid, **_):
    """Create an attestation statement with the TPM format.

    Args:
        atteStmtFmt (str): statement format ('tpm')
        clientDataHash (bytes): hash of the serialized client data
        authData (bytes): authenticator data
        credIdBytes (bytes): credential ID bytes
        keyPair (KeyPair): public/private key pair to sign with
        ca_certificate: CA certificate for the x5c chain
        ca_key_pair (KeyPair): CA key pair used to sign the TPM cert
        aaguid (bytes): raw AAGUID bytes

    Returns:
        dict: TPM attestation statement
              https://www.w3.org/TR/webauthn/#tpm-attestation
    """
    if not ca_certificate:
        raise RuntimeError("TPM Attestation requires a CA certificate to be "
                           "present when the authenticator is created")
    # Generate TPM certificates
    vendorId = CertUtils._long_to_bytes(CertUtils.TPM_VENDOR_ID).hex()
    tpmSan = x509.Name([
        x509.NameAttribute(x509.ObjectIdentifier(CertUtils.TPM_MANUFACTURER), u"id:{}".format(vendorId)),
        x509.NameAttribute(x509.ObjectIdentifier(CertUtils.TPM_VENDOR), u"IBMTPM"),
        x509.NameAttribute(x509.ObjectIdentifier(CertUtils.TPM_FW_VERSION), u"id:1")
    ])
    tpmCert = CertUtils.gen_aik_cert(subject=x509.Name([]),
                                     issuer=ca_certificate.subject,
                                     keyPair=keyPair,
                                     signKeyPair=ca_key_pair,
                                     aaguid=aaguid,
                                     san=tpmSan)
    x5c = [CertUtils.get_encoded(tpmCert), CertUtils.get_encoded(ca_certificate)]

    # Build sign data
    toSign = bytes([*authData, *clientDataHash])
    pubArea = _build_rsa_public_area(keyPair) if isinstance(keyPair.get_public(), rsa.RSAPublicKey) \
              else _build_ec_public_area(keyPair)
    certInfo = _build_cert_info(toSign, pubArea)
    theHash = hashes.SHA256()
    if isinstance(keyPair.get_public(), rsa.RSAPublicKey):
        sig = keyPair.get_private().sign(certInfo, padding.PKCS1v15(), theHash)
    else:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(certInfo)
        sig = keyPair.get_private().sign(digest.finalize(),
                                         ec.ECDSA(utils.Prehashed(theHash)))

    return {
        u"pubArea": pubArea,
        u"certInfo": certInfo,
        u"sig": sig,
        u"ver": u"2.0",
        u"alg": KeyUtils.get_alg_id_from_pubkey_and_hash(keyPair.get_public(), theHash),
        u"x5c": x5c
    }
