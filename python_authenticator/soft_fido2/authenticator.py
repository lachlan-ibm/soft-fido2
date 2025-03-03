import hashlib
import json
import struct
import re
import base64
import binascii
import sys
import array
import os
import time

import cbor2 as cbor
import jwt

from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding, utils
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509

try:
    from soft_fido2.key_pair import KeyPair, KeyUtils
except:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from key_pair import KeyPair, KeyUtils
try:
    from soft_fido2.cert_utils import CertUtils
except:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from cert_utils import CertUtils


class Fido2Authenticator(object):

    def __init__(self,
                 keyPair=None,
                 credId=None,
                 aaguid=None,
                 caKeyPair=None,
                 caCert=None,
                 counter=0,
                 hashingAlg=hashes.SHA256(),
                 transports=None,
                 fKey=None,
                 disable_counter=False):
        """
        Args:
            keyPair (KeyPair): public/private key pair to sign challenges with;
                    default = RSA 2048 key
            credId (`obj`:str, optional): url base64 encoded credential Id to use with authenticator, if None
                    credential Id will be the sha256 of the public key
            aaguid (:obj:`list` of :obj:`int`, optional): aaguid to associate with
                    authenticator; default = [0] * 16
            caKeyPair (KeyPair): public/private key of ca/intermadiate authority
                    for BASIC/ATTCA attestation formats; default = None
            caCert (`cryptography.x509.Certificate`): certificate to use as a trust anchor; default = None
            counter (`int`): Internal counter of token.
            hashingAlg (`cryptography.hazmat.primitives.hashes.HashAlgorithm`): Hashing algorithm to use for "packed"
                        attesttation format.
            transports (list, optional): a list of support transports; default = None
            fKey (cryptography.fernet.Fernet, optional): An optional symmetric key to generate 
                        the cred id with. Can be used to reconstruct private EC key for assertions.
            disable_counter (`bool`, optional): Optionally disable the attestation/assertion internal counter.
        """
        self.counter = counter
        self.userHandle = None
        self.caCertificate = caCert
        self.caKeyPair = caKeyPair
        self.hashAlg = hashingAlg
        self.transports = transports
        self.cred_id_bytes = None
        self.kp = keyPair
        self.fKey = fKey
        self.disable_counter = disable_counter

        if self.kp == None and credId != None and fKey != None:
            try:
                self.kp = self._get_key_pair_from_credential_id(credId, fKey)
            except Exception as e:
                print(e) #set the bytes as the cred_id and generate a key
                self.cred_id_bytes = self._urlb64_decode(credId)

        if self.kp == None:
            #self.kp = KeyPair.generate_rsa()
            #self.kp = KeyPair.generate_ed25519()
            self.kp = KeyPair.generate_ecdsa()

        if credId != None and self.cred_id_bytes == None: # We were not given a sym key so just use the credId as is
            self.cred_id_bytes = self._urlb64_decode(credId)

        if aaguid == None:
            self.aaguid = [0] * 16
        else:
            self.aaguid = aaguid


    @classmethod
    def _urlb64_decode(cls, b64String):
        """Helper function to decode b64 urlencoded strings which may be missing
        the traling padding that python required

        Args:
            b64String (str): string to decode

            str: decoded string
        """
        pad = len(b64String) % 4
        if pad:
            b64String += b'=' * pad
        return base64.urlsafe_b64decode(b64String)

    @classmethod
    def _urlb64_encode(cls, byteString):
        """Helper function or b64 encode a string then remove the trailing padding
        which is not required

        Args:
            byteString (str): string to encode

        Returns:
            str: b64 url encoded string with trailing '=' stripped
        """
        b64String = str(base64.urlsafe_b64encode(byteString), 'utf-8')
        return re.sub(r'=*$', '', b64String)

    def _long_to_bytes(cls, l):
        """Convert a long to a byte representation

        Args:
            l (long): long to convert to bytes

        Returns:
            :obj:`list` of :obj:`bytes`: byte representation of the long value
        """
        limit = 256**4 - 1  #max value we can fit into a struct.pack
        parts = []
        while l:
            parts.append(l & limit)
            l >>= 32
        parts = parts[::-1]
        return struct.pack(">" + 'L' * len(parts), *parts)

    def _bytes_to_long(self, b):
        """Converts an array of bytes to a long

        Args:
            b (:obj:`list` of :obj:`byte`): bytes to convert

        Returns:
            long: value of bytes as a long
        """
        l = len(b) / 4
        parts = struct.unpack(">" + 'L' * l, b)[::-1]
        result = 0
        for i in range(len(parts)):
            temp = parts[i] << (32 * i)
            result += temp

        return result

    def _get_credential_id_bytes(self, keyPair):
        """Get the bytes of a credential ID for a given authenticator.
        If a self.caKeyPair is not None, credId is the encoded bytes of self.kp.get_private

        else credId is the sha256 of the public key

        Args:
            keyPair (KeyPair): key pair to generate Id for
            caKyePair (KeyPair): ca key pair used for encrypting private key, may be None

        Return:
            bytes: credential Id for given key pair and ca key pair
        """
        if self.cred_id_bytes != None:
            return self.cred_id_bytes
        elif self.fKey != None and isinstance(keyPair.get_public(), ec.EllipticCurvePublicKey):
            keyBytes  = keyPair.get_private_bytes()
            self.cred_id_bytes = self.fKey.encrypt(keyPair.get_private_bytes())
            return self.cred_id_bytes
        else:
            return hashlib.sha256(keyPair.get_public_bytes()).digest()

    def get_credential_id(self, keyPair=None):
        """credential ID defaults to the SHA256 of the public key

        Args:
            keyPair (:obj:`KeyPair`, optional): key pair to get credential id for; default = self.kp

        Returns:
            str: b64 encoded byte string of credentail id
        """
        if keyPair == None:
            keyPair = self.kp
        credIdBytes = self._get_credential_id_bytes(keyPair)
        return self._urlb64_encode(credIdBytes)


    @classmethod
    def _get_key_pair_from_credential_id(cls, credId, fKey):
        """Given a credId and caKeyPair attempt to reconstruct the private/public
        key pair

        Args:
            credId (str): url safe base64 encoded private key encrypted using keyPair
            keyPair (KeyPair): key pair usedd to encrypt private key

        Return:
            KeyPair: original key pair stored in credId
        """
        encBytes = cls._urlb64_decode(credId)
        #decrypt the bytes using the Fernet key
        keyBytes = fKey.decrypt(encBytes)
        #Finally reconstruct the key
        return KeyPair.load_key_pair(keyBytes)

    def get_aaguid(self, hexString=True):
        """If hexString returns in the format:
            01020304-0506-0708-0900-010203040506

        else returns format:
            1234567890123456

        Args:
            hexString (:obj:`bool`, optional): toggle wether to output a hexstring or a string representation of
                    aaguid; default = True

        Returns:
            str: representation of aaguid
        """
        result = ''
        if hexString:
            for x in range(16):
                result += binascii.hexlify(bytes(chr(self.aaguid[x]), 'utf-8')).decode('utf-8')
                if x == 3 or x == 5 or x == 7 or x == 9:
                    result += '-'
        else:
            result = bytes(self.aaguid)
        return result

    def credential_create(self, jsonOptions, atteStmtFmt='packed-self', keyPair=None, uv=True, up=True, be=False, bs=False):
        '''Reponds to requests to navigator.credentail.create(). jsonOptions should be
        either a dictionary or a JSON string of the attestation options and usually has the form:
        {
            "rp": {
                "id": "relying.party",
                "name": "Relying Party"
            },
            "user": {
                "id": "my_unique_id",
                "name": "Low Key",
                "displayName": "redacted"
            },
            "timeout": 60000,
            "challenge": "wvhbvWMV5Jsl96WbdZGav6Ifpp8QHnJC0MKhs1vDUes",
            "excludeCredentials": [],
            "authenticatorSelection": {
                "requireResidentKey": true,
                "authenticatorAttachment": "cross-platform",
                "userVerification": "preferred"
            },
            "attestation": "direct",
            "pubKeyCredParams": [
                {
                    "alg": -7,
                    "type": "public-key"
                },
                {
                    "alg": -257,
                    "type": "public-key"
                }
            ]
        }

        Args:
            jsonOptions (dict) :dictionary of options for navigator.credential.create
            atteStmtFormat (:obj:`str`, optional): https://w3c.github.io/webauthn/#defined-attestation-formats
                    default = 'packed-self'
                    for compound attestation the string is prefixed with 'compound:' and the required compound
                    statements are listed with a ',' (comma) separator. eg: `compound:packed-self,tpm`
            keyPair (:obj:`KeyPair`, optional): private/public key pair to sign the attestation; default = self.kp
            uv (:obj:`bool`, optional): if the authenticator should set the user verification flag; default = True
            up (:obj:`bool`, optional): if the authenticator should set the user presence flag; default = True
            be (:obj:`bool`, optional): if the authenticator should set the backup eligible flag; default = False
            bs (:obj:`bool`, optional): if the authenticator should set the backup state flag; default = False

        Returns:
            dict: response to navigator.credential.create
        '''
        if keyPair is None:
            keyPair = self.kp
        options = {}
        if isinstance(jsonOptions, dict):
            options = jsonOptions
        else:
            options = json.loads(jsonOptions)
        cco = self.attestation_options_response_to_credential_create_options(options)
        return self.process_credential_create_options(cco, atteStmtFmt, keyPair, uv, up)

    def credential_request(self, jsonOptions, keyPair=None, uv=True, up=True, be=False, bs=False):
        '''Responds to navigator.credential.get(). jsonOptions should be either a dictionary
        or a JSON string of the assertion options and usually has the form:
        {
            "rpID": "www.my-relying-party.com"
            "userId": "my_unique_id",
            "displayName": "redacted",
            "authenticatorSelection": {
                "requireResidentKey": false,
                "authenticatorAttachment": "cross-platform",
                "userVerification": "preferred"
            },
            "attestation": "direct"
        }

        Args:
            jsonOptions (dict): json dictionary of options for navigator.credentials.get
            keyPair (:obj:`KeyPair`, optional): private/public key pair to sign the assertion; default = self.kp
            uv (:obj:`bool`, optional): if the authenticator should set hte user verification flag, default = True
            up (:obj:`bool`, optional): if the authenticator should set hte user presence flag, default = True
            be (:obj:`bool`, optional): if the authenticator should set the backup eligible flag; default = False
            bs (:obj:`bool`, optional): if the authenticator should set the backup state flag; default = False

        Returns:
            dict: response to navigator.credential.get
        '''
        if keyPair is None:
            keyPair = self.kp
        options = {}
        if isinstance(jsonOptions, dict):
            options = jsonOptions
        else:
            options = json.loads(jsonOptions)
        cro = self.assertion_options_response_to_credential_request_options(options)

        return self.process_credential_request_options(cro, keyPair, uv, up, be, bs)

    def build_client_data_JSON(self, pk):
        """Creates the ClientDataJSON object for attestation and assertion operations

        Args:
            pk (dict): public key dictionary from request options,
                    https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialcreationoptions
                    https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialrequestoptions

        Returns:
            dict: clientDataJSON, https://www.w3.org/TR/webauthn/#sec-client-data
        """
        rp = pk.get('rpId', None)
        mode = 'webauthn.get'
        if not rp:
            rp = pk['rp']['id']
            mode = 'webauthn.create'

        clientDataDict = {'origin': 'https://' + rp, 'challenge': self._urlb64_encode(pk['challenge']), 'type': mode}
        return json.dumps(clientDataDict)

    def process_attested_credential_data(self, publicKey, credIdBytes):
        """create the attested credentail data for attestation requets

        Args:
            publickey: (PublicKey): RSA || EC public key
            credIdBytes (str): byte string of credential id, https://www.w3.org/TR/webauthn/#credential-id

        Returns:
            str: attested credetail data, https://www.w3.org/TR/webauthn/#sec-attested-credential-data
        """
        attestedCredDataBytes = []
        attestedCredDataBytes += array.array('B', self.aaguid).tobytes()
        length = struct.pack('H', len(credIdBytes))
        attestedCredDataBytes += [length[1], length[0]]
        attestedCredDataBytes += credIdBytes
        credPublicKeyCOSE = KeyUtils.get_cose_key(publicKey, self.hashAlg)
        attestedCredDataBytes += cbor.dumps(credPublicKeyCOSE)
        return attestedCredDataBytes

    def build_authenticator_data(self, pk, attStmtFmt, keyPair, uv, up=True, be=False, bs=False):
        """create the authenticator data for the attestation or assertion request

        Args:
            pk (dict): public key dictionary from request options,
                    https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialcreationoptions
                    https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialrequestoptions
            attStmtFmt (str): attestation statement format,
                    https://www.w3.org/TR/webauthn/#defined-attestation-formats
            keyPair (KeyPair): public/private key pair to use
            up (bool): toggle setting the user presence flag
            uv (bool): toggle setting the user verification flag
            be (bool): toggle setting the backup eligible flag
            bs (bool): toggle setting the backup state flag

        Returns:
            str: byte string of authenticator data,
                    https://www.w3.org/TR/webauthn/#sec-authenticator-data
        """
        authDataBytes = []

        rpId = pk.get('rpId', None)
        assertion = True
        if not rpId:
            rpId = pk['rp']['id']
            assertion = False

        rpIdHash = hashlib.sha256(rpId.encode('utf-8')).digest()
        authDataBytes += rpIdHash

        flags = 0x00
        if up:
            flags |= 0x01  # UP
        if not assertion:
            flags |= 0x40  # AT
        if attStmtFmt != 'fido-u2f' and uv != None and uv == True:
            flags |= 0x04  # UV
        if be == True:
            flags |= 0x08
        if bs == True:
            flags |= 0x0F
        authDataBytes += struct.pack("c", chr(flags).encode('utf-8'))

        #Add counter and increment if required
        authDataBytes += struct.pack(">I", self.counter)
        if self.disable_counter == False:  
            self.counter += 1

        if not assertion:
            credIdBytes = self._get_credential_id_bytes(keyPair)
            authDataBytes += self.process_attested_credential_data(keyPair.get_public(), credIdBytes)
        authData = bytes(authDataBytes)
        return authData

    def build_packed_attestation_statement(self, atteStmtFmt, clientDataHash, authData, credIdBytes, keyPair):
        """Create an attestation statment with the packed format. Hashing alg used in this format is controleld by
        the `self.hashAlg` property

        Args:
            atteStmtFmt (str): statement format, either 'packed' or 'packed-self' to indicate self signed attestation
            clientDataHash (str): byte string of clientDataHash,
                    https://www.w3.org/TR/webauthn/#collectedclientdata-hash-of-the-serialized-client-data
            authData (str): byte string of the authentication data,
                    https://www.w3.org/TR/webauthn/#sec-authenticator-data
            credIdBytes (str): byte string of the credential id
            keyPair (KeyPair): public/privte key pair to sign data with

        Returns:
            dict: packed attestation statement,
                    https://www.w3.org/TR/webauthn/#packed-attestation
        """
        result = {} # Key order is important
        result[u"alg"] = KeyUtils.get_alg_id_from_pubkey_and_hash(keyPair.get_public(), self.hashAlg)
        toSign = bytes([*authData, *clientDataHash])
        sig = ""

        if isinstance(keyPair.get_public(), rsa.RSAPublicKey):
            #sig = keyPair.get_private().sign( toSign, padding.PKCS1v15(), hashes.SHA256() )
            sig = keyPair.get_private().sign(toSign, padding.PKCS1v15(), self.hashAlg)

        elif isinstance(keyPair.get_public(), ec.EllipticCurvePublicKey):
            #digest = hashes.Hash(hashes.SHA256())
            digest = hashes.Hash(self.hashAlg)
            digest.update(b''.join([(x.encode() if isinstance(x, str) else bytes([x])) for x in toSign]))
            #sig = keyPair.get_private().sign( digest.finalize(), ec.ECDSA(utils.Prehashed(hashes.SHA256())) )
            sig = keyPair.get_private().sign(digest.finalize(), ec.ECDSA(utils.Prehashed(self.hashAlg)))
        elif isinstance(keyPair.get_public(), ed25519.Ed25519PublicKey):
            sig = keyPair.get_private().sign(toSign)

        else:
            raise Exception("Unsupported key type")

        #Maybe add X5c
        selfAttestation = True if 'self' in atteStmtFmt else False
        if not selfAttestation:
            if not self.caCertificate:
                raise RuntimeError("Packed Attestation requires a CA certificate to be "\
                        "present when the authenticator is created")
            leafSubj = x509.Name([
                x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'leaf'),
                x509.NameAttribute(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME, u'Authenticator Attestation'),
                x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u'AU'),
                x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u'IBM')
            ])
            leafCert = CertUtils.gen_aik_cert(subject=leafSubj,
                                              issuer=self.caCertificate.subject,
                                              keyPair=keyPair,
                                              signKeyPair=self.caKeyPair,
                                              aaguid=self.get_aaguid(hexString=False))
            # Final trust chain to add to AttesationObject
            result['x5c'] = [CertUtils.get_encoded(leafCert), CertUtils.get_encoded(self.caCertificate)]

        result[u"sig"] = sig
        return result

    def build_fido_u2f_attestation_statement(self, atteStmtFmt, clientDataHash, authData, credIdBytes, keyPair):
        """Create an attestation statement with the U2F format.

        Args:
            atteStmtFmt (str): statement format
            clientDataHash (str): byte string of clientDataHash,
                    https://www.w3.org/TR/webauthn/#collectedclientdata-hash-of-the-serialized-client-data
            authData (str): byte string of the authentication data,
                    https://www.w3.org/TR/webauthn/#sec-authenticator-data
            credIdBytes (str): byte string of the credential id
            keyPair (KeyPair): public/privte key pair to sign data with

        Returns:
            dict: u2f attestation statement,
                    https://www.w3.org/TR/webauthn/#fido-u2f-attestation

        """
        if not isinstance(keyPair.get_public(), ec.EllipticCurvePublicKey):
            raise Exception("FIDO U2F only supports ECDSA keys")

        pubKey = ['\x04']
        pubKey += self._long_to_bytes(keyPair.get_public().public_numbers().x)
        pubKey += self._long_to_bytes(keyPair.get_public().public_numbers().y)

        subject = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'root'),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME, u'IBM Security')
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
        result = {'sig': sig, 'x5c': [CertUtils.get_encoded(cert)]}

        return result

    def _build_rsa_public_area(self, keyPair):
        pubArea = []
        pubArea += [0, 1]  # TPM_ALG_ID = TPM_ALG_RSA
        pubArea += [0, 11]  # name_alg = TPM_ALG_SHA256
        pubArea += [0] * 4  # TPMA_OBJECT
        pubArea += [0] * 2  # authPolicy
        pubArea += [0, 0x10]  # symetric = TPM_ALG_NULL
        pubArea += [1, 4]  # scheme = TMP_ALG_RSASSA (PKCS1-v1.5)
        pubArea += [4, 0]  # keySize
        pubArea += [0] * 4  # exponent
        unique = self._long_to_bytes(keyPair.get_public().public_numbers().n)
        uniqueLength = struct.pack("!H", len(unique))
        pubArea += [uniqueLength[0], uniqueLength[1]]
        pubArea += unique
        return bytes(pubArea)

    def _build_ec_public_area(self, keypair):
        pubArea = []
        pubArea += [0, 0x23] # TPM_ALG_ID = TPM_ALG_ECC
        pubArea += [0, 0x0B] # TPM_ALG_SHA256
        pubArea += [0] * 4  # TPMA_OBJECT
        pubArea += [0] * 2  # authPolicy
        pubArea += [0, 0x10]  # symetric = TPM_ALG_NULL
        pubArea += [0, 0x10]  # scheme = TPM_ALG_NULL
        pubArea += [0, 0x03]  # curve_id == TPM_ECC_NIST_P256
        pubArea += [0, 0x10]  # kdf == TPM_ALG_NULL
        xBytes = KeyUtils._long_to_bytes(keypair.get_public().public_numbers().x)
        xByteLen = struct.pack("!H", len(xBytes))
        pubArea += [xByteLen[0], xByteLen[1]]
        pubArea += xBytes
        yBytes = KeyUtils._long_to_bytes(keypair.get_public().public_numbers().y)
        yByteLen = struct.pack("!H", len(yBytes))
        pubArea += [yByteLen[0], yByteLen[1]]
        pubArea += yBytes
        return bytes(pubArea)

    def _build_cert_info(self, attsToSign, pubInfo):
        certInfo = [0xFF, 0x54, 0x43, 0x47]  # TPM_GENERATED
        certInfo += [0x80, 0x17]  # TPM_ST_ATTEST_CERTIFY
        certInfo += [0] * 2  # qualified signer length
        digest = hashes.Hash(hashes.SHA256())
        digest.update(attsToSign)
        sigHash = digest.finalize()
        #certInfo += [ int((len(sigHash) - (len(sigHash) & 0xFF)) / 256), len(sigHash) & 0xFF ]
        sigHashLength = struct.pack("!H", len(sigHash))
        certInfo += [sigHashLength[0], sigHashLength[1]]
        certInfo += sigHash
        certInfo += [0] * 17  # clock info
        vendorId = struct.pack("!L", CertUtils.TPM_VENDOR_ID)
        certInfo += [0] * (8 - len(vendorId))
        certInfo += vendorId
        attestedName = [0x00, 0x0B]  #name_alg
        digest = hashes.Hash(hashes.SHA256())
        digest.update(pubInfo)
        attestedName += digest.finalize()
        attestedNameLength = struct.pack("!H", len(attestedName))
        certInfo += [attestedNameLength[0], attestedNameLength[1]]
        certInfo += attestedName
        certInfo += [0] * 2  # attested qualified name length
        return bytes(certInfo)

    def build_tpm_attestation_statement(self, atteStmtFmt, clientDataHash, authData, credIdBytes, keyPair):
        """Create an attestation statement with the TPM format

        Args:
            atteStmtFmt (str): statement format
            clientDataHash (str): byte string of clientDataHash,
                    https://www.w3.org/TR/webauthn/#collectedclientdata-hash-of-the-serialized-client-data
            authData (str): byte string of the authentication data,
                    https://www.w3.org/TR/webauthn/#sec-authenticator-data
            credIdBytes (str): byte string of the credential id
            keyPair (KeyPair): public/privte key pair to sign data with

        Returns:
            dict: tpm attestation statement,
                    https://www.w3.org/TR/webauthn/#fido-u2f-attestation
        """
        if not self.caCertificate:
            raise RuntimeError("TPM Attestation requires a CA certificate to be "\
                    "present when the authenticator is created")
        #Generate TPM certificates
        vendorId = CertUtils._long_to_bytes(CertUtils.TPM_VENDOR_ID).hex()
        tpmSan = x509.name.Name([
            x509.NameAttribute(x509.oid.ObjectIdentifier(CertUtils.TPM_MANUFACTURER), u"id:{}".format(vendorId)),
            x509.NameAttribute(x509.oid.ObjectIdentifier(CertUtils.TPM_VENDOR), u"IBMTPM"),
            x509.NameAttribute(x509.oid.ObjectIdentifier(CertUtils.TPM_FW_VERSION), u"id:1")
        ])
        tpmCert = CertUtils.gen_aik_cert(subject=x509.Name([]),
                                         issuer=self.caCertificate.subject,
                                         keyPair=keyPair,
                                         signKeyPair=self.caKeyPair,
                                         aaguid=self.get_aaguid(hexString=False),
                                         san=tpmSan)
        x5c = [CertUtils.get_encoded(tpmCert), CertUtils.get_encoded(self.caCertificate)]

        # Build sign data
        toSign = bytes([*authData, *clientDataHash])
        pubArea = self._build_rsa_public_area(keyPair) if isinstance(keyPair.get_public(), rsa.RSAPublicKey) else \
                    self._build_ec_public_area(keyPair)
        certInfo = self._build_cert_info(toSign, pubArea)
        sig = None
        if isinstance(keyPair.get_public(), rsa.RSAPublicKey):
            keyPair.get_private().sign(certInfo, padding.PKCS1v15(), hashes.SHA256())
            sig = keyPair.get_private().sign(certInfo, padding.PKCS1v15(), hashes.SHA256())
        else:
            digest = hashes.Hash(hashes.SHA256())
            digest.update(certInfo)
            sig = keyPair.get_private().sign( digest.finalize(), ec.ECDSA(utils.Prehashed(hashes.SHA256())) )


        # Build attestation
        result = {
            u"pubArea": pubArea,
            u"certInfo": certInfo,
            u"sig": sig,
            u"ver": u"2.0",
            u"alg": -257 if isinstance(keyPair.get_public(), rsa.RSAPublicKey) else -7,  # SHA256 /w RSA (-257) or EC (-7)
            u"x5c": x5c
        }
        return result

    def build_none_attestation_statement(self, atteStmtFmt, clientDataHash, authData, credIdBytes, keyPair):
        """Create an attestation statement with the none format

        Args:
            atteStmtFmt (str): statement format
            clientDataHash (str): byte string of clientDataHash,
                    https://www.w3.org/TR/webauthn/#collectedclientdata-hash-of-the-serialized-client-data
            authData (str): byte string of the authentication data,
                    https://www.w3.org/TR/webauthn/#sec-authenticator-data
            credIdBytes (str): byte string of the credential id
            keyPair (KeyPair): public/privte key pair to sign data with

        Returns:
            dict: none attestation statement,
                    https://www.w3.org/TR/webauthn/#none-attestation
        """
        return {}

    def build_android_safetynet_attestation_statement(self, atteStmtFmt, clientDataHash, authData, credIdBytes,
                                                      keyPair):
        """Create an attestation statement with the Android Safetynet format

        Args:
            atteStmtFmt (str): statement format
            clientDataHash (str): byte string of clientDataHash,
                    https://www.w3.org/TR/webauthn/#collectedclientdata-hash-of-the-serialized-client-data
            authData (str): byte string of the authentication data,
                    https://www.w3.org/TR/webauthn/#sec-authenticator-data
            credIdBytes (str): byte string of the credential id
            keyPair (KeyPair): public/privte key pair to sign data with

        Returns:
            dict: Android safetynet attestation statement,
                    https://www.w3.org/TR/webauthn/#android-safetynet-attestation
        """
        if(isinstance(keyPair.get_public(), ec.EllipticCurvePublicKey)):
           raise RuntimeError("Android safetynet Attestation requires a RSA key")
        leafSubj = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'attest.android.com'),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME, u'Authenticator Attestation'),
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u'AU'),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u'IBM')
        ])
        leafCert = CertUtils.gen_aik_cert(subject=leafSubj,
                                          issuer=self.caCertificate.subject,
                                          keyPair=keyPair,
                                          signKeyPair=self.caKeyPair)
        nonceBytes = [*authData, *clientDataHash]
        nonceHash = hashlib.sha256(bytes(nonceBytes)).digest()
        claims = {
            u'timestampMs': round(time.time() * 1000),
            u'nonce': base64.b64encode(nonceHash).decode(),
            u'apkPackageName': u"com.package.name.of.requesting.app",
            u"apkCertificateDigestSha256": [u"b64 encoded sha256 of cert"],
            u"ctsProfileMatch": True,
            u"basicIntegrity": True
        }
        jwtResponse = jwt.encode(
            claims,
            keyPair.get_private_bytes(),
            algorithm="RS256",
            headers={"x5c": [CertUtils.get_bytes(leafCert).decode(),
                             CertUtils.get_bytes(self.caCertificate).decode()]})
        result = {u'ver': u'some version', u'response': jwtResponse.encode()}
        return result

    def build_android_key_attestation_statement(self, atteStmtFmt, clientDataHash, authData, credIdBytes, keyPair):
        """Create an attestation statement with the Android Keystore format.

        Args:
            atteStmtFmt (str): statement format
            clientDataHash (str): byte string of clientDataHash,
                    https://www.w3.org/TR/webauthn/#collectedclientdata-hash-of-the-serialized-client-data
            authData (str): byte string of the authentication data,
                    https://www.w3.org/TR/webauthn/#sec-authenticator-data
            credIdBytes (str): byte string of the credential id
            keyPair (KeyPair): public/privte key pair to sign data with

        Returns:
            dict: Android Keystore attestation statement,
                    https://www.w3.org/TR/webauthn/#android-key-attestation
        """
        if not self.caCertificate:
            raise RuntimeError("Android Key Attestation requires a CA certificate to be "\
                    "present when the authenticator is created")

        #Build x5c chain
        leafSubj = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'leaf'),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME, u'Authenticator Attestation'),
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u'AU'),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u'IBM')
        ])
        leafCert = CertUtils.gen_aik_cert(subject=leafSubj,
                                          issuer=self.caCertificate.subject,
                                          keyPair=keyPair,
                                          signKeyPair=self.caKeyPair,
                                          androidKeyNonce=bytes(clientDataHash))
        x5c = [CertUtils.get_encoded(leafCert), CertUtils.get_encoded(self.caCertificate)]
        #Sign data
        toSign = [*authData, *clientDataHash]
        sig = None
        if isinstance(keyPair.get_public(), rsa.RSAPublicKey):
            sig = keyPair.get_private().sign(bytes(toSign), padding.PKCS1v15(), hashes.SHA256())
        else: #Must be EC key
            digest = hashes.Hash(hashes.SHA256())
            digest.update(bytes(toSign))
            sig = keyPair.get_private().sign( digest.finalize(), ec.ECDSA(utils.Prehashed(hashes.SHA256())) )

        result = {
            u"x5c": x5c,
            u"sig": sig,
            u"alg": KeyUtils.get_alg_id_from_pubkey_and_hash(keyPair.get_public(), self.hashAlg)
        }
        return result

    def build_apple_attestation_statement(self, atteStmtFmt, clientDataHash, authData, credIdBytes, keyPair):
        """Create an attestaion statement with the Apple Platform format

        Args:
            atteStmtFmt (str): statement format, 'apple'
            clientDataHash (str): byte string of clientDataHash,
                    https://www.w3.org/TR/webauthn/#collectedclientdata-hash-of-the-serialized-client-data
            authData (str): byte string of the authentication data,
                    https://www.w3.org/TR/webauthn/#sec-authenticator-data
            credIdBytes (str): byte string of the credential id
            keyPair (KeyPair): public/privte key pair to sign data with

        Returns:
            dict: Apple platform attestation statement,
                    #TODO has not been published
        """
        if not self.caCertificate:
            raise RuntimeError("Apple Attestation requires a CA certificate to be "\
                    "present when the authenticator is created")
        #First need to generate the apple certificate with the required extension
        nonceBytes = []
        nonceBytes += authData
        nonceBytes += clientDataHash
        nonceHash = hashlib.sha256(bytes(nonceBytes)).digest()
        leafSubj = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'apple'),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME, u'Authenticator Attestation'),
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u'AU'),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u'IBM')
        ])
        appleCert = CertUtils.gen_apple_cert(subject=leafSubj,
                                             issuer=self.caCertificate.subject,
                                             keyPair=keyPair,
                                             signKeyPair=self.caKeyPair,
                                             nonce=nonceHash)
        print(CertUtils.get_encoded(appleCert))
        return {'x5c': [CertUtils.get_encoded(appleCert), CertUtils.get_encoded(self.caCertificate)]}

    def _process_att_stmt(self, atteStmtFmt, clientDataHash, authData, credIdBytes, keyPair):
        try:
            return {
                "none": self.build_none_attestation_statement,
                "packed": self.build_packed_attestation_statement,
                "fido-u2f": self.build_fido_u2f_attestation_statement,
                "packed-self": self.build_packed_attestation_statement,
                "android-key": self.build_android_key_attestation_statement,
                "android-safetynet": self.build_android_safetynet_attestation_statement,
                "tpm": self.build_tpm_attestation_statement,
                "apple": self.build_apple_attestation_statement
            }.get(atteStmtFmt)(atteStmtFmt, clientDataHash, authData, credIdBytes, keyPair)
        except KeyError:
            raise Exception("Unsupported attestation statement format [{}]".format(atteStmtFmt))


    def process_attestation_statement(self, atteStmtFmt, clientDataHash, authData, credIdBytes, keyPair):
        """Helper function that chooses an attestation statement function based on the atteStmtFmt variable

        Args:
            atteStmtFmt (str): statement format
            clientDataHash (str): byte string of clientDataHash,
                    https://www.w3.org/TR/webauthn/#collectedclientdata-hash-of-the-serialized-client-data
            authData (str): byte string of the authentication data,
                    https://www.w3.org/TR/webauthn/#sec-authenticator-data
            credIdBytes (str): byte string of the credential id
            keyPair (KeyPair): public/privte key pair to sign data with

        Returns:
            dict: attestation statement. Type of statement depends on 'atteStmtFmt', see:
                    https://www.w3.org/TR/webauthn/#defined-attestation-formats
        """
        if atteStmtFmt.startswith('compound'):
            stmtsCsv = atteStmtFmt.split(":")
            if stmtsCsv == None or len(stmtsCsv) != 2:
                raise Exception("Unexpected attestation statement format [{}]".format(atteStmtFmt))
            stmts = stmtsCsv[1].split(",")
            if stmts == None or len(stmts) < 2:
                raise Exception("Unexpected attestation statement format [{}]".format(atteStmtFmt))
            result = []
            for stmt in stmts:
                result += [{u'fmt': stmt, u'attStmt': 
                           self._process_att_stmt(stmt, clientDataHash, authData, credIdBytes, keyPair)}]
            return result
        #else
        return self._process_att_stmt(atteStmtFmt, clientDataHash, authData, credIdBytes, keyPair)

    def attestation_options_response_to_credential_create_options(self, options):
        """Take the options provided by the relyig party and extract required information to
        generate the attestation

        Args:
            options (dict): options from navigator.credential.create
                    https://www.w3.org/TR/webauthn/#credentialcreationoptions-extension
        Returns:
            dict: https://www.w3.org/TR/webauthn/#dictionary-makecredentialoptions
        """
        pkcco = {'rp': options['rp']}
        user = {'id': self._urlb64_decode(options['user']['id'].encode('UTF-8'))}
        pkcco['user'] = user
        pkcco['challenge'] = self._urlb64_decode(options['challenge'].encode('UTF-8'))
        pkcco['pubKeyCredParams'] = options['pubKeyCredParams']
        if 'timeout' in options:
            pkcco['timeout'] = options['timeout']

        if 'excludeCredentials' in options:
            pkcco['excludeCredentials'] = options['excludeCredentials']

        if 'authenticatorSelection' in options:
            pkcco['authenticatorSelection'] = options['authenticatorSelection']

        if 'attestation' in options:
            pkcco['attestation'] = options['attestation']

        if 'extensions' in options:
            pkcco['extensions'] = options['extensions']

        cco = {'publicKey': pkcco}
        return cco

    def process_credential_create_options(self, cco, atteStmtFmt, keyPair, uv, up=True, be=False, bs=False):
        """Generate response to parsed credential create request

        Args:
            cco (dict): Credential Create Options,
                    https://www.w3.org/TR/credential-management-1/#credentialcreationoptions-dictionary
            atteStmtFmt (str): required attestation format. see:
                    https://www.w3.org/TR/webauthn/#defined-attestation-formats
            keyPair (KeyPair): public/private kye pair to sign with
            uv (bool): set the user verification flag
            up (bool): set the user presence flag
            be (bool): set the backup eligible flag
            bs (bool): set the backup state flag

        Returns:
            dict: attestation response to credential create request,
                    https://www.w3.org/TR/webauthn/#authenticatorattestationresponse
        """
        pk = cco['publicKey']
        self.userHandle = pk['user']['id']
        clientDataJSON = self.build_client_data_JSON(pk)
        clientDataHash = hashlib.sha256(clientDataJSON.encode('utf-8')).digest()
        clientDataEncoded = base64.urlsafe_b64encode(clientDataJSON.encode('ascii'))

        credIdBytes = self._get_credential_id_bytes(keyPair)

        authData = self.build_authenticator_data(pk, atteStmtFmt, keyPair, uv, up, be, bs)
        attStmt = self.process_attestation_statement(atteStmtFmt, clientDataHash, authData, credIdBytes, keyPair)
        attStmtFmt = str(re.sub('-self', '', atteStmtFmt))
        if atteStmtFmt.startswith('compound'):
            attStmtFmt = atteStmtFmt.split(':')[0]
        attestationObject = {u'authData': authData, u'fmt': attStmtFmt, u'attStmt': attStmt}
        saar = {
            u'clientDataJSON': str(clientDataEncoded, 'utf-8'),
            u'attestationObject': str(base64.urlsafe_b64encode(cbor.dumps(attestationObject)), 'utf-8')
        }
        spkc = {
            u'id': self.get_credential_id(keyPair),
            u'rawId': self.get_credential_id(keyPair),
            u'response': saar,
            u'type': u'public-key',
            u'getClientExtensionResults': {}
        }
        if self.transports is not None:
            spkc['getTransports'] = self.transports
        if(cco.get('extensions') != None 
                and isinstance(cco['extensions'], dict) 
                and "devicePubKey" in cco['extensions'].keys()):
            raise RuntimeError("TODO")
        return spkc

    def assertion_signature(self, authData, clientDataHash, keyPair):
        toSign = []
        toSign += authData
        toSign += clientDataHash
        toSignStr = bytes(toSign)
        sig = b''
        if isinstance(keyPair.get_public(), rsa.RSAPublicKey) == True:
            sig = keyPair.get_private().sign(toSignStr, padding.PKCS1v15(), self.hashAlg)
        elif isinstance(keyPair.get_public(), ec.EllipticCurvePublicKey) == True:
            hasher = hashes.Hash(self.hashAlg)
            hasher.update(toSignStr)
            sig = keyPair.get_private().sign(hasher.finalize(), ec.ECDSA(utils.Prehashed(self.hashAlg)))
        elif isinstance(keyPair.get_public(), ed25519.Ed25519PublicKey):
            sig = keyPair.get_private().sign(toSignStr)
        else:
            raise Exception("Unsupported key alg")
        return sig

    def assertion_options_response_to_credential_request_options(self, options):
        """Take the options provided by the relyig party and extract required information to
        generate the assertion

        Args:
            options (dict): options from navigator.credential.get
                    https://www.w3.org/TR/webauthn/#iface-authenticatorassertionresponse
        Returns:
            dict: https://www.w3.org/TR/credential-management-1/#dictdef-credentialrequestoptions
        """
        cro = {}
        pkcro = {}

        pkcro['challenge'] = self._urlb64_decode(options['challenge'].encode('UTF-8'))
        if 'timeout' in options:
            pkcro['timeout'] = options['timeout']

        pkcro['rpId'] = options['rpId']
        if 'allowedCredentials' in options:
            allowedCreds = options['allowedCredentials']
            pkcro['allowedCredentials'] = []
            for c in allowedCreds:
                cred = {'type': c['type'], 'id': base64.urlsafe_b64decode(c['id'])}
                if 'transports' in c:
                    cred['transports'] = c['transports']
                pkcro['allowedCredentials'].append(cred)

        if 'userVerifation' in options:
            pkcro['userVerification'] = options['userVerification']

        if 'extensions' in options:
            pkcro['extensions'] = options['extensions']

        cro['publicKey'] = pkcro
        return cro

    def process_credential_request_options(self, cro, keyPair, uv, up=True, be=False, bs=False):
        """Generate response to parsed credential get request

        Args:
            cro (dict): Credential Request Options,
                    https://www.w3.org/TR/credential-management-1/#dictdef-credentialrequestoptions
            keyPair (KeyPair): public/private key pair to sign with
            uv (bool): set the user verification flag
            up (bool): set the user presence flag
            be (bool): set the backup eligible flag. This should be consistent with the registration state.
            bs (bool): set the backup state flag

        Returns:
            dict: assertion response to credential get request,
                    https://www.w3.org/TR/webauthn/#authenticatorassertionresponse
        """
        pk = cro["publicKey"]
        clientDataJSON = self.build_client_data_JSON(pk)
        authData = self.build_authenticator_data(pk, None, keyPair, uv, up, be, bs)
        saar = {
            "clientDataJSON": str(base64.urlsafe_b64encode(clientDataJSON.encode('utf-8')), 'utf-8'),
            "authenticatorData": str(base64.urlsafe_b64encode(authData), 'utf-8')
        }
        if self.userHandle != None:
            saar['userHandle'] = self._urlb64_encode(self.userHandle)
        if "attestation" in cro.keys():
            raise RuntimeError("TODO")
        clientDataHash = bytearray(hashlib.sha256(clientDataJSON.encode('utf-8')).digest())

        credIdBytes = self._get_credential_id_bytes(keyPair)

        saar['signature'] = str(base64.urlsafe_b64encode(self.assertion_signature(
                                                            authData, clientDataHash, keyPair)), 'utf-8')
        spkc = {
            'id': self.get_credential_id(keyPair),
            'rawId': self.get_credential_id(keyPair),
            'response': saar,
            'type': 'public-key',
            'getClientExtensionResults': {}
        }
        if(cro.get('extensions', None) != None
                and isinstance(cro['extensions'], dict)
                and "devicePubKey" in cro['extensions'].keys()):
            raise RuntimeError("TODO")
        return spkc


############################# MAIN ##############################

if __name__ == "__main__":
    authenticator = Fido2Authenticator()
    rsp = None
    if sys.argv[1] == 'attestation':
        rsp = authenticator.credential_create(sys.argv[3], atteStmtFmt=sys.argv[2], keyPair=authenticator.kp)
        #write out keys usesd
        with open('private.pem', 'wb') as key_file:
            key_file.write(authenticator.kp.get_private_bytes())

        with open('public.pem', 'wb') as key_file:
            key_file.write(authenticator.kp.get_public_bytes())

    else:
        privateKey = publicKey = None
        with open('private.pem', 'rb') as key_file:
            privateKey = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

        with open('public.pem', 'rb') as key_file:
            publicKey = serialization.load_pem_public_key(key_file.read(), backend=default_backend())

        keyPair = KeyPair(privateKey, publicKey)
        authenticator.kp = keyPair
        rsp = authenticator.credential_request(sys.argv[2], authenticator.kp)
    print(json.dumps(rsp, indent=4))
