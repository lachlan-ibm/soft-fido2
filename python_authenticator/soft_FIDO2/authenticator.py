#!/bin/python3
import hashlib
import json
import datetime
import struct
import re
import base64
import binascii
import cbor2 as cbor
import sys
import array
import os
import jwt

from cryptography.hazmat.primitives.asymmetric import rsa, ec
import cryptography.hazmat.primitives.asymmetric.padding as padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509


try:
    from fido2_authenticator.key_pair import KeyPair
except:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from key_pair import KeyPair
try:
    from fido2_authenticator.cert_utils import CertUtils
except:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from cert_utils import CertUtils



class Fido2Authenticator(object):
    
    
    def __init__(self, keyPair=None, credId=None, aaguid=None, caKeyPair=None, caCert=None, counter=0):
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
            caCert (x509Certificate): certificate to use as a trust anchor; default = None

        """
        self.counter = counter
        self.userHandle = None
        self.caCertificate = caCert
        self.caKeyPair = caKeyPair

        if credId != None and caKeyPair != None:
            #If we havea credId and a caKeyPair try decode key from credId
            self.kp = self._get_key_pair_from_credential_id(credId, caKeyPair)

        elif keyPair:
            #If credId passed in then keyPair will be ignored
            self.kp = keyPair

        else:
            #else fall back to creating key pair
            self.kp = KeyPair.generate_rsa()

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

        Returns:
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
        limit = 256 ** 4 - 1 #max value we can fit into a struct.pack
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


    def _get_credential_id_bytes(self, keyPair, caKeyPair):
        """Get the bytes of a credential ID for a given authenticator.
        If a self.caKeyPair is not None, credId is the encoded bytes of self.kp.get_private

        else credId is the sha256 of the public key
        
        Args:
            keyPair (KeyPair): key pair to generate Id for
            caKyePair (KeyPair): ca key pair used for encrypting private key, may be None

        Return:
            bytes: credential Id for given key pair and ca key pair
        """
        credIdBytes = None
        if caKeyPair != None:
            credIdBytes = caKeyPair.get_public.encrypt( keyPair.get_public_bytes(),
                                                        padding.OEAP(
                                                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                            algorithm=hashes.SHA256(),
                                                            label=None
                                                        )
                                                      )
        else:
            credIdBytes = hashlib.sha256( keyPair.get_public_bytes() ).digest()
        return credIdBytes


    def get_credential_id(self, keyPair=None):
        """credential ID defaults to the SHA256 of the public key

        Args:
            keyPair (:obj:`KeyPair`, optional): key pair to get credential id for; default = self.kp

        Returns:
            str: b64 encoded byte string of credentail id
        """
        if keyPair == None: keyPair = self.kp
        credIdBytes = self.__get_credential_id_bytes(keyPair, self.caKeyPair)
        credId = base64.urlsafe_b64encode( credIdBytes ).decode('utf-8')
        return re.sub(r'[=]+$', '', credId)


    @classmethod
    def _get_key_pair_from_credential_id(cls, credId, keyPair):
        """Given a credId and caKeyPair attempt to reconstruct the private/public
        key pair

        Args:
            credId (str): url safe base64 encoded private key encrypted using keyPair
            keyPair (KeyPair): key pair usedd to encrypt private key

        Return:
            KeyPair: original key pair stored in credId
        """
        private_bytes = keyPair.get_private.decrypt( cls._urlb64_decode(credId),
                                                     padding.OEAP(
                                                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                        algorithm=hashes.SHA256(),
                                                        label=None
                                                     )
                                                   )
        privateKey = serialization.load_pem_private_key(
                    private_bytes,
                    password=None,
                    backend=default_backend() )
        publicKey = privateKey.public_key()
        return KeyPair(privateKey, publicKey)


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
                result += binascii.hexlify(
                        bytes( chr( self.aaguid[x]), 'utf-8')).decode('utf-8')
                if x == 3 or x == 5 or x == 7 or x == 9:
                    result += '-'
        else:
            result = bytes(self.aaguid)
        return result


    def credential_create(self, jsonOptions, atteStmtFmt='packed-self', keyPair=None, uv=True):
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
            keyPair (:obj:`KeyPair`, optional): private/public key pair to sign the attestation; default = self.kp
            uv (:obj:`bool`, optional): if the authenticator should set the user verification flag; default = True

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
        return self.process_credential_create_options(cco, atteStmtFmt, keyPair, uv)


    def credential_request(self, jsonOptions, keyPair=None, uv=True):
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

        return self.process_credential_request_options(cro, keyPair, uv)


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

        clientDataDict = { 'origin' : 'https://' + rp,
                            'challenge' : self._urlb64_encode(pk['challenge']),
                            'type': mode}
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
        attestedCredDataBytes += [ length[1],  length[0] ]
        attestedCredDataBytes += credIdBytes

        credPublicKeyCOSE = {}
        if isinstance(publicKey, rsa.RSAPublicKey):
            credPublicKeyCOSE["1"] = 3
            credPublicKeyCOSE["3"] = -257
            credPublicKeyCOSE["-1"] = self._long_to_bytes(publicKey.public_numbers().n)
            credPublicKeyCOSE["-2"] = self._long_to_bytes(publicKey.public_numbers().e)

        elif isinstance(publicKey, ec.EllipticCurvePublicKey):
            credPublicKeyCOSE["1"] = 2
            credPublicKeyCOSE["3"] = -7
            credPublicKeyCOSE["-1"] = 1
            credPublicKeyCOSE["-2"] = self._long_to_bytes(publicKey.public_numbers().x)
            credPublicKeyCOSE["-3"] = self._long_to_bytes(publicKey.public_numbers().y)
        else:
            raise Exception("Unsupported public key algorithm")

        attestedCredDataBytes += cbor.dumps( credPublicKeyCOSE )
        return attestedCredDataBytes


    def build_authenticator_data(self, pk, attStmtFmt, keyPair, uv):
        """create the authenticator data for the attestation or assertion request

        Args:
            pk (dict): public key dictionary from request options,
                    https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialcreationoptions
                    https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialrequestoptions
            attStmtFmt (str): attestation statement format, 
                    https://www.w3.org/TR/webauthn/#defined-attestation-formats
            keyPair (KeyPair): public/private key pair to use
            uv (bool): toggle setting the user verification flag

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

        rpIdHash = hashlib.sha256( rpId.encode('utf-8') ).digest()
        authDataBytes += rpIdHash
        flags = 0x01 # UP
        if not assertion:
            flags |= 0x40 # AT
        if attStmtFmt != 'fido-u2f' and uv :
            flags |= 0x04 # UV
        authDataBytes += struct.pack("c", chr(flags).encode('utf-8') )
        #Add counter and increment
        authDataBytes += struct.pack("I", self.counter)
        self.counter += 1

        if not assertion:
            credIdBytes = self._get_credential_id_bytes(keyPair, self.caKeyPair)
            authDataBytes += self.process_attested_credential_data(keyPair.get_public(), credIdBytes)
        authData = bytes(authDataBytes)
        return authData


    def build_packed_attestation_statement(self, atteStmtFmt, clientDataHash, authData, credIdBytes, keyPair):
        """Create an attestation statment with the packed format.

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
        result = {}
        toSign = bytes( [ *authData, *clientDataHash ] )
        sig = ""
        selfAttestation = True if 'self' in atteStmtFmt else False
        if not selfAttestation:
            leafSubj = x509.Name( [x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'leaf'), 
                                x509.NameAttribute(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME, u'Authenticator Attestation'),
                                x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u'AU'),
                                x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u'IBM')])
            leafCert = CertUtils.gen_aik_cert(subject=leafSubj, issuer=self.caCertificate.issuer, keyPair=keyPair, 
                    signKeyPair=self.caKeyPair, aaguid=self.get_aaguid(hexString=False) )
            # Final trust chain to add to AttesationObject
            result['x5c'] = [ CertUtils.get_encoded(leafCert), CertUtils.get_encoded(self.caCertificate) ]
        
        if isinstance(keyPair.get_public(), rsa.RSAPublicKey):

            result[u"alg"] = -257
            sig = keyPair.get_private().sign( toSign, padding.PKCS1v15(), hashes.SHA256() )

        elif isinstance(keyPair.get_public(), ec.EllipticCurvePublicKey):
            result[u"alg"] = -7
            sig = keyPair.get_private().sign( toSign, ec.ECDSA(hashes.SHA256()) )

        else:
            raise Exception("Unsupported key type")
        
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
        pubKey += self._long_to_bytes( keyPair.get_public().get_numbers().x )
        pubKey += self._long_to_bytes( keyPair.get_public().get_numbers().y )

        subject = x509.Name( [x509.NameAttribute(NameOID.COMMON_NAME, u'root'),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'IBM Security') ])
        cert = CertUtils.gen_ca_cert(subject=subject, keyPair=keyPair)
        
        rpIdHash = authData[0:32]
        toSign = []
        toSign += ['\x00']
        toSign += rpIdHash
        toSign += clientDataHash
        toSign += credIdBytes
        toSign += pubKey

        sig = keyPair.get_private().sign(toSign, padding.PKCS1v15(), hashes.SHA256())
        result = {
                'sig': sig,
                'x5c': CertUtils.get_encoded(cert)
            }

        return result


    def _build_rsa_public_area(self, caKeyPair):
        pubArea = []
        pubArea += [0, 1] # TPM_ALG_ID = TPM_ALG_RSA
        pubArea += [0, 11] # name_alg = TPM_ALG_SHA256
        pubArea += [0] * 4 # TPMA_OBJECT
        pubArea += [0] * 2 # authPolicy
        pubArea += [0, 1] # symetric = TPM_ALG_NULL
        pubArea += [4, 0] # keySize
        pubArea += [0] * 4 # exponent
        unique = self._long_to_bytes( caKeyPair.get_public.public_numbers().n )
        uniqueLength = struct.pack("!H", len(unique))
        pubArea += unqiueLength
        pubArea += unique

        return bytes(pubArea)


    def _build_rsa_cert_info(self, attsToSign, pubInfo):
        certInfo = [0xFF, 0x54, 0x43, 0x47] # TPM_GENERATED
        certInfo += [ 0x80, 0x17] # TPM_ST_ATTEST_CERTIFY
        certInfo += [0] * 2 # qualified signer length
        sigHash = hashlib.sha256( attsToSign ).digest()
        sigHashLength = struct.pack("!H", len(sigHash))
        certInfo += sigHashLength
        certInfo += sigHash
        certInfo += [0] * 17 # clock info
        vendorId = struct.pack("!L", CertUtils.TPM_VENDOR_ID)
        certInfo += [0] * ( 8 - len(vendorId) )
        certInfo += vendorId
        attestedName = [0x00, 0x0B] #name_alg
        attestedName += hashes.sha256(pubInfo).digest()
        attestedNameLength = struct.pack("!H", len(attestedName))
        certInfo += attestedNameLength
        certInfo += attestedName
        certInfo += [0] * 2 # attested qualified name length

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
        #Generate TPM certificates
        caSubject = x509.Name( [x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'root')])
        caCert = cert_utils.gen_ca_cert(subject=caSubject, keyPair=self.caKeyPair)
        tpmSubj = x509.Name( [] )
        tpmSan = CertUtils.TPM_VENDOR + "=IBMTPB+" + CertUtils.TPM_MANUFACTURER + "=id:" + struct.pack("!L", CertUtils.TPM_VENDOR_ID) \
                + "+" + CertUtils.TPM_FW_VERSION + "=id:1"
        tpmCert = cert_utils.gen_aik_cert(subject=tpmSubj, issuer=caCert, keyPair=keyPair, signKeyPair=self.caKeyPair, 
                aaguid=self.get_aaguid(hexString=False), san=tpmSan, androidKey=False)
        x5c = [CertUtils.get_encoded(tpmCert), CertUtils.get_encoded(caCert)]

        # Build sign data
        toSign = [*authData, *clientDataHash]
        pubInfo = self._build_rsa_public_area(self.caKeyPair)
        certInfo = self_build_rsa_cert_info(toSign, pubInfo)
        sig = keyPair.get_private().sign(toSign, padding.PKCS1v15(), hashes.SHA256())

        # Build attestation
        result = {
                u"pubArea": pubArea,
                u"certInfo": certInfo,
                u"sig": sig,
                u"ver": u"2.0",
                u"alg": -257, # SHA256 /w RSA
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


    def build_android_safetynet_attestation_statement(self, atteStmtFmt, clientDataHash, authData, credIdBytes, keyPair):
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
        jws = {
                u'timestampMs': -1,
                u'nonce': 'nonsense',
                u'apkPackageName': "com.package.name.of.requesting.app",
                u"apkCertificateDigestSha256": ["b64 encoded sha256 of cert"],
                u"ctsProfileMatch": True,
                "basicIntegrity": True
            }
        jwtResponse = jwt.encode(jws, keyPair.get_private_bytes(), algorithm="RS256")
        result = {
                u'ver': u'some version',
                u'response': jwtResponse
            }
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
        leafSubj = x509.Name( [x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'leaf'), 
                            x509.NameAttribute(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME, u'Authenticator Attestation'),
                            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u'AU'),
                            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u'IBM')])
        leafCert = CertUtils.gen_aik_cert(subject=leafSubj, issuer=self.caCertificate.issuer, keyPair=keyPair, 
                signKeyPair=self.caKeyPair, aaguid=self.get_aaguid(hexString=False))
        x5c = [ CertUtils.get_encoded(leafCert), CertUtils.get_encoded(self.caCertificate) ]

        #Sign data
        toSign = []
        toSign += authData
        toSign += clientDataHash
        toSignBytes = bytes(toSign)
        sig = keyPair.get_private().sign( toSign, padding.PKCS1v15(), hashes.SHA256() )

        result = {
                u"x5c": x5c,
                u"sig": sig
            }
        return result


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
        try:
            return { "none": self.build_none_attestation_statement,
                    "packed": self.build_packed_attestation_statement,
                    "fido-u2f": self.build_fido_u2f_attestation_statement,
                    "packed-self": self.build_packed_attestation_statement,
                    "android-key": self.build_android_key_attestation_statement,
                    "android-safetynet": self.build_android_safetynet_attestation_statement,
                    "tpm": self.build_tpm_attestation_statement
                    }.get(atteStmtFmt)(atteStmtFmt, clientDataHash, authData, credIdBytes, keyPair)
        except KeyError:
            raise Exception("Unsupported attestation statement format [{}]".format(atteStmtFmt) )


    def attestation_options_response_to_credential_create_options(self, options):
        """Take the options provided by the relyig party and extract required information to
        generate the attestation
        
        Args:
            options (dict): options from navigator.credential.create
                    https://www.w3.org/TR/webauthn/#credentialcreationoptions-extension
        Returns:
            dict: https://www.w3.org/TR/webauthn/#dictionary-makecredentialoptions
        """
        pkcco = {'rp': options['rp'] }
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


    def process_credential_create_options(self, cco, atteStmtFmt, keyPair, uv):
        """Generate response to parsed credential create request

        Args:
            cco (dict): Credential Create Options,
                    https://www.w3.org/TR/credential-management-1/#credentialcreationoptions-dictionary
            atteStmtFmt (str): required attestation format. see:
                    https://www.w3.org/TR/webauthn/#defined-attestation-formats
            keyPair (KeyPair): public/private kye pair to sign with
            uv (bool): set the user verification flag

        Returns:
            dict: attestation response to credential create request,
                    https://www.w3.org/TR/webauthn/#authenticatorattestationresponse
        """
        pk = cco['publicKey']
        self.userHandle = pk['user']['id']
        clientDataJSON = self.build_client_data_JSON(pk)
        clientDataHash = hashlib.sha256( clientDataJSON.encode('utf-8') ).digest()
        clientDataEncoded = base64.urlsafe_b64encode(clientDataJSON.encode('ascii') )
        
        credIdBytes = self._get_credential_id_bytes(keyPair, self.caKeyPair)
        credIdString = base64.urlsafe_b64encode( credIdBytes )

        authData = self.build_authenticator_data(pk, atteStmtFmt, keyPair, uv)
        attStmt = self.process_attestation_statement(atteStmtFmt, clientDataHash, authData, credIdBytes, keyPair)
        attStmtFmt = str( re.sub('-self', '', atteStmtFmt))
        attestationObject = { u'authData': authData,
                            u'fmt': attStmtFmt,
                            u'attStmt': attStmt
                            }
        saar = { u'clientDataJSON': str(clientDataEncoded, 'utf-8'),
                u'attestationObject': str(base64.urlsafe_b64encode( cbor.dumps(attestationObject)), 'utf-8')
                }
        spkc = { u'id': str(credIdString, 'utf-8'),
                u'rawId': str(credIdString, 'utf-8'),
                u'response': saar,
                u'type': u'public-key',
                u'getClientExtensionResults': {}
                }
        return spkc


    def assertion_signiture(self, authData, clientDataHash, keyPair):
        toSign = []
        toSign += authData
        toSign += clientDataHash
        toSignStr = bytes(toSign)
        sig = keyPair.get_private().sign(toSignStr,
                padding.PKCS1v15(),
                hashes.SHA256())
        return str( base64.urlsafe_b64encode(sig), 'utf-8')


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
                cred = { 'type': c['type'],
                         'id': base64.urlsafe_b64decode(c['id'])
                        }
                if 'transports' in c:
                    cred['transports'] = c['transports']
                pkcro['allowedCredentials'].append(cred)

        if 'userVerifation' in options:
            pkcro['userVerification'] = options['userVerification']
        
        cro['publicKey'] = pkcro
        return cro


    def process_credential_request_options(self, cro, keyPair, uv):
        """Generate response to parsed credential get request

        Args:
            cro (dict): Credential Request Options,
                    https://www.w3.org/TR/credential-management-1/#dictdef-credentialrequestoptions
            keyPair (KeyPair): public/private key pair to sign with
            uv (bool): set the user verification flag

        Returns:
            dict: assertion response to credential get request,
                    https://www.w3.org/TR/webauthn/#authenticatorassertionresponse
        """
        pk = cro["publicKey"]
        clientDataJSON = self.build_client_data_JSON(pk)
        authData = self.build_authenticator_data(pk, None, keyPair, uv)
        saar = {"clientDataJSON":  str( base64.urlsafe_b64encode(clientDataJSON.encode('utf-8')), 'utf-8'),
                "authenticatorData": str(base64.urlsafe_b64encode(authData), 'utf-8')
            }
        if self.userHandle != None:
            saar['userHandle'] = self._urlb64_encode(self.userHandle)
        clientDataHash = bytearray(hashlib.sha256(clientDataJSON.encode('utf-8') ).digest())
        
        credIdBytes = self._get_credential_id_bytes(keyPair, self.caKeyPair)

        if not isinstance(keyPair.get_public(), rsa.RSAPublicKey):
            raise Exception("Only RSA keys supported")

        saar['signature'] = self.assertion_signiture(authData, clientDataHash, keyPair)

        spkc = {'id': str( base64.urlsafe_b64encode(credIdBytes), 'utf-8'),
                'rawId': str( base64.urlsafe_b64encode(credIdBytes), 'utf-8'),
                'response': saar,
                'type': 'public-key',
                'getClientExtensionResults': {}
            }
        return spkc

############################# MAIN ##############################

if __name__ == "__main__":
    authenticator = Fido2Authenticator()
    rsp = None
    if sys.argv[1] == 'attestation':
        rsp = authenticator.credential_create(sys.argv[3], atteStmtFmt=sys.argv[2], keyPair=authenticator.kp)
        #write out keys usesd
        with open('private.pem', 'wb') as key_file:
            key_file.write( authenticator.kp.get_private_bytes() )

        with open('public.pem', 'wb') as key_file:
            key_file.write( authenticator.kp.get_public_bytes() )

    else:
        privateKey = publicKey = None
        with open('private.pem', 'rb') as key_file:
            privateKey = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend() )
        
        with open('public.pem', 'rb') as key_file:
            publicKey = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend() )

        keyPair = KeyPair(privateKey, publicKey)
        authenticator.kp = keyPair
        rsp = authenticator.credential_request(sys.argv[2], authenticator.kp)
    print(json.dumps(rsp, indent=4))
