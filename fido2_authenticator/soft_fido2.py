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

from cryptography import utils
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import cryptography.hazmat.primitives.asymmetric.padding as padding
from cryptography.hazmat.primitives import serialization, hashes, constant_time
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ObjectIdentifier
from cryptography.x509.extensions import Extension, ExtensionType
from cryptography import x509

#from ibm.autotest.util.logger import Logger
#logger = Logger(__name__)

class KeyPair(object):

    def __init__(self, privateKey, publicKey):
        object.__init__(self)
        self.private = privateKey
        self.public = publicKey


    @classmethod
    def generate_rsa(cls, e=65537, key_size=2048, backend=default_backend()):
        privateKey = rsa.generate_private_key(e, key_size, backend)
        publicKey = privateKey.public_key()
        return cls(privateKey, publicKey)


    @classmethod
    def generate_ecdsa(cls, curve=ec.SECP256R1(), backend=default_backend()):
        privateKey = ec.generate_private_key(curve, backend)
        publicKey = privateKey.public_key()
        return cls(privateKey, publicKey)


    def set_key(self, privateKey):
        self.private = privateKey
        self.public = privateKey.get_public()


    def get_public(self):
        return self.public


    def get_private(self):
        return self.private


    def get_public_bytes(self):
        return self.public.public_bytes(encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)


    def get_private_bytes(self):
        return self.private.private_bytes(encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8, 
                encryption_algorithm=serialization.NoEncryption())


class CertUtils(object):
    '''
    Class for generating certificates for FIDO2 Authenticators. methods should be treated as
    static
    '''
    TCG_KP_AIK_CERTIFICATE_ATTRIBUTE = "2.23.133.8.3"
    TPM_MANUFACTURER = "2.23.133.2.1";
    TPM_VENDOR = "2.23.133.2.2";
    TPM_FW_VERSION = "2.23.133.2.3";

    @utils.register_interface(ExtensionType)
    class AAGUIDExtension(object):
        oid = ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")

        def __init__(self, aaguid):
            self._aaguid = aaguid
        
        aaguid = utils.read_only_property("_aaguid")

        def __repr__(self):
            return "<AAGUIDExtension(aaguid={0!r})>".format(self.aaguid)

        def __eq__(self, other):
            if not isinstance(other, AAGUIDExtension):
                return NotImplemented
            return constant_time.bytes_eq(self.aaguid, other.aaguid)

        def __ne__(self, other):
            return not self == other

        def __hash__(self):
            return hash(self.aaguid)


    @utils.register_interface(ExtensionType)
    class AndroidKeystoreExtension(object):
        oid = ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")

        def __init__(self, wrapperFormatVersion, encryptedTransportKey, 
                initilizationVector, keyDescription, secureKey, tag):
            self._wrapperFormatVersion = wrapperFormatVersion
            self._encryptedTransportKey = encryptedTransportKey
            self._initilizationVector = initilizationVector
            self._keyDescription = keyDescription
            self._secureKey = secureKey
            self._tag = tag
        
        wrapperFormatVersion = utils.read_only_property("_wrapperFormatVersion")
        encryptedTransportKey = utils.read_only_property("_encryptedTransportKey")
        initilizationVector = utils.read_only_property("_initilizationVecotr")
        keyDecription = utils.read_only_property("_keyDescription")
        secureKey = utils.read_only_property("_secureKey")
        tag = utils.read_only_property("_tag")

        def __repr__(self):
            return "<AndroidKeystoreExtension(wrapperFormatVersion={0!r},encryptedTransportKey={0!r}," \
                    "initilizationVector={0!r},keyDecription={0!r},secureKey={0!r},tag={0!r})>".format(
                    self.wrapperFormatVersion, self.encryptedTransportKey, self.initilizationVector,
                    self.keyDecription, self.secureKey, self.tag)

        def __eq__(self, other):
            if not isinstance(other, AndroidKeystoreExtension):
                return NotImplemented
            for key in [wrapperFormatVersion, encryptedTransportKey, initilizationVector,
                    keyDecription, secureKey, tag]:
                if not constant_time.bytes_eq(self.key, other.key):
                    return False
            return True

        def __ne__(self, other):
            return not self == other

        def __hash__(self):
            return hash(self.aaguid)


    @classmethod
    def __cert_builder(cls, subject=None, issuer=None, lifetime=265, serial=None, keyPair=None):
        return x509.CertificateBuilder() \
                    .subject_name(subject) \
                    .issuer_name(issuer) \
                    .public_key(keyPair.get_public()) \
                    .serial_number(serial) \
                    .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1)) \
                    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=lifetime)) \


    @classmethod
    def __add_extensions(cls, certBuilder, extensions):
        for extension in extensions:
            #logger.debug("Adding extension: " + str(extension) )
            certBuilder = certBuilder.add_extension(extension, critical=False)
        return certBuilder


    @classmethod
    def get_bytes(cls, cert, encoding=serialization.Encoding.DER):
        encoded = cls.get_encoded(cert, encoding=encoding)
        #This is the ASN.1 DER Encoded certificate
        return base64.b64encode(encoded)


    @classmethod
    def get_encoded(cls, cert, encoding=serialization.Encoding.DER):
        encoded = cert.public_bytes(encoding)
        return encoded


    @classmethod
    def gen_cert(cls, subject=None, issuer=None, lifetime=365, serial=x509.random_serial_number(), 
            extensions=None, keyPair=None, signKeyPair=None, signer=hashes.SHA256(), backend=default_backend()):
        '''
        extension should be tuple (extension, isCritical=False)
        '''
        if issuer == None: #Self signed
            issuer = subject
        if signKeyPair == None: # self signed
            signKeyPair = keyPair

        certBuilder = cls.__cert_builder(subject, issuer, lifetime, serial, keyPair)
        certBuilder = cls.__add_extensions(certBuilder, extensions)
        #logger.debug("certbuilder extensions: " + str(certBuilder._extensions)) 
        return certBuilder.sign(signKeyPair.get_private(), signer, backend)


    @classmethod
    def gen_ca_cert(cls, subject=None, lifetime=365, serial=x509.random_serial_number(), 
            keyPair=None, signer=hashes.SHA256(), backend=default_backend()):
        '''
        generate certificate that can be used as a ca certificate for authenticators. This
        certificate contains the ski extension
        '''

        certBuilder = cls.__cert_builder(subject, subject, lifetime, serial, keyPair)

        # CA cert requires basic contraint, ski, key usage and san extensions
        extensions = [ x509.SubjectKeyIdentifier.from_public_key(keyPair.get_public()),
                        x509.BasicConstraints(True, 2),
                        x509.KeyUsage(True, False, False, False, False, True, True, False, False),
                    ]
        
        return cls.gen_cert(subject, subject, lifetime, serial, extensions, keyPair, keyPair, signer, backend)


    @classmethod
    def gen_aik_cert(cls, subject=None, issuer=None, lifetime=365, serial=x509.random_serial_number(), 
            keyPair=None, signKeyPair=None, aaguid=None, androidKey=False, signer=hashes.SHA256(), 
            backend=default_backend()):
        '''
        Generate Leaf cert in trust chain
        issuer should match the keyPair used to sign the certificate
        '''
        sanId = Fido2Authenticator._long_to_bytes(Fido2Authenticator.TPM_VENDOR_ID)
        san = x509.name.Name([x509.NameAttribute(ObjectIdentifier(cls.TPM_MANUFACTURER), u"IBM"), 
                            x509.NameAttribute(ObjectIdentifier(cls.TPM_VENDOR), u"id:{}".format(binascii.b2a_uu(sanId)) ),
                            x509.NameAttribute(ObjectIdentifier(cls.TPM_FW_VERSION), u"id:1")
                            ])
        extensions = [ x509.BasicConstraints(False, None),
                    x509.KeyUsage(True, True, False, True, False, True, True, False, False),
                    x509.ExtendedKeyUsage( [ObjectIdentifier(cls.TCG_KP_AIK_CERTIFICATE_ATTRIBUTE)] ),
                    x509.SubjectAlternativeName( [x509.DirectoryName( san )] )
                    ]
        if aaguid is not None:
            extensions += [CertUtils.AAGUIDExtension(aaguid)]
        if androidKey:
            extensions += [CertUtils.AndroidKeystoreExtension()]
        
        return cls.gen_cert(subject, issuer, lifetime, serial, extensions, keyPair, signKeyPair, signer, backend)


    @classmethod
    def gen_intermedaite_cert(cls, subject=None, issuer=None, lifetime=365, serial=None, keyPair=None,
            signer=hashes.SHA256(), backend=default_backend()):
        '''
        Generate intermediate certificate in trust chain
        '''
        extensions = [ x509.BasicConstraints(False, None),
                    x509.KeyUsage(True, True, False, True, False, True, True, False, False),
                    x509.ExtendedKeyUsage( ObjectIdentifier(cls.TCG_KP_AIK_CERTIFICATE_ATTRIBUTE) )
                    ]

        return cls.gen_cert(subject, issuer, lifetime, serial, extensions, keyPair, signer, backend)



class Fido2Authenticator(object):
    
    TPM_VENDOR_ID = 0xfffff1d0
    
    def __init__(self, keyPair=None, aaguid=None, caKeyPair=None, caCert=None):
        self.counter = 0
        if keyPair == None:
            self.kp = KeyPair.generate_rsa()
        else:
            self.kp = keyPair

        if aaguid == None:
            self.aaguid = [0] * 16
        else:
            self.aaguid = aaguid
        self.userHandle = None
        self.caCertificate = caCert
        self.caKeyPair = caKeyPair


    def __urlb64_decode(self, b64String):
        pad = len(b64String) % 4
        if pad:
            b64String += b'=' * pad
        return base64.urlsafe_b64decode(b64String)


    @classmethod
    def _long_to_bytes(cls, l):
        limit = 256 ** 4 - 1 #max value we can fit into a struct.pack
        parts = []
        while l:
            parts.append(l & limit)
            l >>= 32
        parts = parts[::-1]
        return struct.pack(">" + 'L' * len(parts), *parts)


    def __bytes_to_long(self, b):
        l = len(b) / 4
        parts = struct.unpack(">" + 'L' * l, b)[::-1]
        result = 0
        for i in range(len(parts)):
            temp = parts[i] << (32 * i)
            result += temp

        return result


    def get_credential_id(self, keyPair=None):
        if keyPair == None: keyPair = self.kp
        credIdBytes = hashlib.sha256( keyPair.get_public_bytes() ).digest()
        credId = base64.urlsafe_b64encode( credIdBytes )
        return re.sub(r'[=]+$', '', credId)


    def get_aaguid(self):
        result = ''
        for x in range(16):
            result += binascii.hexlify( chr( self.aaguid[x] ))
            if x == 3 or x == 5 or x == 7 or x == 9:
                result += '-'
        return result.encode('utf-8')


    def credential_create(self, jsonOptions, atteStmtFmt='packed-self', keyPair=None, uv=True):
        '''
        jsonOptions - json dictionary of options for navigator.credential.create
        atteStmtFormat - https://w3c.github.io/webauthn/#defined-attestation-formats
        keyPair - private/public key pair to sign the attestation
        '''
        if keyPair is None:
            keyPair = self.kp
        options = {}
        if isinstance(jsonOptions, dict):
            options = jsonOptions
        else:
            options = json.loads(jsonOptions)
        #logger.debug("Attestation options:")
        #logger.debug(json.dumps(options, indent=4) + '\n\n')
        cco = self.attestation_options_response_to_credential_create_options(options)
        #logger.debug("CCO: " + str(cco) + '\n\n' )
        return self.process_credential_create_options(cco, atteStmtFmt, keyPair, uv)


    def credential_request(self, jsonOptions, keyPair, uv=True):
        '''
        jsonOptions - json dictionary of options for navigator.credentials.get
        keyPair - private/public key pair to sign the assertion
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


    def attestation_options_response_to_credential_create_options(self, options):
        pkcco = {'rp': options['rp'] }
        user = {'id': self.__urlb64_decode(options['user']['id'].encode('UTF-8'))}
        pkcco['user'] = user
        pkcco['challenge'] = self.__urlb64_decode(options['challenge'].encode('UTF-8'))
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


    def build_client_data_JSON(self, pk):
        rp = None
        mode = None
        if 'rpId' in pk:
            rp = pk['rpId']
            mode = 'webauthn.get'
        else:
            rp = pk['rp']['id']
            mode = 'webauthn.create'

        clientDataDict = { 'origin' : 'https://' + rp,
                            'challenge' : str(base64.urlsafe_b64encode(pk['challenge']), 'ascii'),
                            'type': mode}
        return json.dumps(clientDataDict)


    def process_attested_credential_data(self, publicKey, credIdBytes):
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
        #logger.debug("attestedCredDataBytes: " + base64.b64encode( ''.join(attestedCredDataBytes) ))
        return attestedCredDataBytes


    def build_authenticator_data(self, clientDataJSON, pk, attStmtFmt, keyPair, uv):
        authDataBytes = []

        credIdBytes = hashlib.sha256( keyPair.get_public_bytes() ).digest()
        rpId = None
        assertion = False
        if 'rpId' in pk:
            rpId = pk['rpId']
            assertion = True
            # U2F Assertion extension ignored
        else:
            rpId = pk['rp']['id']

        rpIdHash = hashlib.sha256( rpId.encode('utf-8') ).digest()
        authDataBytes += rpIdHash
        flags = 0x01 # UP
        if not assertion:
            flags |= 0x40 # AT
        if attStmtFmt is not 'fido-u2f' and uv :
            flags |= 0x04 # UV
        authDataBytes += struct.pack("c", chr(flags).encode('utf-8') )
        #Add counter and increment
        authDataBytes += struct.pack("I", self.counter)
        self.counter += 1

        if not assertion:
            authDataBytes += self.process_attested_credential_data(keyPair.get_public(), credIdBytes)
        authData = bytes(authDataBytes)
        return authData


    def build_packed_attestation_statement(self, atteStmtFmt, clientDataHash, authData, credIdBytes, keyPair):
        result = {}
        toSignBytes = []
        toSignBytes += authData
        toSignBytes += clientDataHash
        #logger.debug("clientDataHash: " + base64.b64encode(clientDataHash) )
        toSign = bytes(toSignBytes)
        #logger.debug('toSign: ' + base64.b64encode(toSign))
        sig = ""
        selfAttestation = True if 'self' in atteStmtFmt else False
        if isinstance(keyPair.get_public(), rsa.RSAPublicKey):
            #RSA key identified
            if not selfAttestation:
                leafSubj = x509.Name( [x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'leaf'), 
                                    x509.NameAttribute(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME, u'Authenticator Attestation'),
                                    x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u'AU'),
                                    x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u'IBM')])
                leafCert = CertUtils.gen_aik_cert(subject=leafSubj, issuer=self.caCertificate.issuer, keyPair=keyPair, 
                        signKeyPair=self.caKeyPair, aaguid=self.aaguid)
                # Final trust chain to add to AttesationObject
                result['x5c'] = [ CertUtils.get_encoded(leafCert), CertUtils.get_encoded(self.caCertificate) ]

            else:
                #Self attestation, only need COSE key ID
                pass
            result[u"alg"] = -257
            sig = keyPair.get_private().sign( toSign, padding.PKCS1v15(), hashes.SHA256() )

        elif isinstance(keyPair.get_public(), ec.EllipticCurvePublicKey):
            #ECDAA key identified
            if not selfAttestation:
                #logger.debug("Can't generate trust chain for ECDAA keys")
                raise Exception("Not implemented")

            else:
                result[u"alg"] = -7
            sig = keyPair.get_private().sign( toSign, ec.ECDSA(hashes.SHA256()) )

        else:
            #logger.debug(type(keyPair.get_public()))
            raise Exception("Unsupported key type")
        
        result[u"sig"] = sig
        #logger.debug("sig: " + base64.b64encode(sig))
        #logger.debug('privateKey :' + keyPair.get_private_bytes() )
        #logger.debug('pubKey: ' + keyPair.get_public_bytes() )
        return result


    def build_fido_u2f_attestation_statement(self, atteStmtFmt, clientDataHash, authData, credIdBytes, keyPair):
        if not isinstance(keyPair.get_public(), ec.EllipticCurvePublicKey):
            raise Exception("FIDO U2F only supports ECDSA keys")
        result = {}

        pubKey = ['\x04']
        pubKey += self._long_to_bytes( keyPair.get_public().get_numbers().x )
        pubKey += self._long_to_bytes( keyPair.get_public().get_numbers().y )

        subject = x509.Name( [x509.NameAttribute(NameOID.COMMON_NAME, u'root'),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'IBM Security') ])
        cert = CertUtils.gen_ca_cert(subject=subject, keyPair=keyPair)
        result['x5c'] = CertUtils.get_encoded(cert)
        
        rpIdHash = authData[0:32]
        toSign = []
        toSign += ['\x00']
        toSign += rpIdHash
        toSign += clientDataHash
        toSign += credIdBytes
        toSign += pubKey

        sig = keyPair.get_private().sign(toSign, padding.PKCS1v15(), hashes.SHA256())
        result['sig'] = sig

        return result


    def build_tpm_attestation_statement(self, atteStmtFmt, clientDataHash, authData, credIdBytes, keyPair):
        raise Exception("Not yet implemented")


    def build_none_attestation_statement(self, atteStmtFmt, clientDataHash, authData, credIdBytes, keyPair):
        return {}


    def build_android_safetynet_attestation_statement(self, atteStmtFmt, clientDataHash, authData, credIdBytes, keyPair):
        raise Exception("Not yet implemented")


    def build_android_key_attestation_statement(self, atteStmtFmt, clientDataHash, authData, credIdBytes, keyPair):
        result = {}

        #Add x5c chain
        leafSubj = x509.Name( [x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'leaf'), 
                            x509.NameAttribute(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME, u'Authenticator Attestation'),
                            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u'AU'),
                            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u'IBM')])
        leafCert = CertUtils.gen_aik_cert(subject=leafSubj, issuer=self.caCertificate.issuer, keyPair=keyPair, 
                signKeyPair=self.caKeyPair, aaguid=self.aaguid)
        # Final trust chain to add to AttesationObject
        result['x5c'] = [ CertUtils.get_encoded(leafCert), CertUtils.get_encoded(self.caCertificate) ]

        
        #Sign data
        toSign = []
        toSign += authData
        toSign += clientDataHash
        toSignBytes = bytes(toSign)
        sig = keyPair.get_private().sign( toSign, padding.PKCS1v15(), hashes.SHA256() )
        result[u"sig"] = sig

        return result


    def process_attestation_statement(self, atteStmtFmt, clientDataHash, authData, credIdBytes, keyPair):
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
            raise Exception("Unsupported attestation statement format")


    def process_credential_create_options(self, cco, atteStmtFmt, keyPair, uv):
        pk = cco['publicKey']
        self.userHandle = pk['user']['id']
        clientDataJSON = self.build_client_data_JSON(pk)
        clientDataHash = hashlib.sha256( clientDataJSON.encode('utf-8') ).digest()
        clientDataEncoded = base64.urlsafe_b64encode(clientDataJSON.encode('ascii') )

        credIdBytes = hashlib.sha256( keyPair.get_public_bytes() ).digest()
        credIdString = base64.urlsafe_b64encode( credIdBytes )

        authData = self.build_authenticator_data(clientDataJSON, pk, atteStmtFmt, keyPair, uv)
        #logger.debug("authData: " + base64.b64encode(authData))
        attStmt = self.process_attestation_statement(atteStmtFmt, clientDataHash, authData, credIdBytes, keyPair)
        attStmtFmt = str( re.sub('-self', '', atteStmtFmt))
        #logger.debug("fmt: " + attStmtFmt)
        attestationObject = { u'authData': authData,
                            u'fmt': attStmtFmt,
                            u'attStmt': attStmt
                            }
        #logger.debug("attestationObject " + base64.b64encode( cbor.dumps(attestationObject)))
        saar = { u'clientDataJSON': str(clientDataEncoded, 'utf-8'),
                u'attestationObject': str(base64.urlsafe_b64encode( cbor.dumps(attestationObject)), 'utf-8')
                }
        spkc = { u'id': str(credIdString, 'utf-8'),
                u'rawId': str(credIdString, 'utf-8'),
                u'response': saar,
                u'type': u'public-key',
                u'getClientExtensionResults': str(base64.urlsafe_b64encode(cbor.dumps( {})), 'utf-8')
                }
        return spkc


    def assertion_options_response_to_credential_request_options(self, options):
        cro = {}
        pkcro = {}

        pkcro['challenge'] = self.__urlb64_decode(options['challenge'].encode('UTF-8'))
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
        spkc = {}
        saar = {}
        pk = cro["publicKey"]
        clientDataJSON = self.build_client_data_JSON(pk)
        """clientDataBytes = bytearray(clientDataJSON)"""
        saar["clientDataJSON"] = str( base64.urlsafe_b64encode(clientDataJSON.encode('utf-8')), 'utf-8')

        authData = self.build_authenticator_data(clientDataJSON, pk, None, keyPair, uv)
        saar['authenticatorData'] = str(base64.urlsafe_b64encode(authData), 'utf-8')
        if self.userHandle != None:
            saar['userHandle'] = bytearray(self.userHandle)
        clientDataHash = bytearray(hashlib.sha256(clientDataJSON.encode('utf-8') ).digest())

        credIdBytes = hashlib.sha256(keyPair.get_public().public_bytes(
                encoding=serialization.Encoding.PEM, 
                format=serialization.PublicFormat.SubjectPublicKeyInfo))

        if not isinstance(keyPair.get_public(), rsa.RSAPublicKey):
            raise Exception("Only RSA keys supported")

        toSign = []
        toSign += authData
        toSign += clientDataHash
        toSignStr = bytes(toSign)
        sig = keyPair.get_private().sign(toSignStr,
                padding.PKCS1v15(),
                hashes.SHA256())
        saar['signature'] = str( base64.urlsafe_b64encode(sig), 'utf-8')

        spkc['id'] = spkc['rawId'] = str( base64.urlsafe_b64encode(credIdBytes.digest()), 'utf-8')
        spkc['response'] = saar
        spkc['type'] = 'public-key'

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
