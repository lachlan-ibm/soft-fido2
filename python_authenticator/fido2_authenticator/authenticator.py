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


    def __urlb64_encode(self, byteString):
        b64String = str(base64.urlsafe_b64encode(byteString), 'utf-8')
        return re.sub(r'=*$', '', b64String)


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


    def credential_request(self, jsonOptions, keyPair=None, uv=True):
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
            saar['userHandle'] = self.__urlb64_encode(self.userHandle)
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
