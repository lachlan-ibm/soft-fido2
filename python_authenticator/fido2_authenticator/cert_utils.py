#!/bin/python3
import hashlib
import json
import datetime
import struct
import re
import base64
import binascii
import cbor2 as cbor
import asn1
import sys
import array

from cryptography import utils
from cryptography.hazmat.primitives import serialization, hashes, constant_time
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ObjectIdentifier
from cryptography.x509.extensions import Extension, ExtensionType
from cryptography import x509


class CertUtils(object):
    '''
    Class for generating certificates for FIDO2 Authenticators. methods should be treated as
    static
    '''
    TCG_KP_AIK_CERTIFICATE_ATTRIBUTE = "2.23.133.8.3"
    TPM_MANUFACTURER = "2.23.133.2.1";
    TPM_VENDOR = "2.23.133.2.2";
    TPM_FW_VERSION = "2.23.133.2.3";

    TPM_VENDOR_ID = 0xfffff1d0

    @classmethod
    def _long_to_bytes(cls, l):
        limit = 256 ** 4 - 1 #max value we can fit into a struct.pack
        parts = []
        while l:
            parts.append(l & limit)
            l >>= 32
        parts = parts[::-1]
        return struct.pack(">" + 'L' * len(parts), *parts)


    @utils.register_interface(ExtensionType)
    class AAGUIDExtension(x509.UnrecognizedExtension):

        def __init__(self, aaguid, oid=ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4") ):
            super().__init__(oid, aaguid)


    @utils.register_interface(ExtensionType)
    class AndroidKeystoreExtension(x509.UnrecognizedExtension):

        def __init__(self, wrapperFormatVersion, encryptedTransportKey, initilizationVector, 
                keyDescription, secureKey, tag, oid=ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")):
            '''
            self._wrapperFormatVersion = wrapperFormatVersion
            self._encryptedTransportKey = encryptedTransportKey
            self._initilizationVector = initilizationVector
            self._keyDescription = keyDescription
            self._secureKey = secureKey
            self._tag = tag
            '''
            value = ''
            super().__init__(oid, value)


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
            certBuilder = certBuilder.add_extension(extension, critical=False)
        return certBuilder


    @classmethod
    def get_bytes(cls, cert, encoding=serialization.Encoding.DER):
        encoded = cls.get_encoded(cert, encoding=encoding)
        #This is the ASN.1 DER Encoded certificate
        return base64.b64encode(encoded)


    @classmethod
    def get_encoded(cls, cert, encoding=serialization.Encoding.DER):
        encoded = cert.public_bytes(encoding=encoding)
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
            keyPair=None, signKeyPair=None, aaguid=None, san=None, androidKey=False, signer=hashes.SHA256(), 
            backend=default_backend()):
        '''
        Generate Leaf cert in trust chain
        issuer should match the keyPair used to sign the certificate
        '''
        sanId = cls._long_to_bytes(cls.TPM_VENDOR_ID)
        if san is None:
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
            encoder = asn1.Encoder()
            encoder.start()
            encoder.write(aaguid)
            encodedAAGUID = encoder.output()
            extensions += [CertUtils.AAGUIDExtension(encodedAAGUID)]
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


