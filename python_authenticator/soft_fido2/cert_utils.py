import datetime
import struct
import base64
import binascii

import asn1

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ObjectIdentifier
from cryptography.x509.extensions import ExtensionType
from cryptography import x509


class CertUtils(object):
    '''
    Class for generating certificates for FIDO2 Authenticators. methods should be treated as
    static
    '''
    TCG_KP_AIK_CERTIFICATE_ATTRIBUTE = "2.23.133.8.3"
    TPM_MANUFACTURER = "2.23.133.2.1"
    TPM_VENDOR = "2.23.133.2.2"
    TPM_FW_VERSION = "2.23.133.2.3"
    TPM_VENDOR_ID = 0xfffff1d0

    @classmethod
    def _long_to_bytes(cls, l):
        limit = 256**4 - 1  #max value we can fit into a struct.pack
        parts = []
        while l:
            parts.append(l & limit)
            l >>= 32
        parts = parts[::-1]
        return struct.pack(">" + 'L' * len(parts), *parts)

    class AAGUIDExtension(x509.UnrecognizedExtension):

        def __init__(self, aaguid, oid=ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")):
            encoder = asn1.Encoder()
            encoder.start()
            encoder.write(aaguid, nr=asn1.Numbers.OctetString)
            encodedAAGUID = encoder.output()
            super().__init__(oid, encodedAAGUID)

    class AndroidKeystoreExtension(x509.UnrecognizedExtension):
        '''
        KeyDescription ::= SEQUENCE
        {
          attestationVersion         INTEGER,
          attestationSecurityLevel   SecurityLevel,
          keymasterVersion           INTEGER,
          keymasterSecurityLevel     SecurityLevel,
          attestationChallenge       OCTET_STRING,
          uniqueId                   OCTET_STRING,
          softwareEnforced           AuthorizationList,
          teeEnforced                AuthorizationList
        }
        SecurityLevel ::= ENUMERATED
        {
          software,
          trustedenvironment,
          strongbox
        }
        AuthorizationList ::= SEQUENCE {
          purpose                     [1] EXPLICIT SET OF INTEGER OPTIONAL,
          algorithm                   [2] EXPLICIT INTEGER OPTIONAL,
          keySize                     [3] EXPLICIT INTEGER OPTIONAL,
          digest                      [5] EXPLICIT SET OF INTEGER OPTIONAL,
          padding                     [6] EXPLICIT SET OF INTEGER OPTIONAL,
          ecCurve                     [10] EXPLICIT INTEGER OPTIONAL,
          rsaPublicExponent           [200] EXPLICIT INTEGER OPTIONAL,
          rollbackResistance          [303] EXPLICIT NULL OPTIONAL,
          activeDateTime              [400] EXPLICIT INTEGER OPTIONAL,
          originationExpireDateTime   [401] EXPLICIT INTEGER OPTIONAL,
          usageExpireDateTime         [402] EXPLICIT INTEGER OPTIONAL,
          noAuthRequired              [503] EXPLICIT NULL OPTIONAL,
          userAuthType                [504] EXPLICIT INTEGER OPTIONAL,
          authTimeout                 [505] EXPLICIT INTEGER OPTIONAL,
          allowWhileOnBody            [506] EXPLICIT NULL OPTIONAL,
          trustedUserPresenceRequired [507] EXPLICIT NULL OPTIONAL,
          trustedConfirmationRequired [508] EXPLICIT NULL OPTIONAL,
          unlockedDeviceRequired      [509] EXPLICIT NULL OPTIONAL,
          allApplications             [600] EXPLICIT NULL OPTIONAL,
          applicationId               [601] EXPLICIT OCTET_STRING OPTIONAL,
          creationDateTime            [701] EXPLICIT INTEGER OPTIONAL,
          origin                      [702] EXPLICIT INTEGER OPTIONAL,
          rollbackResistant           [703] EXPLICIT NULL OPTIONAL,
          rootOfTrust                 [704] EXPLICIT RootOfTrust OPTIONAL,
          osVersion                   [705] EXPLICIT INTEGER OPTIONAL,
          osPatchLevel                [706] EXPLICIT INTEGER OPTIONAL,
          attestationApplicationId    [709] EXPLICIT OCTET_STRING OPTIONAL,
          attestationIdBrand          [710] EXPLICIT OCTET_STRING OPTIONAL,
          attestationIdDevice         [711] EXPLICIT OCTET_STRING OPTIONAL,
          attestationIdProduct        [712] EXPLICIT OCTET_STRING OPTIONAL,
          attestationIdSerial         [713] EXPLICIT OCTET_STRING OPTIONAL,
          attestationIdImei           [714] EXPLICIT OCTET_STRING OPTIONAL,
          attestationIdMeid           [715] EXPLICIT OCTET_STRING OPTIONAL,
          attestationIdManufacturer   [716] EXPLICIT OCTET_STRING OPTIONAL,
          attestationIdModel          [717] EXPLICIT OCTET_STRING OPTIONAL,
          vendorPatchLevel            [718] EXPLICIT INTEGER OPTIONAL,
          bootPatchLevel              [719] EXPLICIT INTEGER OPTIONAL
        }
        RootOfTrust ::= SEQUENCE
        {
          verifiedBootKey            OCTET_STRING,
          deviceLocked               BOOLEAN,
          verifiedBootState          VerifiedBootState,
          verifiedBootHash           OCTET_STRING
        }
        VerifiedBootState ::= ENUMERATED
        {
          verified,
          selfsigned,
          unverified,
          failed
        }


        MIICyjCCAnCgAwIBAgIBATAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlm
        b3JuaWExFTATBgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDE7MDkGA1UEAwwyQW5k
        cm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBJbnRlcm1lZGlhdGUwHhcNMTgxMjAyMDkx
        MDI1WhcNMjgxMjAyMDkxMDI1WjAfMR0wGwYDVQQDDBRBbmRyb2lkIEtleXN0b3JlIEtleTBZMBMGByqG
        SM49AgEGCCqGSM49AwEHA0IABDhJog/eJsNLAIg5GlgneD3/k4gLFlQIiq369XollUmhdDxLUkXPJoXP
        kQVDZ81Pr7lITnBZNlEBH8DcznYhxo+jggExMIIBLTALBgNVHQ8EBAMCB4AwgfwGCisGAQQB1nkCAREE
        ge0wgeoCAQIKAQACAQEKAQEEICpDgte72J2LW98Xcs/syhQ5JIe5/VcfLrcr35feBtS2BAAwgYK/gxAI
        AgYBZ24u4XC/gxEIAgYBsOqNrXC/gxIIAgYBsOqNrXC/hT0IAgYBZ24u3+i/hUVOBEwwSjEkMCIEHWNv
        bS5nb29nbGUuYXR0ZXN0YXRpb25leGFtcGxlAgEBMSIEIFrQXsIhyPg6ImEn3sVXUAw+V0vGASWp3CHL
        C+SgBmCVMDOhBTEDAgECogMCAQOjBAICAQClBTEDAgEEqgMCAQG/g3gDAgEXv4N5AwIBHr+FPgMCAQAw
        HwYDVR0jBBgwFoAUP/ys1hqxOp6BILjVJRzFZbsekakwCgYIKoZIzj0EAwIDSAAwRQIgZ3c5CJOAVf1j
        TuQT6q/CHYrHqUQb35evY5FPmzsAr/4CIQC5wMiUWMJSjisl+ojE1j3cdeG8gPuU3MYiiVLQT4EkGA==
        '''

        def __init__(self, nonce, oid=ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")):
            # https://source.android.com/security/keystore/attestation#attestation-extension
            encoder = asn1.Encoder()
            encoder.start()
            encoder.enter(asn1.Numbers.Sequence)
            encoder.write(3, nr=asn1.Numbers.Integer)  # Sequence[0] == attestationVersion
            encoder.write(0, nr=asn1.Numbers.Enumerated)  # Sequence[1] == attestationSecurityLevel
            encoder.write(1, nr=asn1.Numbers.Integer)  # Sequence[2] == keymasterVersion
            encoder.write(1, nr=asn1.Numbers.Enumerated)  # Sequence[3] == keymasterSecurityLevel
            encoder.write(nonce, nr=asn1.Numbers.OctetString)  # Sequece[4] == attestationChallenge
            encoder.write(b'9001', nr=asn1.Numbers.OctetString)  # Sequece[5] == uniqueId
            encoder.enter(asn1.Numbers.Sequence)  # Sequence[6] == softwareEnforced
            encoder.enter(400, asn1.Classes.Context)
            encoder.write(123456, nr=asn1.Numbers.Integer)
            encoder.leave()
            encoder.enter(401, asn1.Classes.Context)
            encoder.write(654321, nr=asn1.Numbers.Integer)
            encoder.leave()
            encoder.enter(701, asn1.Classes.Context)
            encoder.write(3152425, nr=asn1.Numbers.Integer)
            encoder.leave()
            encoder.leave()  # end Sequence[7]
            encoder.enter(asn1.Numbers.Sequence)  # Sequence[7] == teeEnforced
            encoder.enter(1, asn1.Classes.Context)
            encoder.enter(asn1.Numbers.Set)
            encoder.write(2, nr=asn1.Numbers.Integer)
            encoder.leave()
            encoder.leave()  #end set
            encoder.enter(3, asn1.Classes.Context)
            encoder.write(256, nr=asn1.Numbers.Integer)
            encoder.leave()
            encoder.enter(504, asn1.Classes.Context)
            encoder.write(23, nr=asn1.Numbers.Integer)
            encoder.leave()
            encoder.enter(505, asn1.Classes.Context)
            encoder.write(30, nr=asn1.Numbers.Integer)
            encoder.leave()
            encoder.enter(702, asn1.Classes.Context)
            encoder.write(0, nr=asn1.Numbers.Integer)
            encoder.leave()
            encoder.leave()  # end Sequence[7]
            encoder.leave()  # end androidKey asn1
            super().__init__(oid, encoder.output())

    class AppleNonceExtension(x509.UnrecognizedExtension):

        def __init__(self, nonce, oid=ObjectIdentifier("1.2.840.113635.100.8.2")):
            encoder = asn1.Encoder()
            encoder.start()
            encoder.enter(asn1.Numbers.Sequence)
            encoder.enter(0, asn1.Classes.Context)
            encoder.write(nonce)
            encoder.leave()
            encoder.leave()
            encodedNonce = encoder.output()
            super().__init__(oid, encodedNonce)

    @classmethod
    def __cert_builder(cls, subject=None, issuer=None, lifetime=265, serial=None, keyPair=None):
        return x509.CertificateBuilder() \
                    .subject_name(subject) \
                    .issuer_name(issuer) \
                    .public_key(keyPair.get_public()) \
                    .serial_number(serial) \
                    .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)) \
                    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=lifetime)) \

    @classmethod
    def __add_extensions(cls, certBuilder, extensions):
        for extension in extensions:
            certBuilder = certBuilder.add_extension(extension,
                                                    critical=True if extension.oid._name == 'subjectAltName' else False)
        return certBuilder

    @classmethod
    def get_bytes(cls, cert, encoding=serialization.Encoding.DER):
        encoded = cls.get_encoded(cert, encoding=encoding)
        #This is the ASN.1 DER Encoded certificate
        return base64.b64encode(encoded)

    @classmethod
    def load_der_certificate(cls, certBytes):
        return x509.load_der_x509_certificate(certBytes, default_backend())

    @classmethod
    def get_encoded(cls, cert, encoding=serialization.Encoding.DER):
        encoded = cert.public_bytes(encoding=encoding)
        return encoded

    @classmethod
    def gen_cert(cls,
                 subject=None,
                 issuer=None,
                 lifetime=365,
                 serial=x509.random_serial_number(),
                 extensions=None,
                 keyPair=None,
                 signKeyPair=None,
                 signer=hashes.SHA256(),
                 backend=default_backend()):
        '''
        extension should be tuple (extension, isCritical=False)
        '''
        if issuer == None:  #Self signed
            issuer = subject
        if signKeyPair == None:  # self signed
            signKeyPair = keyPair

        certBuilder = cls.__cert_builder(subject, issuer, lifetime, serial, keyPair)
        certBuilder = cls.__add_extensions(certBuilder, extensions)
        return certBuilder.sign(signKeyPair.get_private(), signer, backend)

    @classmethod
    def gen_ca_cert(cls,
                    subject=None,
                    lifetime=365,
                    serial=x509.random_serial_number(),
                    keyPair=None,
                    signer=hashes.SHA256(),
                    backend=default_backend()):
        '''
        generate certificate that can be used as a ca certificate for authenticators. This
        certificate contains the ski extension
        '''
        # CA cert requires basic contraint, ski, key usage and san extensions
        extensions = [
            x509.SubjectKeyIdentifier.from_public_key(keyPair.get_public()),
            x509.BasicConstraints(True, 3),
            x509.KeyUsage(True, False, False, False, False, True, True, False, False),
        ]

        return cls.gen_cert(subject, subject, lifetime, serial, extensions, keyPair, keyPair, signer, backend)

    @classmethod
    def gen_aik_cert(cls,
                     subject=None,
                     issuer=None,
                     lifetime=365,
                     serial=x509.random_serial_number(),
                     keyPair=None,
                     signKeyPair=None,
                     aaguid=None,
                     san=None,
                     androidKeyNonce=None,
                     signer=hashes.SHA256(),
                     backend=default_backend()):
        '''
        Generate Leaf cert in trust chain
        issuer should match the keyPair used to sign the certificate
        '''
        if san is None:
            sanId = cls._long_to_bytes(cls.TPM_VENDOR_ID)
            san = x509.name.Name([
                x509.NameAttribute(ObjectIdentifier(cls.TPM_MANUFACTURER), u"IBM"),
                x509.NameAttribute(ObjectIdentifier(cls.TPM_VENDOR), u"id:{}".format(binascii.b2a_uu(sanId))),
                x509.NameAttribute(ObjectIdentifier(cls.TPM_FW_VERSION), u"id:1")
            ])
        extensions = [
            x509.BasicConstraints(False, None),
            x509.KeyUsage(True, True, False, True, False, True, True, False, False),
            x509.ExtendedKeyUsage([ObjectIdentifier(cls.TCG_KP_AIK_CERTIFICATE_ATTRIBUTE)]),
            x509.SubjectAlternativeName([x509.DirectoryName(san)])
        ]
        if aaguid is not None:
            extensions += [CertUtils.AAGUIDExtension(aaguid)]
        if androidKeyNonce is not None:
            extensions += [CertUtils.AndroidKeystoreExtension(androidKeyNonce)]

        return cls.gen_cert(subject, issuer, lifetime, serial, extensions, keyPair, signKeyPair, signer, backend)

    @classmethod
    def gen_intermedaite_cert(cls,
                              subject=None,
                              issuer=None,
                              lifetime=365,
                              serial=x509.random_serial_number(),
                              keyPair=None,
                              signKeyPair=None,
                              signer=hashes.SHA256(),
                              backend=default_backend()):
        '''
        Generate intermediate certificate in trust chain
        '''
        extensions = [
            x509.BasicConstraints(True, 3),
            x509.KeyUsage(True, True, False, True, False, True, True, False, False),
            x509.ExtendedKeyUsage([ObjectIdentifier(cls.TCG_KP_AIK_CERTIFICATE_ATTRIBUTE)])
        ]

        return cls.gen_cert(subject, issuer, lifetime, serial, extensions, keyPair, signKeyPair, signer, backend)

    @classmethod
    def gen_apple_cert(cls,
                       subject=None,
                       issuer=None,
                       lifetime=365,
                       serial=x509.random_serial_number(),
                       keyPair=None,
                       signKeyPair=None,
                       nonce=None,
                       signer=hashes.SHA256(),
                       backend=default_backend()):
        '''
        Generate Apple Attestation certificate. At the moment this is just a x509 with some apple extension
        which I am sure is very useful to apple.
        '''
        extensions = [CertUtils.AppleNonceExtension(nonce)]
        return cls.gen_cert(subject, issuer, lifetime, serial, extensions, keyPair, signKeyPair, signer, backend)

    @classmethod
    def derive_aes_key_from_x509(cls, cert, key):
        '''
        Use the Elliptic Curve key exchange with ourself to generate a AES key we can use
        to seed the Fido2Authenticator with.
        '''
        for ext in cert.extensions:
            if ext.oid == CertUtils.EncryptedAesKeyExtension.OID:
                return key.exchange(ec.ECDH(), cert.public_key())
        return None
