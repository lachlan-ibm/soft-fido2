import struct
import cbor2 as cbor
import base64
import secrets

from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class KeyUtils(object):

    @classmethod
    def _long_to_bytes(cls, l):
        limit = 256**4 - 1  #max value we can fit into a struct.pack
        parts = []
        while l:
            parts.append(l & limit)
            l >>= 32
        parts = parts[::-1]
        return struct.pack(">" + 'L' * len(parts), *parts)


    @classmethod
    def _bytes_to_long(cls, b):
        l = int(len(b) / 4)
        parts = struct.unpack(">" + 'L' * l, b)[::-1]
        result = 0
        for i in range(len(parts)):
            temp = parts[i] << (32 * i)
            result += temp

        return result

    @classmethod
    def load_ec_key(cls, key):
        c = {   ec.SECP256R1().name: ec.SECP256R1,
                ec.SECP521R1().name: ec.SECP521R1
            }.get(key.get('c'))()
        pk = ec.derive_private_key(key.get('pv'), c)
        return KeyPair(pk, pk.public_key())

    @classmethod
    def cbor_ec_key(cls, pk):
        if pk == None or not isinstance(pk, ec.EllipticCurvePrivateKey):
            raise ValueError("{} not EllipticCurvePrivateKey".format(pk))
        return cbor.dumps({ 'pv': pk.private_numbers.private_value,
                            'c': pk.curve.name})

    @classmethod
    def get_alg_id_from_pubkey_and_hash(cls, publicKey, alg, ecdh=False):
        if isinstance(publicKey, rsa.RSAPublicKey):
            if isinstance(alg, hashes.SHA256):
                return -257
            if isinstance(alg, hashes.SHA384):
                return -258
            elif isinstance(alg, hashes.SHA512):
                return -259
            elif isinstance(alg, hashes.SHA1):
                return -65535
        elif isinstance(publicKey, ec.EllipticCurvePublicKey):
            if isinstance(alg, hashes.SHA256):
                return -7 if ecdh == False else -25
            if isinstance(alg, hashes.SHA384):
                return -35
            elif isinstance(alg, hashes.SHA512):
                return -36 if ecdh == False else -26
        elif isinstance(publicKey, ed25519.Ed25519PublicKey):
            return -8
        return 0

    @classmethod
    def get_cose_key(cls, publicKey, alg, ecdh=False):
        if isinstance(publicKey, rsa.RSAPublicKey):
            return {1: 3,
                      3: cls.get_alg_id_from_pubkey_and_hash(publicKey, alg),
                     -1: cls._long_to_bytes(publicKey.public_numbers().n),
                     -2: cls._long_to_bytes(publicKey.public_numbers().e)
                 }
        elif isinstance(publicKey, ec.EllipticCurvePublicKey):
            if ecdh == True:
                return {1: 2,
                        3: cls.get_alg_id_from_pubkey_and_hash(publicKey, alg, ecdh),
                       -1: 1,
                       -2: cls._long_to_bytes(publicKey.public_numbers().x),
                       -3: cls._long_to_bytes(publicKey.public_numbers().y)
                    }
            return {1: 2,
                      3: cls.get_alg_id_from_pubkey_and_hash(publicKey, alg),
                     -1: 1,
                     -2: cls._long_to_bytes(publicKey.public_numbers().x),
                     -3: cls._long_to_bytes(publicKey.public_numbers().y)
                 }
        elif isinstance(publicKey, ed25519.Ed25519PublicKey):
            return {1: 6,
                      3: cls.get_alg_id_from_pubkey_and_hash(publicKey, alg),
                     -1: 6,
                     -2: publicKey.public_bytes(encoding=serialization.Encoding.Raw,
                                                  format=serialization.PublicFormat.Raw)
                 }
        else:
            raise Exception("Unsupported public key algorithm")


    @classmethod
    def update_passkey(cls, resCred, pinHash, passkeyFilename):
        '''
        Add a resident cred to a .passkey file
        '''
        passkey = cls._load_passkey(pinHash, passkeyFilename)
        passkey['res_creds'] = [ *passkey.get('res_creds', []), resCred]
        cls._save_passkey(passkey, pinHash, passkeyFilename)

    @classmethod
    def _load_passkey(cls, pinHash, passkeyFilename):
        passkey = {}
        with open(passkeyFilename, 'rb') as f:
            everything = f.read()
            iv = everything[:16]
            tag = everything[16:32]
            encPasskey = everything[32:]
            aesKey = algorithms.AES128(pinHash)
            decryptor = Cipher(aesKey, modes.GCM(iv, tag)).decryptor()
            cborKeyAndPem = decryptor.update(encPasskey) + decryptor.finalize()
            passkey = cbor.loads(cborKeyAndPem)
            f.close()
        return passkey

    @classmethod
    def _save_passkey(cls, passkey, pinHash, passkeyFilename):
        iv = secrets.token_bytes(16)
        aesKey = algorithms.AES128(pinHash)
        encryptor = Cipher(aesKey, modes.GCM(iv)).encryptor()
        cborPasskey = cbor.dumps(passkey)
        everything = encryptor.update(cborPasskey) + encryptor.finalize()
        with open(passkeyFilename, 'wb') as f:
            f.write(iv + encryptor.tag + everything)
            f.close()


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

    @classmethod
    def generate_ed25519(cls):
        privateKey = ed25519.Ed25519PrivateKey.generate()
        publicKey = privateKey.public_key()
        return cls(privateKey, publicKey)

    @classmethod
    def load_key_pair(cls, pk, password=None):
        privateKey = serialization.load_pem_private_key(pk, password=password, backend=default_backend())
        publicKey = privateKey.public_key()
        return cls(privateKey, publicKey)

    @classmethod
    def create_pcks12_bag(cls, key, cert, name, secret, cas=None):
        return serialization.pcks12.serialize_key_and_certificates(
                name, key, cert, cas, serialization.BestAvailableEncryption(secret))

    @classmethod
    def load_pcks12_bag(cls, data, secret):
        '''
        Returns Tuple(private_key, cert, additional_certs)
        '''
        return serialization.pkcs12.load_pkcs12(data, secret)

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
