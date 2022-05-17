from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


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
