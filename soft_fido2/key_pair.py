# Copyrite IBM 2022, 2025
# IBM Confidential

import logging
import struct
import os
import cbor2 as cbor
import secrets
import base64

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, utils
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from soft_fido2.cert_utils import CertUtils



class KeyUtils(object):

    @classmethod
    def get_passkey_seed(cls, entropy, key):
        """
        Generate a 32 byte seed from a domain and a private key.

        Entropy is typically the bytes of the rp.id. Key is an Elliptic Curve key.

        Entropy is hashed using SHA256 before signing.

        Returned bytestring is b64_url encoded.
        """
        if not isinstance(entropy, bytes):
            raise ValueError(f"Entropy must be bytes: {entropy}")
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError(f"Key must be an EllipticCurvePrivateKey: {key}")
        theHash = hashes.SHA256()
        digester = hashes.Hash(theHash)
        digester.update(entropy)
        sig = key.sign(digester.finalize(),
                        ec.ECDSA(utils.Prehashed(theHash), deterministic_signing=True))
        digester = hashes.Hash(theHash)
        digester.update(sig)
        result = base64.urlsafe_b64encode(digester.finalize()[:32])
        #logging.debug(f"start: {entropy}; sig: {sig}; return {result}")
        return result


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
    def load_der_key(cls, key, secret=None):
        '''
        load DER encoded key, returns KeyPair
        '''
        pk = serialization.load_der_private_key(key, 
                password=None,
                backend=default_backend())
        return KeyPair(pk, pk.public_key())

    @classmethod
    def load_mldsa_key(cls, alg, seed):
        from oqs.oqs import Signature
        ml_key: Signature = Signature(alg, seed)
        pubkey: bytes = ml_key.generate_keypair_seed()
        return KeyPair(ml_key, pubkey)

    @classmethod
    def der_enc_key(cls, pk):
        return pk.private_bytes(encoding=serialization.Encoding.DER,
                                format=serialization.PrivateFormat.PKCS8,
                                encryption_algorithm=serialization.NoEncryption())

    @classmethod
    def get_alg_id_from_pubkey_and_hash(cls, publicKey, alg, eckx=False):
        if isinstance(publicKey, rsa.RSAPublicKey):
            return {
                hashes.SHA1: -65535,
                hashes.SHA256: -257,
                hashes.SHA384: -258,
                hashes.SHA512: -259,
            }.get(alg, 0)
        elif isinstance(publicKey, ec.EllipticCurvePublicKey):
            if isinstance(alg, hashes.SHA256):
                return -7 if eckx == False else -25
            if isinstance(alg, hashes.SHA384):
                return -35
            elif isinstance(alg, hashes.SHA512):
                return -36 if eckx == False else -26
        elif isinstance(publicKey, ed25519.Ed25519PublicKey):
            return -8
        elif isinstance(publicKey, bytes): #TODO guessing poorly supported PQC
            #Guess the type based on the length?
            #print(f"bytes[{len(publicKey)}]: {publicKey}")
            return {
                1312: -48, # Draft ML-DSA-44 with SHA256?
                1952: -49, # Draft ML-DSA-65 with SHA256?
                2592: -50 # Draft ML-DSA-87 with SHA256?
            }.get(len(publicKey), 9001)
        return 0

    @classmethod
    def get_cose_key(cls, publicKey, alg, eckx=False):
        '''
        COSE key representation of the public key
        :param publicKey: public key interface
        :param alg: hashing algorithm used
        :param eckx: True if key is used for Elliptic Curve Key Exchange (modifies key type|kty)
        :return:
        '''
        if isinstance(publicKey, rsa.RSAPublicKey):
            return {1: 3,
                    3: cls.get_alg_id_from_pubkey_and_hash(publicKey, alg),
                   -1: cls._long_to_bytes(publicKey.public_numbers().n),
                   -2: cls._long_to_bytes(publicKey.public_numbers().e)
                 }
        elif isinstance(publicKey, ec.EllipticCurvePublicKey):
            return {1: 2,
                    3: cls.get_alg_id_from_pubkey_and_hash(publicKey, alg, eckx),
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
        elif isinstance(publicKey, bytes): #guess poorly supported PQC pubkey
            return {1: 7,
                    3: cls.get_alg_id_from_pubkey_and_hash(publicKey, alg),
                   -1: publicKey,
            }
        else:
            raise Exception("Unsupported public key algorithm")

    @classmethod
    def generate_passkey(cls):
        '''
        Generate the data required for a passkey capable of
        packed attestation with a claimed aaguid.

        '''       
        # Generate key pair
        kp = KeyPair.generate_ecdsa()
        
        # Generate certificate
        subj = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, u'Pirate Passkey'),
            x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, u'EyeBeeKey')
        ])
        pem = CertUtils.gen_ca_cert(subject=subj, lifetime=9999, keyPair=kp)
        
        # Create passkey data
        passkey_data = {
            'x5c': pem,
            'key': kp.get_private(),
            #seed === sha256 of rp.id signed by key
        }
        return passkey_data

    @classmethod
    def update_passkey(cls, resCred, pinHash, passkeyFilename):
        '''
        Add a resident cred to a .passkey file
        '''
        passkey = cls._load_passkey(pinHash, passkeyFilename)
        res_creds = [ *passkey.get('res.creds', []), resCred]
        cls._save_passkey(
            passkey['key'],
            passkey['x5c'],
            res_creds,
            passkey['pin.hash'],
            passkeyFilename
        )

    '''
    Passkey File:
        key: EC key
        x5c: X509 certificate issued to key
        res.creds: list of resident credentials (dictionary of "rp.id", "user.id", "cred.id")
        pin.hash: SHA256 of user provided secret, only the lower half (16 bytes) of this value
                  is provided during pin auth protocol 1

        File: Header | Body
        Header: enc.upper.hash: bytes(230)
        Body: pkcs12.len: bytes(4) | pkcs12.file: bytes(pcks12.len) | enc.res.creds: bytes(remaining)

    Write file process:
        upper.hash: bytes 16-32 of the full 32-byte hash of pin (pin.hash)
        enc.upper.hash: ec_encrypt upper.hash with ${FIDO_HOME}/platform.key
        header: enc.upper.hash
        pkcs12.bytes: use pin.hash as secret to generate encrypted pkcs12 bytes of key + x5c
        pkcs12.bytes.len: len(pcks12.bytes)
        enc.res.creds : encrypt cbor.encode(res_creds) with key
        body: concatenate pcks12.bytes.len | pkcs12.bytes | enc.res.creds
        file: concatenate header | body
        write file to disk

    Read file process:
        collect pin (lower pin hash for pin auth protocol, ect,)
        read file, split header from body
        upper.hash: ec_decrypt enc.upper.hash with ${FIDO_HOME}/platform.key
        pin.hash: concatenate lower.hash | upper.hash
        read pkcs12.bytes.len
        read pkcs12.bytes 
        key | x5c: use pin hash to decrypt pcks12 file
        enc.res.creds: read remaining
        cbor.res.creds: decrypt enc.res.creds with key
        res.creds: cbor.decode(cbor.res.creds)

    '''

    @classmethod
    def __read_passkey(cls, passkeyFilename):
        if not passkeyFilename.endswith('.passkey'):
            passkeyFilename += '.passkey'
        passkey_path = os.path.join(os.environ.get('FIDO_HOME', os.path.expanduser('~/.fido')), passkeyFilename)
        with open(passkey_path, 'rb') as f:
            # Read the entire file
            file_content = f.read()
            
            # Split header from body
            # Header is the encrypted upper hash (32 bytes)
            header = file_content[:230]
            body = file_content[230:]
        return header, body

    @classmethod
    def __get_upper_hash(cls, ciphertext, secret):
        # Get platform key to decrypt the header
        platform_key_path = os.environ.get('FIDO_HOME', os.path.expanduser('~/.fido')) + '/platform.key'
        with open(platform_key_path, 'rb') as key_file:
            platform_key_pem = key_file.read()
            platform_key = serialization.load_pem_private_key(
                platform_key_pem,
                password=secret,
                backend=default_backend()
            ) 
        # Decrypt the upper hash using the platform key
        return cls.ec_decrypt(ciphertext, platform_key)

    @classmethod
    def _load_passkey(cls, pinHash, passkeyFilename, secret=None):
        """
        Read passkey file according to the process described in the comments.
        
        Args:
            pinHash: SHA256 hash of the user's PIN (lower half for pin auth protocol)
            passkeyFilename: Path to the passkey file
            secret [optional]: Secret used to open platform key.
            
        Returns:
            Dictionary containing key, x5c, and res.creds
        """
        # We expect pinHash to be the lower half (16 bytes) used for pin auth protocol
        header, body = cls.__read_passkey(passkeyFilename)
        passkey = {}
        pin_hash = pinHash
        if len(pinHash) == 16:
            # Reconstruct the full pin hash
            pin_hash = pinHash + cls.__get_upper_hash(header, secret) 

        # Read PKCS12
        pkcs12_len = int.from_bytes(body[:4], 'little')
        pkcs12_bytes = body[4:4+pkcs12_len]
        key, certificate = cls.load_key_and_cert(pkcs12_bytes,
                                                      base64.b64encode(pin_hash))

        res_creds = []
        if len(body) > (pkcs12_len + 4):
            cbor_res_creds = cls.ec_decrypt(body[4+pkcs12_len:], key.get_private())
            res_creds = cbor.loads(cbor_res_creds)
            if not isinstance(res_creds, list):
                raise ValueError('res_creds is not a list')
            elif len(res_creds) > 0 and not isinstance(res_creds[0], dict):
                raise ValueError('res_creds is not a list of credentials')
        else: 
            raise ValueError("No resident credentials found")
        # Construct the passkey dictionary
        passkey = {
            'key': key.get_private(),
            'x5c': certificate,
            'res.creds': res_creds,
            'pin.hash': pin_hash  # Store the full pin hash for future use
        }
        
        return passkey

    @classmethod
    def _save_passkey(cls, key, x5c, resCreds, pinHash, passkeyFilename, secret=None):
        """
        Write passkey file according to the process described in the comments.
        
        Args:
            key: EC Private Key
            x5c: X509 Certificate (CA)
            resCreds: list of resident credentials ({rp.id:<>,user.id:<>,cred.id:<>})
            pinHash: SHA256 hash of the user's PIN
            passkeyFilename: Path to the passkey file
        """
        # Cache upper hash for loading during pin auth protocol
        if len(pinHash) != 32:
            raise ValueError("pinHash must be 32 bytes long")
        #TODO else if upper hash does not match current file, sync error
        upper_hash = pinHash[16:]
        platform_key = cls.__get_platform_kp(secret).get_private()
        header = cls.ec_encrypt(upper_hash, platform_key)
        pkcs12_bytes = cls.create_pcks12_bytes(
            key,
            x5c,
            b"Pirate Passkey Secret Stash",
            base64.b64encode(pinHash),  # Use full pin hash as secret
        )
        
        # Get PKCS12 bytes length
        pkcs12_len = len(pkcs12_bytes)
        pkcs12_len_bytes = pkcs12_len.to_bytes(4, 'little')
        # Encrypt resident credentials with key
        cbor_res_creds = cbor.dumps(resCreds)
        enc_res_creds = cls.ec_encrypt(cbor_res_creds, key)

        # Write file
        body = pkcs12_len_bytes + pkcs12_bytes + enc_res_creds

        if not passkeyFilename.endswith('.passkey'):
            passkeyFilename += '.passkey'
        passkey_path = os.path.join(os.environ.get('FIDO_HOME', os.path.expanduser('~/.fido')), passkeyFilename)
        with open(passkey_path, 'wb') as f:
            f.write(header + body)
            f.close()

    @classmethod
    def __get_platform_kp(cls, secret=None, filename='platform.key'):
        # Get platform key to manage cached pin hashes
        platform_key_path = os.path.join(os.environ.get('FIDO_HOME', os.path.expanduser('~/.fido')), filename)
        with open(platform_key_path, 'rb') as key_file:
            platform_key_pem = key_file.read()
            return KeyPair.load_key_pair(platform_key_pem, secret)

    @classmethod
    def create_platform_key(cls, secret=None, filename='platform.key'):
        plat_key = KeyPair.generate_ecdsa()
        platform_key_path = os.path.join(os.environ.get('FIDO_HOME', os.path.expanduser('~/.fido')), filename)
        with open(platform_key_path, 'wb') as key_file:
            key_file.write(plat_key.get_private_bytes(secret=secret))
        return KeyPair(plat_key, plat_key.get_public())

    @classmethod
    def get_pin_hash(cls, pin, alg=hashes.SHA256()):
        digest = hashes.Hash(alg)
        if not isinstance(pin, bytes):
             pin = pin.encode()
        digest.update(pin)
        return digest.finalize()


    @classmethod
    def create_pcks12_bytes(cls, key, cert, name, secret):
        """
        return pcks12 file bytes for given key, certificate with provided secret.

        Args:
            key: The private key to be serialized.
            cert: The certificate to be serialized.
            name: The name (alias) of the certificate.
            secret: The secret to be used for encryption.

        Returns: The bytes of the serialized pcks12 file.
        """
        return pkcs12.serialize_key_and_certificates(
                name, key, cert, None, serialization.BestAvailableEncryption(secret))


    @classmethod
    def load_key_and_cert(cls, source, password=None):
        """
        Load a private key and X.509 certificate from a file or bytes.
        
        Args:
            source: bytes containing the key and certificate.
            password: Optional password for encrypted keys

        Returns:
            Tuple(KeyPair, x509.Certificate): The loaded key pair and certificate
        """
        
        # Load as PKCS12 first, no additional certs
        private_key, certificate, additional = pkcs12.load_key_and_certificates(source, password)
        if not private_key:
            raise ValueError("Failed to load PKCS12 key")
        if not certificate:
            raise ValueError("Failed to load PKCS12 certificate")
        key_pair = KeyPair(private_key, private_key.public_key())
        return key_pair, certificate
            

    @classmethod
    def ec_encrypt(cls, plaintext, key):
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError("Key must be an EllipticCurvePrivateKey")
        iv = secrets.token_bytes(16)
        anon_kp = KeyPair.generate_ecdsa()
        shared_raw = anon_kp.get_private().exchange(ec.ECDH(), key.public_key())
        
        # Hash the shared secret with SHA-256 to match Java's implementation
        digest = hashes.Hash(hashes.SHA256())
        digest.update(shared_raw)
        shared = digest.finalize()
        
        encryptor = Cipher(algorithms.AES256(shared),
                                                  modes.GCM(iv)).encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        anon_pub = anon_kp.get_public_bytes()
        annon_pub_bytes = len(anon_pub).to_bytes(4, 'big') + anon_pub
        return annon_pub_bytes + iv + encryptor.tag + ciphertext
    
    @classmethod
    def ec_decrypt(cls, encrypted, key):
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError("Key must be an EllipticCurvePrivateKey")
        pub_bytes_len = int.from_bytes(encrypted[:4], 'big')
        pub_bytes = encrypted[4:pub_bytes_len + 4]
        pubkey = serialization.load_pem_public_key(pub_bytes)
        if not isinstance(pubkey, ec.EllipticCurvePublicKey):
            raise ValueError("Public key must be an EllipticCurvePublicKey")
        ciphertext = encrypted[pub_bytes_len + 4:]
        iv = ciphertext[:16]
        tag = ciphertext[16:32]
        shared_raw = key.exchange(ec.ECDH(), pubkey)
        
        # Hash the shared secret with SHA-256 to match Java's implementation
        digest = hashes.Hash(hashes.SHA256())
        digest.update(shared_raw)
        shared = digest.finalize()
        
        decryptor = Cipher(algorithms.AES256(shared),
                                     modes.GCM(iv, tag=tag)).decryptor()
        return decryptor.update(ciphertext[32:]) + decryptor.finalize()


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
    def generate_mldsa(cls, alg="ML-DSA-44", seed=None):
        from oqs.oqs import Signature
        privateKey: Signature = Signature(alg, secret_key=seed)
        publicKey: bytes = privateKey.generate_keypair()
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

    def get_private_bytes(self, secret=None):
        return self.private.private_bytes(encoding=serialization.Encoding.PEM,
                                          format=serialization.PrivateFormat.PKCS8,
                                          encryption_algorithm=serialization.BestAvailableEncryption(secret) if secret 
                                                                else serialization.NoEncryption())
