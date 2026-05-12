# Copyrite IBM 2022, 2025
# IBM Confidential

import struct
import os
import cbor2 as cbor
import secrets
import base64
import json
import logging

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, mldsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from soft_fido2.cert_utils import CertUtils



class KeyUtils(object):

    # Default KDF info for credential derivation
    DEFAULT_CREDENTIAL_INFO = "CTAP2-CRED-INFO-v1"

    # Key type configuration for credential ID generation
    # Maps private key types to their COSE algorithm IDs and key extraction methods
    _KEY_TYPE_CONFIG = {
        ec.EllipticCurvePrivateKey: {
            'alg_id': -7,  # ES256 (ECDSA with SHA-256)
            'extract_key': lambda pk: pk.private_numbers().private_value.to_bytes(
                pk.curve.key_size // 8, byteorder='big'
            )
        },
        mldsa.MLDSA44PrivateKey: {
            'alg_id': -48,  # ML-DSA-44
            'extract_key': lambda pk: pk.private_bytes_raw()
        },
        mldsa.MLDSA65PrivateKey: {
            'alg_id': -49,  # ML-DSA-65
            'extract_key': lambda pk: pk.private_bytes_raw()
        },
        mldsa.MLDSA87PrivateKey: {
            'alg_id': -50,  # ML-DSA-87
            'extract_key': lambda pk: pk.private_bytes_raw()
        }
    }

    @classmethod
    def get_passkey_seed(cls, entropy, key):
        """
        Generate a 32 byte seed using HKDF from entropy and a private key.
        
        Entropy is typically the bytes of the rp.id. Key is an Elliptic Curve key.
        
        Uses HKDF with:
        - Salt: entropy (rp.id bytes) for domain separation
        - IKM: private key bytes
        - Info: application context string
        
        Returned bytestring is b64_url encoded.
        """
        if not isinstance(entropy, bytes):
            raise ValueError(f"Entropy must be bytes: {entropy}")
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError(f"Key must be an EllipticCurvePrivateKey: {key}")
        
        # Extract private key bytes as Input Key Material
        key_material = key.private_bytes(encoding=serialization.Encoding.DER, 
                    format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=entropy,
                        info=b"FIDO2-PASSKEY-SEED", backend=default_backend())
        seed_bytes = hkdf.derive(key_material)
        return base64.urlsafe_b64encode(seed_bytes)

    @classmethod
    def _get_key_config(cls, private_key):
        """Get configuration for a given private key type.
        
        Args:
            private_key: Private key object
            
        Returns:
            dict: Configuration with 'alg_id' and 'extract_key' function
            
        Raises:
            ValueError: If key type is unsupported
        """
        if private_key is None:
            raise ValueError("Private key cannot be None")
        
        for key_type, config in cls._KEY_TYPE_CONFIG.items():
            if isinstance(private_key, key_type):
                return config
        
        supported_types = ', '.join(kt.__name__ for kt in cls._KEY_TYPE_CONFIG.keys())
        raise ValueError(
            f"Unsupported key type: {type(private_key).__name__}. "
            f"Supported types: {supported_types}"
        )

    @classmethod
    def _extract_key_material(cls, private_key):
        """Extract raw key material from private key.
        
        Args:
            private_key: Private key object
            
        Returns:
            bytes: Raw key material
            
        Raises:
            ValueError: If key type is unsupported
        """
        config = cls._get_key_config(private_key)
        return config['extract_key'](private_key)

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
        """
        Load ML-DSA keypair from a 32-byte seed.
        
        Args:
            alg: ML-DSA algorithm name ("ML-DSA-44", "ML-DSA-65", or "ML-DSA-87")
            seed: 32-byte seed for deterministic key generation
            
        Returns:
            KeyPair with ML-DSA private key and public key
            
        Raises:
            ValueError: If algorithm is unsupported or seed is not 32 bytes
        """
        from cryptography.hazmat.primitives.asymmetric.mldsa import (
            MLDSA44PrivateKey,
            MLDSA65PrivateKey,
            MLDSA87PrivateKey
        )
        
        # Map algorithm name to cryptography class
        alg_map = {
            "ML-DSA-44": MLDSA44PrivateKey,
            "ML-DSA-65": MLDSA65PrivateKey,
            "ML-DSA-87": MLDSA87PrivateKey,
        }
        
        key_class = alg_map.get(alg)
        if key_class is None:
            raise ValueError(f"Unsupported ML-DSA algorithm: {alg}")

        private_key = key_class.from_seed_bytes(seed)
        public_key = private_key.public_key()
        
        return KeyPair(private_key, public_key)

    @classmethod
    def der_enc_key(cls, pk):
        return pk.private_bytes(encoding=serialization.Encoding.DER,
                                format=serialization.PrivateFormat.PKCS8,
                                encryption_algorithm=serialization.NoEncryption())

    @classmethod
    def get_alg_id_from_pubkey_and_hash(cls, publicKey, alg, eckx=False, pss=False):
        if isinstance(publicKey, rsa.RSAPublicKey):
            algName = alg.name if alg and hasattr(alg, 'name') else 'unknown'
            if pss:
                return {
                    'sha256': -37,
                    'sha384': -38,
                    'sha512': -39,
                }.get(alg, 0)
            return {
                'sha1': -65535,
                'sha256': -257,
                'sha384': -258,
                'sha512': -259,
            }.get(algName, 0)
        elif isinstance(publicKey, ec.EllipticCurvePublicKey):
            if isinstance(alg, hashes.SHA256):
                return -7 if eckx == False else -25
            if isinstance(alg, hashes.SHA384):
                return -35
            elif isinstance(alg, hashes.SHA512):
                return -36 if eckx == False else -26
        elif isinstance(publicKey, ed25519.Ed25519PublicKey):
            return -8
        elif isinstance(publicKey, mldsa.MLDSA44PublicKey):
            return -48  # ML-DSA-44
        elif isinstance(publicKey, mldsa.MLDSA65PublicKey):
            return -49  # ML-DSA-65
        elif isinstance(publicKey, mldsa.MLDSA87PublicKey):
            return -50  # ML-DSA-87
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
        elif isinstance(publicKey, (mldsa.MLDSA44PublicKey, mldsa.MLDSA65PublicKey, mldsa.MLDSA87PublicKey)):
            # ML-DSA public keys - COSE key type 7 (experimental/draft)
            return {1: 7,
                    3: cls.get_alg_id_from_pubkey_and_hash(publicKey, alg),
                   -1: publicKey.public_bytes(encoding=serialization.Encoding.Raw,
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
    def __get_upper_hash(cls, ciphertext, secret=None):
        # Get platform key via message queue to decrypt the header
        platform_key = cls.__request_platform_kp().get_private()
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
            secret: Secret for platform key (optional)
        """
        # Cache upper hash for loading during pin auth protocol
        if len(pinHash) != 32:
            raise ValueError("pinHash must be 32 bytes long")
        #TODO else if upper hash does not match current file, sync error
        upper_hash = pinHash[16:]
        
        platform_key = cls.__request_platform_kp().get_private()

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
    def __request_platform_kp(cls, timeout: float = 0.5):
        """Request platform key from systray_app via message queue"""
        import uuid
        import time
        try:
            from soft_fido2.message_queues import (
                MessageQueue, PlatformKeyRequest, PlatformKeyResponse
            )
        except:
            from message_queues import (
                MessageQueue, PlatformKeyRequest, PlatformKeyResponse
            )
        
        request_id = str(uuid.uuid4())
        request = PlatformKeyRequest(request_id)
        
        MessageQueue.platform_key_requests.put(request)
        
        # Wait for response
        start_time = time.time()
        while time.time() - start_time < timeout:
            if MessageQueue.platform_key_responses.qsize() > 0:
                response = MessageQueue.platform_key_responses.get()
                if response.request_id == request_id:
                    if response.error:
                        raise Exception(f"Platform key error: {response.error}")
                    return response.key_pair
            time.sleep(0.01)
        
        raise TimeoutError("Platform key request timed out")

    @classmethod
    def _get_platform_kp(cls, secret=None, filename='platform.key'):
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
            raise ValueError(f"{key} must be an EllipticCurvePrivateKey")
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
            raise ValueError(f"{key} must be an EllipticCurvePrivateKey")
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

    @classmethod
    def _get_platform_info_path(cls) -> str:
        """
        Get full path to platform.info file.
        Uses FIDO_HOME environment variable.
        If FIDO_HOME is not set, raise a RuntimeError.
        """
        fido_home = os.environ.get('FIDO_HOME')
        if fido_home is None:
            raise RuntimeError("FIDO_HOME environment variable is not set")
        return os.path.join(fido_home, "platform.info")

    @classmethod
    def get_credential_kdf_info(cls) -> bytes:
        """
        Load and decrypt KDF info from platform.info file.
        
        Returns:
            bytes: The KDF info value (UTF-8 encoded)
            
        Process:
            1. Check if platform.info exists
            2. If missing, return default value
            3. Read file (base64 string)
            4. Base64 decode → encrypted blob
            5. Get platform key via _get_platform_kp()
            6. Decrypt using ec_decrypt()
            7. CBOR decode to get {"info": bytes}
            8. Return the "info" value
            
        Error handling:
            - FileNotFoundError: return default
            - Decryption error: log warning, return default
            - CBOR decode error: log warning, return default
        """
        try:
            info_path = cls._get_platform_info_path()
            
            # Return default if file doesn't exist
            if not os.path.exists(info_path):
                return cls.DEFAULT_CREDENTIAL_INFO.encode('utf-8')
            
            # Read base64-encoded encrypted file
            with open(info_path, 'r') as f:
                b64_encrypted = f.read().strip()
            
            # Decode base64
            encrypted_blob = base64.b64decode(b64_encrypted)
            
            # Get platform key
            platform_key = cls._get_platform_kp()
            
            # Decrypt using existing ec_decrypt method
            cbor_bytes = cls.ec_decrypt(encrypted_blob, platform_key.get_private())
            
            # CBOR decode
            config_map = cbor.loads(cbor_bytes)
            
            # Extract info value
            return config_map.get("info", cls.DEFAULT_CREDENTIAL_INFO.encode('utf-8'))
            
        except Exception as e:
            # Log warning and return default
            logging.warning(f"Failed to load KDF info from platform.info: {e}")
            return cls.DEFAULT_CREDENTIAL_INFO.encode('utf-8')

    @classmethod
    def set_credential_kdf_info(cls, value: str) -> None:
        """
        Encrypt and save KDF info to platform.info file.
        
        Args:
            value: The KDF info string to save
            
        Process:
            1. Validate value (non-empty, UTF-8 safe, length cap)
            2. Encode value as UTF-8 bytes
            3. Create CBOR map: {"info": value_bytes}
            4. CBOR encode the map
            5. Get platform key via _get_platform_kp()
            6. Encrypt using ec_encrypt()
            7. Base64 encode the encrypted blob
            8. Write to platform.info with 0o600 permissions
            
        Raises:
            ValueError: If value is invalid
            Exception: If platform key unavailable or encryption fails
        """
        # Validation rules (Phase 1.2)
        if not value or not value.strip():
            raise ValueError("credential_kdf_info cannot be empty")
        
        if len(value) > 128:
            raise ValueError("credential_kdf_info cannot exceed 128 characters")
        
        # Verify UTF-8 encoding
        try:
            value.encode('utf-8')
        except UnicodeEncodeError:
            raise ValueError("credential_kdf_info must be UTF-8 safe")
        
        # Encode value as UTF-8
        value_bytes = value.encode('utf-8')
        
        # Create CBOR map
        config_map = {"info": value_bytes}
        
        # CBOR encode
        cbor_bytes = cbor.dumps(config_map)
        
        # Get platform key
        platform_key = cls._get_platform_kp()
        
        # Encrypt using existing ec_encrypt method
        encrypted_blob = cls.ec_encrypt(cbor_bytes, platform_key.get_private())
        
        # Base64 encode
        b64_encrypted = base64.b64encode(encrypted_blob).decode('ascii')
        
        # Write to file with secure permissions
        info_path = cls._get_platform_info_path()
        
        # Write atomically using temp file
        temp_path = info_path + ".tmp"
        with open(temp_path, 'w') as f:
            f.write(b64_encrypted)
        
        # Set permissions before moving (user read/write only)
        os.chmod(temp_path, 0o600)
        
        # Atomic rename
        os.rename(temp_path, info_path)

    @classmethod
    def get_default_credential_kdf_info(cls) -> str:
        """Return the default KDF info constant."""
        return cls.DEFAULT_CREDENTIAL_INFO

    @classmethod
    def derive_credential_key_material(
        cls,
        master_secret: bytes,
        rp_id: bytes,
        credential_nonce: bytes,
        cose_alg: int,
        length: int,
        alg_suffix: bytes,
    ) -> bytes:
        """
        Derive credential key material using HKDF.
        
        Args:
            master_secret: Master secret (passkey seed)
            rp_id: Relying Party ID as bytes (used as salt)
            credential_nonce: Random nonce for this credential
            cose_alg: COSE algorithm identifier
            length: Desired output length in bytes
            alg_suffix: Algorithm-specific suffix (e.g., b"|EC" or b"|MLDSA")
            
        Returns:
            Derived key material of specified length
        """
        cose_alg_bytes = cose_alg.to_bytes(2, byteorder="big", signed=True)
        base_info = cls.get_credential_kdf_info()
        info = base_info + alg_suffix + credential_nonce + cose_alg_bytes
        return HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=rp_id,
            info=info,
            backend=default_backend(),
        ).derive(master_secret)

    @classmethod
    def derive_p256_keypair(
        cls,
        master_secret: bytes,
        rp_id: bytes,
        credential_nonce: bytes,
    ):
        """
        Derive a deterministic P-256 (ECDSA) keypair.
        
        Args:
            master_secret: Master secret (passkey seed)
            rp_id: Relying Party ID as bytes
            credential_nonce: Random nonce for this credential
            
        Returns:
            KeyPair: Deterministically derived EC P-256 keypair
        """
        material = cls.derive_credential_key_material(
            master_secret=master_secret,
            rp_id=rp_id,
            credential_nonce=credential_nonce,
            cose_alg=-7,
            length=48,
            alg_suffix=b"|EC",
        )

        order = int(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
            16,
        )
        scalar = (int.from_bytes(material, "big") % (order - 1)) + 1
        private_key = ec.derive_private_key(scalar, ec.SECP256R1(), default_backend())
        return KeyPair(private_key, private_key.public_key())

    @classmethod
    def derive_mldsa_keypair(
        cls,
        master_secret: bytes,
        rp_id: bytes,
        credential_nonce: bytes,
        alg_name: str,
        cose_alg: int,
    ):
        """
        Derive a deterministic ML-DSA keypair.
        
        Args:
            master_secret: Master secret (passkey seed)
            rp_id: Relying Party ID as bytes
            credential_nonce: Random nonce for this credential
            alg_name: ML-DSA algorithm name (e.g., "ML-DSA-44")
            cose_alg: COSE algorithm identifier
            
        Returns:
            KeyPair: Deterministically derived ML-DSA keypair
        """
        seed = cls.derive_credential_key_material(
            master_secret=master_secret,
            rp_id=rp_id,
            credential_nonce=credential_nonce,
            cose_alg=cose_alg,
            length=32,
            alg_suffix=b"|MLDSA",
        )
        return cls.load_mldsa_key(alg_name, seed)

    @classmethod
    def derive_keypair_from_context(
        cls,
        master_secret: bytes,
        rp_id: bytes,
        credential_nonce: bytes,
        cose_alg: int,
    ):
        """
        Derive a keypair based on the COSE algorithm identifier.
        
        This is a dispatch helper that routes to the appropriate
        algorithm-specific derivation method.
        
        Args:
            master_secret: Master secret (passkey seed)
            rp_id: Relying Party ID as bytes
            credential_nonce: Random nonce for this credential
            cose_alg: COSE algorithm identifier
            
        Returns:
            KeyPair: Deterministically derived keypair
            
        Raises:
            ValueError: If the COSE algorithm is not supported
        """
        if cose_alg == -7:
            return cls.derive_p256_keypair(master_secret, rp_id, credential_nonce)
        if cose_alg == -48:
            return cls.derive_mldsa_keypair(
                master_secret, rp_id, credential_nonce, "ML-DSA-44", -48
            )
        raise ValueError(f"Unsupported COSE algorithm: {cose_alg}")


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
        """
        Generate ML-DSA keypair using cryptography library v47+.
        
        Args:
            alg: ML-DSA algorithm name (default: "ML-DSA-44")
            seed: Optional 32-byte seed for deterministic generation
            
        Returns:
            KeyPair with ML-DSA private key and public key
        """
        from cryptography.hazmat.primitives.asymmetric.mldsa import (
            MLDSA44PrivateKey,
            MLDSA65PrivateKey,
            MLDSA87PrivateKey
        )
        
        alg_map = {
            "ML-DSA-44": MLDSA44PrivateKey,
            "ML-DSA-65": MLDSA65PrivateKey,
            "ML-DSA-87": MLDSA87PrivateKey,
        }
        
        key_class = alg_map.get(alg)
        if key_class is None:
            raise ValueError(f"Unsupported ML-DSA algorithm: {alg}")
        
        if seed is not None:
            # Deterministic generation from seed
            private_key = key_class.from_seed_bytes(seed)
        else:
            # Random generation
            private_key = key_class.generate()
        
        public_key = private_key.public_key()
        return cls(private_key, public_key)

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
