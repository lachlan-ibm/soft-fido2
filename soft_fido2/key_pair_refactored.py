"""
Key pair management utilities for FIDO2 authenticator.

This module provides classes for managing cryptographic key pairs and related operations
for FIDO2 authenticator implementations.
"""

import secrets
import struct
from typing import Any, Dict, List, Optional, Union, Type, cast

import cbor2 as cbor
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import Certificate

# Type aliases for better readability
PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey]
PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey]
HashAlgorithm = Type[hashes.HashAlgorithm]


class KeyUtils:
    """Utility class for cryptographic key operations."""

    # Constants for COSE key types
    COSE_KTY_RSA = 3
    COSE_KTY_EC2 = 2
    COSE_KTY_OKP = 6
    
    # Constants for COSE algorithm identifiers https://www.iana.org/assignments/cose/cose.xhtml
    COSE_ID_MAP = {
        # RSA algorithms
        "RSA_SHA1": -65535,
        "RSA_SHA256": -257,
        "RSA_SHA384": -258,
        "RSA_SHA512": -259,
        # ECDSA algorithms
        "ECDSA_SHA256": -7,
        "ECDSA_SHA384": -35,
        "ECDSA_SHA512": -36,
        # ECDH algorithms
        "ECDH_SHA256": -25,
        "ECDH_SHA512": -26,
        # EdDSA algorithms
        "EDDSA": -8,
        # Elliptic Curve Id's
        "SECP256R1": 1,
        "SECP384R1": 2,
        "SECP521R1": 3,
        "ED25519": 6,
    }

    @classmethod
    def long_to_bytes(cls, value: int) -> bytes:
        """
        Convert a long integer to bytes.
        
        Args:
            value: The integer value to convert
            
        Returns:
            The byte representation of the integer
        """
        limit = 256**4 - 1  # max value we can fit into a struct.pack
        parts = []
        while value:
            parts.append(value & limit)
            value >>= 32
        parts = parts[::-1]
        return struct.pack(">" + 'L' * len(parts), *parts) if parts else b'\x00'

    @classmethod
    def bytes_to_long(cls, data: bytes) -> int:
        """
        Convert bytes to a long integer.
        
        Args:
            data: The bytes to convert
            
        Returns:
            The integer representation of the bytes
        """
        if not data:
            return 0
            
        length = int(len(data) / 4)
        parts = struct.unpack(">" + 'L' * length, data)[::-1]
        result = 0
        for i, part in enumerate(parts):
            result += part << (32 * i)
        return result

    @classmethod
    def load_ec_key(cls, key: Dict[str, Any]) -> 'KeyPair':
        """
        Load an elliptic curve key from a dictionary representation.
        
        Args:
            key: Dictionary containing key parameters
            
        Returns:
            A KeyPair instance
            
        Raises:
            ValueError: If the key is missing required parameters
        """
        if 'c' not in key:
            raise ValueError("Key missing curve name")
        if 'pv' not in key:
            raise ValueError("Key missing scalar value")
            
        curve_map = {
            ec.SECP256R1.name: ec.SECP256R1,
            ec.SECP521R1.name: ec.SECP521R1
        }
        
        if key['c'] not in curve_map:
            raise ValueError(f"Unsupported curve: {key['c']}")
            
        curve = curve_map[key['c']]()
        # Ensure pv is an integer
        private_value = key.get('pv')
        if private_value is None:
            raise ValueError("Key missing private value")
            
        private_key = ec.derive_private_key(int(private_value), curve, default_backend())
        return KeyPair(private_key, private_key.public_key())

    @classmethod
    def cbor_ec_key(cls, private_key: ec.EllipticCurvePrivateKey) -> bytes:
        """
        Serialize an elliptic curve private key to CBOR format.
        
        Args:
            private_key: The EC private key to serialize
            
        Returns:
            CBOR encoded key data
            
        Raises:
            ValueError: If the key is not an EllipticCurvePrivateKey
        """
        if private_key is None or not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise ValueError(f"{private_key} not EllipticCurvePrivateKey")
            
        return cbor.dumps({
            'pv': private_key.private_numbers().private_value,
            'c': private_key.curve.name
        })

    @classmethod
    def get_alg_id_from_pubkey_and_hash(
        cls, 
        public_key: PublicKey, 
        hash_alg: HashAlgorithm, 
        ecdh: bool = False
    ) -> int:
        """
        Get the COSE algorithm identifier for a public key and hash algorithm.
        
        Args:
            public_key: The public key
            hash_alg: The hash algorithm
            ecdh: Whether to use ECDH mode
            
        Returns:
            The COSE algorithm identifier
        """
        if isinstance(public_key, rsa.RSAPublicKey):
            if hash_alg.name is None:
                raise ValueError("Hashing algorithm is missing the name property")
            alg_name = str(hash_alg.name)  # Convert property to string
            return cls.COSE_ID_MAP.get("RSA_" + alg_name.upper(), 0)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            if isinstance(hash_alg, hashes.SHA256):
                return cls.COSE_ID_MAP["ECDH_SHA256"] if ecdh else cls.COSE_ID_MAP["ECDSA_SHA256"]
            elif isinstance(hash_alg, hashes.SHA384):
                return cls.COSE_ID_MAP["ECDSA_SHA384"]
            elif isinstance(hash_alg, hashes.SHA512):
                return cls.COSE_ID_MAP["ECDH_SHA512"] if ecdh else cls.COSE_ID_MAP["ECDSA_SHA512"]
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            return cls.COSE_ID_MAP["EDDSA"]
        return 0

    @classmethod
    def get_cose_key(
        cls, 
        public_key: PublicKey, 
        hash_alg: HashAlgorithm, 
        ecdh: bool = False
    ) -> Dict[int, Any]:
        """
        Create a COSE key representation of a public key.
        
        Args:
            public_key: The public key
            hash_alg: The hash algorithm
            ecdh: Whether to use ECDH mode
            
        Returns:
            A COSE key representation as a dictionary
            
        Raises:
            ValueError: If the public key type is not supported
        """
        if isinstance(public_key, rsa.RSAPublicKey):
            return {
                1: cls.COSE_KTY_RSA,
                3: cls.get_alg_id_from_pubkey_and_hash(public_key, hash_alg),
                -1: cls.long_to_bytes(public_key.public_numbers().n),
                -2: cls.long_to_bytes(public_key.public_numbers().e)
            }
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            return {
                1: cls.COSE_KTY_EC2,
                3: cls.get_alg_id_from_pubkey_and_hash(public_key, hash_alg, ecdh),
                -1: cls.COSE_ID_MAP[public_key.curve.name.upper()],
                -2: cls.long_to_bytes(public_key.public_numbers().x),
                -3: cls.long_to_bytes(public_key.public_numbers().y)
            }
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            return {
                1: cls.COSE_KTY_OKP,
                3: cls.get_alg_id_from_pubkey_and_hash(public_key, hash_alg),
                -1: cls.COSE_ID_MAP["ED25519"],
                -2: public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            }
        else:
            raise ValueError("Unsupported public key algorithm")

    @classmethod
    def update_passkey(cls, res_cred: Dict[str, Any], pin_hash: bytes, passkey_filename: str) -> None:
        """
        Add a resident credential to a .passkey file.
        
        Args:
            res_cred: The resident credential to add
            pin_hash: The PIN hash for encryption
            passkey_filename: The filename of the passkey file
        """
        passkey = cls._load_passkey(pin_hash, passkey_filename)
        passkey['res_creds'] = [*passkey.get('res_creds', []), res_cred]
        cls._save_passkey(passkey, pin_hash, passkey_filename)

    @classmethod
    def _load_passkey(cls, pin_hash: bytes, passkey_filename: str) -> Dict[str, Any]:
        """
        Load and decrypt a passkey file.
        
        Args:
            pin_hash: The PIN hash for decryption
            passkey_filename: The filename of the passkey file
            
        Returns:
            The decrypted passkey data
        """
        passkey = {}
        with open(passkey_filename, 'rb') as f:
            data = f.read()
            iv = data[:16]
            tag = data[16:32]
            enc_passkey = data[32:]
            
            aes_key = algorithms.AES128(pin_hash)
            decryptor = Cipher(aes_key, modes.GCM(iv, tag), backend=default_backend()).decryptor()
            cbor_key_and_pem = decryptor.update(enc_passkey) + decryptor.finalize()
            passkey = cbor.loads(cbor_key_and_pem)
            
        return passkey

    @classmethod
    def _save_passkey(cls, passkey: Dict[str, Any], pin_hash: bytes, passkey_filename: str) -> None:
        """
        Encrypt and save a passkey file.
        
        Args:
            passkey: The passkey data to save
            pin_hash: The PIN hash for encryption
            passkey_filename: The filename of the passkey file
        """
        iv = secrets.token_bytes(16)
        aes_key = algorithms.AES128(pin_hash)
        encryptor = Cipher(aes_key, modes.GCM(iv), backend=default_backend()).encryptor()
        
        cbor_passkey = cbor.dumps(passkey)
        encrypted_data = encryptor.update(cbor_passkey) + encryptor.finalize()
        
        with open(passkey_filename, 'wb') as f:
            f.write(iv + encryptor.tag + encrypted_data)


class KeyPair:
    """
    Class representing a cryptographic key pair.
    
    This class provides methods for generating, loading, and using cryptographic key pairs
    for various algorithms including RSA, ECDSA, and Ed25519.
    """

    def __init__(self, private_key: PrivateKey, public_key: PublicKey):
        """
        Initialize a KeyPair with private and public keys.
        
        Args:
            private_key: The private key
            public_key: The public key
        """
        self.private = private_key
        self.public = public_key

    @classmethod
    def generate_rsa(
        cls, 
        public_exponent: int = 65537, 
        key_size: int = 2048, 
        backend: Any = None
    ) -> 'KeyPair':
        """
        Generate an RSA key pair.
        
        Args:
            public_exponent: The public exponent (default: 65537)
            key_size: The key size in bits (default: 2048)
            backend: The cryptography backend (default: default_backend())
            
        Returns:
            A KeyPair instance with the generated keys
        """
        if backend is None:
            backend = default_backend()
            
        private_key = rsa.generate_private_key(
            public_exponent=public_exponent,
            key_size=key_size,
            backend=backend
        )
        public_key = private_key.public_key()
        return cls(private_key, public_key)

    @classmethod
    def generate_ecdsa(
        cls,
        curve: ec.EllipticCurve = ec.SECP256R1(),
        backend: Any = None
    ) -> 'KeyPair':
        """
        Generate an ECDSA key pair.
        
        Args:
            curve: The elliptic curve to use (default: SECP256R1)
            backend: The cryptography backend (default: default_backend())
            
        Returns:
            A KeyPair instance with the generated keys
        """
            
        if backend is None:
            backend = default_backend()
            
        private_key = ec.generate_private_key(curve, backend)
        public_key = private_key.public_key()
        return cls(private_key, public_key)

    @classmethod
    def generate_ed25519(cls) -> 'KeyPair':
        """
        Generate an Ed25519 key pair.
        
        Returns:
            A KeyPair instance with the generated keys
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return cls(private_key, public_key)

    @classmethod
    def load_key_pair(cls, pk_data: bytes, password: Optional[bytes] = None) -> 'KeyPair':
        """
        Load a key pair from PEM-encoded private key data.
        
        Args:
            pk_data: The PEM-encoded private key data
            password: Optional password for encrypted keys
            
        Returns:
            A KeyPair instance with the loaded keys
            
        Raises:
            ValueError: If the private key is not of a supported type
        """
        private_key = serialization.load_pem_private_key(
            pk_data,
            password=password,
            backend=default_backend()
        )
        
        # Validate the private key type
        if not isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey)):
            raise ValueError(f"Unsupported private key type: {type(private_key)}")
            
        public_key = private_key.public_key()
        
        # Validate the public key type
        if not isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey)):
            raise ValueError(f"Unsupported public key type: {type(public_key)}")
            
        return cls(cast(PrivateKey, private_key), cast(PublicKey, public_key))

    @classmethod
    def create_pcks12_bag(
        cls,
        key: PrivateKey,
        cert: Certificate,
        name: bytes,
        secret: bytes,
        cas: Optional[List[Certificate]] = None
    ) -> bytes:
        """
        Create a PKCS#12 container.
        
        Args:
            key: The private key
            cert: The certificate
            name: The friendly name
            secret: The passphrase
            cas: Optional list of CA certificates
            
        Returns:
            The serialized PKCS#12 data
        """
        return pkcs12.serialize_key_and_certificates(
            name,
            key,
            cert,
            cas,
            serialization.BestAvailableEncryption(secret)
        )

    @classmethod
    def load_pcks12_bag(cls, data: bytes, secret: bytes) -> pkcs12.PKCS12KeyAndCertificates:
        """
        Load a PKCS#12 container.
        
        Args:
            data: The PKCS#12 data
            secret: The passphrase
            
        Returns:
            A PKCS12KeyAndCertificates object containing the private key, certificate, and additional certificates
        """
        return pkcs12.load_pkcs12(data, secret)

    def get_public(self) -> PublicKey:
        """
        Get the public key.
        
        Returns:
            The public key
        """
        return self.public

    def get_private(self) -> PrivateKey:
        """
        Get the private key.
        
        Returns:
            The private key
        """
        return self.private

    def get_public_bytes(self) -> bytes:
        """
        Get the PEM-encoded public key.
        
        Returns:
            The PEM-encoded public key
        """
        return self.public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def get_private_bytes(self) -> bytes:
        """
        Get the PEM-encoded private key.
        
        Returns:
            The PEM-encoded private key
        """
        return self.private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

# Made with Bob
