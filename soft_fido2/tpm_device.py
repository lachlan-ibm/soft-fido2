import logging
import os
import sys
import tempfile
from contextlib import contextmanager
from tpm2_pytss import ESAPI, TPM2B_PUBLIC, TPM2B_SENSITIVE_CREATE, ESYS_TR, TPM2B_DATA, TPML_PCR_SELECTION, TPM2_CAP, TPM2B_MAX_BUFFER
from tpm2_pytss.types import TPM2_HANDLE, TPM2B_ECC_POINT, TPM2_ALG
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key


@contextmanager
def redirect_tcti_to_logging():
    """Context manager to redirect TCTI stderr output to logging at debug level"""
    stderr_fd = sys.stderr.fileno()
    
    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp_file:
        tmp_path = tmp_file.name
    
    old_stderr = os.dup(stderr_fd)
    tmp_fd = os.open(tmp_path, os.O_RDWR | os.O_CREAT)
    os.dup2(tmp_fd, stderr_fd)
    
    try:
        yield
    finally:
        os.dup2(old_stderr, stderr_fd)
        os.close(old_stderr)
        os.close(tmp_fd)
        
        try:
            with open(tmp_path, 'r') as f:
                stderr_content = f.read().strip()
                if stderr_content:
                    for line in stderr_content.split('\n'):
                        if line.strip():
                            logging.debug(f"TCTI: {line}")
        finally:
            os.unlink(tmp_path)


class TPMDevice(object):

    FIDO2_KEY_BASE = 0x8104F1D0  # Start of FIDO2 key range
    
    # TPM Algorithm Constants
    TPM_ALG_ECC = 0x0023
    TPM_ALG_SHA256 = 0x000B
    TPM_ALG_NULL = 0x0010
    TPM_ALG_ECDSA = 0x0018
    TPM_ECC_NIST_P256 = 0x0003
    
    # Object Attributes for FIDO2 key
    FIDO2_KEY_ATTRIBUTES = 0x00020072  # fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | decrypt

    _has_tpm = None

    @classmethod
    def is_available(cls) -> bool:
        """Check if TPM device is available and accessible.
        
        Returns:
            bool: True if TPM device is available, False otherwise
        """
        if cls._has_tpm is not None:
            return cls._has_tpm
        try:
            with redirect_tcti_to_logging():
                esapi = ESAPI()
                esapi.get_capability(
                    capability=TPM2_CAP.ALGS,
                    prop=0,
                    property_count=1
                )
            logging.info("TPM device available")
            cls._has_tpm = True
            return True
        except Exception as e:
            logging.warning(f"TPM device not available: {e}")
            cls._has_tpm = True
            return False

    def is_handle_available(self, candidate):
        """Check if a persistent handle is available (not in use)
        
        Args:
            candidate: Handle value to check
            
        Returns:
            int: The candidate handle if available
            
        Raises:
            Exception: If handle is already in use
        """
        try:
            with redirect_tcti_to_logging():
                esapi = ESAPI()
                esapi.tr_from_tpmpublic(candidate)
            raise Exception(f"Handle {hex(candidate)} is already in use")
        except:
            return candidate
       

    def allocate_handle(self, base: int = FIDO2_KEY_BASE, max_search: int = 1) -> int:
        """Find and return an available handle
        
        Args:
            base: Base handle to start searching from
            max_search: Maximum number of handles to check
            
        Returns:
            int: Available handle value
            
        Raises:
            Exception: If no available handles found in range
        """
        for offset in range(max_search):
            candidate = base + offset
            try:
                if self.is_handle_available(candidate):
                    return candidate
            except:
                continue
        raise Exception(f"No available handles in range {hex(base)}")

    def _create_ec_p256_template(self):
        """Create TPM2B_PUBLIC template for EC P-256 key
        
        Returns:
            TPM2B_PUBLIC: Configured template for EC P-256 FIDO2 key
        """
        in_public = TPM2B_PUBLIC()
        in_public.publicArea.type = self.TPM_ALG_ECC
        in_public.publicArea.nameAlg = self.TPM_ALG_SHA256
        in_public.publicArea.objectAttributes = self.FIDO2_KEY_ATTRIBUTES
        
        in_public.publicArea.parameters.eccDetail.symmetric.algorithm = self.TPM_ALG_NULL
        in_public.publicArea.parameters.eccDetail.scheme.scheme = self.TPM_ALG_NULL
        in_public.publicArea.parameters.eccDetail.curveID = self.TPM_ECC_NIST_P256
        in_public.publicArea.parameters.eccDetail.kdf.scheme = self.TPM_ALG_NULL
        
        return in_public

    def create_key(self, password: bytes = b""):
        """Generate or retrieve the FIDO2 platform key at FIDO2_KEY_BASE handle
        
        Creates an EC P-256 primary key in the TPM and persists it at the
        FIDO2_KEY_BASE handle. If a key already exists at this handle,
        returns the existing key.
        
        Args:
            password: Optional password to protect the key (bytes)
        
        Returns:
            tuple: (handle, public_key) where handle is ESYS_TR and
                   public_key is TPM2B_PUBLIC
                   
        Raises:
            Exception: If key generation or persistence fails
        """
        with redirect_tcti_to_logging():
            esapi = ESAPI()
        
        try:
            return self.get_key()
        except Exception as e:
            logging.debug(f"Key not found at {hex(self.FIDO2_KEY_BASE)}, creating new key: {e}")
        
        in_public = self._create_ec_p256_template()
        
        # Set password in sensitive structure
        if password:
            from tpm2_pytss.types import TPM2B_AUTH, TPMS_SENSITIVE_CREATE
            auth = TPM2B_AUTH(password)
            in_sensitive = TPM2B_SENSITIVE_CREATE(
                TPMS_SENSITIVE_CREATE(userAuth=auth)
            )
        else:
            in_sensitive = TPM2B_SENSITIVE_CREATE()
        
        outside_info = TPM2B_DATA()
        creation_pcr = TPML_PCR_SELECTION()
        
        primary_handle, out_public, _, _, _ = esapi.create_primary(
            primary_handle=ESYS_TR.OWNER,
            in_sensitive=in_sensitive,
            in_public=in_public,
            outside_info=outside_info,
            creation_pcr=creation_pcr
        )
        
        try:
            persistent_handle = esapi.evict_control(
                auth=ESYS_TR.OWNER,
                object_handle=primary_handle,
                persistent_handle=self.FIDO2_KEY_BASE
            )
            
            esapi.flush_context(primary_handle)
            return (persistent_handle, out_public)
            
        except Exception as e:
            esapi.flush_context(primary_handle)
            raise Exception(f"Failed to persist key: {e}")

    def get_key(self):
        """Retrieve the existing FIDO2 platform key from FIDO2_KEY_BASE handle
        
        Returns:
            tuple: (persistent_handle, public_key) where persistent_handle is a TPM2_HANDLE
                   and public_key is TPM2B_PUBLIC
                    
        Raises:
            Exception: If key does not exist at FIDO2_KEY_BASE handle
        """
        with redirect_tcti_to_logging():
            esapi = ESAPI()
        
        try:
            persistent_handle = TPM2_HANDLE(self.FIDO2_KEY_BASE)
            handle = esapi.tr_from_tpmpublic(persistent_handle)
            public_key, _, _ = esapi.read_public(handle)
            
            return (persistent_handle, public_key)
            
        except Exception as e:
            raise Exception(f"Key does not exist at handle {hex(self.FIDO2_KEY_BASE)}: {e}")

    def delete_key(self):
        """Delete the FIDO2 platform key from TPM persistent storage
        
        Removes the key stored at FIDO2_KEY_BASE handle from the TPM.
        
        Raises:
            Exception: If key deletion fails or key doesn't exist
        """
        with redirect_tcti_to_logging():
            esapi = ESAPI()
        
        try:
            handle = esapi.tr_from_tpmpublic(TPM2_HANDLE(self.FIDO2_KEY_BASE))
            esapi.evict_control(
                auth=ESYS_TR.OWNER,
                object_handle=handle,
                persistent_handle=self.FIDO2_KEY_BASE
            )
            
        except Exception as e:
            raise Exception(f"Failed to delete key at handle {hex(self.FIDO2_KEY_BASE)}: {e}")

    def _public_key_to_tpm_ecc_point(self, public_key):
        """Convert a cryptography EC public key into TPM2B_ECC_POINT."""
        numbers = public_key.public_numbers()
        point = TPM2B_ECC_POINT()
        point.point.x.buffer = numbers.x.to_bytes(32, 'big')
        point.point.y.buffer = numbers.y.to_bytes(32, 'big')
        return point

    def ecdh_encrypt(self, plaintext: bytes, public_key, persistent_handle=None, password: bytes = b""):
        """Encrypt plaintext for this TPM key using ECDH and AES-GCM.
        
        Args:
            plaintext: Data to encrypt
            public_key: Ephemeral public key for ECDH
            persistent_handle: TPM handle (defaults to FIDO2_KEY_BASE)
            password: Optional password to unlock the key (bytes)
        
        Returns the same blob format as [`KeyUtils.ec_encrypt()`](soft_fido2/key_pair.py:566):
        4-byte PEM length || ephemeral public PEM || iv || tag || ciphertext
        """
        with redirect_tcti_to_logging():
            esapi = ESAPI()
            if persistent_handle is None:
                persistent_handle = TPM2_HANDLE(self.FIDO2_KEY_BASE)
            handle = esapi.tr_from_tpmpublic(persistent_handle)
            esapi.tr_set_auth(handle, password if password else b"")

        in_point = self._public_key_to_tpm_ecc_point(public_key)
        z_point = esapi.ecdh_zgen(handle, in_point)

        shared_raw = bytes(z_point.point.x)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(shared_raw)
        shared = digest.finalize()

        iv = os.urandom(16)
        encryptor = Cipher(algorithms.AES256(shared), modes.GCM(iv)).encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        anon_pub = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        anon_pub_bytes = len(anon_pub).to_bytes(4, 'big') + anon_pub
        return anon_pub_bytes + iv + encryptor.tag + ciphertext

    def ecdh_decrypt(self, encrypted: bytes, persistent_handle=None, password: bytes = b""):
        """Decrypt blob encrypted to the TPM platform key using ECDH and AES-GCM.
        
        Args:
            encrypted: Encrypted data blob
            persistent_handle: TPM handle (defaults to FIDO2_KEY_BASE)
            password: Optional password to unlock the key (bytes)
        
        Returns:
            bytes: Decrypted plaintext
        """
        pub_bytes_len = int.from_bytes(encrypted[:4], 'big')
        pub_bytes = encrypted[4:pub_bytes_len + 4]
        pubkey = load_pem_public_key(pub_bytes)
        if not isinstance(pubkey, ec.EllipticCurvePublicKey):
            raise ValueError("Public key must be an EllipticCurvePublicKey")

        with redirect_tcti_to_logging():
            esapi = ESAPI()
            if persistent_handle is None:
                persistent_handle = TPM2_HANDLE(self.FIDO2_KEY_BASE)
            handle = esapi.tr_from_tpmpublic(persistent_handle)
            esapi.tr_set_auth(handle, password if password else b"")

        in_point = self._public_key_to_tpm_ecc_point(pubkey)
        z_point = esapi.ecdh_zgen(handle, in_point)

        shared_raw = bytes(z_point.point.x)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(shared_raw)
        shared = digest.finalize()

        ciphertext = encrypted[pub_bytes_len + 4:]
        iv = ciphertext[:16]
        tag = ciphertext[16:32]
        decryptor = Cipher(algorithms.AES256(shared), modes.GCM(iv, tag=tag)).decryptor()
        return decryptor.update(ciphertext[32:]) + decryptor.finalize()


    def hmac(self, data: bytes, persistent_handle=None, password: bytes = b""):
        """
        Perform HMAC-SHA256 operation using TPM key.
        
        This method uses the TPM's HMAC capability to compute an HMAC
        over the provided data using the key stored at the persistent handle.
        The private key material never leaves the TPM.
        
        Args:
            data: Data to HMAC (bytes)
            persistent_handle: TPM handle (defaults to FIDO2_KEY_BASE)
            password: Optional password to unlock the key (bytes)
            
        Returns:
            bytes: HMAC output (32 bytes for SHA256)
            
        Raises:
            Exception: If HMAC operation fails
        """
        with redirect_tcti_to_logging():
            esapi = ESAPI()
            if persistent_handle is None:
                persistent_handle = TPM2_HANDLE(self.FIDO2_KEY_BASE)
            handle = esapi.tr_from_tpmpublic(persistent_handle)
            esapi.tr_set_auth(handle, password if password else b"")
        
        # Prepare input buffer
        buffer = TPM2B_MAX_BUFFER()
        buffer.buffer = data
        
        # Perform HMAC operation
        result = esapi.hmac(
            handle=handle,
            buffer=buffer,
            hash_alg=TPM2_ALG.SHA256
        )
        
        return bytes(result.buffer)


class TPMKeyPair:
    """
    Wrapper class for TPM-backed key pairs.
    
    This class provides a KeyPair-compatible interface for keys stored in the TPM,
    allowing transparent use of TPM keys alongside software keys. The private key
    material never leaves the TPM hardware.
    
    Attributes:
        tpm_handle: TPM persistent handle for the key
        tpm_password: Password to unlock the TPM key (bytes)
        public_key: The public key corresponding to the TPM private key
        is_tpm: Always True to identify this as a TPM-backed key
    """
    
    def __init__(self, tpm_handle: int, public_key, tpm_password: bytes = b""):
        """
        Initialize a TPM key pair wrapper.
        
        Args:
            tpm_handle: TPM persistent handle for the key
            public_key: The public key (cryptography EC public key object)
            tpm_password: Optional password to unlock the key (bytes)
        """
        self.tpm_handle = tpm_handle
        self.tpm_password = tpm_password if tpm_password else b""
        self.public = public_key
        self.private = None  # TPM keys don't expose private key material
        self.is_tpm = True
        self._tpm_device = None
    
    @property
    def tpm_device(self):
        """Lazy-load TPM device to avoid initialization overhead."""
        if self._tpm_device is None:
            self._tpm_device = TPMDevice()
        return self._tpm_device
    
    @property
    def handle(self):
        """Alias for tpm_handle for backward compatibility."""
        return self.tpm_handle
    
    def get_public(self):
        """Get the public key."""
        return self.public
    
    def get_private(self):
        """
        Get private key (not available for TPM keys).
        
        Raises:
            ValueError: Always, as TPM private keys cannot be exported
        """
        raise ValueError("TPM private keys cannot be exported from hardware")
    
    def get_public_bytes(self):
        """Get public key as PEM-encoded bytes."""
        from cryptography.hazmat.primitives import serialization
        return self.public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def tpm_decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt data using TPM key with stored password.
        
        Args:
            ciphertext: Encrypted data blob
            
        Returns:
            bytes: Decrypted plaintext
        """
        return self.tpm_device.ecdh_decrypt(
            ciphertext,
            self.tpm_handle,
            password=self.tpm_password
        )
    
    def tpm_encrypt(self, plaintext: bytes, public_key) -> bytes:
        """
        Encrypt data for this TPM key using ECDH.
        
        Args:
            plaintext: Data to encrypt
            public_key: Ephemeral public key for ECDH
            
        Returns:
            bytes: Encrypted data blob
        """
        return self.tpm_device.ecdh_encrypt(
            plaintext,
            public_key,
            self.tpm_handle,
            password=self.tpm_password
        )
    
    def __repr__(self):
        return f"TPMKeyPair(handle={hex(self.tpm_handle)}, password_protected={bool(self.tpm_password)})"