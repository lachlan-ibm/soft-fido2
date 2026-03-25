import logging
import os
import sys
import tempfile
from contextlib import contextmanager
from tpm2_pytss import ESAPI, TPM2B_PUBLIC, TPM2B_SENSITIVE_CREATE, ESYS_TR, TPM2B_DATA, TPML_PCR_SELECTION
from tpm2_pytss.types import TPMT_PUBLIC, TPMS_ECC_PARMS, TPMT_SYM_DEF_OBJECT, TPMT_ECC_SCHEME, TPM2_HANDLE
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend


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
    FIDO2_KEY_ATTRIBUTES = 0x00040072  # fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | sign | restricted


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
        in_public.publicArea.parameters.eccDetail.scheme.scheme = self.TPM_ALG_ECDSA
        in_public.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg = self.TPM_ALG_SHA256
        in_public.publicArea.parameters.eccDetail.curveID = self.TPM_ECC_NIST_P256
        in_public.publicArea.parameters.eccDetail.kdf.scheme = self.TPM_ALG_NULL
        
        return in_public

    def create_key(self):
        """Generate or retrieve the FIDO2 platform key at FIDO2_KEY_BASE handle
        
        Creates an EC P-256 primary key in the TPM and persists it at the
        FIDO2_KEY_BASE handle. If a key already exists at this handle,
        returns the existing key.
        
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
            tuple: (handle, public_key) where handle is ESYS_TR and
                   public_key is TPM2B_PUBLIC
                   
        Raises:
            Exception: If key does not exist at FIDO2_KEY_BASE handle
        """
        with redirect_tcti_to_logging():
            esapi = ESAPI()
        
        try:
            handle = esapi.tr_from_tpmpublic(TPM2_HANDLE(self.FIDO2_KEY_BASE))
            public_key, _, _ = esapi.read_public(handle)
            
            return (handle, public_key)
            
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
