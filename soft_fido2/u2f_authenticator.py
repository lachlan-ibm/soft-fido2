# Copyrite IBM 2022, 2025
# IBM Confidential

import hashlib
import logging
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography import x509

from .key_pair import KeyPair, KeyUtils
from .cert_utils import CertUtils
from .symmetric_key import SymmetricKey


# Credential-ID prefix — same sentinel as Fido2Authenticator so that
# CTAPHIDevice._u2f_authenticate check-only can reuse CRED_PREFIX comparisons.
CRED_PREFIX = b"1337C0D3"


class U2FAuthenticator:
    """
    Implements CTAP1/U2F REGISTER and AUTHENTICATE operations.

    """

    def __init__(
        self,
        keyPair: Optional[KeyPair] = None,
        credId: Optional[bytes] = None,
        sKey: Optional[SymmetricKey] = None,
    ) -> None:
        """
        Args:
            keyPair: Signing key pair. Used directly when supplied.
            credId:  Raw credential-ID bytes (CRED_PREFIX + encrypted material).
                     Used with sKey to recover the signing keypair.
            sKey:    SymmetricKey used to decrypt/encrypt the credential ID.
                     Required when credId is provided.
        """
        self.sKey: Optional[SymmetricKey] = sKey
        self.cib: Optional[bytes] = credId

        # Signing keypair — priority 1: keyPair, 2: recover from credId, 3: generate fresh
        self.kp: KeyPair = self._init_kp(keyPair, credId, sKey)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _init_kp(
        self,
        keyPair: Optional[KeyPair],
        credId: Optional[bytes],
        sKey: Optional[SymmetricKey],
    ) -> KeyPair:
        if keyPair is not None:
            return keyPair
        if credId is not None and sKey is not None:
            try:
                return self._recover_kp(credId, sKey)
            except Exception as e:
                logging.warning(f"U2FAuthenticator: could not recover kp from credId: {e}")
        return KeyPair.generate_ecdsa()

    def _recover_kp(self, credId: bytes, sKey: SymmetricKey) -> KeyPair:
        """
        Decrypt credId to recover the signing KeyPair.

        credId format: CRED_PREFIX (8 bytes) || sKey.encrypt([2-byte COSE alg || 32-byte key material])

        Delegates to KeyUtils machinery used by Fido2Authenticator so that
        credential IDs are interoperable between CTAP1 and CTAP2 paths on the
        same platform key.
        """
        if len(credId) < len(CRED_PREFIX) or credId[:len(CRED_PREFIX)] != CRED_PREFIX:
            raise ValueError("credId missing expected prefix")
        encrypted = credId[len(CRED_PREFIX):]
        plaintext = sKey.decrypt(encrypted)
        # plaintext: [2 bytes COSE alg][32 bytes key material]
        if len(plaintext) != 34:
            raise ValueError(f"Unexpected plaintext length: {len(plaintext)}")
        alg_id = int.from_bytes(plaintext[0:2], byteorder="big", signed=True)
        key_material = plaintext[2:34]
        private_key = KeyUtils.reconstruct_key_from_alg_id(alg_id, key_material)
        return KeyPair(private_key, private_key.public_key())

    def _build_cred_id(self) -> bytes:
        """
        Encrypt the signing keypair into a credential ID and cache it in self.cib.

        Format: CRED_PREFIX || sKey.encrypt([2-byte COSE alg || 32-byte key material])

        Falls back to SHA-256 of the public key bytes when no sKey is available
        (self-attested / test path — no credential recovery possible).
        """
        if self.cib is not None:
            return self.cib

        private_key = self.kp.get_private()

        if self.sKey is not None:
            key_material = private_key.private_numbers().private_value.to_bytes(
                (private_key.curve.key_size + 7) // 8, byteorder="big"
            )
            cose_alg = (-7).to_bytes(2, byteorder="big", signed=True)
            plaintext = cose_alg + key_material
            encrypted = self.sKey.encrypt(plaintext)
            self.cib = CRED_PREFIX + encrypted
        else:
            self.cib = hashlib.sha256(self.kp.get_public_bytes()).digest()

        return self.cib

    def _att_cert_der(self) -> bytes:
        """
        Generate a self-signed attestation certificate using self.kp, then return
        raw DER bytes via CertUtils.get_encoded().

        Note: CertUtils.get_bytes() returns base64(DER). CertUtils.get_encoded()
        returns the raw DER bytes directly — that is the correct choice here since
        the U2F response wire format requires raw DER, not base64.
        """
        subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, u"root"),
            x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, u"IBM Security"),
        ])
        cert = CertUtils.gen_ca_cert(subject=subject, keyPair=self.kp)
        return CertUtils.get_encoded(cert)  # raw DER bytes

    def _pub_key_uncompressed(self) -> bytes:
        """Return the signing public key as an uncompressed EC point: 0x04 || X || Y."""
        pub_nums = self.kp.get_public().public_numbers()
        x = pub_nums.x.to_bytes(32, "big")
        y = pub_nums.y.to_bytes(32, "big")
        return b"\x04" + x + y

    def _ecdsa_sign(self, data: bytes, key_pair: KeyPair) -> bytes:
        """
        Hash data with SHA-256 then sign with ECDSA using key_pair's private key.

        The EC private key .sign() API requires a pre-hashed digest when using
        utils.Prehashed, which avoids double-hashing inside the library.
        """
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        return key_pair.get_private().sign(
            digest.finalize(),
            ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register(self, app_id_hash: bytes, client_data_hash: bytes) -> bytes:
        """
        Produce a U2F REGISTER response body (without SW1SW2).

        Args:
            app_id_hash:      32-byte SHA-256 of the application / origin facet ID.
            client_data_hash: 32-byte SHA-256 of the ClientData JSON.

        Returns:
            bytes: Registration response body per FIDO U2F Raw Message Formats §4.3:
                0x05 || pub_key (65) || kh_len (1) || key_handle || att_cert_der || sig

        The signature is computed over:
            0x00 || app_id_hash || client_data_hash || key_handle || pub_key_uncompressed
        using self.kp.
        """
        if len(app_id_hash) != 32:
            raise ValueError("app_id_hash must be 32 bytes")
        if len(client_data_hash) != 32:
            raise ValueError("client_data_hash must be 32 bytes")

        pub_key = self._pub_key_uncompressed()       # 65 bytes
        key_handle = self._build_cred_id()           # variable length
        kh_len = len(key_handle).to_bytes(1, "big")
        att_cert_der = self._att_cert_der()

        to_sign = b"\x00" + app_id_hash + client_data_hash + key_handle + pub_key
        sig = self._ecdsa_sign(to_sign, self.kp)

        return b"\x05" + pub_key + kh_len + key_handle + att_cert_der + sig

    def authenticate(self, app_id_hash: bytes, client_data_hash: bytes) -> bytes:
        """
        Produce a U2F AUTHENTICATE response body (without SW1SW2).

        Args:
            app_id_hash:      32-byte SHA-256 of the application / origin facet ID.
            client_data_hash: 32-byte SHA-256 of the ClientData JSON.

        Returns:
            bytes: Authentication response body per FIDO U2F Raw Message Formats §5.4:
                user_presence (1) || sig

        The signature is computed over:
            app_id_hash || user_presence || client_data_hash
        using self.kp (the credential signing key recovered from the key handle).

        No counter: U2F ceremonies always have user presence confirmed by the
        get_info interaction, so a counter field carries no additional security
        value in this implementation.
        """
        if len(app_id_hash) != 32:
            raise ValueError("app_id_hash must be 32 bytes")
        if len(client_data_hash) != 32:
            raise ValueError("client_data_hash must be 32 bytes")

        user_presence = b"\x01"

        to_sign = app_id_hash + user_presence + client_data_hash
        sig = self._ecdsa_sign(to_sign, self.kp)

        return user_presence + sig
