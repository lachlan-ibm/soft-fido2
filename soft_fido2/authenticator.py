# Copyrite IBM 2022, 2025
# IBM Confidential

import hashlib, json, struct, re, base64, binascii, sys, array, os, logging
import cbor2 as cbor
from typing import Optional, List, Union, Any

from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, mldsa,  padding, utils
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.fernet import Fernet

from .key_pair import KeyPair, KeyUtils
from .attestation import process_attestation_statement  as _build_att_stmt
from .symmetric_key import SymmetricKey


class Fido2Authenticator(object):

    CRED_PREFIX = b"1337C0D3"

    userHandle: Optional[Union[bytes,str]] = None

    def __init__(self,
            keyPair: Optional[KeyPair] = None,
            credId: Optional[bytes] = None,
            aaguid: Optional[List[int]] = None,
            caKeyPair: Optional[KeyPair] = None,
            caCert: Optional[x509.Certificate] = None,
            counter: int = 0,
            hashingAlg: hashes.HashAlgorithm = hashes.SHA256(),
            transports: Optional[List[str]] = None,
            fKey: Optional[Fernet] = None,
            sKey: Optional[SymmetricKey] = None,
            disableCounter: bool = False,
            ctsProfileMatch: bool = True,
            saltLength: Optional[int] = None,
    ) -> None:
        """Initialize a FIDO2 Authenticator with the specified parameters.
        
        Args:
            keyPair (KeyPair, optional): Public/private key pair to sign challenges with.
                    Default = None (EC 256 key will be generated)
            credId (bytes, optional): Credential ID (raw bytes) to use with authenticator.
                    Default = None (will be derived from keyPair)
            aaguid (List[int], optional): AAGUID to associate with authenticator.
                    Default = None (will use null aaguid)
            caKeyPair (KeyPair, optional): Public/private key of CA/intermediate authority
                    for BASIC/ATTCA/TPM/Android attestation formats. Default = None
            caCert (x509.Certificate, optional): Certificate to use as a trust anchor.
                    Default = None
            counter (int): Internal counter of token. Default = 0
            hashingAlg (hashes.HashAlgorithm): Hashing algorithm for "packed" attestation.
                    Default = SHA256
            transports (List[str], optional): List of supported transports. Default = None
            fKey (Fernet, optional): Symmetric key to generate credential ID.
                    Can be used to reconstruct private EC key for assertions. Default = None
                    *Depreciated*: Use SymmetricKey instead.
            sKey (SymmetricKey, optional): Alternative symmetric key to generate credential ID.
                    Can be used to reconstruct private EC key for assertions. Default = None
            disableCounter (bool, optional): Whether to disable the attestation/assertion counter.
                    Default = False
            ctsProfileMatch (bool, optional): Whether to disable the CTS Profile match for Android Safetynet
                                    attestation statements. Default = True
            saltLength (int, optional): Length of salt to use for "packed" attestation (RSAPSS).
                    This is expected to be the same length as the digest of the hashing 
                    algorithm used.
        """
        if aaguid and len(aaguid) != 16:
            raise ValueError("AAGUID must be 16 bytes long")
        elif not aaguid:
            aaguid = [0] * 16

        # Core authenticator properties
        self.counter = counter
        self.hashAlg = hashingAlg
        self.disable_counter = disableCounter
        self.aaguid = aaguid
        self.salt_len = saltLength
        self.ctsProfileMatch = ctsProfileMatch

        # Credential and key management
        self.kp = keyPair
        self.fKey = fKey
        self.sKey = sKey
        self.cib = None  # Credential ID bytes

        # Certificate and trust chain
        self.caCertificate = caCert
        self.caKeyPair = caKeyPair
        # Transports
        self.transports = transports

        # Initialize key pair based on credential ID
        self._init_key_pair(credId)

    def _init_key_pair(self, credId):
        if credId is not None:
            # Store the credential ID as-is (it's already in the format: prefix + base64_encoded_data)
            self.cib = credId
            key = self.fKey or self.sKey
            if self.kp is None and key is not None:
                self.kp = self._get_key_pair_from_credential_id(credId, key)

        # Generate a new key pair if we still don't have one
        if self.kp is None:
            self.kp = KeyPair.generate_ecdsa()
            self.cib = None  # Force regeneration

    @classmethod
    def _urlb64_decode(cls, b64String):
        """Helper function to decode b64 urlencoded strings which may be missing
        the trailing padding that Python requires.

        Args:
            b64String (str): URL-safe base64 encoded string to decode

        Returns:
            bytes: Decoded bytes
        """
        pad = len(b64String) % 4
        if pad:
            b64String += b'=' * pad
        return base64.urlsafe_b64decode(b64String)

    @classmethod
    def _urlb64_encode(cls, byteString):
        """Helper function or b64 encode a string then remove the trailing padding
        which is not required

        Args:
            byteString (str): string to encode

        Returns:
            str: b64 url encoded string with trailing '=' stripped
        """
        b64String = str(base64.urlsafe_b64encode(byteString), 'utf-8')
        return re.sub(r'=*$', '', b64String)

    @classmethod
    def _long_to_bytes(cls, l):
        """Convert a long to a byte representation

        Args:
            l (long): long to convert to bytes

        Returns:
            :obj:`list` of :obj:`bytes`: byte representation of the long value
        """
        limit = 256**4 - 1  #max value we can fit into a struct.pack
        parts = []
        while l:
            parts.append(l & limit)
            l >>= 32
        parts = parts[::-1]
        return struct.pack(">" + 'L' * len(parts), *parts)

    def _bytes_to_long(self, b):
        """Converts an array of bytes to a long

        Args:
            b (:obj:`list` of :obj:`byte`): bytes to convert

        Returns:
            long: value of bytes as a long
        """
        l = len(b) / 4
        parts = struct.unpack(">" + 'L' * int(l), b)[::-1]
        result = 0
        for i in range(len(parts)):
            temp = parts[i] << (32 * i)
            result += temp

        return result

    @classmethod
    def _build_credential_id_plaintext(cls, cose_alg: int, key_material: bytes) -> bytes:
        """Build plaintext for F1D0 credential ID.
        
        Format: [2 bytes COSE alg][32 bytes key material] = 34 bytes
        
        Args:
            cose_alg: COSE algorithm identifier (e.g., -7 for ES256, -48 for ML-DSA-44)
            key_material: 32-byte private key material
            
        Returns:
            bytes: 34-byte plaintext to be encrypted
            
        Raises:
            ValueError: If key_material is not 32 bytes
        """
        cose_alg_bytes = cose_alg.to_bytes(2, byteorder="big", signed=True)
        if len(key_material) != 32:
            raise ValueError("key_material must be 32 bytes")
        return cose_alg_bytes + key_material

    @classmethod
    def _parse_credential_id_plaintext(cls, plaintext: bytes):
        """Parse plaintext from F1D0 credential ID.
        
        Format: [2 bytes COSE alg][32 bytes key material] = 34 bytes
        
        Args:
            plaintext: 34-byte decrypted plaintext
            
        Returns:
            tuple: (cose_alg, key_material)
            
        Raises:
            ValueError: If plaintext length is invalid
        """
        if len(plaintext) != 34:
            raise ValueError(f"Invalid credential ID plaintext length: {len(plaintext)} (expected 34)")
        cose_alg = int.from_bytes(plaintext[0:2], byteorder="big", signed=True)
        key_material = plaintext[2:34]
        return cose_alg, key_material

    def _get_credential_id_bytes(self, keyPair, alg_id=None):
        """Generate F1D0 format credential ID.
        
        Format: PREFIX || E(alg_id || key_material)
        
        Args:
            keyPair (KeyPair): Key pair to generate ID for
            alg_id (int, optional): COSE algorithm ID (inferred if None)
            
        Returns:
            bytes: F1D0 format credential ID
        """
        if self.cib is not None:
            return self.cib
        
        key = self.sKey or self.fKey
        if not key:
            # Fallback to hash if no encryption key
            self.cib = hashlib.sha256(keyPair.get_public_bytes()).digest()
            return self.cib
        
        private_key = keyPair.get_private()
        
        # Determine algorithm ID and extract key material
        config = KeyUtils._get_key_config(private_key, self.hashAlg)
        alg_id = alg_id if alg_id is not None else config.alg_id
        key_material = config.extract_key(private_key)
        
        # Build plaintext and encrypt
        plaintext = self._build_credential_id_plaintext(alg_id, key_material)
        encrypted = key.encrypt(plaintext)
        
        # Add prefix
        self.cib = self.CRED_PREFIX + encrypted
        return self.cib

    def get_credential_id(self, keyPair=None):
        """Get the credential ID for this authenticator.
        
        Returns the cached credential ID if available, otherwise falls back to SHA256 of public key.

        Args:
            keyPair (:obj:`KeyPair`, optional): Key pair to get credential id for; default = self.kp

        Returns:
            str: b64 encoded byte string of credential id
        """
        if self.cib is None:
            kp = keyPair or self.kp
            self._get_credential_id_bytes(kp)
        return self._urlb64_encode(self.cib)


    @classmethod
    def _decrypt_credential_context(cls, credId, decryptor):
        """Decrypt and parse credential ID metadata with prefix support.
        
        Args:
            credId: URL-safe base64 encoded credential ID (with or without prefix)
            decryptor: Symmetric key used to decrypt the credential ID
            
        Returns:
            tuple: (cose_alg, key_material)
        """
        encBytes = cls._urlb64_decode(credId)
        
        # Check for and skip CRED_PREFIX if present
        if len(encBytes) >= len(cls.CRED_PREFIX) and encBytes[:len(cls.CRED_PREFIX)] == cls.CRED_PREFIX:
            encBytes = encBytes[len(cls.CRED_PREFIX):]
        
        plaintext = decryptor.decrypt(encBytes)
        return cls._parse_credential_id_plaintext(plaintext)

    @classmethod
    def _get_key_pair_from_credential_id(cls, credId, decryptor):
        """Reconstruct KeyPair from credential ID with prefix.
        
        Args:
            credId (bytes): Credential ID in format: CRED_PREFIX + base64_encoded_encrypted_data
            decryptor (Union[Fernet,SymmetricKey]): Symmetric key for decryption
            
        Returns:
            KeyPair: Reconstructed key pair
            
        Raises:
            ValueError: If credential ID format is invalid or algorithm is unsupported
        """
        # Check for CRED_PREFIX (it's ASCII bytes, not encrypted)
        if len(credId) < len(cls.CRED_PREFIX) or credId[:len(cls.CRED_PREFIX)] != cls.CRED_PREFIX:
            raise ValueError(f"Invalid credential ID: missing {cls.CRED_PREFIX} prefix")
        
        # Extract the base64-encoded encrypted part (after the prefix)
        base64_encrypted = credId[len(cls.CRED_PREFIX):]
        plaintext = decryptor.decrypt(base64_encrypted)
        alg_id, key_material = cls._parse_credential_id_plaintext(plaintext)
        private_key = KeyUtils.reconstruct_key_from_alg_id(alg_id, key_material)
        return KeyPair(private_key, private_key.public_key())

    def get_aaguid(self, hexString=True):
        """If hexString returns in the format:
            01020304-0506-0708-0900-010203040506

        else returns format:
            1234567890123456

        Args:
            hexString (:obj:`bool`, optional): toggle wether to output a hexstring or a string representation of
                    aaguid; default = True

        Returns:
            str: representation of aaguid
        """
        result = ''
        if hexString:
            for x in range(16):
                result += binascii.hexlify(bytes(chr(self.aaguid[x]), 'utf-8')).decode('utf-8')
                if x == 3 or x == 5 or x == 7 or x == 9:
                    result += '-'
        else:
            result = bytes(self.aaguid)
        return result

    def credential_create(self, jsonOptions, atteStmtFmt='packed-self', keyPair=None, uv=True, up=True, be=False, bs=False):
        '''Responds to requests to navigator.credential.create(). jsonOptions should be
        either a dictionary or a JSON string of the attestation options and usually has the form:
        {
            "rp": {
                "id": "relying.party",
                "name": "Relying Party"
            },
            "user": {
                "id": "my_unique_id",
                "name": "Low Key",
                "displayName": "redacted"
            },
            "timeout": 60000,
            "challenge": "wvhbvWMV5Jsl96WbdZGav6Ifpp8QHnJC0MKhs1vDUes",
            "excludeCredentials": [],
            "authenticatorSelection": {
                "requireResidentKey": true,
                "authenticatorAttachment": "cross-platform",
                "userVerification": "preferred"
            },
            "attestation": "direct",
            "pubKeyCredParams": [
                {
                    "alg": -7,
                    "type": "public-key"
                },
                {
                    "alg": -257,
                    "type": "public-key"
                }
            ]
        }

        Args:
            jsonOptions (dict or str): Dictionary or JSON string of options for navigator.credential.create
            atteStmtFmt (str, optional): Attestation statement format as defined in
                    https://w3c.github.io/webauthn/#defined-attestation-formats
                    Defaults to 'packed-self'.
                    For compound attestation, the string is prefixed with 'compound:' and the required compound
                    statements are listed with a ',' (comma) separator. e.g.: `compound:packed-self,tpm`
            keyPair (KeyPair, optional): Private/public key pair to sign the attestation. Defaults to self.kp.
            uv (bool, optional): Whether the authenticator should set the user verification flag. Defaults to True.
            up (bool, optional): Whether the authenticator should set the user presence flag. Defaults to True.
            be (bool, optional): Whether the authenticator should set the backup eligible flag. Defaults to False.
            bs (bool, optional): Whether the authenticator should set the backup state flag. Defaults to False.

        Returns:
            dict: Response to navigator.credential.create containing the attestation
        '''
        if keyPair is None:
            keyPair = self.kp
        options = {}
        if isinstance(jsonOptions, dict):
            options = jsonOptions
        else:
            options = json.loads(jsonOptions)
        cco = self.attestation_options_response_to_credential_create_options(options)
        return self.process_credential_create_options(cco, atteStmtFmt, keyPair, uv, up, be, bs)

    def credential_request(self, jsonOptions, keyPair=None, uv=True, up=True, be=False, bs=False):
        '''Responds to navigator.credential.get(). jsonOptions should be either a dictionary
        or a JSON string of the assertion options and usually has the form:
        {
            "rpID": "www.my-relying-party.com"
            "userId": "my_unique_id",
            "displayName": "redacted",
            "authenticatorSelection": {
                "requireResidentKey": false,
                "authenticatorAttachment": "cross-platform",
                "userVerification": "preferred"
            },
            "attestation": "direct"
        }

        If you want to use a different origin you can add it to the Public-Key dictionary as a 
        top level key.

        Args:
            jsonOptions (dict): json dictionary of options for navigator.credentials.get
            keyPair (:obj:`KeyPair`, optional): private/public key pair to sign the assertion; default = self.kp
            uv (:obj:`bool`, optional): if the authenticator should set hte user verification flag, default = True
            up (:obj:`bool`, optional): if the authenticator should set hte user presence flag, default = True
            be (:obj:`bool`, optional): if the authenticator should set the backup eligible flag; default = False
            bs (:obj:`bool`, optional): if the authenticator should set the backup state flag; default = False

        Returns:
            dict: response to navigator.credential.get
        '''
        if keyPair is None:
            keyPair = self.kp
        options = {}
        if isinstance(jsonOptions, dict):
            options = jsonOptions
        else:
            options = json.loads(jsonOptions)
        cro = self.assertion_options_response_to_credential_request_options(options)

        return self.process_credential_request_options(cro, keyPair, uv, up, be, bs)

    def build_client_data_JSON(self, pk):
        """Creates the ClientDataJSON object for attestation and assertion operations

        Args:
            pk (dict): public key dictionary from request options,
                    https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialcreationoptions
                    https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialrequestoptions

        Returns:
            dict: clientDataJSON, https://www.w3.org/TR/webauthn/#sec-client-data
        """
        mode = 'webauthn.get' if 'rpId' in pk else 'webauthn.create'
        origin = pk.get('origin', None)
        if not origin and 'rpId' in pk:
            origin = 'https://' + pk['rpId']
        if not origin:
            origin = 'https://' + pk['rp']['id']

        clientDataDict = {'origin': origin, 'challenge': self._urlb64_encode(pk['challenge']), 'type': mode}
        return json.dumps(clientDataDict)

    def process_attested_credential_data(self, publicKey, credIdBytes):
        """create the attested credentail data for attestation requets

        Args:
            publickey: (PublicKey): RSA || EC public key
            credIdBytes (str): byte string of credential id, https://www.w3.org/TR/webauthn/#credential-id

        Returns:
            str: attested credetail data, https://www.w3.org/TR/webauthn/#sec-attested-credential-data
        """
        attestedCredDataBytes = []
        attestedCredDataBytes += array.array('B', self.aaguid).tobytes()
        length = struct.pack('H', len(credIdBytes))
        attestedCredDataBytes += [length[1], length[0]]
        attestedCredDataBytes += credIdBytes
        credPublicKeyCOSE = KeyUtils.get_cose_key(publicKey, self.hashAlg)
        attestedCredDataBytes += cbor.dumps(credPublicKeyCOSE)
        return attestedCredDataBytes

    def build_authenticator_data(self, pk, attStmtFmt, keyPair, uv, up=True, be=False, bs=False):
        """Create the authenticator data for the attestation or assertion request.

        Args:
            pk (dict): Public key dictionary from request options.
                    For attestation: https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialcreationoptions
                    For assertion: https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialrequestoptions
            attStmtFmt (str): Attestation statement format as defined in
                    https://www.w3.org/TR/webauthn/#defined-attestation-formats
            keyPair (KeyPair): Public/private key pair to use
            uv (bool): Whether to set the user verification flag
            up (bool, optional): Whether to set the user presence flag. Defaults to True.
            be (bool, optional): Whether to set the backup eligible flag. Defaults to False.
            bs (bool, optional): Whether to set the backup state flag. Defaults to False.

        Returns:
            bytes: Authenticator data as defined in
                  https://www.w3.org/TR/webauthn/#sec-authenticator-data
        """
        authDataBytes = []

        rpId = pk.get('rpId', None)
        assertion = True
        if not rpId:
            rpId = pk['rp']['id']
            assertion = False

        rpIdHash = hashlib.sha256(rpId.encode('utf-8')).digest()
        authDataBytes += rpIdHash

        flags = 0x00
        if up:
            flags |= 0x01  # UP
        if not assertion:
            flags |= 0x40  # AT
        if attStmtFmt != 'fido-u2f' and uv != None and uv == True:
            flags |= 0x04  # UV
        if be == True:
            flags |= 0x08
        if bs == True:
            flags |= 0x0F
        authDataBytes += struct.pack("c", chr(flags).encode('utf-8'))

        #Add counter and increment if required
        authDataBytes += struct.pack(">I", self.counter)
        if self.disable_counter == False:  
            self.counter += 1

        if not assertion:
            if self.cib is None:
                self.cib = self._get_credential_id_bytes(keyPair)
            authDataBytes += self.process_attested_credential_data(keyPair.get_public(), self.cib)
        authData = bytes(authDataBytes)
        return authData

    def process_attestation_statement(self, atteStmtFmt, clientDataHash,
                                        authData, credIdBytes, keyPair):
        return _build_att_stmt(
            atteStmtFmt, clientDataHash, authData, credIdBytes, keyPair,
            hash_alg=self.hashAlg,
            salt_len=self.salt_len,
            ca_certificate=self.caCertificate,
            ca_key_pair=self.caKeyPair,
            aaguid=self.get_aaguid(hexString=False),
            cts_profile_match=self.ctsProfileMatch,
        )

    def attestation_options_response_to_credential_create_options(self, options):
        """Take the options provided by the relying party and extract required information to
        generate the attestation.

        Args:
            options (dict): Options from navigator.credential.create as defined in
                    https://www.w3.org/TR/webauthn/#credentialcreationoptions-extension

        Returns:
            dict: Credential creation options as defined in
                  https://www.w3.org/TR/webauthn/#dictionary-makecredentialoptions
        """
        pkcco = {'rp': options['rp']}
        user = {'id': self._urlb64_decode(options['user']['id'].encode('UTF-8'))}
        pkcco['user'] = user
        pkcco['challenge'] = self._urlb64_decode(options['challenge'].encode('UTF-8'))
        pkcco['pubKeyCredParams'] = options['pubKeyCredParams']
        if 'timeout' in options:
            pkcco['timeout'] = options['timeout']

        if 'excludeCredentials' in options:
            pkcco['excludeCredentials'] = options['excludeCredentials']

        if 'authenticatorSelection' in options:
            pkcco['authenticatorSelection'] = options['authenticatorSelection']

        if 'attestation' in options:
            pkcco['attestation'] = options['attestation']

        if 'extensions' in options:
            pkcco['extensions'] = options['extensions']

        if 'origin' in options:
            pkcco['origin'] = options['origin']

        cco = {'publicKey': pkcco}
        return cco

    def process_credential_create_options(self, cco, atteStmtFmt, keyPair, uv, up=True, be=False, bs=False):
        """Generate response to parsed credential create request

        Args:
            cco (dict): Credential Create Options,
                    https://www.w3.org/TR/credential-management-1/#credentialcreationoptions-dictionary
            atteStmtFmt (str): required attestation format. see:
                    https://www.w3.org/TR/webauthn/#defined-attestation-formats
            keyPair (KeyPair): public/private kye pair to sign with
            uv (bool): set the user verification flag
            up (bool): set the user presence flag
            be (bool): set the backup eligible flag
            bs (bool): set the backup state flag

        Returns:
            dict: attestation response to credential create request,
                    https://www.w3.org/TR/webauthn/#authenticatorattestationresponse
        """
        pk = cco['publicKey']
        self.userHandle = pk['user']['id']
        clientDataJSON = self.build_client_data_JSON(pk)
        clientDataHash = hashlib.sha256(clientDataJSON.encode('utf-8')).digest()
        clientDataEncoded = base64.urlsafe_b64encode(clientDataJSON.encode('ascii'))

        if self.cib is None:
            self._get_credential_id_bytes(keyPair)

        authData = self.build_authenticator_data(pk, atteStmtFmt, keyPair, uv, up, be, bs)
        attStmt = self.process_attestation_statement(atteStmtFmt, clientDataHash, authData, self.cib, keyPair)
        attStmtFmt = str(re.sub('-self', '', atteStmtFmt))
        if atteStmtFmt.startswith('compound'):
            attStmtFmt = atteStmtFmt.split(':')[0]
        attestationObject = {u'authData': authData, u'fmt': attStmtFmt, u'attStmt': attStmt}
        saar = {
            u'clientDataJSON': str(clientDataEncoded, 'utf-8'),
            u'attestationObject': str(base64.urlsafe_b64encode(cbor.dumps(attestationObject)), 'utf-8')
        }
        spkc: dict[str, Any] = {
            u'id': self.get_credential_id(keyPair),
            u'rawId': self.get_credential_id(keyPair),
            u'response': saar,
            u'type': u'public-key',
            u'getClientExtensionResults': {}
        }
        if self.transports is not None:
            spkc['getTransports'] = self.transports
        if(cco.get('extensions') != None 
                and isinstance(cco['extensions'], dict) 
                and "devicePubKey" in cco['extensions'].keys()):
            raise RuntimeError("devicePubKey not implemented")
        return spkc

    def assertion_signature(self, authData, clientDataHash, keyPair):
        """Generate a signature for an assertion using the appropriate algorithm for the key type.

        Args:
            authData (bytes): Authenticator data
            clientDataHash (bytes): Hash of the client data
            keyPair (KeyPair): Public/private key pair to sign with

        Returns:
            bytes: Signature of the combined authenticator data and client data hash

        Raises:
            Exception: If the key algorithm is not supported
        """
        toSign = []
        toSign += authData
        toSign += clientDataHash
        toSignStr = bytes(toSign)
        sig = b''
        if isinstance(keyPair.get_public(), rsa.RSAPublicKey) == True:
            if self.salt_len:
                sig = keyPair.get_private().sign(toSignStr, padding.PSS(mgf=padding.MGF1(self.hashAlg), salt_length=self.salt_len), self.hashAlg)
            else:
                sig = keyPair.get_private().sign(toSignStr, padding.PKCS1v15(), self.hashAlg)
        elif isinstance(keyPair.get_public(), ec.EllipticCurvePublicKey) == True:
            hasher = hashes.Hash(self.hashAlg)
            hasher.update(toSignStr)
            sig = keyPair.get_private().sign(hasher.finalize(),
                                                  ec.ECDSA(utils.Prehashed(self.hashAlg)))
        elif isinstance(keyPair.get_public(), ed25519.Ed25519PublicKey):
            sig = keyPair.get_private().sign(toSignStr)
        elif isinstance(keyPair.get_public(),
                    (mldsa.MLDSA44PublicKey, mldsa.MLDSA65PublicKey, mldsa.MLDSA87PublicKey)):
            sig = keyPair.get_private().sign(toSignStr)
        else:
            raise Exception("Unsupported key algorithm")
        return sig

    def assertion_options_response_to_credential_request_options(self, options):
        """Take the options provided by the relyig party and extract required information to
        generate the assertion

        Args:
            options (dict): options from navigator.credential.get
                    https://www.w3.org/TR/webauthn/#iface-authenticatorassertionresponse
        Returns:
            dict: https://www.w3.org/TR/credential-management-1/#dictdef-credentialrequestoptions
        """
        cro = {}
        pkcro = {}

        pkcro['challenge'] = self._urlb64_decode(options['challenge'].encode('UTF-8'))
        if 'timeout' in options:
            pkcro['timeout'] = options['timeout']

        pkcro['rpId'] = options['rpId']
        if 'allowedCredentials' in options:
            allowedCreds = options['allowedCredentials']
            pkcro['allowedCredentials'] = []
            for c in allowedCreds:
                cred = {'type': c['type'], 'id': base64.urlsafe_b64decode(c['id'])}
                if 'transports' in c:
                    cred['transports'] = c['transports']
                pkcro['allowedCredentials'].append(cred)

        if 'userVerifation' in options:
            pkcro['userVerification'] = options['userVerification']

        if 'extensions' in options:
            pkcro['extensions'] = options['extensions']

        if 'origin' in options:
            pkcro['origin'] = options['origin']

        cro['publicKey'] = pkcro
        return cro

    def process_credential_request_options(self, cro, keyPair, uv, up=True, be=False, bs=False):
        """Generate response to parsed credential get request

        Args:
            cro (dict): Credential Request Options,
                    https://www.w3.org/TR/credential-management-1/#dictdef-credentialrequestoptions
            keyPair (KeyPair): public/private key pair to sign with
            uv (bool): set the user verification flag
            up (bool): set the user presence flag
            be (bool): set the backup eligible flag. This should be consistent with the registration state.
            bs (bool): set the backup state flag

        Returns:
            dict: assertion response to credential get request,
                    https://www.w3.org/TR/webauthn/#authenticatorassertionresponse
        """
        pk = cro["publicKey"]
        clientDataJSON = self.build_client_data_JSON(pk)
        authData = self.build_authenticator_data(pk, None, keyPair, uv, up, be, bs)
        saar = {
            "clientDataJSON": str(base64.urlsafe_b64encode(clientDataJSON.encode('utf-8')), 'utf-8'),
            "authenticatorData": str(base64.urlsafe_b64encode(authData), 'utf-8')
        }
        if isinstance(self.userHandle, (str, bytes)):
            saar['userHandle'] = self._urlb64_encode(self.userHandle)
        if "attestation" in cro.keys():
            raise RuntimeError("TODO")
        clientDataHash = bytearray(hashlib.sha256(clientDataJSON.encode('utf-8')).digest())

        saar['signature'] = str(base64.urlsafe_b64encode(self.assertion_signature(
                                                            authData, clientDataHash, keyPair)), 'utf-8')
        spkc = {
            'id': self.get_credential_id(keyPair),
            'rawId': self.get_credential_id(keyPair),
            'response': saar,
            'type': 'public-key',
            'getClientExtensionResults': {}
        }
        if(cro.get('extensions', None) != None
                and isinstance(cro['extensions'], dict)
                and "devicePubKey" in cro['extensions'].keys()):
            raise RuntimeError("TODO")
        return spkc


############################# MAIN ##############################

if __name__ == "__main__":
    if "FIDO_HOME" not in os.environ:
        logging.debug("Cannot find passkey home \"FIDO_HOME\"")
        sys.exit(1)
    authenticator = Fido2Authenticator()
    rsp = None
    pubPath = os.path.join(os.environ['FIDO_HOME'], 'test_public.pem')
    pivPath = os.path.join(os.environ['FIDO_HOME'], 'test_private.pem')
    if sys.argv[1] == 'attestation':
        if authenticator.kp is not None:
            rsp = authenticator.credential_create(sys.argv[3], 
                                                                  atteStmtFmt=sys.argv[2], 
                                                                  keyPair=authenticator.kp)
            with open(pivPath, 'wb') as key_file:
                key_file.write(authenticator.kp.get_private_bytes())
            with open(pubPath, 'wb') as key_file:
                key_file.write(authenticator.kp.get_public_bytes())
    elif sys.argv[1] == 'assertion':
        privateKey = publicKey = None
        with open(pivPath, 'rb') as key_file:
            privateKey = serialization.load_pem_private_key(key_file.read(), 
                                                                             password=None,
                                                                             backend=default_backend())

        with open(pubPath, 'rb') as key_file:
            publicKey = serialization.load_pem_public_key(key_file.read(),
                                                                          backend=default_backend())

        keyPair = KeyPair(privateKey, publicKey)
        authenticator.kp = keyPair
        rsp = authenticator.credential_request(sys.argv[2], authenticator.kp)
    else:
        logging.debug("Must specify a ceeremony (attestation || assertion) to perform.")
        sys.exit(1)
    print(json.dumps(rsp, indent=4))
