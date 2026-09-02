# Copyright IBM Corp. 2022, 2025
# IBM Confidential

"""Singleton per-channel authenticator state: CID cache, PIN protocol,
user-presence, passkey resolution, attestation, and assertion output.
"""

from multiprocessing.synchronize import Lock

import base64, multiprocessing, os, threading, time, secrets, typing, logging, math
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes

from .constants import CBORStatusCode
from .packet import bcolors, colour_print

from ..key_pair import KeyPair, KeyUtils
from ..authenticator import Fido2Authenticator
from ..symmetric_key import SymmetricKey
from ..qt.ux.config import PlatformConfig


class AuthenticatorAPI(object):
    '''
    Implementation of CTAP2 authenticator commands:

    getInfo
    makeCredential
    getNextAssertion
    clientPin
    authenticatorSelection
    '''

    _exp_time: int = 30

    _open_keys = {}

    _watchdog = None
    _lock: Lock = multiprocessing.Lock()

    _pin_retry: int = 5

    _quit: bool = False
    
    # Biometric + TPM mode state
    _biometric_tpm_mode_enabled: bool = False
    _biometric_tpm_mode_lock: threading.Lock = threading.Lock()

    def __new__(cls):
        cls._watchdog = threading.Thread(target=cls._token_expiry_check)
        cls._watchdog.start()

    @classmethod
    def _token_expiry_check(cls):
        '''
        Ejects expired in-memory passkeys handled by open CIDs
        '''
        while not cls._quit:
            time.sleep(0.005)
            if not cls._lock.acquire():
                return # denied
            cid_list = list(cls._open_keys.keys())
            for cid in cid_list:
                if math.floor(time.time() - cls._open_keys[cid]["tStart"]) == cls._exp_time:
                    cls._open_keys.pop(cid)
                    colour_print(colour=bcolors.FAIL, component='Authenticator_token_expiry_check',
                                 msg='CID {} has expired!\nExisting tokens: {}'.format(cid, cls._open_keys))
            cls._lock.release()


    @classmethod
    def has_cached_up(cls, cid) -> bool:
        if not cls._lock.acquire():
            return False # denied
        try:
            if cid in cls._open_keys:
                cached_up = cls._open_keys[cid].get("upv") in ("present", "verified")
                colour_print(colour=bcolors.OKBLUE, component='AuthenticatorAPI.has_cached_up',
                            msg=f'CID {cid.hex()} exists in _open_keys, UP={cached_up}')
                return cached_up
            colour_print(colour=bcolors.WARNING, component='AuthenticatorAPI.has_cached_up',
                        msg=f'CID {cid.hex()} NOT in _open_keys')
            return False
        finally:
            cls._lock.release()

    @classmethod
    def get_user_state(cls, cid) -> str:
        """Get the user authentication state for a CID.

        Args:
            cid: Channel ID

        Returns:
            "verified" if user is fully verified (PIN or biometric)
            "present" if user presence only (UP only)
            "unknown" if CID not found or upv not yet set
        """
        cls._lock.acquire()
        try:
            if cid in cls._open_keys:
                user_state = cls._open_keys[cid].get("upv", "unknown")
                colour_print(colour=bcolors.OKBLUE, component='AuthenticatorAPI.get_user_state',
                            msg=f'CID {cid.hex()} user state: {user_state}')
                return user_state
            colour_print(colour=bcolors.WARNING, component='AuthenticatorAPI.get_user_state',
                        msg=f'CID {cid.hex()} NOT in _open_keys')
            return "unknown"
        finally:
            cls._lock.release()

    @classmethod
    def cache_up(cls, cid, user_state: str):
        """Cache user presence/verification state.

        Args:
            cid: Channel ID
            user_state: Either "verified" (full UV) or "present" (UP only)
        """
        with cls._lock:
            if cid in cls._open_keys:
                cls._open_keys[cid]["upv"] = user_state
                colour_print(colour=bcolors.OKGREEN, component='AuthenticatorAPI.cache_up',
                            msg=f'Updated CID entry: upv={user_state} for CID {cid.hex()}')
            else:
                cls._open_keys[cid] = {
                    "upv": user_state,
                    "tStart": time.time()
                }
                colour_print(colour=bcolors.OKGREEN, component='AuthenticatorAPI.cache_up',
                            msg=f'Created CID entry: upv={user_state} for CID {cid.hex()}')

    @classmethod
    def initialize_biometric_tpm_mode(cls):
        """Initialize and validate biometric + TPM mode.
        
        This mode enables seamless authentication when both:
        - Biometric device (fingerprint) is available
        - TPM device is available with platform key
        
        Returns:
            True if mode successfully enabled, False otherwise
        """
        with cls._biometric_tpm_mode_lock:
            try: # Check biometric device
                from soft_fido2.platform import get_biometric_device as get_fprint_device
                if not get_fprint_device().is_available():
                    colour_print(colour=bcolors.WARNING,
                               component='AuthenticatorAPI.initialize_biometric_tpm_mode',
                               msg='Biometric device not available')
                    cls._biometric_tpm_mode_enabled = False
                    return False
                colour_print(colour=bcolors.OKGREEN,
                           component='AuthenticatorAPI.initialize_biometric_tpm_mode',
                           msg='Biometric device available')
            except ImportError:
                colour_print(colour=bcolors.WARNING,
                           component='AuthenticatorAPI.initialize_biometric_tpm_mode',
                           msg='D-Bus Python bindings not installed')
                cls._biometric_tpm_mode_enabled = False
                return False
            
            try: # Check TPM device
                from soft_fido2.platform import TPMDevice
                if not TPMDevice.is_available():
                    colour_print(colour=bcolors.WARNING,
                               component='AuthenticatorAPI.initialize_biometric_tpm_mode',
                               msg='TPM device not available')
                    cls._biometric_tpm_mode_enabled = False
                    return False
            except ImportError:
                colour_print(colour=bcolors.WARNING,
                           component='AuthenticatorAPI.initialize_biometric_tpm_mode',
                           msg='TPM module not available')
                cls._biometric_tpm_mode_enabled = False
                return False
            
            try: # Verify TPM key exists
                from soft_fido2.key_pair import KeyUtils
                tpm_key = KeyUtils._get_platform_kp()
                if tpm_key is None:
                    colour_print(colour=bcolors.FAIL,
                               component='AuthenticatorAPI.initialize_biometric_tpm_mode',
                               msg='TPM key not available')
                    cls._biometric_tpm_mode_enabled = False
                    return False
            except Exception as e:
                colour_print(colour=bcolors.FAIL,
                           component='AuthenticatorAPI.initialize_biometric_tpm_mode',
                           msg=f'TPM key check failed: {e}')
                cls._biometric_tpm_mode_enabled = False
                return False
            
            cls._biometric_tpm_mode_enabled = True
            colour_print(colour=bcolors.OKGREEN,
                       component='AuthenticatorAPI.initialize_biometric_tpm_mode',
                       msg='Biometric + TPM mode enabled')
            return True
    
    @classmethod
    def is_biometric_tpm_mode_enabled(cls) -> bool:
        """Check if biometric + TPM mode is enabled."""
        with cls._biometric_tpm_mode_lock:
            return cls._biometric_tpm_mode_enabled

    @classmethod
    def _get_or_create_pin_token_kp(cls, cid: bytes) -> KeyPair:
        """
        Get or create pin token key pair for this CID.
        This is called during get_pin_cose_key() before PIN validation.
        """
        with cls._lock:
            if cid not in cls._open_keys:
                cls._open_keys[cid] = {
                    'pin_token_kp': KeyPair.generate_ecdsa(),
                    'tStart': time.time()
                }
            elif 'pin_token_kp' not in cls._open_keys[cid]:
                # Add pin token key to existing CID entry
                cls._open_keys[cid]['pin_token_kp'] = KeyPair.generate_ecdsa()
            
            return cls._open_keys[cid]['pin_token_kp']

    @classmethod
    def get_pin_auth_token(cls, cid):
        cls._lock.acquire()
        try:
            open_key = AuthenticatorAPI._open_keys.get(cid, {})
            return open_key.get('pinAuth')
        finally:
            cls._lock.release()

    @classmethod
    def _validate_pin(cls, pinHash: bytes, cid: bytes) -> typing.Optional[bytes]:
        """
        Validates a PIN by attempting to decrypt passkey files in the FIDO_HOME directory.
        
        If a valid passkey file is found, it loads the certificate and key pair,
        stores the information in the class's _open_keys dictionary with the channel
        id as the key, and returns a generated PIN authentication token.
        
        Args:
            pinHash: The hash of the PIN to validate
            cid: The channel ID to associate with the opened keys
            
        Returns:
            A PIN authentication token if validation succeeds, None otherwise
        """
        # Check if FIDO_HOME environment variable exists and directory is accessible
        if not cls._is_fido_home_valid():
            return None
        fido_home_dir = os.path.realpath(os.environ["FIDO_HOME"])
        for passkey_file in cls._get_passkey_files(fido_home_dir):
            try:
                return cls._process_passkey_file(passkey_file, pinHash, cid)
            except Exception as e:
                colour_print(
                    colour=bcolors.WARNING, 
                    component='Authenticator_validate_pin',
                    msg=f'Failed to process {os.path.basename(passkey_file)}:\n{e}'
                )
                continue
        
        colour_print(
            colour=bcolors.FAIL, 
            component='Authenticator_validate_pin',
            msg='No valid pin found!'
        )
        return None

    @classmethod
    def _is_fido_home_valid(cls) -> bool:
        """
        Checks if the FIDO_HOME environment variable exists and points to a valid directory.
        
        Returns:
            bool: True if FIDO_HOME is valid, False otherwise
        """
        if "FIDO_HOME" not in os.environ:
            logging.debug("FIDO_HOME not set, can't do much . . .")
            return False
            
        fido_home_dir = os.path.realpath(os.environ["FIDO_HOME"])
        if not os.path.exists(fido_home_dir):
            logging.debug("FIDO_HOME directory not found, can't do much . . .")
            return False
            
        return True

    @classmethod
    def _get_passkey_files(cls, directory: str) -> typing.List[str]:
        """
        Returns a list of valid .passkey files in the specified directory.
        Only returns .passkey files that have corresponding .stash files.
        
        Args:
            directory: The directory to search for .passkey files
            
        Returns:
            A list of full paths to .passkey files
        """
        passkey_files = []
        for filename in os.listdir(directory):
            if filename.endswith('.passkey'):
                passkey_path = os.path.join(directory, filename)
                
                # Check for corresponding .stash file
                base_name = filename[:-8]  # Remove .passkey
                stash_path = os.path.join(directory, base_name + '.stash')
                
                if os.path.exists(stash_path):
                    passkey_files.append(passkey_path)
                else:
                    colour_print(
                        colour=bcolors.WARNING,
                        component='Authenticator_validate_pin',
                        msg=f'{filename} missing corresponding .stash file'
                    )
            elif not filename.endswith('.stash'):
                colour_print(
                    colour=bcolors.WARNING,
                    component='Authenticator_validate_pin',
                    msg=f'{filename} has invalid file type'
                )
        return passkey_files

    @classmethod
    def _validate_and_create_keypair(cls, passkey, passkey_file):
        """
        Validates passkey structure and creates KeyPair.
        
        Args:
            passkey: Decrypted passkey dictionary
            passkey_file: Path to passkey file (for error messages)
            
        Returns:
            Tuple of (x5c certificate bytes, KeyPair instance)
            
        Raises:
            ValueError: If key is not valid
        """
        ca_x5c = passkey.get('x5c')
        key = passkey.get('key')
        
        if isinstance(key, ec.EllipticCurvePrivateKey):
            return ca_x5c, KeyPair(key, key.public_key())
        
        raise ValueError(
            f"Key in {passkey_file} must be an EllipticCurvePrivateKey or KeyPair, got {type(key)}. "
            f"The passkey file may be corrupted. Please recreate it."
        )

    @classmethod
    def _process_passkey_file(cls, passkey_file: str, pinHash: bytes, cid: bytes) -> typing.Optional[bytes]:
        """
        Attempts to decrypt and process a passkey file.
        
        Args:
            passkey_file: Path to the passkey file
            pinHash: The hash of the PIN to validate
            cid: The channel ID to associate with the opened keys
            
        Returns:
            A PIN authentication token if processing succeeds, None otherwise
            
        Raises:
            Various exceptions if file processing fails
        """
        passkey = KeyUtils._load_passkey(pinHash, passkey_file) 
        colour_print(
            colour=bcolors.OKPINK, 
            component='Authenticator_validate_pin',
            msg='Pin decrypted a .passkey file'
        )
        ca_x5c, key_pair = cls._validate_and_create_keypair(passkey, passkey_file)
        cls._pin_retry = 5
        
        # Generate authentication token
        pin_auth_token = secrets.token_bytes(32)

        with cls._lock:
            existing_pin_token_kp = cls._open_keys.get(cid, {}).get('pin_token_kp')

            cls._open_keys[cid] = {
                'x5c': ca_x5c,
                'kp': key_pair,
                'file': passkey_file,
                'ph': pinHash,
                'pinAuth': pin_auth_token,
                'pin_token_kp': existing_pin_token_kp,  # Preserve the pin_token_kp
                'upv': 'verified',   # Correct PIN constitutes UV
                'tStart': time.time() # Extend the expiry time
            }
            return pin_auth_token


    @classmethod
    def get_pin_cose_key(cls, pin_req, cid):
        """
        Return the authenticator's public key for PIN protocol.
        """
        pin_token_kp = cls._get_or_create_pin_token_kp(cid)
        return {1: KeyUtils.get_cose_key(pin_token_kp.get_public(), hashes.SHA256(), eckx=True)}

    @classmethod
    def get_pin_retries(cls, pin_req, cid):
        cls._pin_retry -= 1
        return {3: cls._pin_retry}

    @classmethod
    def decapsulate(cls, ecCoseKey, cid: bytes):
        """
        Perform ECDH key exchange using the per-CID pin token key.
        """
        cose_type_to_curve_map = { #These are kind of made up, as per
        #https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#pinProto1
                    -25: ec.SECP256R1,
                    -26: ec.SECP521R1
                }
        ec_pub_numbs = ec.EllipticCurvePublicNumbers(KeyUtils._bytes_to_long(ecCoseKey[-2]),
                            KeyUtils._bytes_to_long(ecCoseKey[-3]),
                            cose_type_to_curve_map[ecCoseKey[3]]())
        pubkey = ec_pub_numbs.public_key()
        with cls._lock:
            if cid not in cls._open_keys or 'pin_token_kp' not in cls._open_keys[cid]:
                raise ValueError(f"Pin token key not found for CID {cid.hex()}")
            pin_token_kp = cls._open_keys[cid]['pin_token_kp']
        
        shared_point = pin_token_kp.get_private().exchange(ec.ECDH(), pubkey)
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(shared_point)
        return hasher.finalize()

    @classmethod
    def get_pin_token(cls, pin_req, cid):
        #https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#getPinToken
        logging.debug(f"pin_req: {pin_req}")
        platform_cose_key = pin_req[3]
        pin_hash_enc = pin_req[6]
        colour_print(colour=bcolors.OKPINK, component='Authenticator.get_pin_token',
                     msg='plat cose key: {}; pinHashEnc: {}'.format(platform_cose_key, pin_hash_enc))
        sharedSecret = cls.decapsulate(platform_cose_key, cid)
        colour_print(colour=bcolors.OKPINK, component='Authenticator.get_pin_token',
                     msg='shared secret: {};'.format(sharedSecret))
        cipher = Cipher(algorithms.AES256(sharedSecret), modes.CBC(bytes([0] * 16))) # nosemgrep part of the CTAP2 spec
        decryptor = cipher.decryptor() # nosemgrep
        pin_hash = decryptor.update(pin_hash_enc) + decryptor.finalize()
        pinAuthToken = cls._validate_pin(pin_hash, cid)
        if pinAuthToken != None:
            encryptor = cipher.encryptor()
            pinAuthTokenEnc = encryptor.update(pinAuthToken) + encryptor.finalize()
            return {2: pinAuthTokenEnc}
        return None

    @classmethod
    def _validate_cid(cls, cid) -> bool:
        """Validate that CID exists in open keys."""
        return cid in cls._open_keys

    @classmethod
    def _validate_ca_keypair(cls, ca_kp) -> bool:
        """Validate that CA keypair is valid KeyPair instance."""
        return isinstance(ca_kp, KeyPair)

    @classmethod
    def _resolve_passkey(cls, options, cid):
        """
        Resolve the signing keypair based on user authentication strength.
        Preference unlocked .passkey file

        Returns: (passkey_dict, resident_creds, attestation_type, request_rk)
        """
        options = options or {}
        req_rk = options.get('rk', False)
        user_state = cls.get_user_state(cid)
        if user_state == "verified":
            passkey = cls._open_keys[cid] # Strongest path: user was verified via PIN/biometric
            if isinstance(passkey, dict) and 'ph' in passkey:
                colour_print(colour=bcolors.OKGREEN, component='AuthenticatorAPI._resolve_passkey',
                            msg='UV context - using pin protected .passkey file key')
                res_creds = KeyUtils._load_passkey(passkey['ph'],
                                                passkey['file']).get('res.creds')
                return passkey, res_creds, 'packed', req_rk
        else:
            colour_print(colour=bcolors.OKGREEN, component='AuthenticatorAPI._resolve_passkey',
                        msg='UP context - using platform key')
        return { # Fallback: use platform key
            'kp': KeyUtils._get_platform_kp()
        }, None, 'packed-self', False


    @classmethod
    def _check_credential_excluded(cls, rp_id: str, user_id: bytes, res_creds) -> bool:
        """
        Check if credential already exists for rpID:userID combination.
        Returns True if credential should be excluded.
        """
        if not res_creds:
            return False
        
        for cred in res_creds:
            if rp_id == cred['rp.id'] and user_id == cred['user.id']:
                colour_print(
                    colour=bcolors.FAIL,
                    component='Authenticator.attestation_out',
                    msg=f'existing rpID and userID found: {rp_id}, {user_id}'
                )
                return True
        
        return False

    @classmethod
    def _select_algorithm(cls, pubKeyCredParams) -> int:
        """Select the best supported COSE algorithm from pubKeyCredParams.
        
        maybe try ML-DSA-44 (-48) if ES256 (-7) not offered.
        
        Args:
            pubKeyCredParams: List of public key credential parameters from the RP
            
        Returns:
            int: Selected COSE algorithm identifier
        """
        supported_algs = [
            int(param.get("alg"))
            for param in pubKeyCredParams
            if param.get("type") == "public-key"
        ]
        if -7 in supported_algs:
            return -7
        if -48 in supported_algs:
            return -48 #TODO check support for cert chain EC -> PQC
        # Fallback to ES256 if nothing matches
        return -7

    @classmethod
    def _get_hkdf_info(cls) -> str:
        """Load configured info string from platform configuration."""
        fido_home = os.environ.get('FIDO_HOME', os.path.expanduser('~/.fido'))
        return PlatformConfig(fido_home).info_string

    @classmethod
    def _create_authenticator(cls, rp_id: str, passkey, pubKeyCredParams) -> tuple[Fido2Authenticator, bytes]:
        """
        Create authenticator and derrive key.
        
        Args:
            rp_id: Relying party identifier
            passkey: Passkey data containing master key
            pubKeyCredParams: Public key credential parameters from RP
            
        Returns:
            tuple: (authenticator, keypair, credential_id)
        """
        ca_kp = passkey.get('kp')
        if ca_kp is None or not isinstance(ca_kp, KeyPair):
            raise RuntimeError("Corrupted Passkey Data")
        
        seed = KeyUtils.get_passkey_seed(
            rp_id.encode(),
            ca_kp if hasattr(ca_kp, 'is_tpm') else ca_kp.get_private(),
            info=cls._get_hkdf_info()
        )
        skey = SymmetricKey(seed.decode())
        
        authenticator = Fido2Authenticator(
            caKeyPair=ca_kp,
            caCert=passkey.get('x5c'),
            sKey=skey
        )
        
        cred_id = authenticator._get_credential_id_bytes(authenticator.kp)

        logging.debug(f"RP ID: {rp_id}")
        logging.debug(f"Credential ID (hex): {cred_id.hex()}")
        
        return authenticator, cred_id

    @classmethod
    def attestation_out(cls, clientDataHash, rp, user, pkCredsParams, excludeList, exts, options, cid):
        colour_print(colour=bcolors.OKPINK, component='Authenticator.attestation_out',
                     msg='open keys: {}'.format(cls._open_keys))

        try:
            passkey, res_creds, attestation, req_rk = cls._resolve_passkey(options, cid)
        except PermissionError as e:
            colour_print(colour=bcolors.FAIL, component='Authenticator.attestation_out', msg=str(e))
            return CBORStatusCode.CTAP2_ERR_PUAT_REQUIRED, None, None
        ca_kp = passkey.get('kp')
        if not cls._validate_ca_keypair(ca_kp):
            colour_print(
                colour=bcolors.OKPINK,
                component='Authenticator.attestation_out',
                msg="panic!"
            )
            return CBORStatusCode.CTAP1_ERR_OTHER, None, None
        
        if cls._check_credential_excluded(rp['id'], user['id'], res_creds):
            return CBORStatusCode.CTAP2_ERR_CREDENTIAL_EXCLUDED, None, None

        authenticator, cred_id = cls._create_authenticator(rp['id'], passkey, pkCredsParams)
        authData = authenticator.build_authenticator_data({'rp': rp}, 
                                attestation, authenticator.kp, uv=True, up=True, be=False, bs=False)
        colour_print(colour=bcolors.OKPINK, component='Authenticator.attestation_out',
                    msg=f'credId: {cred_id}; toSign: {base64.b64encode(bytes([*authData, *clientDataHash])).decode()}')
        attStmt = authenticator.process_attestation_statement(attestation,
                                                    clientDataHash, authData, None, authenticator.kp)
        colour_print(colour=bcolors.OKPINK, component='Authenticator.attestation_out', 
                     msg='attStmt: {}'.format(attStmt))
        if req_rk == True:
            colour_print(colour=bcolors.OKPINK, component='Authenticator.attestation_out',
                    msg=f"Storing resident credential in {passkey['file']}")
            KeyUtils.update_passkey({'cred.id': cred_id, 'user.id': user['id'], 'rp.id': rp['id']},
                                    passkey['ph'], passkey['file'])
        return None, authData, attStmt


    @classmethod
    def _maybe_next_assertion(cls, rpId, ca_kp, ca_x5c, clientDataHash, cred):
        seed = KeyUtils.get_passkey_seed(
            rpId.encode(),
            ca_kp.get_private(),
            info=cls._get_hkdf_info()
        )
        skey = SymmetricKey(seed.decode())

        logging.debug(f"RP ID: {rpId}")
        logging.debug(f"Credential ID (hex): {cred.get('id').hex()}")
        colour_print(colour=bcolors.OKPINK, component='FIDO2Authenticator.assertion_outputs',
                        msg='We have a usable key, sign the challenge')
        _authenticator = Fido2Authenticator(credId=cred.get('id'), aaguid=[0] * 16,
                                            caKeyPair=ca_kp, caCert=ca_x5c, sKey=skey)
        #Generate the assertion response data
        authData = _authenticator.build_authenticator_data({'rpId': rpId}, 'packed',
                                    _authenticator.kp, True, up=True, be=False, bs=False)
        sig = _authenticator.assertion_signature(authData, clientDataHash, _authenticator.kp)
        userHandle = cred.get("user")
        credential = {
                "id": cred.get('id'),
                "type" : "public-key"
            }
        return None, credential, authData, sig, userHandle


    @classmethod
    def _maybe_platform_assertion(cls, rpId, clientDataHash, allowedList):
        plat_key = KeyUtils._get_platform_kp()
        seed = KeyUtils.get_passkey_seed(
            rpId.encode(),
            plat_key if hasattr(plat_key, 'is_tpm') else plat_key.get_private(),
            info=cls._get_hkdf_info()
        )
        skey = SymmetricKey(seed.decode())
        
        for cred in allowedList:
            try:
                cred_id = cred.get('id')
                if not cred_id.startswith(Fido2Authenticator.CRED_PREFIX):
                    continue
                logging.debug(f"Credential ID (hex): {cred.get('id').hex()}")
                colour_print(colour=bcolors.OKPINK, component='FIDO2Authenticator.assertion_outputs',
                                msg='We have a usable key, sign the challenge')
                _authenticator = Fido2Authenticator(credId=cred_id, aaguid=[0] * 16,
                                                    caKeyPair=plat_key, caCert=None, sKey=skey)
                #Generate the assertion response data
                authData = _authenticator.build_authenticator_data({'rpId': rpId}, 'packed',
                                    _authenticator.kp, True, up=True, be=False, bs=False)
                sig = _authenticator.assertion_signature(authData, clientDataHash, _authenticator.kp)
                credential = {
                        "id": cred_id,
                        "type" : "public-key"
                    }
                return None, credential, authData, sig, None
            except Exception as e:
                colour_print(colour=bcolors.FAIL, component='FIDO2Authenticator.assertion_out',
                            msg=f'Could not retrieve key pair from credential id {cred} and platform KeyPair')
                logging.exception(e, stack_info=True)
                continue
        return CBORStatusCode.CTAP2_ERR_NO_CREDENTIALS, None, None, None, None

    @classmethod
    def assertion_out(cls, rpId, clientDataHash, allowedList, exts, cid):
        if cid in cls._open_keys.keys() and isinstance(cls._open_keys[cid].get('kp'), KeyPair): ## Try return a res cred assertion
            passkey = cls._open_keys[cid]
            ca_x5c = passkey.get('x5c')
            ca_kp = passkey.get('kp')
            if 'ph' in passkey and 'file' in passkey:
                resCreds = KeyUtils._load_passkey(passkey['ph'],
                            passkey['file']).get('res.creds')
                if resCreds != None and isinstance(resCreds, list):
                    colour_print(colour=bcolors.OKPINK, component='FIDO2Authenticator.assertion_out',
                                msg='passkey has resident credentials, adding them to allowed list')
                    for cred in resCreds:
                        if cred.get('rp.id') == rpId:
                            allowedList += [{'id': cred.get('cred.id'), 'user': cred.get('user.id')}]
                for cred in allowedList:
                    try:
                        return cls._maybe_next_assertion(rpId, ca_kp, ca_x5c, clientDataHash, cred)
                    except Exception as e:
                        colour_print(colour=bcolors.FAIL, component='FIDO2Authenticator.assertion_out',
                                    msg=f'Could not retrieve key pair from credential id {cred}')
                        logging.exception(e, stack_info=True)
                        continue
        ## No resident or passkeyCA credentials...try platform key
        return cls._maybe_platform_assertion(rpId, clientDataHash, allowedList)


    @classmethod
    def quit(cls):
        cls._quit = True
        if cls._watchdog:
            cls._watchdog.join()
