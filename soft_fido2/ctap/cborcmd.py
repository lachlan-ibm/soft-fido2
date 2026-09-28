# Copyright IBM Corp. 2022, 2025
# IBM Confidential

"""Per-message CTAP2 framing, CBOR command dispatch, and user-presence
orchestration.

Inner CommandByte / CBORStatusCode enums are imported from constants.
U2F (_u2f_*) methods delegate to U2FHandler.
"""

import os, threading, time, typing, logging, queue
import cbor2 as cbor
from cryptography.hazmat.primitives import hashes, hmac

from .constants import CommandByte, CBORStatusCode
from .api import AuthenticatorAPI
from .pending import KeepAliveWorker
from .packet import bcolors, colour_print, dump_bytes
from .u2fapi import U2FHandler

from ..platform.message_queues import QueueMessageType, MessageQueue
from ..qt.ux.config import PlatformConfig


class CBORCommand(object):

    # Keep as class attributes for backward-compatibility with any code that
    # does  CBORCommand.CommandByte  or  CBORCommand.CBORStatusCode
    CommandByte    = CommandByte
    CBORStatusCode = CBORStatusCode

    cid = 0xFFFFFFFF
    request = []
    response: list[int] = []
    response_segment = 0
    response_ready = False
    length = 0
    request_segment = 0
    sequence_buffer = {}  # {seq_num: bytes}
    cmd = None
    ctaphid_cmd = 0
    bcnt = 0
    _pending = None

    def __init__(self, cid, ba, skip_init=False):
        self.cid = cid
        if ba == None and skip_init == True:
            return #Create an empty command as we will directly set the response buffer later with the assigned CID.
        if len(ba) <= 1:
            colour_print(colour=bcolors.OKYELLOW, component='CBORCommand.__init__', 
                    msg="Byte Array must be at least one byte long")
        # Length of the incoming CBOR message (total).
        self.length = int.from_bytes(ba[0:2], 'big') - 1 # subtract CMD byte
        # Request buffer. This stores the incoming CBOR message and grows until all segments have been received
        self.request = ba[3:]
        # Track then number of response segments transmitted, the number transmitted in the continue sequence packet
        # should always be one less than this number
        self.response_segment = 0
        # Track the number of request segments received
        self.request_segment = 0
        self.sequence_buffer = {}
        # Response buffer. This stores the outgoing response to the received CBOR message and shrinks until the entire
        # response has been transmitted
        self.response = []
        # Command received in CTAPHID frame, this is likely 0x90 (CBOR_MSG) but might be different
        self.ctaphid_cmd = 0
        # Authenticator API command byte received in initial packet
        self.cmd = self.CommandByte(int.from_bytes(ba[2:3], 'big'))
        #Length of the payload bytes
        self.bcnt = 0
        # Signal that the response buffer is ready to be sent back to the client
        self.response_ready = False
        colour_print(colour=bcolors.OKPURPLE, component='CBORCommand.__init__', 
                msg="command {}; length {}; self.request[{}]".format(self.cmd, self.length, len(self.request)))
        if self.length >= len(self.request):
            colour_print(colour=bcolors.OKPURPLE, component='CBORCommand.__init__', 
                    msg="request is segmented, wait for the whole message")
        else: #We have the whole message
            self.unpack()
            dump_bytes(self.response, colour=bcolors.OKPINK,
                       component='CBORCommand.__init__', msg='CTAP response')

    def append_segment(self, seg_buf, seq_num):
        """Append segment data, handling out-of-order packets.
        
        Args:
            seg_buf: Segment data bytes
            seq_num: Sequence number (required for out-of-order handling)
        """
        colour_print(colour=bcolors.OKBLUE, component='CBORCommand.append_segment',
                    msg=f'seq [{seq_num}], expecting [{self.request_segment}], len={len(self.request)}/{self.length}')
        
        # Check if this is the expected sequence
        if seq_num == self.request_segment:
            # Expected sequence - append it
            self.request_segment += 1
            self.request += seg_buf
            colour_print(colour=bcolors.OKGREEN, component='CBORCommand.append_segment',
                        msg=f'Appended seq [{seq_num}], now expecting [{self.request_segment}], len={len(self.request)}/{self.length}')
            
            # Process any buffered sequences now in order
            while self.request_segment in self.sequence_buffer:
                buffered = self.sequence_buffer.pop(self.request_segment)
                self.request_segment += 1
                self.request += buffered
                colour_print(colour=bcolors.OKGREEN, component='CBORCommand.append_segment',
                            msg=f'Processed buffered seq, now expecting [{self.request_segment}], len={len(self.request)}/{self.length}')
        elif seq_num > self.request_segment:
            # Future sequence - buffer it
            self.sequence_buffer[seq_num] = seg_buf
            colour_print(colour=bcolors.WARNING, component='CBORCommand.append_segment',
                        msg=f'Buffered out-of-order seq [{seq_num}], expecting [{self.request_segment}]')
            return
        else:
            colour_print(colour=bcolors.WARNING, component='CBORCommand.append_segment',
                        msg=f'Ignoring old/duplicate seq [{seq_num}], expecting [{self.request_segment}]')
            return
        
        # Check if message is complete
        colour_print(colour=bcolors.OKBLUE, component='CBORCommand.append_segment',
                    msg=f'Checking completion: len={len(self.request)} >= {self.length}?')
        if len(self.request) >= self.length:
            colour_print(colour=bcolors.OKGREEN, component='CBORCommand.append_segment',
                        msg='Message complete, unpacking...')
            self.unpack()
            dump_bytes(self.response, colour=bcolors.OKPINK,
                       component='CBORCommand.append_segment', msg='CTAP response')

    def _error(self, ba):
        self.response = list(self.CBORStatusCode.CTAP1_ERR_INVALID_COMMAND.to_bytes(1, 'big'))
        self.bcnt = 0
        self.response_ready = True

    #Return CBOR response if entire command has been received or None if still 
    #waiting for segments
    def unpack(self):
        if self.cmd == None:
            return self._error(None)
        return {
            self.CommandByte.MAKE_CREDENTIAL: self._make_cred,
            self.CommandByte.GET_NEXT_ASSERTION: self._get_assertion,
            self.CommandByte.GET_INFO: self._get_info,
            self.CommandByte.CLIENT_PIN: self._client_pin,
            self.CommandByte.AUTHENTICATOR_SELECTION: self._auth_select
            }.get(self.cmd, self._error)(bytes(self.request))

    def _set_rsp_fields(self, rsp=[]):
        self.response = rsp
        self.bcnt = len(rsp)
        self.response_ready = True

    def get_rsp_seg(self, num_bytes):
        if not isinstance(num_bytes, int):
            raise RuntimeError("panic!")
        self.response_segment += 1
        #sequence is offset by two to account for init pkt and zero index start for continue sequence
        seg_num = max(self.response_segment - 2, 0)
        colour_print(colour=bcolors.WARNING, component='CBORCommand.get_rsp_seg', 
                msg='self.response_segment = {}'.format(self.response_segment))
        colour_print(colour=bcolors.WARNING, component='CBORCommand.get_rsp_seg', 
                msg='self.response_segment - 2 = {}'.format(self.response_segment - 2))
        colour_print(colour=bcolors.WARNING, component='CBORCommand.get_rsp_seg', 
                msg='segment number = {}'.format(seg_num))
        seg = self.response
        if num_bytes >= len(self.response):
            self.response = []
        else:
            seg = self.response[:num_bytes]
            self.response = self.response[num_bytes:]
        return seg, seg_num

    @classmethod
    def set_pending(cls, pending):
        cls._pending = pending

    def prompt_for_fprint(self, result_queue):
        """
        Run fingerprint verification in parallel with GUI prompt.
        Puts result in queue when complete.
        
        Args:
            result_queue: Queue to put the verification result ('fprint', True/None)
        """
        from soft_fido2.platform import get_biometric_device as get_fprint_device, BiometricResult
        fprint_device = get_fprint_device()
        if not fprint_device.is_available():
            result_queue.put(('fprint', None))
            return
            
        colour_print(colour=bcolors.OKBLUE, component='Authenticator.gather_user_presence',
                    msg='Starting fingerprint verification...')
        
        # Callback for when VerifyFingerSelected signal is received
        def on_finger_needed(finger_name):
            colour_print(colour=bcolors.OKBLUE, component='Authenticator.gather_user_presence',
                        msg=f'Place {finger_name} finger on scanner')
        
        result, message = fprint_device.verify_with_retries(
            username=None,
            on_finger_needed=on_finger_needed,
            timeout=15.0,
            max_retries=3
        )
        
        if result == BiometricResult.SUCCESS:
            colour_print(colour=bcolors.OKGREEN, component='Authenticator.gather_user_presence',
                        msg='Fingerprint verified - cancelling GUI prompt')
            MessageQueue.notify_sysapp.put(QueueMessageType.AUTH_RESPONSE)
            result_queue.put(('fprint', True)) # Cancel any pending GUI notifications
        else:
            colour_print(colour=bcolors.WARNING, component='Authenticator.gather_user_presence',
                        msg=f'Fingerprint verification failed: {message}')
            result_queue.put(('fprint', None))


    def gather_user_presence(self, context='default'):
        """
        Gather user presence with concurrent fingerprint and GUI verification.
        
        Args:
            context: Context for the UP request - 'getinfo', 'makecred', 'getassertion', or 'default'
                    This determines the keepalive status code sent to the client.
        
        Authentication adapts to credential type and UV requirements:
        - Passkey + UV Required/Preferred: PIN (already validated) + Fingerprint
        - UV Discouraged: Fingerprint only
        - 2nd Factor: Fingerprint only
        
        Both fingerprint and GUI can run concurrently. Whichever completes first wins.
        """
        if os.environ.get('SOFT_FIDO2_SKIP_UP', 'False').lower() in ['y', 'yes', '1', 'true', 't']:
            colour_print(colour=bcolors.WARNING, component='Authenticator.gather_user_presence',
                    msg='Skipping user presence check')
            AuthenticatorAPI.cache_up(self.cid, "verified")
            return True
        
        if AuthenticatorAPI.has_cached_up(self.cid):
            colour_print(colour=bcolors.OKGREEN, component='Authenticator.gather_user_presence',
                    msg=f'Using cached UP for context: {context}')
            return True
        
        
        result_queue = queue.Queue()
        
        from soft_fido2.platform import get_biometric_device as get_fprint_device
        fprint_device = get_fprint_device()
        fprint_available = fprint_device.is_available()
        
        # Start bioauth thread if available
        fprint_thread = None
        if fprint_available:
            try:
                fprint_thread = threading.Thread(
                    target=self.prompt_for_fprint,
                    args=(result_queue,),
                    daemon=True
                )
                fprint_thread.start()
                colour_print(colour=bcolors.OKBLUE, component='Authenticator.gather_user_presence',
                            msg='Started fingerprint verification thread')
            except ImportError:
                # D-Bus Python bindings not installed
                fprint_available = False
        
        # Start GUI prompt (always show this)
        colour_print(colour=bcolors.OKBLUE, component='Authenticator.gather_user_presence',
                    msg=f'Starting GUI prompt for user presence (context: {context})')
        start_time = time.time()
        MessageQueue.notify_auth.queue.clear()
        MessageQueue.notify_sysapp.put(
            QueueMessageType.USER_REQUEST_FPRINT if fprint_thread is not None
            else QueueMessageType.USER_REQUEST)
  
        status_code = 0x02 # = STATUS_UPNEEDED (waiting for user presence)        
        colour_print(colour=bcolors.OKBLUE, component='Authenticator.gather_user_presence',
                    msg=f'Starting KeepAliveWorker with status_code=0x{status_code:02x} (STATUS_UPNEEDED)')
        worker = KeepAliveWorker(self._pending, self.cid, status_code=status_code)
        worker.start()
        
        # Poll for results from either fingerprint or GUI
        gui_msg = None
        fprint_result = None
        current_time = time.time()
        
        while current_time - start_time < 15:
            time.sleep(0.002)
            current_time = time.time()
            
            # Check for fingerprint result
            if fprint_available and not fprint_result and not result_queue.empty():
                source, fprint_result = result_queue.get()
                if fprint_result:  # Fingerprint succeeded
                    colour_print(colour=bcolors.OKGREEN, component='Authenticator.gather_user_presence',
                                msg='Fingerprint verification succeeded')
                    worker.interrupt()
                    worker.join()
                    AuthenticatorAPI.cache_up(self.cid, "verified")
                    return True
                # If fingerprint failed, continue waiting for GUI
            
            # Check for GUI click
            if MessageQueue.notify_auth.qsize() > 0:
                gui_msg = MessageQueue.notify_auth.get()
                if gui_msg == QueueMessageType.USER_RESPONSE_ACCEPT:
                    colour_print(colour=bcolors.OKGREEN, component='Authenticator.gather_user_presence',
                                msg='GUI click accepted')
                    worker.interrupt()
                    worker.join()
                    AuthenticatorAPI.cache_up(self.cid, "verified")
                    return True
                else: # User rejected, CLOSE_EVENT, or timeout. Signal the UI to dismiss the notification
                    MessageQueue.notify_sysapp.put(QueueMessageType.AUTH_RESPONSE)
                    break
        
        # Cleanup
        worker.interrupt()
        worker.join()
        time.sleep(0.002)  # Maybe wait for out to sync
        
        colour_print(colour=bcolors.FAIL, component='Authenticator.gather_user_presence',
                    msg=f'User presence denied or timeout for context: {context}')
        return False

    def _verify_pin_token(self, clientDataHash, pinUvAuthParam):
        if pinUvAuthParam not in [None, b'']:
            pinAuth = AuthenticatorAPI.get_pin_auth_token(self.cid)
            # Verify token using client data hash
            h = hmac.HMAC(pinAuth, hashes.SHA256())
            h.update(clientDataHash)
            sig = h.finalize()
            if pinUvAuthParam != sig[:16]: # valid if the first 16 bytes of sig match req pinUvAuthParam
                return False
            return True
        return False

    def _client_pin(self, ba):
        # https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#authenticatorClientPIN
        pin_sub_cmds = { 
                      1: AuthenticatorAPI.get_pin_retries,
                      2: AuthenticatorAPI.get_pin_cose_key,
            #SET_PIN = 0x3
            #CHANGE_PIN = 0x4
                      5: AuthenticatorAPI.get_pin_token
                }
        req_data = cbor.loads(ba)
        colour_print(colour=bcolors.OKGREEN, component='CBORCommand._client_pin',
                     msg='Packet request: {}'.format(req_data))
        sub_cmd = req_data[2]
        colour_print(colour=bcolors.OKGREEN, component='CBORCommand._client_pin',
                     msg='pin sub_cmd: {}'.format(sub_cmd))
        rsp = pin_sub_cmds[sub_cmd](req_data, self.cid)
        result = (self.CBORStatusCode.CTAP2_ERR_PIN_INVALID).to_bytes(1, 'big')
        if rsp != None:
            result = (self.CBORStatusCode.CTAP2_OK).to_bytes(1, 'big') + cbor.dumps(rsp)
        return self._set_rsp_fields(list(result))


    # authenticatorSelection - return ok if UP; else error
    def _auth_select(self, _):
        result = (self.CBORStatusCode.CTAP2_ERR_OPERATION_DENIED).to_bytes(1, 'big')
        if AuthenticatorAPI.has_cached_up(self.cid):
            result = (self.CBORStatusCode.CTAP2_OK).to_bytes(1, 'big')
        return self._set_rsp_fields(list(result))


    # authenticatorGetInfo - now gathers user presence before returning info
    def _get_info(self, _):
        # Gather user presence with keepalive support
        if not self.gather_user_presence(context='getinfo'):
            colour_print(colour=bcolors.FAIL, component='CBORCommand._get_info',
                        msg='User presence verification failed or denied')
            return self._set_rsp_fields(
                list((self.CBORStatusCode.CTAP2_ERR_OPERATION_DENIED).to_bytes(1, 'big'))
            )

        fido_home = os.environ.get('FIDO_HOME', os.path.expanduser('~/.fido'))
        ctap1_mode = (PlatformConfig(fido_home).ctap_version == PlatformConfig.CTAP_VERSION_CTAP1)

        result: dict[int, typing.Any] = {
            0x01: ["FIDO_2_1", "FIDO_2_0"],
            0x02: ['hmac-secret'],
            #0x03: b"\xF1D0" * 4,
            0x03: b"\x00" * 16,
            0x04: {'rk': True, 'up': True, 'plat': False, 'clientPin': True},
            0x05: 1200,
            0x06: [1],
        }

        if ctap1_mode:
            result[0x01] = ["FIDO_2_0", "U2F_V2"]
            result[0x04] = {'up': True, 'plat': False}
            del result[0x06]
            colour_print(colour=bcolors.OKBLUE, component='CBORCommand._get_info',
                        msg='CTAP1 mode: advertising U2F_V2, no PIN protocol')
        else:
            colour_print(colour=bcolors.OKBLUE, component='CBORCommand._get_info',
                        msg='CTAP2 mode: advertising FIDO_2_1 with PIN protocol')

        result_bytes = bytes((self.CBORStatusCode.CTAP2_OK).to_bytes(1, 'big') + cbor.dumps(result))
        logging.debug(f"len: {len(result_bytes)}")
        return self._set_rsp_fields(list(result_bytes))

    def _make_cred(self, ba):
        # https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#authenticatorMakeCredential
        # Verify UP/UV was already gathered during getInfo
        if not AuthenticatorAPI.has_cached_up(self.cid):
            colour_print(colour=bcolors.FAIL, component='CBORCommand._make_cred',
                        msg='UP not cached - should have been gathered in getInfo')
            return self._set_rsp_fields(list((self.CBORStatusCode.CTAP2_ERR_OPERATION_DENIED).to_bytes(1, 'big')))
        
        req = cbor.loads(ba)
        colour_print(colour=bcolors.FAIL, component='CBORCommand._make_cred',
                     msg='CBOR request {}'.format(req))
        for prop in [(0x01, 'clientDataHash'), (0x02, 'rp'), (0x03, 'user'), (0x04, 'pubkeyCredParams')]:
            if not prop[0] in req.keys():
                colour_print(colour=bcolors.FAIL, component='CBORCommand._make_cred',
                             msg='{} missing from request:\n{}'.format(prop[1], cbor.dumps(req)))
                logging.debug("Missing required property %s" % prop[1])
                return self._set_rsp_fields( list((self.CBORStatusCode.CTAP2_ERR_MISSING_PARAMETER).to_bytes(1, 'big')) )

        # Get user authentication state and options
        options = req.get(0x07, {})
        rk_required = options.get('rk', False)
        uv_required = options.get('uv', False)        
        if uv_required and AuthenticatorAPI.get_user_state(self.cid) != "verified": # only ask for lock if uv in req
            colour_print(colour=bcolors.FAIL, component='CBORCommand._make_cred',
                        msg='UV required by RP but not provided by user')
            return self._set_rsp_fields(list((self.CBORStatusCode.CTAP2_ERR_PUAT_REQUIRED).to_bytes(1, 'big')))
        
        pinAuth = req.get(0x08)
        if pinAuth: # If pinAuth is present, validate it
            result = (self.CBORStatusCode.CTAP2_ERR_PUAT_REQUIRED).to_bytes(1, 'big')
            if not self._verify_pin_token(req.get(0x01), pinAuth):
                if self.cid in AuthenticatorAPI._open_keys:
                    result = (self.CBORStatusCode.CTAP2_ERR_PIN_AUTH_INVALID).to_bytes(1, 'big')
                return self._set_rsp_fields(list(result))
        error, authData, attStmt = AuthenticatorAPI.attestation_out(req.get(0x01), req.get(0x02), req.get(0x03),
                                            req.get(0x04), req.get(0x05), req.get(0x06), 
                                            req.get(0x07, None), self.cid)
        result = (self.CBORStatusCode.CTAP1_ERR_OTHER).to_bytes(1, 'big')
        if error:
            result = error.to_bytes(1, 'big')
        if authData and attStmt:
            rsp = {
                0x01: 'packed', #fmt
                0x02: authData,
                0x03: attStmt
            }
            result = (self.CBORStatusCode.CTAP2_OK).to_bytes(1, 'big') + cbor.dumps(rsp)
        return self._set_rsp_fields(list(result))

    # --- U2F delegation ---

    def _u2f_rsp(self, cid, cmd_byte: int, payload: bytes,
                 sw: bytes = b'\x90\x00') -> 'CBORCommand':
        """Build a U2F APDU response CBORCommand."""
        return U2FHandler.build_response(cid, cmd_byte, payload, CBORCommand, sw=sw)

    def _u2f_req(self, cid, cmd_byte: int, apdu: bytes) -> 'CBORCommand':
        """Parse the CTAPHID_MSG APDU and dispatch to the appropriate U2F handler."""
        return U2FHandler.dispatch(cid, cmd_byte, apdu, CBORCommand)

    def _get_assertion(self, ba):
        # https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#authenticatorGetAssertion
        # Verify UP was already gathered during getInfo
        if not AuthenticatorAPI.has_cached_up(self.cid):
            colour_print(colour=bcolors.FAIL, component='CBORCommand._get_assertion',
                        msg='UP not cached - should have been gathered in getInfo')
            return self._set_rsp_fields(list((self.CBORStatusCode.CTAP2_ERR_OPERATION_DENIED).to_bytes(1, 'big')))
        
        req = cbor.loads(ba)
        colour_print(colour=bcolors.FAIL, component='CBORCommand._get_assertion',
                     msg='CBOR request {}'.format(req))
        for prop in [(0x01, 'rpId'), (0x02, 'clientDataHash')]:
            if not prop[0] in req:
                colour_print(colour=bcolors.FAIL, component='CBORCommand._get_assertion',
                             msg='{} missing from request:\n{}'.format(prop[1], cbor.dumps(req)))
                logging.debug("Missing required property %s" % prop[1])
                return self._set_rsp_fields( list((self.CBORStatusCode.CTAP2_ERR_MISSING_PARAMETER).to_bytes(1, 'big')) )
        
        pinAuth = req.get(0x06)
        options = req.get(0x05, {})
        uv_required = options.get('uv', False)
        if uv_required and not pinAuth: # If UV is required but pinAuth is missing, fail
            colour_print(colour=bcolors.FAIL, component='CBORCommand._get_assertion',
                        msg='UV required but pinAuth missing')
            return self._set_rsp_fields(list((self.CBORStatusCode.CTAP2_ERR_PUAT_REQUIRED).to_bytes(1, 'big')))

        if pinAuth: # If pinAuth is present, validate it
            if not self._verify_pin_token(req.get(0x02), pinAuth):
                result = (self.CBORStatusCode.CTAP2_ERR_PUAT_REQUIRED).to_bytes(1, 'big')
                if self.cid in AuthenticatorAPI._open_keys:
                    result = (self.CBORStatusCode.CTAP2_ERR_PIN_AUTH_INVALID).to_bytes(1, 'big')
                return self._set_rsp_fields(list(result))
        
        error, credential, authData, signature, userHandle = AuthenticatorAPI.assertion_out(req.get(0x01),
                                                req.get(0x02), req.get(0x03, []), req.get(0x04, {}), self.cid)
        result = (self.CBORStatusCode.CTAP1_ERR_OTHER).to_bytes(1, 'big')
        if error:
            result = error.to_bytes(1, 'big')
        elif credential and authData and signature:
            rsp = {
                    0x01: credential,
                    0x02: authData,
                    0x03: signature
            }
            if userHandle:
                rsp[0x04] = {'id': userHandle}
            result = (self.CBORStatusCode.CTAP2_OK).to_bytes(1, 'big') + cbor.dumps(rsp)
        return self._set_rsp_fields(list(result))
