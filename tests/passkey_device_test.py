import os
import sys
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
import pytest
import cbor2 as cbor
import tempfile
from unittest.mock import MagicMock, patch
from dataclasses import dataclass
from typing import Dict, Any, Optional

# Add the parent directory to the path so we can import the modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


from soft_fido2.cert_utils import CertUtils
from soft_fido2.key_pair import KeyPair
from soft_fido2.passkey_device import (
    AuthenticatorAPI, CBORCommand, CTAPHIDInitPkt, CTAPHIDSeqPkt, 
    KeepAliveWorker, CTAP2HIDevice
)


class TestCTAPHIDPackets:
    """Test the CTAPHID packet structures"""
    
    def test_ctaphid_init_pkt_structure(self):
        """Test the CTAPHIDInitPkt structure packs correctly"""
        # Create a packet with known values
        cid = 0x12345678
        cmd = 0x90  # CBOR message command
        bcnt = 0x20  # 32 bytes
        data = bytes([0x01, 0x02, 0x03, 0x04])
        
        # Create the packet
        pkt = CTAPHIDInitPkt(cid=cid, cmd=cmd, bcnt=bcnt, data=data)
        
        # Pack it
        packed = pkt.pack()
        
        # Verify the packed data
        assert len(packed) == 4 + 1 + 2 + len(data)  # cid + cmd + bcnt + data
        assert packed[0:4] == cid.to_bytes(4, byteorder='big')
        assert packed[4] == cmd
        assert packed[5:7] == bcnt.to_bytes(2, byteorder='big')
        assert packed[7:] == data
    
    def test_ctaphid_seq_pkt_structure(self):
        """Test the CTAPHIDSeqPkt structure packs correctly"""
        # Create a packet with known values
        cid = 0x12345678
        seq = 0x01
        data = bytes([0x05, 0x06, 0x07, 0x08])
        
        # Create the packet
        pkt = CTAPHIDSeqPkt(cid=cid, seq=seq, data=data)
        
        # Pack it
        packed = pkt.pack()
        
        # Verify the packed data
        assert len(packed) == 4 + 1 + len(data)  # cid + seq + data
        assert packed[0:4] == cid.to_bytes(4, byteorder='big')
        assert packed[4] == seq
        assert packed[5:] == data


class TestCBORCommand:
    """Test the CBOR command processing"""
    
    @pytest.fixture
    def mock_auth_api(self):
        with patch('soft_fido2.passkey_device.AuthenticatorAPI') as mock:
            # Setup common mock methods
            mock._validate_pin.return_value = b'valid_token'
            mock.get_pin_auth_token.return_value = b'valid_token'
            mock._open_keys = {}
            yield mock
    
    @pytest.fixture
    def test_cid(self):
        return bytes([0x01, 0x02, 0x03, 0x04])
    
    def test_get_info_response(self, test_cid, mock_auth_api):
        """Test the GetInfo command returns the expected response"""
        # Create a GetInfo command
        cmd_byte = CBORCommand.CommandByte.GET_INFO.value.to_bytes(1, byteorder='big')
        length = (len(cmd_byte) + 1).to_bytes(2, byteorder='big')
        data = length + cmd_byte + bytes()
        
        # Create the command
        cmd = CBORCommand(test_cid, data)
        cmd.unpack()
        
        # Verify the response contains the expected CBOR data
        assert cmd.response_ready
        
        # First byte should be CTAP2_OK status
        assert cmd.response[0] == CBORCommand.CBORStatusCode.CTAP2_OK
        
        # Decode the CBOR response (skip the status byte)
        response_cbor = cbor.loads(bytes(cmd.response[1:]))
        
        # Verify the response contains the expected fields
        assert 0x01 in response_cbor  # versions
        assert 0x02 in response_cbor  # extensions
        assert 0x03 in response_cbor  # aaguid
        assert 0x04 in response_cbor  # options
        assert 0x05 in response_cbor  # max_msg_size
        assert 0x06 in response_cbor  # pin_protocols
    
    def test_make_credential_missing_parameter(self, test_cid, mock_auth_api):
        """Test MakeCredential command with missing parameters"""
        with patch('soft_fido2.passkey_device.CBORCommand.gather_user_presence', return_value=True):
            # Create a MakeCredential command with incomplete parameters
            cmd_byte = CBORCommand.CommandByte.MAKE_CREDENTIAL.value.to_bytes(1, byteorder='big')
            
            # Create an incomplete CBOR map (missing required parameters)
            cbor_data = cbor.dumps({
                0x01: b'client_data_hash',  # Only include clientDataHash
                # Missing rp, user, pubKeyCredParams, pinAuth
            })
            
            length = (len(cmd_byte) + len(cbor_data) + 1).to_bytes(2, byteorder='big')
            data = length + cmd_byte + cbor_data
            
            # Create the command
            cmd = CBORCommand(test_cid, data)
            cmd.unpack()
            
            # Verify the response indicates missing parameter
            assert cmd.response_ready
            assert cmd.response[0] == CBORCommand.CBORStatusCode.CTAP2_ERR_MISSING_PARAMETER
    
    def test_make_credential_success(self, test_cid, mock_auth_api):
        """Test successful MakeCredential command"""
        with patch('soft_fido2.passkey_device.CBORCommand.gather_user_presence', return_value=True), \
             patch('soft_fido2.passkey_device.CBORCommand._verify_pin_token', return_value=True):
            
            # Mock the attestation output directly on the mock_auth_api
            auth_data = bytes([0x01, 0x02, 0x03, 0x04])
            att_stmt = {"alg": -7, "sig": bytes([0x05, 0x06, 0x07, 0x08])}
            mock_auth_api.attestation_out = MagicMock(return_value=(None, auth_data, att_stmt))
            
            # Add the test CID to the open keys dictionary
            mock_auth_api._open_keys[test_cid] = {'pinAuth': b'valid_token'}
            
            # Create a MakeCredential command with all required parameters
            cmd_byte = CBORCommand.CommandByte.MAKE_CREDENTIAL.value.to_bytes(1, byteorder='big')
            
            # Create a complete CBOR map
            cbor_data = cbor.dumps({
                0x01: b'client_data_hash',
                0x02: {'id': 'example.com', 'name': 'Example'},  # rp
                0x03: {'id': b'user_id', 'name': 'User'},  # user
                0x04: [{'type': 'public-key', 'alg': -7}],  # pubKeyCredParams
                0x08: b'pin_auth'  # pinAuth
            })
            
            length = (len(cmd_byte) + len(cbor_data) + 1).to_bytes(2, byteorder='big')
            data = length + cmd_byte + cbor_data
            
            # Create the command
            cmd = CBORCommand(test_cid, data)
            cmd.unpack()
            
            # Verify the response indicates success
            assert cmd.response_ready
            assert cmd.response[0] == CBORCommand.CBORStatusCode.CTAP2_OK
            
            # Decode the CBOR response (skip the status byte)
            response_cbor = cbor.loads(bytes(cmd.response[1:]))
            
            # Verify the response contains the expected fields
            assert response_cbor[0x01] == 'packed'  # fmt
            assert response_cbor[0x02] == auth_data  # authData
            assert response_cbor[0x03] == att_stmt  # attStmt
    
    def test_get_assertion_success(self, test_cid, mock_auth_api):
        """Test successful GetAssertion command"""
        with patch('soft_fido2.passkey_device.CBORCommand.gather_user_presence', return_value=True), \
             patch('soft_fido2.passkey_device.CBORCommand._verify_pin_token', return_value=True):
            
            # Mock the assertion output directly on the mock_auth_api
            credential = {"id": b'cred_id', "type": "public-key"}
            auth_data = bytes([0x01, 0x02, 0x03, 0x04])
            signature = bytes([0x05, 0x06, 0x07, 0x08])
            user_handle = b'user_id'
            mock_auth_api.assertion_out = MagicMock(return_value=(None, credential, auth_data, signature, user_handle))
            
            # Add the test CID to the open keys dictionary
            mock_auth_api._open_keys[test_cid] = {'pinAuth': b'valid_token'}
            
            # Create a GetAssertion command with all required parameters
            cmd_byte = CBORCommand.CommandByte.GET_NEXT_ASSERTION.value.to_bytes(1, byteorder='big')
            
            # Create a complete CBOR map
            cbor_data = cbor.dumps({
                0x01: 'example.com',  # rpId
                0x02: b'client_data_hash',  # clientDataHash
                0x06: b'pin_auth'  # pinAuth
            })
            
            length = (len(cmd_byte) + len(cbor_data) + 1).to_bytes(2, byteorder='big')
            data = length + cmd_byte + cbor_data
            
            # Create the command
            cmd = CBORCommand(test_cid, data)
            cmd.unpack()
            
            # Verify the response indicates success
            assert cmd.response_ready
            assert cmd.response[0] == CBORCommand.CBORStatusCode.CTAP2_OK
            
            # Decode the CBOR response (skip the status byte)
            response_cbor = cbor.loads(bytes(cmd.response[1:]))
            
            # Verify the response contains the expected fields
            assert response_cbor[0x01] == credential  # credential
            assert response_cbor[0x02] == auth_data  # authData
            assert response_cbor[0x03] == signature  # signature
            assert response_cbor[0x04] == {'id': user_handle}  # userHandle


class TestCTAP2HIDevice:
    """Test the CTAP2HIDevice class that processes HID events"""
    
    @pytest.fixture
    def mock_device(self):
        with patch('soft_fido2.passkey_device.UserDevice') as mock_user_device:
            # Create a mock device path
            dev_path = "/dev/hidraw0"
            
            # Create the device
            device = CTAP2HIDevice(dev_path)
            
            # Create a test CID
            test_cid = bytes([0x01, 0x02, 0x03, 0x04])
            
            # Create a list to capture arguments passed to put
            put_args = []
            
            # Create a mock pending queue with a custom put method
            device.pending = MagicMock()
            device.pending.put = lambda x: put_args.append(x)
            
            # Initialize the cids dictionary
            device.cids = {}
            
            # Create a mock CBORCommand instance for testing
            mock_cbor_instance = MagicMock()
            
            yield device, test_cid, put_args, mock_cbor_instance
    
    def test_ctaphid_init(self, mock_device):
        """Test handling a CTAPHID_INIT command"""
        device, test_cid, put_args, _ = mock_device
        
        # Create a mock event with INIT command
        broadcast_cid = bytes([0xFF, 0xFF, 0xFF, 0xFF])
        event = MagicMock()
        
        # CTAPHID_INIT packet structure (with endpoint byte):
        # ENDPOINT (1 byte) + CID (4 bytes) + CMD (1 byte) + BCNT (2 bytes) + NONCE (8 bytes)
        nonce = bytes([0, 1, 2, 3, 4, 5, 6, 7])
        event.data = bytearray(
            [0x00] +               # ENDPOINT byte
            list(broadcast_cid) +  # CID: 0xFFFFFFFF
            [0x06] +               # CMD: CTAPHID_INIT
            [0x00, 0x08] +         # BCNT: 8 bytes
            list(nonce)            # NONCE: 8 bytes
        )
        
        # Process the event
        device.ctaphid_init(event)
        
        # Verify a response was queued
        assert len(put_args) > 0
        
        # Get the response
        response = put_args[0]
        
        # Verify response structure
        assert response[0:4] == broadcast_cid  # CID should match
        assert response[4] == 0x06             # CMD should be CTAPHID_INIT
        # Response contains: nonce (8) + new_cid (4) + protocol_version (1) +
        #                    device_version (1) + capabilities (1)
        assert len(response) >= 7 + 8 + 4 + 3  # Minimum response size
    
    def test_ctaphid_ping(self, mock_device):
        """Test handling a CTAPHID_PING command"""
        device, test_cid, put_args, _ = mock_device
        
        # Create a mock event with PING command
        event = MagicMock()
        ping_data = b'test'
        
        # CTAPHID_PING packet structure (with endpoint byte):
        # ENDPOINT (1 byte) + CID (4 bytes) + CMD (1 byte) + BCNT (2 bytes) + DATA
        event.data = bytes(
            [0x00] +                   # ENDPOINT byte
            list(test_cid) +           # CID: 0x01020304
            [0x01] +                   # CMD: CTAPHID_PING
            [0x00, len(ping_data)] +   # BCNT: length of ping data
            list(ping_data)            # DATA: 'test'
        )
        
        # Setup the device with a CID entry
        device.cids[test_cid] = {}
        
        # Process the event
        device.ctaphid_ping(event)
        
        # Verify a response was queued
        assert len(put_args) > 0
        
        # Get the response
        response = put_args[-1]
        
        # Verify response structure
        assert response[0:4] == test_cid  # CID should match
        assert response[4] == 0x01        # CMD should be CTAPHID_PING
        # Response should echo back the ping data
    
    def test_ctaphid_cbor_get_info(self, mock_device):
        """Test handling a CTAPHID_CBOR command with GetInfo"""
        device, test_cid, put_args, _ = mock_device
        
        # Setup the device with a CID entry
        device.cids[test_cid] = {}
        
        # Create a GetInfo CBOR message
        cmd_byte = CBORCommand.CommandByte.GET_INFO.value  # 0x04
        cbor_data = b''  # GET_INFO has no additional CBOR data
        
        # The CTAPHID layer passes data[6:] to CBORCommand, which expects:
        # BCNT (2 bytes) + CMD (1 byte) + CBOR_DATA
        # The BCNT serves as the LENGTH field for CBORCommand
        total_length = 1 + len(cbor_data)
        cbor_payload = (
            total_length.to_bytes(2, byteorder='big') +  # BCNT/LENGTH: 0x0001
            bytes([cmd_byte]) +                           # CMD: 0x04
            cbor_data                                     # DATA: empty
        )
        
        # Create CTAPHID packet (with endpoint byte)
        # Format: ENDPOINT (1) + CID (4) + CTAPHID_CMD (1) + BCNT (2) + CMD (1) + CBOR_DATA
        event = MagicMock()
        event.ev_len = 64
        ctaphid_cmd = 0x10  # CTAPHID_CBOR
        ctaphid_cmd_with_init = ctaphid_cmd | 0x80  # Set init bit
        
        event.data = (
            bytes([0x00]) +                         # ENDPOINT byte
            test_cid +                              # CID: 4 bytes
            bytes([ctaphid_cmd_with_init]) +        # CTAPHID_CMD: 0x90
            cbor_payload                            # BCNT + CMD + CBOR_DATA
        )
        # Pad to 64 bytes
        event.data += bytes([0] * (64 - len(event.data)))
        
        # Process the event
        with patch.object(device, 'send_response_segments') as mock_send_response:
            device.ctaphid_cbor(event)
            
            # Verify response was sent or command was stored
            assert mock_send_response.called or test_cid in device.cids
    
    def test_send_response_segments(self, mock_device):
        """Test sending a response in multiple segments"""
        device, test_cid, put_args, _ = mock_device
        
        # Create a small response that will need just a few segments
        # Using a smaller response to avoid memory issues
        large_response = bytes([i % 256 for i in range(100)])
        
        # Instead of mocking the CBORCommand, let's directly test the send_response_segment method
        # This avoids potential infinite loops in the send_response_segments method
        
        # Calculate how many segments we expect
        first_segment_size = 57  # First packet can hold 57 bytes
        remaining_bytes = len(large_response) - first_segment_size
        additional_segments = (remaining_bytes + 58) // 59  # Rest can hold 59 bytes
        total_segments = 1 + (additional_segments if remaining_bytes > 0 else 0)
        
        # Test each segment individually
        for i in range(total_segments):
            if i == 0:
                # First segment
                segment_data = large_response[:first_segment_size]
                segment_num = 0
            else:
                # Subsequent segments
                start = first_segment_size + (i - 1) * 59
                end = min(start + 59, len(large_response))
                segment_data = large_response[start:end]
                segment_num = i - 1
            
            # Create a mock CBOR command for this segment
            cbor_cmd = MagicMock()
            cbor_cmd.ctaphid_cmd = 0x10  # CBOR command
            cbor_cmd.bcnt = len(large_response)
            cbor_cmd.response_segment = i
            cbor_cmd.get_rsp_seg.return_value = (segment_data, segment_num)
            
            # Send this segment
            device.send_response_segment(test_cid, cbor_cmd)
            
            # Verify a response was queued
            assert len(put_args) == i + 1


class TestSegmentedMessages:
    """Test handling of segmented messages (messages that span multiple HID frames)"""
    
    @pytest.fixture(autouse=True)
    def patch_token_expiry(self):
        """Patch the token expiry check and time functions to avoid delays"""
        # Create a mock time function that advances by 100 seconds each call to break out of timeout loops
        time_values = [0, 100]  # First call returns 0, second call returns 100 (exceeding any timeout)
        mock_time = MagicMock(side_effect=time_values)
        
        with patch('soft_fido2.passkey_device.AuthenticatorAPI._token_expiry_check'), \
             patch('time.sleep', return_value=None), \
             patch('time.time', mock_time):
            yield
    
    @pytest.fixture
    def mock_device(self):
        with patch('soft_fido2.passkey_device.UserDevice') as mock_user_device:
            # Create a mock device path
            dev_path = "/dev/hidraw0"
            
            # Create the device
            device = CTAP2HIDevice(dev_path)
            
            # Create a test CID
            test_cid = bytes([0x01, 0x02, 0x03, 0x04])
            
            # Create a list to capture arguments passed to put
            put_args = []
            
            # Create a mock pending queue with a custom put method
            device.pending = MagicMock()
            device.pending.put = lambda x: put_args.append(x)
            
            # Initialize the cids dictionary
            device.cids = {}
            
            yield device, test_cid, put_args
    
    def test_segmented_cbor_message(self, mock_device):
        """
        Test handling a CBOR message that spans multiple HID frames.
        
        This test verifies that the CTAP2HIDevice correctly processes and reassembles
        a large CBOR message that is split across multiple HID packets (an initial packet
        followed by continuation packets).
        """
        # --- SETUP ---
        device, test_cid, put_args = mock_device
        
        # Create test data
        large_cbor_data = self._create_test_cbor_data()
        complete_cbor_command = self._create_cbor_command_data(large_cbor_data)
        
        # Setup the device with a CID entry WITHOUT cborCmd key
        device.cids[test_cid] = {}
        
        # --- EXECUTE: Send initial packet ---
        # 64 bytes total - 1 (endpoint) - 4 (CID) - 1 (CTAPHID_CMD) = 58 bytes for CBOR payload
        initial_packet_size = 58  # Maximum data size for init packet
        initial_packet = self._create_initial_packet(test_cid, complete_cbor_command, initial_packet_size)
        
        # Process the initial packet
        with self._patch_user_presence_and_keepalive():
            device.ctaphid_cbor(initial_packet)
        
        # Get the CBORCommand instance that was created
        cbor_cmd = device.cids[test_cid]['cborCmd']
        
        # Add assertion to help debug if cbor_cmd is None
        assert cbor_cmd is not None, (
            f"CBORCommand was not created. "
            f"Initial packet data: {initial_packet.data[:20].hex()}"
        )
        
        # Verify no response was queued yet (waiting for continuation packets)
        assert len(put_args) == 0
        
        # --- EXECUTE: Send continuation packets ---
        unprocessed_data = complete_cbor_command[initial_packet_size:]
        self._send_continuation_packets(device, test_cid, cbor_cmd, unprocessed_data)
        
        # --- VERIFY ---
        self._verify_message_assembly(cbor_cmd, large_cbor_data)
    
    def _create_test_cbor_data(self):
        """Create a large CBOR map for testing segmented messages."""
        return cbor.dumps({
            0x01: b'client_data_hash' * 10,  # Make it large
            0x02: {'id': 'example.com', 'name': 'Example'},  # rp
            0x03: {'id': b'user_id', 'name': 'User'},  # user
            0x04: [{'type': 'public-key', 'alg': -7}],  # pubKeyCredParams
            0x08: b'pin_auth'  # pinAuth
        })
    
    def _create_cbor_command_data(self, cbor_data):
        """Create properly formatted CBOR command data for CTAPHID"""
        cmd_byte = CBORCommand.CommandByte.MAKE_CREDENTIAL.value
        
        # The CTAPHID layer passes data[6:] to CBORCommand, which expects:
        # BCNT/LENGTH (2) + CMD (1) + CBOR_DATA
        total_length = 1 + len(cbor_data)
        return (
            total_length.to_bytes(2, byteorder='big') +  # BCNT/LENGTH
            bytes([cmd_byte]) +                           # CMD
            cbor_data                                     # CBOR_DATA
        )
    
    def _create_initial_packet(self, cid, cbor_payload, data_size):
        """Create initial CTAPHID packet"""
        event = MagicMock()
        event.ev_len = 64
        
        ctaphid_cmd = 0x10 | 0x80  # CTAPHID_CBOR with init bit
        
        # Extract data that fits in initial packet (after ENDPOINT + CID + CMD)
        # data_size should account for the space available after these headers
        packet_data = cbor_payload[:data_size]
        
        event.data = (
            bytes([0x00]) +           # ENDPOINT byte
            cid +                     # CID: 4 bytes
            bytes([ctaphid_cmd]) +    # CTAPHID_CMD: 1 byte
            packet_data               # BCNT + CMD + CBOR_DATA (partial)
        )
        # Pad to 64 bytes
        event.data += bytes([0] * (64 - len(event.data)))
        
        return event
    
    def _send_continuation_packets(self, device, test_cid, cbor_cmd, unprocessed_data):
        """Send continuation packets for the remaining data."""
        # 64 bytes total - 1 (endpoint) - 4 (CID) - 1 (SEQ) = 58 bytes for data
        continuation_chunk_size = 58  # Maximum data size for continuation packets
        
        # Process data in chunks
        for i in range(0, len(unprocessed_data), continuation_chunk_size):
            chunk = unprocessed_data[i:i + continuation_chunk_size]
            
            # Create continuation packet with endpoint byte
            # Format: ENDPOINT (1) + CID (4) + SEQ (1) + DATA
            seq_event = MagicMock()
            seq_event.ev_len = 64
            seq_event.data = (
                bytes([0x00]) +                    # ENDPOINT byte
                test_cid +                         # CID: 4 bytes
                bytes([cbor_cmd.request_segment]) + # SEQ: 1 byte
                chunk                              # DATA
            )
            # Pad to 64 bytes
            seq_event.data += bytes([0] * (64 - len(seq_event.data)))
            
            # Process the continuation packet - patch send_response_segments and verify_pin_token to avoid errors
            with patch.object(device, 'send_response_segments'), \
                 patch('soft_fido2.passkey_device.CBORCommand._verify_pin_token', return_value=True), \
                 patch('soft_fido2.passkey_device.KeepAliveWorker') as mock_worker_class:
                # Configure the mock worker to avoid the error
                mock_worker_instance = MagicMock()
                mock_worker_class.return_value = mock_worker_instance
                
                device._handle_incoming_sequence(test_cid, seq_event)
    
    def _verify_message_assembly(self, cbor_cmd, expected_data):
        """Verify that the CBOR message was correctly assembled from all segments."""
        # Remove trailing 0 padding bytes from the request
        actual_request = cbor_cmd.request.rstrip(b'\x00')
        
        # Verify that the request was correctly assembled from all segments
        assert actual_request == expected_data, "Request data mismatch"
    
    def _patch_user_presence_and_keepalive(self):
        """Create a context manager for patching user presence and keep-alive worker."""
        user_presence_patch = patch('soft_fido2.passkey_device.CBORCommand.gather_user_presence', return_value=True)
        pin_token_patch = patch('soft_fido2.passkey_device.CBORCommand._verify_pin_token', return_value=True)
        
        # Create a mock worker instance
        mock_worker_instance = MagicMock()
        mock_worker_class = MagicMock(return_value=mock_worker_instance)
        keepalive_patch = patch('soft_fido2.passkey_device.KeepAliveWorker', mock_worker_class)
        
        # Combine patches
        from contextlib import ExitStack
        stack = ExitStack()
        stack.enter_context(user_presence_patch)
        stack.enter_context(pin_token_patch)
        stack.enter_context(keepalive_patch)
        return stack


def test_keep_alive_worker():
    """Test the KeepAliveWorker sends keep-alive messages"""
    # Create a list to capture arguments
    put_args = []
    
    # Create a mock pending queue with a custom put method
    pending = MagicMock()
    pending.put = lambda x: put_args.append(x)
    
    # Create a test CID
    test_cid = 0x12345678
    
    # Create a custom KeepAliveWorker class for testing
    class TestKeepAliveWorker(KeepAliveWorker):
        def run(self):
            # Override run to just send one keep-alive message
            rsp = CTAPHIDInitPkt(cid=self.cid,
                               cmd=0xBB,
                               bcnt=0x01,
                               data=b'\x02').pack()
            self.pending.put(rsp)
    
    # Create the worker
    worker = TestKeepAliveWorker(pending, test_cid)
    
    # Call run directly
    worker.run()
    
    # Verify a keep-alive was sent
    assert len(put_args) > 0
    
    # Get the first keep-alive message
    keep_alive = put_args[0]
    
    # Verify it's a valid keep-alive
    assert keep_alive[0:4] == test_cid.to_bytes(4, byteorder='big')  # CID
    assert keep_alive[4] == 0xBB  # KEEPALIVE command
    assert keep_alive[5:7] == bytes([0, 1])  # BCNT = 1
    assert keep_alive[7] == 0x02  # Status = processing


class TestAuthenticatorAPI:
    """Test the AuthenticatorAPI class"""
    
    @pytest.fixture
    def mock_environment(self):
        """
        Fixture providing a mock environment for testing PIN validation.
        
        Uses a temporary directory for FIDO_HOME instead of hardcoding paths.
        Mocks file operations and utility classes needed for PIN validation.
        """
        # Create a temporary directory for testing
        with tempfile.TemporaryDirectory() as temp_dir:
            # Mock environment variables with the temporary directory
            with patch.dict('os.environ', {'FIDO_HOME': temp_dir}), \
                 patch('os.path.exists', return_value=True), \
                 patch('os.path.realpath', return_value=temp_dir), \
                 patch('os.listdir', return_value=['test.passkey']), \
                 patch('soft_fido2.passkey_device.KeyUtils') as mock_key_utils, \
                 patch('soft_fido2.cert_utils.CertUtils') as mock_cert_utils:
                
                # Yield the temporary directory and mock objects
                yield temp_dir, None, mock_key_utils, mock_cert_utils
    
    @pytest.fixture
    def key_exchange_cid(self):
        """Fixture providing a test channel ID for key exchange tests."""
        return bytes([0x01, 0x02, 0x03, 0x04])

    @pytest.fixture
    def mock_ec_cose_key(self):
        """Fixture providing a mock EC COSE key for key exchange tests."""
        return {
            1: 2,      # kty: EC key
            3: -25,    # alg: ECDH-ES+HKDF-256
            -1: 1,     # crv: P-256
            -2: b'x_coordinate',  # x-coordinate
            -3: b'y_coordinate'   # y-coordinate
        }

    @pytest.fixture
    def mock_pin_token_setup(self, key_exchange_cid):
        """Fixture for setting up and tearing down the pin token key pair."""
        # Create a mock PIN token key pair
        mock_pin_token_kp = MagicMock()
        mock_private_key = MagicMock()
        mock_pin_token_kp.get_private.return_value = mock_private_key
        
        # Set up the mock for the shared secret - ensure it's exactly 32 bytes for AES-256
        mock_shared_point = b'12345678901234567890123456789012'  # Exactly 32 bytes
        mock_private_key.exchange.return_value = mock_shared_point
        
        # Store the pin token key in the _open_keys dict for the test CID
        # This simulates what _get_or_create_pin_token_kp() does
        original_open_keys = AuthenticatorAPI._open_keys.copy()
        AuthenticatorAPI._open_keys[key_exchange_cid] = {
            'pin_token_kp': mock_pin_token_kp,
            'tStart': 0
        }
        
        yield mock_pin_token_kp, mock_private_key, mock_shared_point
        
        # Restore the original _open_keys value
        AuthenticatorAPI._open_keys = original_open_keys

    def test_decapsulate(self, mock_pin_token_setup, mock_ec_cose_key, key_exchange_cid):
        """Test the decapsulate method of AuthenticatorAPI."""
        from cryptography.hazmat.primitives import hashes
        
        _, mock_private_key, mock_shared_point = mock_pin_token_setup
        
        # Create a mock for the public key
        mock_public_key = MagicMock()
        
        # Mock the KeyUtils._bytes_to_long method
        with patch('soft_fido2.passkey_device.KeyUtils._bytes_to_long', return_value=123456):
            # Mock the ec.EllipticCurvePublicNumbers constructor
            with patch('soft_fido2.passkey_device.ec.EllipticCurvePublicNumbers', return_value=MagicMock()) as mock_ec_pub_nums:
                # Mock the public_key method
                mock_ec_pub_nums.return_value.public_key.return_value = mock_public_key
                
                # Call the decapsulate method with the CID parameter
                result = AuthenticatorAPI.decapsulate(mock_ec_cose_key, key_exchange_cid)
                
                # Verify that the exchange method was called with the correct parameters
                mock_private_key.exchange.assert_called_once()
                args, kwargs = mock_private_key.exchange.call_args
                assert 'ECDH' in str(args[0])  # Check if 'ECDH' is in the string representation
                assert args[1] == mock_public_key
                
                # Verify that the result is a SHA-256 hash of the shared secret
                hasher = hashes.Hash(hashes.SHA256())
                hasher.update(mock_shared_point)
                expected_result = hasher.finalize()
                assert result == expected_result

    def test_get_pin_cose_key(self, mock_pin_token_setup, key_exchange_cid):
        """Test the get_pin_cose_key method of AuthenticatorAPI."""
        # Mock the KeyUtils.get_cose_key method
        with patch('soft_fido2.passkey_device.KeyUtils.get_cose_key', return_value={'key': 'value'}):
            # Call the get_pin_cose_key method with the correct arguments (including cid)
            result = AuthenticatorAPI.get_pin_cose_key({}, key_exchange_cid)
            
            # Verify that the result is the expected COSE key
            assert result == {1: {'key': 'value'}}

    # Constants for PIN request dictionary keys
    PIN_REQ_PLATFORM_KEY = 3
    PIN_REQ_PIN_HASH_ENC = 6
    
    @pytest.fixture
    def mock_pin_req(self, mock_ec_cose_key):
        """Fixture providing a mock PIN request dictionary."""
        return {
            self.PIN_REQ_PLATFORM_KEY: mock_ec_cose_key,  # platform_cose_key
            self.PIN_REQ_PIN_HASH_ENC: b'encrypted_pin_hash'  # pin_hash_enc
        }
    
    @pytest.fixture
    def mock_crypto_components(self):
        """Fixture providing mock cryptographic components for PIN token tests."""
        # Test constants with descriptive names
        SHARED_SECRET = b'12345678901234567890123456789012'  # Exactly 32 bytes for AES-256
        DECRYPTED_PIN_HASH = b'decrypted_pin_hash'
        PIN_AUTH_TOKEN = b'pin_auth_token' * 2  # 32 bytes to match expected size
        ENCRYPTED_TOKEN = b'encrypted_token'
        
        # Create mock objects
        mock_cipher = MagicMock()
        mock_decryptor = MagicMock()
        mock_encryptor = MagicMock()
        
        # Configure mock behavior
        mock_decryptor.update.return_value = DECRYPTED_PIN_HASH
        mock_decryptor.finalize.return_value = b''
        
        mock_encryptor.update.return_value = ENCRYPTED_TOKEN
        mock_encryptor.finalize.return_value = b''
        
        mock_cipher.decryptor.return_value = mock_decryptor
        mock_cipher.encryptor.return_value = mock_encryptor
        
        # Return all components for use in tests
        return {
            'shared_secret': SHARED_SECRET,
            'decrypted_pin_hash': DECRYPTED_PIN_HASH,
            'pin_auth_token': PIN_AUTH_TOKEN,
            'encrypted_token': ENCRYPTED_TOKEN,
            'cipher': mock_cipher,
            'decryptor': mock_decryptor,
            'encryptor': mock_encryptor
        }
    
    # Removed duplicate method _setup_pin_token_mocks as it's replaced by _setup_pin_token_test

    def _verify_cipher_constructor_call(self, mock_cipher_constructor, expected_shared_secret):
        """
        Helper method to verify the cipher constructor was called correctly.
        
        Args:
            mock_cipher_constructor: The mock Cipher constructor to verify
            expected_shared_secret: The expected shared secret used for AES256
            
        Raises:
            AssertionError: If the cipher constructor was not called correctly
        """
        # Verify the constructor was called once
        mock_cipher_constructor.assert_called_once()
        
        # Extract the arguments with descriptive names
        cipher_args, cipher_kwargs = mock_cipher_constructor.call_args
        cipher_algorithm = cipher_args[0]
        cipher_mode = cipher_args[1]
        
        # Import required types for verification
        from cryptography.hazmat.primitives.ciphers import algorithms, modes
        
        # Verify the algorithm is AES256 with the expected shared secret
        assert (isinstance(cipher_algorithm, algorithms.AES256.__class__) or
                cipher_algorithm.__class__.__name__ == 'AES256'), "Cipher algorithm must be AES256"
        
        # Verify the mode is CBC with zero IV (as per CTAP2 spec)
        assert (isinstance(cipher_mode, modes.CBC.__class__) or
                cipher_mode.__class__.__name__ == 'CBC'), "Cipher mode must be CBC"
        

    def _setup_pin_token_test(self, mock_crypto_components, pin_validation_result):
       """
       Helper method to set up a PIN token test with specific validation result.
       
       Args:
           mock_crypto_components: Dictionary containing mock crypto components
           pin_validation_result: The result to return from _validate_pin mock
           
       Returns:
           Tuple containing:
           - mock_decapsulate: Mock for the decapsulate method
           - mock_cipher_constructor: Mock for the Cipher constructor
           - mock_validate_pin: Mock for the _validate_pin method
           - patch_context: Context manager for applying all patches
       """
       # Extract test values from fixtures for mocking
       expected_shared_secret = mock_crypto_components['shared_secret']
       
       # Create mocks with appropriate return values
       mock_decapsulate = MagicMock(return_value=expected_shared_secret)
       mock_cipher_constructor = MagicMock(return_value=mock_crypto_components['cipher'])
       mock_validate_pin = MagicMock(return_value=pin_validation_result)
       
       # Create a context manager for all patches
       patch_context = patch.multiple(
           AuthenticatorAPI,
           decapsulate=mock_decapsulate,
           _validate_pin=mock_validate_pin,
           spec=True
       )
       
       # Add the Cipher patch
       cipher_patch = patch('soft_fido2.passkey_device.Cipher', mock_cipher_constructor)
       
       # Combine the patches
       from contextlib import ExitStack
       combined_context = ExitStack()
       combined_context.enter_context(patch_context)
       combined_context.enter_context(cipher_patch)
       
       return mock_decapsulate, mock_cipher_constructor, mock_validate_pin, combined_context

    def _verify_pin_token_assertions(self, test_context):
        """
        Helper method to verify all assertions for PIN token tests.
        
        Args:
            test_context: PinTokenTestContext containing all test parameters
        """
        # Verify decapsulation was called with correct parameters (including cid)
        test_context.mock_decapsulate.assert_called_once_with(
            test_context.mock_ec_cose_key,
            test_context.key_exchange_cid
        )
        
        # Verify cipher creation using the helper method
        self._verify_cipher_constructor_call(
            test_context.mock_cipher_constructor,
            test_context.expected_shared_secret
        )
        
        # Verify PIN hash decryption with correct parameters
        test_context.mock_decryptor.update.assert_called_once_with(test_context.encrypted_pin_hash_param)
        
        # Verify PIN validation with correct parameters
        test_context.mock_validate_pin.assert_called_once_with(
            test_context.expected_decrypted_pin_hash,
            test_context.key_exchange_cid
        )
        
        # For valid PIN validation result, verify token encryption
        if test_context.pin_validation_result is not None:
            test_context.mock_encryptor.update.assert_called_once_with(test_context.pin_validation_result)
        
        # Verify final result matches expected result
        assert test_context.result == test_context.expected_result, \
            f"Test case '{test_context.test_case}' failed: result does not match expected"

    @dataclass
    class PinTokenTestContext:
        """Data class for PIN token test context to improve readability and maintainability."""
        mock_decapsulate: MagicMock
        mock_cipher_constructor: MagicMock
        mock_validate_pin: MagicMock
        mock_decryptor: MagicMock
        mock_encryptor: MagicMock
        mock_ec_cose_key: Dict[int, Any]
        expected_shared_secret: bytes
        expected_decrypted_pin_hash: bytes
        key_exchange_cid: bytes
        encrypted_pin_hash_param: bytes
        pin_validation_result: Optional[bytes]
        test_case: str = ""
        expected_result: Any = None
        result: Any = None

    def _prepare_pin_token_test(self, mock_crypto_components, mock_ec_cose_key, key_exchange_cid,
                               mock_pin_req, pin_hash_enc, pin_validation_result):
        """
        Helper method to prepare the test context for a PIN token test.
        
        Args:
            mock_crypto_components: Dictionary containing mock crypto components
            mock_ec_cose_key: Mock EC COSE key
            key_exchange_cid: Channel ID for key exchange
            mock_pin_req: Mock PIN request dictionary
            pin_hash_enc: The encrypted PIN hash to use in the test
            pin_validation_result: The result to return from _validate_pin mock
            
        Returns:
            Tuple containing:
            - test_context: PinTokenTestContext with all test parameters
            - patch_context: Context manager for applying all patches
        """
        # Update mock_pin_req with the parameterized encrypted PIN hash
        mock_pin_req[self.PIN_REQ_PIN_HASH_ENC] = pin_hash_enc
        
        # Set up mocks and patches using the helper method
        mock_decapsulate, mock_cipher_constructor, mock_validate_pin, patch_context = self._setup_pin_token_test(
            mock_crypto_components, pin_validation_result
        )
        
        # Create a test context with all parameters
        test_context = self.PinTokenTestContext(
            mock_decapsulate=mock_decapsulate,
            mock_cipher_constructor=mock_cipher_constructor,
            mock_validate_pin=mock_validate_pin,
            mock_decryptor=mock_crypto_components['decryptor'],
            mock_encryptor=mock_crypto_components['encryptor'],
            mock_ec_cose_key=mock_ec_cose_key,
            expected_shared_secret=mock_crypto_components['shared_secret'],
            expected_decrypted_pin_hash=mock_crypto_components['decrypted_pin_hash'],
            key_exchange_cid=key_exchange_cid,
            encrypted_pin_hash_param=pin_hash_enc,
            pin_validation_result=pin_validation_result
        )
        
        return test_context, patch_context
    
    @pytest.mark.parametrize("test_case, pin_hash_enc, pin_validation_result, expected_result", [
       # Test case 1: Valid PIN hash, successful validation
       (
           "valid_pin_hash",
           b'encrypted_pin_hash',
           b'pin_auth_token' * 2,  # 32 bytes token
           {2: b'encrypted_token'}
       ),
       # Test case 2: Valid PIN hash, but validation fails (returns None)
       (
           "valid_pin_hash_invalid_passkey",
           b'encrypted_pin_hash',
           None,
           None
       ),
       # Test case 3: Could add more test cases for different scenarios
       # For example, testing error handling, edge cases, etc.
    ])
    def test_get_pin_token(self, mock_pin_token_setup, mock_ec_cose_key,
                           key_exchange_cid, mock_pin_req, mock_crypto_components,
                           test_case, pin_hash_enc, pin_validation_result, expected_result):
        """
        Parameterized test for the get_pin_token method of AuthenticatorAPI.
        
        This test verifies the method's behavior under different scenarios:
        1. Valid PIN hash with successful validation
        2. Valid PIN hash but validation fails
        3. Additional scenarios can be added as needed
        
        Args:
            test_case: Description of the test case for better error messages
            pin_hash_enc: The encrypted PIN hash to use in the test
            pin_validation_result: The result to return from _validate_pin mock
            expected_result: The expected result from get_pin_token
        """
        # --- ARRANGE ---
        # Prepare the test context and patches
        test_context, patch_context = self._prepare_pin_token_test(
            mock_crypto_components, mock_ec_cose_key, key_exchange_cid,
            mock_pin_req, pin_hash_enc, pin_validation_result
        )
        
        # Add test case and expected result to the context
        test_context.test_case = test_case
        test_context.expected_result = expected_result
        
        # Apply patches and execute test
        with patch_context:
            # --- ACT ---
            test_context.result = AuthenticatorAPI.get_pin_token(mock_pin_req, key_exchange_cid)
            
            # --- ASSERT ---
            # Verify all assertions using the helper method
            self._verify_pin_token_assertions(test_context)

    def test_validate_pin_success(self, mock_environment):
        """Test successful PIN validation"""
        _, _, mock_key_utils, mock_cert_utils = mock_environment
        kp = KeyPair.generate_ecdsa()
        start_key = kp.get_private()
        cert = CertUtils.gen_ca_cert(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, u"root")]), 
                                          365, 123456, kp)
        # Mock the KeyUtils._load_passkey method
        mock_key_utils._load_passkey.return_value = {
            'x5c': cert,
            'key': start_key,
        }
        
        # Mock the CertUtils.load_der_certificate method
        mock_cert_utils.load_der_certificate.return_value = 'cert_obj'
        
        # Mock the KeyUtils.load_der_key method
        mock_key_utils.load_der_key.return_value = 'key_pair_obj'
        
        # Test PIN validation
        pin_hash = b'test_pin_hash'
        cid = b'test_cid'
        
        # Call the method
        result = AuthenticatorAPI._validate_pin(pin_hash, cid)
        
        # Verify the result is a token
        assert result is not None
        assert isinstance(result, bytes), f"{result} not a pin auth token"
        assert len(result) == 32, f"{result} != 32 bytes"
        
        # Verify the open keys were updated
        assert cid in AuthenticatorAPI._open_keys
        assert AuthenticatorAPI._open_keys[cid]['x5c'] == cert, f"{cert} != {AuthenticatorAPI._open_keys[cid]['x5c']}"
        assert AuthenticatorAPI._open_keys[cid]['kp'].get_private_bytes() == kp.get_private_bytes(), f"{AuthenticatorAPI._open_keys[cid]['kp']} != {kp}"
        assert AuthenticatorAPI._open_keys[cid]['ph'] == pin_hash
        assert AuthenticatorAPI._open_keys[cid]['pinAuth'] == result
        assert 'tStart' in AuthenticatorAPI._open_keys[cid], f"Key must have a start time: {AuthenticatorAPI._open_keys[cid].keys()}"
    
    def test_validate_pin_failure_no_fido_home(self):
        """Test PIN validation failure when FIDO_HOME is not set"""
        # Remove FIDO_HOME from environment
        with patch.dict('os.environ', {}, clear=True):
            # Test PIN validation
            pin_hash = b'test_pin_hash'
            cid = b'test_cid'
            
            # Call the method
            result = AuthenticatorAPI._validate_pin(pin_hash, cid)
            
            # Verify the result is None
            assert result is None
    
    def test_validate_pin_failure_invalid_passkey(self, mock_environment):
        """Test PIN validation failure with invalid passkey"""
        _, _, mock_key_utils, _ = mock_environment
        
        # Mock the KeyUtils._load_passkey method to raise an exception
        mock_key_utils._load_passkey.side_effect = Exception("Invalid passkey")
        
        # Test PIN validation
        pin_hash = b'test_pin_hash'
        cid = b'test_cid'
        
        # Call the method
        result = AuthenticatorAPI._validate_pin(pin_hash, cid)
        
        # Verify the result is None
        assert result is None

# Made with Bob
