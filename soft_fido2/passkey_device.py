# Copyrite IBM 2022, 2025
# IBM Confidential
# Assisted by watsonx Code Assistant

import datetime, random, threading, logging, time


from .uhid_device import UserDevice
from .ctap import (
    MAX_DATA_FRAME, AuthenticatorAPI, CBORCommand,
    CTAPHIDInitPkt, CTAPHIDSeqPkt, bcolors, dump_bytes, 
    colour_print
)


class CTAPHIDevice(UserDevice):
    #This will contain the current set of channel id's and associated state
    cids = {}
    # Lock to prevent race conditions when processing packets in parallel threads
    cids_lock = threading.Lock()

    def __init__(self, devpath):
        super().__init__(devPath=devpath)
        self.start_time = datetime.datetime.now()
        CBORCommand.set_pending(self.pending)

    def _bytes_to_str(self, b):
        return ''.join("%02X" % x for x in b)


    def send_response_segment(self, cid, cbor_cmd):
        rsp_data = None
        if cbor_cmd.response_segment == 0: #We send the init pkt
            logging.debug(f"bcnt from init pkt: {cbor_cmd.bcnt}")
            data, _ = cbor_cmd.get_rsp_seg(57)
            logging.debug(f"bcnt: {cbor_cmd.bcnt}")
            rsp_data = CTAPHIDInitPkt(cid=int.from_bytes(cid, 'big'), 
                                    cmd=cbor_cmd.ctaphid_cmd,
                                    bcnt=cbor_cmd.bcnt,
                                    data=bytes(data)).pack()
        else: #We send the continue sequence pkt
            data, seq_num = cbor_cmd.get_rsp_seg(59)
            colour_print(colour=bcolors.WARNING, component='send_response_segment', 
                    msg='Sequence number {}'.format(seq_num))
            rsp_data = CTAPHIDSeqPkt(cid=int.from_bytes(cid, 'big'),
                                     seq=seq_num,
                                     data=bytes(data)).pack()
        colour_print(colour=bcolors.WARNING, component='send_response_segment', 
                msg='pad with {} 0 bytes'.format(MAX_DATA_FRAME - len(rsp_data)))
        rsp_data += b'\00' * (MAX_DATA_FRAME - len(rsp_data)) # pad the 64 byte frame with 0x00 if required
        dump_bytes(rsp_data, colour=bcolors.OKGREEN, component='CTAPHIDevice.send_response_segment', 
                   msg='Packed response: ')
        self.pending.put(rsp_data)


    def send_response_segments(self, cid, cbor_cmd):
        while len(cbor_cmd.response) > 0:
            self.send_response_segment(cid, cbor_cmd)
            logging.debug(f"response left: {cbor_cmd}")


    def ctaphid_ping(self, usb_req):
        cid = usb_req.data[1:5]
        cborCmd = CBORCommand(cid, None, skip_init=True)
        cborCmd.ctaphid_cmd = 0x01
        cborCmd.response = list(b'U2F_V2')
        self.send_response_segment(cid, cborCmd)

    def ctaphid_msg(self, usb_req):
        cid      = usb_req.data[1:5]
        cmd      = usb_req.data[5:6]
        cmd_byte = int.from_bytes(cmd, 'big')

        if cid not in self.cids:
            colour_print(colour=bcolors.FAIL, component='CTAPHIDevice.ctaphid_msg',
                         msg='Unknown CID {}'.format(cid))

        apdu = usb_req.data[8:]
        bcnt = int.from_bytes(usb_req.data[6:8], 'big')
        colour_print(colour=bcolors.OKPURPLE, component='CTAPHIDevice.ctaphid_msg',
                     msg='CTAPHID_MSG CID={} cmd_byte=0x{:02x} bcnt={}'.format(
                         self._bytes_to_str(cid), cmd_byte, bcnt))
        dump_bytes(apdu[:bcnt], colour=bcolors.OKPURPLE,
                   component='CTAPHIDevice.ctaphid_msg', msg='raw APDU bytes: ')

        rsp = CBORCommand(cid, None, skip_init=True)._u2f_req(cid, cmd_byte, apdu)
        self.send_response_segments(cid, rsp)

    def ctaphid_init(self, usb_req):
        cid = usb_req.data[1:5]
        cmd = usb_req.data[5:6]
        bcnt = usb_req.data[6:8]
        nonce = usb_req.data[8:16]
        colour_print(colour=bcolors.OKGREEN, component='CTAPHIDevice.ctaphid_init', 
                msg='Nonce {}'.format(self._bytes_to_str(nonce)))
        assignedCID = bytes([0, random.randint(0, 255), 0, random.randint(0, 255)])
        colour_print(colour=bcolors.OKGREEN, component='CTAPHIDevice.ctaphid_init', 
                    msg='Assigning a new CID to {}'.format(self._bytes_to_str(assignedCID)))
        data = nonce + assignedCID
        # protocol == 2; major version == 5; minor version = 1; build version = 2; flags === CAPABILITY_WINK | CAPABILITY_CBOR
        for i in [2, 5, 1, 2, 0x01 | 0x04]:
            data += i.to_bytes(1, 'big')
        dump_bytes(data, colour=bcolors.OKGREEN, component='CTAPHIDevice.ctaphid_init', msg='Response data')
        data += b'\00' * (57 - len(data)) # 64 - 4 (CID) - 1 (cmd) - 2 (bcnt) - len of response
        initCmd = CBORCommand(cid, None, skip_init=True)
        self.cids[assignedCID] = { }
        initCmd.response = data
        initCmd.ctaphid_cmd = int.from_bytes(cmd, 'big')
        initCmd.bcnt = 17
        self.send_response_segment(cid, initCmd)

    def ctaphid_cbor(self, usb_req):
        cid = usb_req.data[1:5]
        colour_print(colour=bcolors.OKGREEN, component='CTAPHIDevice.ctaphid_cbor',
                    msg='CBOR message recieved on channel {}'.format(self._bytes_to_str(cid)))
        cmd = usb_req.data[5:6]
        bcnt = usb_req.data[6:8]
        ctap_cmd = usb_req.data[8:9]
        logging.debug(f"CBOR bcnt: {int.from_bytes(bcnt, 'big') - 1}")
        cbor_data = usb_req.data[9: 8 + int.from_bytes(bcnt, 'big')]
        colour_print(colour=bcolors.OKGREEN, component='CTAPHIDevice.ctaphid_cbor',
                     msg='CBOR msg frame cmd: {}; bcnt: {}'.format(self._bytes_to_str(ctap_cmd),
                                                                   self._bytes_to_str(bcnt)))
        dump_bytes(cbor_data, colour=bcolors.OKGREEN, component='CTAPHIDevice.ctaphid_cbor',
                    msg='CBOR encoded bytes: ')
        
        with self.cids_lock: # Check if there's a pending transaction for this CID
            if cid in self.cids and 'cborCmd' in self.cids[cid]:
                colour_print(colour=bcolors.FAIL, component='CTAPHIDevice.ctaphid_cbor',
                            msg='CID {} has pending transaction, ignoring new command until complete'.format(
                                self._bytes_to_str(cid)))
                return
            
            cbor_cmd = CBORCommand(cid, usb_req.data[6:MAX_DATA_FRAME+1])
            cbor_cmd.ctaphid_cmd = int.from_bytes(cmd, 'big')
            
            if cbor_cmd.response_ready == True: #We can respond immediately
                dump_bytes(cbor_cmd.response, colour=bcolors.OKGREEN,
                           component='CTAPHIDevice.ctaphid_cbor', msg='CBOR response: ')
                self.send_response_segments(cid, cbor_cmd)
            else:
                # Store the command while holding the lock to prevent race with sequence packets
                self.cids[cid]['cborCmd'] = cbor_cmd
                colour_print(colour=bcolors.OKYELLOW, component='CTAPHIDevice.ctaphid_cbor',
                             msg="Waiting for rest of command to arrive . . .")
                return


    def _ctap_ack(self, usb_req):
        cid = usb_req.data[1:5]
        rsp = CBORCommand(cid, None, skip_init=True)
        rsp.response = []
        self.send_response_segment(cid, rsp)

    def ctaphid_cancel(self, usb_req):
        return self._ctap_ack(usb_req)

    def ctaphid_keepalive(self, usb_req):
        return

    def ctaphid_wink(self, usb_req):        
        time.sleep(1)#s
        return self._ctap_ack(usb_req)

    def ctaphid_error(self, usb_req):
        return self._ctap_ack(usb_req)

    def ctaphid_unknown(self, usb_req):
        colour_print(colour=bcolors.FAIL, component='CTAPHIDevice.ctaphid_unknown', msg='Unkown request recieved')
        self._ctap_ack(usb_req)

    def _handle_incoming_cmd(self, cmd, usb_req):
        ctapCmd = int.from_bytes(cmd, 'big') & 0x7F
        colour_print(colour=bcolors.OKGREEN, component='CTAPHIDevice._handle_incoming_cmd', 
                    msg='recieved command {}'.format(ctapCmd))
        return {
            1: self.ctaphid_ping,
            3: self.ctaphid_msg,
            6: self.ctaphid_init,
            8: self.ctaphid_wink,
            16: self.ctaphid_cbor,
            17: self.ctaphid_cancel,
            59: self.ctaphid_keepalive,
            63: self.ctaphid_error,
        }.get(ctapCmd, self.ctaphid_unknown)(usb_req)

    def _handle_incoming_sequence(self, cid, usb_req):
        seqNum = int.from_bytes(usb_req.data[5:6], 'big')
        
        transaction = None
        with self.cids_lock:
            context = self.cids.get(cid)
            if context is None:
                colour_print(colour=bcolors.FAIL, component='CTAPHIDevice._handle_incoming_sequence',
                            msg='CID not found')
                return
                
            transaction = context.get("cborCmd")
            if transaction is None:
                colour_print(colour=bcolors.FAIL, component='CTAPHIDevice._handle_incoming_sequence',
                            msg='No transaction for CID')
                return
            
            transaction.append_segment(usb_req.data[6:MAX_DATA_FRAME+1], seq_num=seqNum)
            
            if transaction.response_ready:
                del self.cids[cid]['cborCmd']
            else:
                return
        
        # Send response outside lock
        if transaction and transaction.response_ready:
            self.send_response_segments(cid, transaction)

    def process_output(self, event):
        ep = event.data[0]
        cid = event.data[1:5]
        cmd = event.data[5:6]
        dump_bytes(event.data[1:event.ev_len+1])

        colour_print(colour=bcolors.OKGREEN, component='CTAPHIDevice._handle_incoming',
                    msg='EP: {} CID: {}; CMD/SEQ {}; DATA: {}'.format(
                        ep, cid, cmd, self._bytes_to_str(event.data[1:event.ev_len+1])))

        if(int.from_bytes(cmd, 'big') & 0x80) > 0:
            colour_print(colour=bcolors.FAIL, component='CTAPHIDevice._handle_incoming',
                        msg='bit 8 set we got a command msg')
            return self._handle_incoming_cmd(cmd, event)
        else:
            colour_print(colour=bcolors.OKPURPLE, component='CTAPHIDevice._handle_incoming',
                         msg='Recieved a sequence segment, appending it to the current msg context')
            return self._handle_incoming_sequence(cid, event)

    def join(self, timeout=None):
        super().join()
        AuthenticatorAPI.quit()
