# Copyrite IBM 2022

# CTAP2HID reads bytes from endpoint 1,building the frames into a CTAPMsg. A CTAPMsg is used to initalize a 
#FIDO2Transaction thread which will reply on endpoint 2 when the transaction is complete.

import base64, datetime, threading, os, sys, random, queue
from enum import Enum
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from usb_ip import BaseStructure, USBDevice, InterfaceDescriptor, DeviceConfigurations, EndPoint, USBContainer, \
                    USBIPCMDSubmit, bcolors, dump_bytes, colour_print


# Classes to create a USB device object, connect it to the system usb daemon and begin tx/rx
class CTAP2HIDClass(BaseStructure):
    _fields_ = [
        ('bLength', 'B', 9),
        ('bDescriptorType', 'B', 0x21),  # HID
        ('bcdHID', 'H'),
        ('bCountryCode', 'B'),
        ('bNumDescriptors', 'B'),
        ('bDescriptprType2', 'B'),
        ('wDescriptionLength', 'H'),
    ]


hid_class = CTAP2HIDClass(bcdHID=0x0100,  # HID version number
                     bCountryCode=0x0,
                     bNumDescriptors=0x1,
                     bDescriptprType2=0x22,  # Report
                     wDescriptionLength=0x3F00)  # Little endian


interface_d = InterfaceDescriptor(bAlternateSetting=0,
                                  bNumEndpoints=2,
                                  bInterfaceClass=3,  # class HID
                                  bInterfaceSubClass=0, # no interface subclass
                                  bInterfaceProtocol=0, # no interface protocol
                                  iInterface=0)


end_point_one = EndPoint(bEndpointAddress=0x04, # HOST OUT / USB IN
                     bmAttributes=0x3, # Interrupt transfer
                     wMaxPacketSize=(64&0x00FF)<<8 | (64&0xFF00),  # 64-byte packet max
                     bInterval=5)  # Poll every 5 millisecond


end_point_two = EndPoint(bEndpointAddress=0x8E, # HOST IN / USB OUT
                     bmAttributes=0x3, # Interrupt transfer
                     wMaxPacketSize=(64&0x00FF)<<8 | (64&0xFF00),  # 64-byte packet max, bussit
                     bInterval=5)  # Poll every 5 millisecond


interface_d.descriptions = [hid_class]  # Supports only one description
interface_d.endpoints = [end_point_two, end_point_one]  # Supports two endpoint
# wTotalLength = len( interface_d.pack() + hid_class.pack() + end_point_one.pack() + end_point_two.pack() + 18)
configuration = DeviceConfigurations(wTotalLength=0x2900,
                                     bNumInterfaces=0x1,
                                     bConfigurationValue=0x1,
                                     iConfiguration=0x0,  # No string
                                     bmAttributes=0x80,  # valid self powered
                                     bMaxPower=50)  # 50 mah current
configuration.interfaces = [interface_d]   # Supports only one interface


class FIDO2Authenticator(object):

    _ca_cert = None
    _ca_kp = None
    _fernet_key = None
    _lock = None

    def __new__(cls):
        if cls._ca_cert == None and cls_.ca_kp == None:
            #Get the PKCS12 file
            p12_file = os.environ.get("FIDO_AUTHENTICATOR_PCKS12", os.path.expanduser("~/.fido2/authenticator.p12"))
            p12_data = open(p12_file, 'rb')
            ca_key, cls._ca_cert, _ = KeyPair.load_pcks12_bag(p12_data, 
                                                    os.environ.get("FIDO_AUTHENTICATOR_PCKS12_SECRET"))
            cls._ca_kp = KeyPair(ca_key, ca_key.get_public())
            # Retrieve and decrypt the symmetrical key
            cls._fernet_key = CertUtils.derive_aes_key_from_x509_oid(cls._ca_cert, ca_key)


    @staticmethod
    def attestation_outputs(clientDataHash, rp, user, pkCredsParams, excludeList, exts):
        _authenticator = Fido2Authenticator(aaguid=[b'\x00'*16], 
                            caKeyPair=cls._ca_kp, caCert=cls._ca_cert, fKey=cls._fernet_key)
        authData = _authenticator.build_authenticator_data(rp, 'packed', _authenticator.kp, False)
        credId = _authenticator._get_credential_id_bytes(_authenticator.kp)
        attStmt = _authenticator.build_packed_attestation_statement('packed', clentDataHash, credId, _authenticator.kp)
        return authData, attStmt


    @staticmethod
    def assertion_outputs(rpId, clientDataHash, allowedList, exts):
        for cred in allowedList:
            try:
                #Create the authenticator
                kp = Fido2Authenticator._get_key_pair_from_credential_id(assert_opts['credential_id'], cls._ca_key)
                _authenticator = Fido2Authenticator(key_pair=kp, aaguid=[b'\x00'*16], caKeyPair=cls._ca_kp, 
                                                    caCert=cls._ca_cert, fKey=cls._fernet_key)
                credential = {
                        "type" : "public-key",
                        "id": _authenticator._get_credential_id_bytes(_authenticator.kp),
                        "transports": ["usb"]}
                #Generate the assertion response data
                authData = _authenticator.build_authenticator_data({'rpId': rpId}, 'packed', _authenticator.kp, False)
                #Sign it
                sig = _authenticator.assertion_signature(authData, clientDataHash, _authenticator.kp)
                return credential, authData, sig
            except Exception:
                colour_print(colour=bcolors.FAIL, component='FIDO2Authenticator.assertion_outputs',
                             msg='Could not retrieve key pair from credential id {}'.format(cred))
                continue
        return None, None, None

class CBORCommand(object):

    class CommandByte(Enum):
        MAKE_CREDENTIAL = 0x1
        GET_NEXT_ASSERTION = 0x2
        GET_INFO = 0x4
        CLIENT_PIN = 0x6
        RESET = 0x7
        CREDENTIAL_MANAGEMENT = 0x9
        AUTHENTICATOR_SELECTION = 0xB
        AUTHENTICATOR_CONFIG = 0xD

        def __repr__(self):
            return f'{self.__class__.__name__}.{self.name}'

    request = []
    response = []
    response_segment = 0
    length = 0
    next_segment = 0
    cmd = None

    def __init__(self, ba):
        if len(ba) < 1:
            colour_print(colour=bcolors.OKYELLOW, component='CBORCommand.__init__', 
                    msg="Byte Array must be at least one byte long")
            self.cmd = ba[0:1]
            self.length = ba[1:2]
            self.response = self.unpack(ba[2:])

    #Return CBOR response if entire command has been received or None if still 
    #waiting for segments
    def unpack(self, segment):
        return {
            CommandByte.MAKE_CREDENTIAL: self._make_cred,
            CommandByte.GET_NEXT_ASSERTION: self._get_assertion,
            CommandByte.GET_INFO: self._get_info,
            }.get(cmd)(segment)

    # authenticatorGetInfo takes no inputs so return immediately
    def _get_info(self, ba):
        result = {
            0x01: ["FIDO_2_1", "FIDO_2_0"],
            0x03: b'\x00' * 16,
            0x04: {'rk': True, 'up': True, 'plat': False, 'clientPin': True},
            0x05: 2000,
            0x06: [1],
            0x09: ["usb"]
        }
        self.response += cbor.dumps(result)


    def __generate_attestation(self, options):
        # https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#authenticatorMakeCredential
        authData, attStmt = Authenticator.attestation_outputs(options.get(0x01), options.get(0x02), options.get(0x03),
                                            options.get(0x04), options.get(0x05), options.get(0x06))
        result = {
            0x01: 'packed', #fmt
            0x02 : authData,
            0x03: attStmt,
            0x04: False, #epAtt
            0x06: {} #unsigned extensions output
        }
        return result

    def __generate_assertion(self, options):
        # https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#authenticatorGetAssertion
        credential, authData, signature = Authenticator.assertion_outputs(options.get(0x01), options.get(0x02),
                                                            options.get(0x03), options.get(0x04))
        result = {
                0x01: credential,
                0x02: authData,
                0x03: signature
                0x08: {}, #unsigned extensions output
                0x09: False #epAtt
        }
        return result


    def _make_cred(self, ba):
        self.request += bytes(ba)
        if len(self.request) >= self.length:
            #We have the whole request, we can generate a response now
            req = cbor.loads(b''.join(i.to_bytes(1) for i in self.request[:self.length]))
            for props in [(0x01, 'clientDataHash'), (0x02, 'rp'), (0x03, 'user'), (0x04, 'pubkeyCredParams')]:
                if not prop[0] in req:
                    colour_print(colour=bcolors.FAIL, component='CBORCommand._make_cred',
                                 msg='{} misssing from request:\n{}'.format(prop[1], cbor.dumps(req)))
                    raise Exception("Missing required property %s" % prop[1])
            rsp = self.__generate_attestation(req)
            self.response = cbor.dumps(rsp)


    def _get_assertion(self, ba):
        self.request += bytes(ba)
        if len(self.request) >= self.length:
            #We have the whole request, we can generate a response now
            req = cbor.loads(b''.join(i.to_bytes(1) for i in self.request[:self.length]))
            for props in [(0x01, 'rpId'), (0x02, 'clientDataHash')]:
                if not prop[0] in req:
                    colour_print(colour=bcolors.FAIL, component='CBORCommand._make_cred',
                                 msg='{} misssing from request:\n{}'.format(prop[1], cbor.dumps(req)))
                    raise Exception("Missing required property %s" % prop[1])
            rsp = self.__generate_assertion(req)
            self.response = cbor.dumps(rsp)


class CTAPInitResponse(BaseStructure):
    _fields_ = [
        ('cid', 'I'),
        ('cmd', 'B'),
        ('bcnt', 'H'),
    ]

    def __init__(self, **kwargs):
        if 'data' in kwargs:
            index = None
            for i, field in enumerate(self._fields_):
                if field[0] == 'data':
                    index = i
                    break
            if index == None:
                print("setting data field")
                self._fields_ += [('data', '%ds' % len(kwargs['data']))]
            else:
                print('data already exists as a field, updating it')
                self._fields_[index] = ('data', '%ds' % len(kwargs['data']))
            print(self._fields_)
        super().__init__(**kwargs)

class CtapContinueResponse(BaseStructure):

    def __init__(self, **kwargs):
        print(kwargs)
        if 'data' in kwargs:
            index = None
            for i, field in enumerate(self._fields_):
                if field[0] == 'data':
                    index = i
                    break
            if index == None:
                print("setting data field")
                self._fields_ += [('data', '%ds' % len(kwargs['data']))]
            else:
                print('data already exists as a field, updating it')
                self._fields_[index] = ('data', '%ds' % len(kwargs['data']))
            print(self._fields_)
        super(CTAPContinueResponse, self).__init__(**kwargs)

    _fields_ = [
        ('cid', 'I'),
        ('seq', 'B'),
    ]


class CTAP2HIDevice(USBDevice):
    speed = 2
    vendorID = 0x3713
    productID = 0x3713
    bcdDevice = 0x0
    bcdUSB = 0x0
    bNumConfigurations = 0x1
    bNumInterfaces = 0x1
    bConfigurationValue = 0x1
    bDeviceClass = 0x0
    bDeviceSubClass = 0x0
    bDeviceProtocol = 0x0
    bNumConfigurations = 1
    bConfigurationValue = 1
    bNumInterfaces = 1
    configurations = [configuration]  # Supports only one configuration

    #This will contain the current set of channel id's and associated state
    cids = {}
    pending = []

    def __init__(self):
        USBDevice.__init__(self)
        self.start_time = datetime.datetime.now()

    def unlink(self, usb_req):
        index = None
        for i, req in enumerate(self.pending):
            if req.seqnum == usb_req.unlink_seqnum:
                index = i
        if index != None:
            del self.pending[index]
            colour_print(component='CTAP2HIDevice.unlink', msg='unlinked request {}'.format(usb_req.unlink_seqnum))
            return True
        return False

    def generate_fido2_report(self):
        arr = [0x06, 0xd0, 0xf1,        # USAGE_PAGE (FIDO Alliance)
                0x09, 0x01,             # USAGE (CTAPHID)
                0xa1, 0x01,             # HID_Collection(HID_Application)
                0x09, 0x20,             # USAGE (Input Report Data)
                0x15, 0x00,             # LOGICAL_MINIMUM (0)
                0x26, 0xff, 0x00,       # LOGICAL_MAXIMUM (255)
                0x75, 0x08,             # REPORT_SIZE (8)
                0x95, 0x40,             # REPORT_COUNT (64)
                0x81, 0x02,             # INPUT (Data,Var,Abs)
                0x09, 0x21,             # USAGE(Output Report Data)
                0x15, 0x00,             # LOGICAL_MINIMUM (0)
                0x26, 0xff, 0x00,       # LOGICAL_MAXIMUM (255)
                0x75, 0x08,             # REPORT_SIZE (8)
                0x95, 0x40,             # REPORT_COUNT (64)
                0x91, 0x02,             # OUTPUT (Data,Var,Abs)
            0xc0]                   # End Collection
        return bytes(arr) 

    def _bytes_to_str(self, b):
        return ''.join("%02X" % x for x in b)


    def send_response_segment(self, cid, cbor_cmd):
        rsp_data = cid
        rsp_data += int.to_bytes(cbor_cmd.response_segment, 1)
        if len(cbor_cmd.response) > 58:
            rsp_data += cbor_cmd.response[:58]
            cbor_cmd.response = cbor_cmd.response[58:]
        else:
            rsp_data += cbor_cmd.response
        # Pad out to 64 bytes
        rsp_data += b'\x00' * (64 - len(rsp_data))
        self.send_usb_req(rsp_data, len(rsp), start_frame=0xFFFFFFFF, packets=0, 
                          ep=0, direction=0, seqnum=self.pending[0].seqnum)
        del self.pending[0]
        cbor_cmd.response_segment += 1
        return


    def ctaphid_ping(self, usb_req):
        return

    def ctaphid_msg(self, usb_req):
        cid = usb_req.data_frame[0:4]
        if not cid in self.cids:
            colour_print(colour=bcolors.FAIL, component='USBDevice.ctaphid_msg', 
                         msg='Unknown CID {}'.format(cid))
        cmd = usb_req.data_frame[4:5]
        u2f_cmd = usb_req.data_frame[5:7]
        u2f_p1 = usb_req.data_frame[7:9]
        u2f_p2 = usb_req.data_frame[9:11]
        u2f_lc = usb_req.data_frame[11:13]
        u2f_req_data = None
        if int.from_bytes(u2f_lc) > 0:
            u2f_req_data = usb_req.data_frame[13:13 + int.from_bytes(u2f_lc)]
        u2f_le = None
        if len(usb.rwq.data_frame) > (13 + int.from_bytes(u2f_lc)):
            u2f_le = usb_req.data_frame[13 + int.from_bytes(u2f_lc):]
        return

    def ctaphid_init(self, usb_req):
        cid = usb_req.data_frame[0:4]
        cmd = usb_req.data_frame[4:5]
        bcnt = usb_req.data_frame[5:7]
        nonce = usb_req.data_frame[7:15]
        assignedCID = bytes([0, random.randint(0, 255), 0, random.randint(0, 255)])
        # protocol == 2; major version == 1; minor version = 2; build version = 5
        data = nonce + assignedCID + int.to_bytes(2) + int.to_bytes(5) + int.to_bytes(1) + int.to_bytes(2) \
                + int.to_bytes(5)
        dump_bytes(data, colour=bcolors.OKGREEN, component='USBDevice.ctaphid_init', msg='Response data')
        data += b'\00' * (57 - len(data)) # 64 - 4 (CID) - 1 (cmd) - 2 (bcnt) - len of response
        rsp = CTAPInitResponse(cid=int.from_bytes(cid), cmd=int.from_bytes(cmd), bcnt=17, data=data).pack()
        dump_bytes(rsp, colour=bcolors.OKGREEN, component='USBDevice.ctaphid_init', msg='Packed response')
        self.cids[assignedCID] = {'message': [rsp]}
        #return self.send_usb_req(usb_req, rsp, 64, ep=0x81, start_frame=int.from_bytes(cid))
        #self.send_usb_req(usb_req, b'', 0, ep=usb_req.ep)
        self.send_usb_req(rsp, len(rsp), start_frame=0xFFFFFFFF, packets=0, 
                          ep=0, direction=0, seqnum=self.pending[0].seqnum)
        del self.pending[0]

    def ctaphid_cbor(self, usb_req):
        cid = usb_req.data_frame[0:4]
        colour_print(colour=bcolors.OKGREEn, component='USBDevice.ctaphid_cbor', 
                    msg='CBOR message recieved on channel {}'.format(cid))
        cmd = usb_req.data_frame[4:5]
        bcnt = usb_req.data_frame[5:7]
        ctap_cmd = usb_req.data_frame[7:8]
        cbor_data = usb_req.data_frame[8: int.from_bytes(bcnt) - 1]
        dump_bytes(cbor_data, colour=bcolors.OKCYAN, component='USBDevice.ctaphid_cbor', 
                    msg='CBOR encoded bytes:')
        cbor_cmd = CBORCommand(usb_req.data_frame[7:])
        self.cids[cid]['currentReq'] = cbor_cmd
        if len(cbor_cmd.response) != 0:
            #We can respond immediatly
            return self.send_response_segment(cid, cbor_cmd)
        else:
            colour_print(colour=bcolors.YELLOW, component='USBDevice.ctaphid_cbor', 
                         msg="Waiting for rest of command to arrive . . .")
            return

    def ctaphid_cancel(self, usb_req):
        return

    def ctaphid_keepalive(self, usb_req):
        return

    def ctaphid_error(self, usb_req):
        return

    def ctaphid_unknown(self, usb_req):
        colour_print(colour=bcolors.FAIL, component='USBDevice.ctaphid_unknown', msg='Unkown request recieved')
        self.send_usb_req(b'', 0, ep=usb_req.ep, seqnum=usb_req.seqnum)

    def handle_data(self, usb_req):
        '''
        if usb_req.start_frame == 0xFFFFFFFF:
            colour_print(component='USBDevice.handle_data', msg='Don\'t know what to do with this request')
            self.send_usb_req(b'', 0, seqnum=usb_req.seqnum)
        '''
        if usb_req.ep == 0xE: #HOST In endpoint, add it to the queue so we can use it when we have data 
            # or use it to send the current in progress transaction
            colour_print(component='USBDevice.handle_data', msg='Adding request to pending')
            self.pending.append(usb_req)
            for cid, context in self.cids.items():
                if context.get('currentRsp') != None:
                    colour_print(component='USBDevice.handle_data', 
                                msg='Using pending request to send response segment')
                    self.send_response_segment(cid, context)
            return
        else:
            #We have data, work out what to do with it and if we have a pending request we can respond with
            if len(self.pending) == 0:
                colour_print(colour=bolors.FAIL, component="USBDevice.handle_data", 
                             msg="No pending request to respond with :(")
            else:
                self.send_usb_req('', 64, ep=0, start_frame=0xFFFFFFFF, seqnum=usb_req.seqnum)

        cid = usb_req.data_frame[0:4]
        cmd = usb_req.data_frame[4:5]
        colour_print(colour=bcolors.OKGREEN, component='USBDevice.handle_data', 
                    msg='CID: {}; command: {}'.format(self._bytes_to_str(cid), self._bytes_to_str(cmd)))
        if(int.from_bytes(cmd) & 0x80) == 0:
            colour_print(colour=bcolors.FAIL, component='USBDevice.handle_data', 
                        msg='bit 7 not set in command byte')
            ctapCmd = int.from_bytes(cmd) & 0x7F
            return {
                1: self.ctaphid_ping,
                3: self.ctaphid_msg,
                6: self.ctaphid_init,
                16: self.ctaphid_cbor,
                17: self.ctaphid_cancel,
                59: self.ctaphid_keepalive,
                63: self.ctaphid_error,
            }.get(ctapCmd, self.ctaphid_unknown)(usb_req)
        else:
            colour_print(colour=bcolors.OKPURPLE, component='USBDevice.handle_data',
                         msg='Recieved a sequence segment, appending it to the current msg context')
            context = self.cids.get(cid)
            if context != None:
                transaction = context.get("currentReq")
                seqNum = usb_req.data_frame[4:5]
                if transaction != None and seqNum = transaction.next_segment:
                    response = transaction.unpack(usb_req.data_frame[5:])
                    if response == None:
                        transaction.next_segment += 1
                    else:
                        context['currentRsp'] = response
                        self.send_response_segment(cid, context)
                else:
                    colour_print(colour=bcolors.FAIL, component='USBDevice.handle_data', 
                                 msg='Sequence number [{}] not the next expected sequence [{}]'.format(
                                     seqNum,transaction.next_segment))
            else:
                colour_print(colour=bcolors.FAIL, component='USBDevice.handle_data', 
                             msg='CID not found in device context, don\'t know what to do')


    def handle_unknown_control(self, control_req, usb_req):
        handled = False
        if control_req.bmRequestType == 0x81: #Interface request
            if control_req.bRequest == 0x6:  # Get Descriptor
                if control_req.wValue == 0x22:  # send initial report
                    print('[' + bcolors.OKGREEN + 'USBDevice' + bcolors.ENDC + '] Send initial report ')
                    ret=self.generate_fido2_report()
                    self.send_usb_req(ret, len(ret), seqnum=usb_req.seqnum)
                    handled = True
        elif control_req.bmRequestType == 0x21:  # Host Request
            if control_req.bRequest == 0x0a:  # set idle
                print('[' + bcolors.OKGREEN + 'USBDevice' + bcolors.ENDC + '] HID Idle ')
                self.send_usb_req(b'', 0, seqnum=usb_req.seqnum)
                handled = True
        else:
            print('[' + bcolors.FAIL + 'USBDevice' + bcolors.ENDC + '] Unknown control [{}] '.format(
                ', '.join( hex(x) for x in list(usb_req.setup.to_bytes(8, 'big')) )))
            print('[' + bcolors.FAIL + 'USBDevice' + bcolors.ENDC + '] Unknown flags [{}] '.format(
                ', '.join( hex(x) for x in list(usb_req.flags.to_bytes(8, 'big')) )))
            print('[' + bcolors.FAIL + 'USBDevice' + bcolors.ENDC + '] Unknown data [{}] '.format(
                ', '.join( hex(x) for x in list(usb_req.data_frame) )))
            #raise RuntimeError("unknown control")
            self.send_usb_req(b"\x01\x00",2, seqnum=usb_req.seqnum)
            pass
        return handled


'''
To run:
    on CLIENT::
    $ python hid_device.py

    on SERVER::
    sudo modprobe vhci-hcd
    sudo usbip -d list -r 127.0.0.1
    sudo usbip -d attach -r 127.0.0.1 -b 1-1.1
    lsusb -v -d 1337:1337
'''

usb_dev = CTAP2HIDevice()
usb_container = USBContainer()
usb_container.add_usb_device(usb_dev)  # Supports only one device!
usb_container.run()
