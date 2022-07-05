# Copyrite IBM 2022

# CTAP2HID reads bytes from endpoint 1,building the frames into a CTAPMsg. A CTAPMsg is used to initalize a 
#FIDO2Transaction thread which will reply on endpoint 2 when the transaction is complete.

import base64, datetime, threading, os, sys, random
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from usb_ip import BaseStucture, USBDevice, InterfaceDescriptor, DeviceConfigurations, EndPoint, USBContainer, USBIPCMDSubmit

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

CTAPHID_BROADCAST_CHANNEL = 0xffffffff
CTAPHID_PING = 0x01
CTAPHID_MSG = 0x03
CTAPHID_INIT = 0x06
CTAPHID_CBOR = 0x10
CTAPHID_CANCEL = 0x11
CTAPHID_KEEPALIVE = 0x3b
CTAPHID_ERROR = 0x3f


# Class processes a compelete CTAP message, creating a thread to run any FIDO operation,
# then sends the complete data frame back when the transaction is done.
class FIDO2Transaction():
    #TODO
    #Complete msg
    msg = None
    #Hande to usb device to send response
    usb_req = None
    error = False
    complete = False
    authenticator = None
    _thread = None

    def __init__(self, msg, usb_req):
        self.msg = msg
        self.usb_req = usb_req
        #Mandatory commands
        fptr = {
                CTAPHID_PING: self.ping, #CTAPHID_PING (0x01)
                CTAPHID_MSG: self.u2f_msg, #CTAPHID_MSG (0x03)
                CTAPHID_INIT: self.cid_init, #CTAPHID_INIT (0x06)
                CTAPHID_CBOR: self.cbor_msg, #CTAPHID_CBOR (0x10)
                CTAPHID_CANCEL: self.cancel, #CTAPHID_CANCEL (0x11)
                CTAPHID_KEEPALIVE: self.keep_alive, #CTAPHID_KEEPALIVE (0x3B)
                CTAPHID_ERROR: self.error #CTAPHID_ERROR (0x3F)
            }.get(msg.cmd, self.error)
        if not fptr:
            print('[' + bcolors.FAIL + 'FIDO2Transaction' + bcolors.ENDC + '] command not found {} '.format(msg.cmd))
        fptr()


    def error(self):
        #TODO
        return


    def u2f_msg(self):
        #TODO
        return

    def cbor_msg(self):
        #TODO
        return

    def ping(self):
        #TODO
        return


    def cancel(self):
        #TODO
        return

    def keep_alive(self):
        #TODO
        return

    def cid_init(self):
        #TODO
        return


# Container class to incrementally builda  CTAP message. When the entire message has arrived the complete
# attribute is set.
class CTAPMsg():
    cmd = 0x00
    cid = 0xffffffff
    data_len = -1
    cbor_data = []
    seq = -1
    complete = False

    def __init__(self, usb_req):
        print('[' + bcolors.OKGREEN + 'CTAPMsg' + bcolors.ENDC + '] __init__ [{}]'.format(
            ', '.join( hex(x) for x in list(usb_req) )))
        self.cid = usb_req[:8]
        self.data_len = int.from_bytes(usb_req[8:10], 'big')
        self.cbor_data += usb_req[10: min(self.data_len, 64)]
        self._is_complete()
        print('[' + bcolors.OKGREEN + 'CTAPMsg' + bcolors.ENDC + '] _is_complete() {} '.format(self.complete))


    def _is_complete(self):
        if len(self.cbor_data) >= self.data_len: self.complete = True
        return self.complete


    def update(self, usb_req):
        if self.complete == True:
            return CTAPMsg(usb_req)
        else:
            if self.seq + 1 != usb_req[4:5]:
                raise RuntimeError("invalid sequence")
            self.seq += 1
            self.cbor_data += usb_req[5:]
        self._is_complete()


# Classes to create a USB device object, connect it to the system usb daemon and begin tx/rx
class CTAP2HIDClass(BaseStucture):
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


end_point_one = EndPoint(bEndpointAddress=0x01, # OUT
                     bmAttributes=0x3, # Interrupt transfer
                     wMaxPacketSize=(64&0x00FF)<<8 | (64&0xFF00),  # 64-byte packet max
                     bInterval=5)  # Poll every 5 millisecond


end_point_two = EndPoint(bEndpointAddress=0x81, # IN
                     bmAttributes=0x3, # Interrupt transfer
                     wMaxPacketSize=(64&0x00FF)<<8 | (64&0xFF00),  # 64-byte packet max, bussit
                     bInterval=5)  # Poll every 5 millisecond


interface_d.descriptions = [hid_class]  # Supports only one description
interface_d.endpoints = [end_point_one, end_point_two]  # Supports two endpoint
# wTotalLength = len( interface_d.pack() + hid_class.pack() + end_point_one.pack() + end_point_two.pack() + 18)
configuration = DeviceConfigurations(wTotalLength=0x2900,
                                     bNumInterfaces=0x1,
                                     bConfigurationValue=0x1,
                                     iConfiguration=0x0,  # No string
                                     bmAttributes=0x80,  # valid self powered
                                     bMaxPower=50)  # 50 mah current
configuration.interfaces = [interface_d]   # Supports only one interface

class CTAP2HID(USBDevice):
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

    def __init__(self):
        USBDevice.__init__(self)
        self.start_time = datetime.datetime.now()


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


    def handle_data(self, control_req, data):
        #TODO
        print('[' + bcolors.WARNING + 'CTAP2HIDevice' + bcolors.ENDC + '] Request data [{}] '.format(
            ', '.join( hex(x) for x in list(data) )))
        cid = control_req.start_frame.to_bytes(4, 'big')
        print('[' + bcolors.WARNING + 'CTAP2HIDevice' + bcolors.ENDC + '] CID [{}]'.format(
            ', '.join( hex(x) for x in list(cid) )))
        if cid in self.cids:
            self.cids[cid]['msg'] = self.cids[cid]['msg'].update(data)
        elif int.from_bytes(cid, 'big') == CTAPHID_BROADCAST_CHANNEL:
            cid = random.randbytes(4)
            print('[' + bcolors.OKGREEN + 'CTAP2HIDevice' + bcolors.ENDC + '] assign CID [{}]'.format(
                ', '.join( hex(x) for x in list(cid) )))
            new_cid = {
                    "cid": cid,
                    "msg": CTAPMsg(control_req.data)
                }
            self.cids[cid] = new_cid
        else:
            print('[' + bcolors.FAIL + 'CTAP2HIDevice' + bcolors.ENDC + '] Don\'t know what to do')
            #print(base64.b64encode(data).decode())
            #raise RuntimeError("invalid frame")
            self.send_usb_req(usb_req, '', 0,0)
            #self.send_usb_req(usb_req, b"\x01\x00",2)
            return
        cid_state = self.cids[cid]
        if not cid_state:
            raise RuntimeError("message lost for cid {}".format(base64.b64encode(cid).decode()))
        if cid_state['msg'].complete == True:
            cid_state['txn'] = FIDO2Transaction(cid_state['msg'], data)


    def handle_unknown_control(self, control_req, usb_req):
        handled = False
        if control_req.bmRequestType == 0x81: #Interface request
            if control_req.bRequest == 0x6:  # Get Descriptor
                if control_req.wValue == 0x22:  # send initial report
                    print('[' + bcolors.OKGREEN + 'USBDevice' + bcolors.ENDC + '] Send initial report ')
                    ret=self.generate_fido2_report()
                    self.send_usb_req(usb_req, ret, len(ret))
                    handled = True
        elif control_req.bmRequestType == 0x21:  # Host Request
            if control_req.bRequest == 0x0a:  # set idle
                print('[' + bcolors.OKGREEN + 'USBDevice' + bcolors.ENDC + '] HID Idle ')
                self.send_usb_req(usb_req, '', 0,1)
                handled = True
        else:
            print('[' + bcolors.FAIL + 'USBDevice' + bcolors.ENDC + '] Unknown control [{}] '.format(
                ', '.join( hex(x) for x in list(usb_req.setup.to_bytes(8, 'big')) )))
            print('[' + bcolors.FAIL + 'USBDevice' + bcolors.ENDC + '] Unknown flags [{}] '.format(
                ', '.join( hex(x) for x in list(usb_req.flags.to_bytes(8, 'big')) )))
            print('[' + bcolors.FAIL + 'USBDevice' + bcolors.ENDC + '] Unknown data [{}] '.format(
                ', '.join( hex(x) for x in list(usb_req.data) )))
            #raise RuntimeError("unknown control")
            self.send_usb_req(usb_req, b"\x01\x00",2)
            pass
        return handled


usb_dev = CTAP2HID()
usb_container = USBContainer()
usb_container.add_usb_device(usb_dev)  # Supports only one device!
usb_container.run()
