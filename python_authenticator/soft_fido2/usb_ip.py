'''
Copyright (c) 2014 Yaron Shani <yaron.shani@gmail.com>.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.

This software is provided ``as is'' and any express or implied
warranties, including, but not limited to, the implied warranties of
merchantability and fitness for a particular purpose are
disclaimed. In no event shall author or contributors be liable for any
direct, indirect, incidental, special, exemplary, or consequential
damages (including, but not limited to, procurement of substitute
goods or services; loss of use, data, or profits; or business
interruption) however caused and on any theory of liability, whether
in contract, strict liability, or tort (including negligence or
otherwise) arising in any way out of the use of this software, even if
advised of the possibility of such damage.

Update 2022 by Lachlan Gleeson for python 3
'''

import socketserver, datetime, struct, traceback, re


# Hey StackOverflow !
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    OKPINK = '\033[95m'
    OKYELLOW = '\033[93m'
    OKPURPLE = '\033[35m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def colour_print(colour=bcolors.OKBLUE, component='USB/IP', msg=''):
    print('[' + colour + component + bcolors.ENDC + '] ' + msg)


def print_bytes(*args):
    result = ""
    count = 0
    for ba in args:
        for x in ba:
            result += "%02X " % x
            count += 1
            if count == 8 :
                result += " "
            elif count == 16:
                print("\t" + result)
                result = ""
                count = 0
    print('\t' + result + '\n')

def dump_bytes(*args, colour=bcolors.OKPURPLE, component='USB/IP CONTROLLER', msg=''):
    #Print bytes in nice format
    c = colour if colour != None else bcolors.OKPURPLE
    colour_print(colour=colour, component=component, msg=msg)
    print_bytes(*args)


class BaseStructure(object):
    _fields_ = []

    def __init__(self, **kwargs):
        self.init_from_dict(**kwargs)
        for field in self._fields_:
            if len(field) > 2:
                if not hasattr(self, field[0]):
                    setattr(self, field[0], field[2])

    def init_from_dict(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    def size(self):
        return struct.calcsize(self.format())

    def format(self):
        pack_format = '>'
        for field in self._fields_:
            if isinstance(field[1], BaseStructure):
                pack_format += str(field[1].size()) + 's'
            elif 'si' == field[1]:
                pack_format += 'c'
            elif '<' in field[1] or '>' in field[1]:
                pack_format += field[1][1:]
            else:
                pack_format += field[1]
        #print(pack_format)
        return pack_format.encode('utf-8')

    def formatDevicesList(self, devicesCount):

        pack_format = '>'
        i = 0
        for field in self._fields_:
            if (i == devicesCount + 2):
                break
            if isinstance(field[1], BaseStructure):
                pack_format += str(field[1].size()) + 's'
            elif 'si' == field[1]:
                pack_format += 'c'
            elif '<' in field[1]:
                pack_format += field[1][1:]
            else:
                pack_format += field[1]
            i += 1
        #print(pack_format)
        return pack_format.encode('utf-8')

    def pack(self):
        values = []
        for field in self._fields_:
            #print("Field: {}".format(field))
            if isinstance(field[1], BaseStructure):
                values.append(getattr(self, field[0], 0).pack())
            elif re.match(r'\d*x', field[1]):
                #Skipp padding
                continue
            else:
                if 'si' == field[1]:
                    values.append(chr(getattr(self, field[0], 0)))
                else:
                    values.append(getattr(self, field[0], 0))
        #Python 2 -> 3, str != bytestring so conditionally remap any strings we find.
        values = [bytes(v, 'utf-8') if isinstance(v, str) else v for v in values]
        #print(values)
        packed = struct.pack(self.format(), *values)
        #print("packed [{}]".format(packed))
        return packed 

    def packDevicesList(self, devicesCount):
        values = []
        i = 0
        for field in self._fields_:
            if (i == devicesCount + 2):
                break
            if isinstance(field[1], BaseStructure):
                values.append(getattr(self, field[0], 0).pack())
            else:
                if 'si' == field[1]:
                    values.append(chr(getattr(self, field[0], 0)))
                else:
                    values.append(getattr(self, field[0], 0))
            i += 1
        return struct.pack(self.formatDevicesList(devicesCount), *values)

    def unpack(self, buf):
        values = struct.unpack(self.format(), buf)
        i=0
        keys_vals = {}
        for val in values:
            if '<' in self._fields_[i][1][0]:
                val = struct.unpack('<' +self._fields_[i][1][1], struct.pack('>' + self._fields_[i][1][1], val))[0]
            keys_vals[self._fields_[i][0]]=val
            i+=1
        #print(keys_vals)
        self.init_from_dict(**keys_vals)


class USBIPHeader(BaseStructure):
    _fields_ = [
        ('version', 'H', 273),
        ('command', 'H'),
        ('status', 'I')
    ]


class USBInterface(BaseStructure):
    _fields_ = [
        ('bInterfaceClass', 'B'),
        ('bInterfaceSubClass', 'B'),
        ('bInterfaceProtocol', 'B'),
        ('align', 'B', 0)
    ]

class USBIPDevice(BaseStructure):
    _fields_ = [
        ('usbPath', '256s'),
        ('busID', '32s'),
        ('busnum', 'I'),
        ('devnum', 'I'),
        ('speed', 'I'),
        ('idVendor', 'H'),
        ('idProduct', 'H'),
        ('bcdDevice', 'H'),
        ('bDeviceClass', 'B'),
        ('bDeviceSubClass', 'B'),
        ('bDeviceProtocol', 'B'),
        ('bConfigurationValue', 'B'),
        ('bNumConfigurations', 'B'),
        ('bNumInterfaces', 'B'),
        ('interfaces', USBInterface())
    ]

class OPREPDevList(BaseStructure):

    def __init__(self, dictArg, count):
        self._fields_ = [
            ('base', USBIPHeader(), USBIPHeader(command=5,status=0)), # Declare this here to make sure it's in the right order
            ('nExportedDevice', 'I', count) # Same for this guy
        ]

        for key, value in dictArg.items():
            field = (str(key), value[0], value[1])
            self._fields_.append(field)

        for field in self._fields_:
            if len(field) > 2:
                if not hasattr(self, field[0]):
                    setattr(self, field[0], field[2])

class OPREPImport(BaseStructure):
    _fields_ = [
        ('base', USBIPHeader()),
        ('usbPath', '256s'),
        ('busID', '32s'),
        ('busnum', 'I'),
        ('devnum', 'I'),
        ('speed', 'I'),
        ('idVendor', 'H'),
        ('idProduct', 'H'),
        ('bcdDevice', 'H'),
        ('bDeviceClass', 'B'),
        ('bDeviceSubClass', 'B'),
        ('bDeviceProtocol', 'B'),
        ('bConfigurationValue', 'B'),
        ('bNumConfigurations', 'B'),
        ('bNumInterfaces', 'B')
    ]

# https://www.kernel.org/doc/html/v5.14/usb/usbip_protocol.html

class USBIPRETSubmit(BaseStructure):

    '''
    def __init__(self, **kwargs):
        if 'data_frame' in kwargs:
            self._fields_ += [('data_frame', "%ds" % len(kwargs['data_frame']))]
            print(self._fields_)
        super(USBIPRETSubmit, self).__init__(**kwargs)
    '''

    _fields_ = [
        ('command', 'I'),
        ('seqnum', 'I'),
        ('devid', 'I'),
        ('direction', 'I'),
        ('ep', 'I'),
        ('status', 'I'),
        ('actual_length', 'I'),
        ('start_frame', 'I'),
        ('number_of_packets', 'I'),
        ('error_count', 'I'),
        ('padding', 'Q')
    ]

    def pack(self):
        packed_data = BaseStructure.pack(self)
        #print("packed_data: [{}]".format(packed_data))
        #print("self.data: [{}]".format(self.data))
        if isinstance(self.data_frame, str):
            self.data_frame = self.data_frame.encode()
        packed_data += self.data_frame
        return packed_data

class USBIPCMDUnlink(BaseStructure):
    _fields_ = [
        ('seqnum', 'I'),
        ('devid', 'I'),
        ('direction', 'I'),
        ('ep', 'I'),
        ('seqnum2', 'I'),
    ]

'''
class USBIBCMDBasic(BaseStructure):
    _fields_ = [
        ('command', 'I'), #0x1
        ('seqnum', 'I'),
        ('devid', 'I'),
        ('direction', 'I'),
        ('ep', 'I')
    ]
'''

class USBIPCMDSubmit(BaseStructure):
    _fields_ = [
        ('command', 'I'),
        ('seqnum', 'I'),
        ('devid', 'I'),
        ('direction', 'I'),
        ('ep', 'I'),
        ('transfer_flags', 'I'),
        ('transfer_buffer_length', 'I'),
        ('start_frame', 'I'),
        ('number_of_packets', 'I'),
        ('interval', 'I'),
        ('setup', 'Q')
    ]

class USBIPUnlinkReq(BaseStructure):
    _fields_ = [
        ('seqnum', 'I'),
        ('devid', 'I'),
        ('direction', 'I'),
        ('ep', 'I'),
        ('unlink_seqnum', 'I'),
        ('padding', '24x')
    ]

class USBIPUnlinkRet(BaseStructure):
    _fields_ = [
        ('command', 'I', 0x4),
        ('seqnum', 'I'),
        ('devid', 'I', 0x2),
        ('direction', 'I'),
        ('ep', 'I'),
        ('status', 'I'),
        ('padding', '24x')
    ]


class StandardDeviceRequest(BaseStructure):
    _fields_ = [
        ('bmRequestType', 'B'),
        ('bRequest', 'B'),
        ('wValue', 'H'),
        ('wIndex', 'H'),
        ('wLength', '<H')
    ]

class DeviceDescriptor(BaseStructure):
    _fields_ = [
        ('bLength', 'B', 18),
        ('bDescriptorType', 'B', 1),
        ('bcdUSB', 'H', 0x1001),
        ('bDeviceClass', 'B'),
        ('bDeviceSubClass', 'B'),
        ('bDeviceProtocol', 'B'),
        ('bMaxPacketSize0', 'B'),
        ('idVendor', '>H'),
        ('idProduct', '>H'),
        ('bcdDevice', 'H'),
        ('iManufacturer', 'B'),
        ('iProduct', 'B'),
        ('iSerialNumber', 'B'),
        ('bNumConfigurations', 'B')
    ]

class DeviceConfigurations(BaseStructure):
    _fields_ = [
        ('bLength', 'B', 9),
        ('bDescriptorType', 'B', 2),
        ('wTotalLength', 'H', 0x2900),
        ('bNumInterfaces', 'B', 1),
        ('bConfigurationValue', 'B', 1),
        ('iConfiguration', 'B', 0),
        ('bmAttributes', 'B', 0x80),
        ('bMaxPower', 'B', 0x32)
    ]


class InterfaceDescriptor(BaseStructure):
    _fields_ = [
        ('bLength', 'B', 9),
        ('bDescriptorType', 'B', 4),
        ('bInterfaceNumber', 'B', 0),
        ('bAlternateSetting', 'B', 0),
        ('bNumEndpoints', 'B', 1),
        ('bInterfaceClass', 'B', 3),
        ('bInterfaceSubClass', 'B', 1),
        ('bInterfaceProtocol', 'B', 2),
        ('iInterface', 'B', 0)
    ]


class EndPoint(BaseStructure):
    _fields_ = [
        ('bLength', 'B', 7),
        ('bDescriptorType', 'B', 0x5),
        ('bEndpointAddress', 'B', 0x81),
        ('bmAttributes', 'B', 0x3),
        ('wMaxPacketSize', 'H', 0x8000),
        ('bInterval', 'B', 0x0A)
    ]



class USBRequest():
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class USBDevice():
    '''interfaces = [USBInterface(bInterfaceClass=0x3, bInterfaceSubClass=0x0, bInterfaceProtocol=0x0)]
    speed=2
    speed = 2
    vendorID = 0xc410
    productID = 0x0
    bcdDevice = 0x0
    bDeviceClass = 0x0
    bDeviceSubClass = 0x0
    bDeviceProtocol = 0x0
    bNumConfigurations = 1
    bConfigurationValue = 1
    bNumInterfaces = 1'''

    def __init__(self):
        self.generate_raw_configuration()
        self.start_time = datetime.datetime.now()

    def generate_raw_configuration(self):
        _str = self.configurations[0].pack()
        _str += self.configurations[0].interfaces[0].pack()
        _str += self.configurations[0].interfaces[0].descriptions[0].pack()
        #_str += self.configurations[0].interfaces[0].endpoints[0].pack()
        for e in self.configurations[0].interfaces[0].endpoints:
            _str += e.pack()
        self.all_configurations = _str


    def send_usb_req(self, usb_res, usb_len, status=0, ep=0, start_frame=0, packets=0, seqnum=None, 
                     direction=0):
        rsp = USBIPRETSubmit(command=0x3,
                             seqnum=seqnum,
                             devid=0,
                             direction=direction,
                             ep=ep,
                             status=status,
                             actual_length=usb_len,
                             start_frame=start_frame,
                             number_of_packets=packets,
                             error_count=0,
                             interval=0x0,
                             padding=0,
                             data_frame=usb_res).pack()
        dump_bytes(list(rsp), colour=bcolors.FAIL, component='USBDevice(response)', msg='response bytes:')
        self.connection.sendall(rsp)

    def handle_get_descriptor(self, control_req, usb_req):
        handled = False
        #print("handle_get_descriptor {}".format(control_req.wValue,'n'))
        if control_req.wValue == 0x1: # Device
            handled = True
            ret=DeviceDescriptor(bDeviceClass=self.bDeviceClass,
                                 bDeviceSubClass=self.bDeviceSubClass,
                                 bDeviceProtocol=self.bDeviceProtocol,
                                 bMaxPacketSize0=8,
                                 idVendor=self.vendorID,
                                 idProduct=self.productID,
                                 bcdDevice=self.bcdDevice,
                                 iManufacturer=0,
                                 iProduct=0,
                                 iSerialNumber=0,
                                 bNumConfigurations=1).pack()
            self.send_usb_req(ret, len(ret), seqnum=usb_req.seqnum)
        elif control_req.wValue == 0x2: # configuration descriptor
            handled = True
            ret= self.all_configurations[:control_req.wLength]
            #print(ret)
            self.send_usb_req(ret, len(ret), seqnum=usb_req.seqnum)
        return handled


    def handle_set_configuration(self, control_req, usb_req):
        handled = True
        self.send_usb_req(b'', 0, seqnum=usb_req.seqnum)
        return handled

    def handle_usb_control(self, usb_req):
        control_req = StandardDeviceRequest()
        control_req.unpack(usb_req.setup.to_bytes(8, 'big'))
        handled = False
        print('[' + bcolors.OKBLUE + 'USBDevice(handle_usb_control)' + bcolors.ENDC + "] UC Request Type" + \
                " {}; UC Request {}; UC Value  {}; UCIndex  {}; UC Length {}".format(
                control_req.bmRequestType, control_req.bRequest, control_req.wValue, control_req.wIndex,
                control_req.wLength))
        if control_req.bmRequestType == 0x80: # Host Request
            if control_req.bRequest == 0x06: # Get Descriptor
                handled = self.handle_get_descriptor(control_req, usb_req)
            if control_req.bRequest == 0x00: # Get STATUS
                self.send_usb_req(b"\x01\x00", 2, seqnum=usb_req.seqnum);
                handled = True

        if control_req.bmRequestType == 0x00: # Host Request
            if control_req.bRequest == 0x09: # Set Configuration
                handled = self.handle_set_configuration(control_req, usb_req)
        if not handled:
            self.handle_unknown_control(control_req, usb_req)

    def handle_usb_request(self, usb_req):
        try:
            if usb_req.ep == 0:
                print('[' + bcolors.OKBLUE + 'USBDevice(handle_usb_request)' + bcolors.ENDC + '] Control request')
                self.handle_usb_control(usb_req)
            else:
                print('[' + bcolors.OKBLUE + 'USBDevice(handle_usb_request)' + bcolors.ENDC + \
                        '] Data request for ep {}'.format(usb_req.ep))
                self.handle_data(usb_req)
        except Exception as e:
            print(e)
            traceback.print_exc()
            raise e

class USBContainer:
    usb_devices = {}
    attached_devices = {}
    devices_count = 0

    def add_usb_device(self, usb_device):
        self.devices_count += 1
        busID = '1-1.' + str(self.devices_count)
        self.usb_devices[busID] = usb_device
        self.attached_devices[busID] = False

    def remove_usb_device(self, usb_device):
        for busid, dev in self.usb_devices.items():
            if dev == usb_device:
                del self.attached_devices[busid]
                del self.usb_devices[busid]
                break
        self.devices_count -= 1

    def detach_all(self):
        self.attached_devices = {}
        self.usb_devices = {}
        self.devices_count = 0

    def handle_attach(self, busid):
        if (self.usb_devices[busid] != None):
            busnum = int(busid[4:])
            return OPREPImport(base=USBIPHeader(command=3, status=0),
                               usbPath='/sys/devices/pci0000:00/0000:00:01.2/usb1/' + busid,
                               busID=busid,
                               busnum=busnum,
                               devnum=2,
                               speed=2,
                               idVendor=self.usb_devices[busid].vendorID,
                               idProduct=self.usb_devices[busid].productID,
                               bcdDevice=self.usb_devices[busid].bcdDevice,
                               bDeviceClass=self.usb_devices[busid].bDeviceClass,
                               bDeviceSubClass=self.usb_devices[busid].bDeviceSubClass,
                               bDeviceProtocol=self.usb_devices[busid].bDeviceProtocol,
                               bNumConfigurations=self.usb_devices[busid].bNumConfigurations,
                               bConfigurationValue=self.usb_devices[busid].bConfigurationValue,
                               bNumInterfaces=self.usb_devices[busid].bNumInterfaces)

    def handle_device_list(self):
        devices = {}

        i = 0
        for busid, usb_dev in self.usb_devices.items():
            i += 1
            devices['device' + str(i)] = [USBIPDevice(), USBIPDevice(
                usbPath='/sys/devices/pci0000:00/0000:00:01.2/usb1/' + busid,
                busID=busid,
                busnum=i,
                devnum=2,
                speed=2,
                idVendor=self.usb_devices[busid].vendorID,
                idProduct=self.usb_devices[busid].productID,
                bcdDevice=self.usb_devices[busid].bcdDevice,
                bDeviceClass=self.usb_devices[busid].bDeviceClass,
                bDeviceSubClass=self.usb_devices[busid].bDeviceSubClass,
                bDeviceProtocol=self.usb_devices[busid].bDeviceProtocol,
                bNumConfigurations=self.usb_devices[busid].bNumConfigurations,
                bConfigurationValue=self.usb_devices[busid].bConfigurationValue,
                bNumInterfaces=self.usb_devices[busid].bNumInterfaces,
                interfaces=USBInterface(bInterfaceClass=self.usb_devices[busid].configurations[0].interfaces[0].bInterfaceClass,
                                        bInterfaceSubClass=self.usb_devices[busid].configurations[0].interfaces[0].bInterfaceSubClass,
                                        bInterfaceProtocol=self.usb_devices[busid].configurations[0].interfaces[0].bInterfaceProtocol)
            )]

        return OPREPDevList(devices, len(self.usb_devices))


    def run(self, ip='0.0.0.0', port=3240):
        colour_print(colour=bcolors.OKBLUE, component='USBIP', msg='Starting server')
        socketserver.TCPServer.allow_reuse_address = True
        self.server = socketserver.ThreadingTCPServer((ip, port), USBIPConnection)
        self.server.usbcontainer = self
        self.server.serve_forever()


class USBIPConnection(socketserver.BaseRequestHandler):
    attached = False
    attachedBusID = ''

    def handle(self):
        endpoint_requests = {}
        colour_print(colour=bcolors.OKBLUE, component='USBIP', msg='New connection from {}'.format(self.client_address))
        req = USBIPHeader()
        while 1:
            if not self.attached:
                data = self.request.recv(8)
                if not data:
                    break
                req.unpack(data)
                colour_print(colour=bcolors.OKBLUE, component='USBIP', msg='Header packet is valid')
                colour_print(colour=bcolors.OKBLUE, component='USBIP', msg='Command is {}'.format(hex(req.command)))
                if req.command == 0x8005:
                    colour_print(colour=bcolors.OKBLUE, component='USBIP', msg='Querying device list')
                    self.request.sendall(self.server.usbcontainer.handle_device_list().pack())
                elif req.command == 0x8003:
                    busid = self.request.recv(5).strip()  # receive bus id
                    colour_print(colour=bcolors.OKBLUE, component='USBIP', 
                                 msg='Attaching to device with busid [{}]'.format(busid.decode()))
                    self.request.recv(27)
                    self.request.sendall(self.server.usbcontainer.handle_attach(busid.decode()).pack())
                    self.attached = True
                    self.attachedBusID = busid.decode()
                    colour_print(colour=bcolors.OKBLUE, component='USBIP', msg='attached')

            else:
                #print(self.server.usbcontainer.usb_devices)
                if (not self.attachedBusID in self.server.usbcontainer.usb_devices):
                    colour_print(colour=bcolors.WARNING, component='USBIP', msg='closing')
                    self.request.close()
                    break
                else:
                    colour_print(component='USB/IP', msg='waiting for command')
                    command = self.request.recv(4)
                    dump_bytes(command, msg='USB/IP command bytes recieved:')
                    cmdVal = struct.unpack('>I', command)[0]
                    '''
                    if (cmdVal == 0x00000003):
                        cmd = USBIPCMDUnlink()
                        data = self.request.recv(cmd.size())
                        cmd.unpack(data)
                        colour_print(component='USBIP', msg='Detaching device with seqnum {}'.format(cmd.seqnum))
                        # We probably don't even need to handle that, the windows client doesn't even send this packet
                    '''
                    if (cmdVal == 0x00000001):
                        cmd = USBIPCMDSubmit()
                        data = self.request.recv(cmd.size() - 4)
                        cmd.unpack(command + data)
                        msg = 'USB/IP Command::\n\tseqnum: {}; devid: {};\n\tdirection: {}; ep: {};\n\tflags: {};'\
                                'transfer buffer: {};\n\tstart_frame: {}; no. of pkts: {}; '\
                                '\n\tinterval: {}; setup: {}'.format(
                            cmd.seqnum,cmd.devid,cmd.direction,cmd.ep,cmd.transfer_flags,cmd.transfer_buffer_length,
                            cmd.start_frame,cmd.number_of_packets,cmd.interval,list(cmd.setup.to_bytes(8, 'big')))
                        colour_print(colour=bcolors.OKBLUE, component='USBIPConnection.handle', msg=msg)
                        if endpoint_requests.get(cmd.ep) == None:
                            endpoint_requests[cmd.ep] = 1
                        else:
                            endpoint_requests[cmd.ep] = endpoint_requests.get(cmd.ep) + 1
                        msg = "Endpoint requests: {}".format( endpoint_requests)
                        colour_print(component='USBIPConnection.handle', msg=msg)
                        data_frame = b''
                        if cmd.start_frame == 0xFFFFFFFF and cmd.transfer_flags == 0x0:
                            colour_print(colour=bcolors.OKYELLOW, component='USBIPConnection.handle', msg='CTAPHID:: '\
                                    'FIDO2 Authenticator recieved start_frame, reading rest of data maybe . . .')
                            data_frame = self.request.recv(cmd.transfer_buffer_length)
                            dump_bytes(data_frame, component='USBIPConnection.handle', msg='data bytes recieved:')
                        usb_req = USBRequest(seqnum=cmd.seqnum,
                                             devid=cmd.devid,
                                             direction=cmd.direction,
                                             ep=cmd.ep,
                                             flags=cmd.transfer_flags,
                                             number_of_packets=cmd.number_of_packets,
                                             interval=cmd.interval,
                                             setup=cmd.setup,
                                             cmd_frame=cmd.pack(),
                                             data_frame=data_frame)
                        dump_bytes(list(usb_req.setup.to_bytes(8, 'big')), colour=bcolors.FAIL, 
                                   component='USBDevice(send_usb_req)', msg='setup bytes:')
                        dump_bytes(list(usb_req.cmd_frame), list(usb_req.data_frame), colour=bcolors.FAIL, 
                                    component='USBDevice(request)', msg='whole recieved message:')
                        self.server.usbcontainer.usb_devices[self.attachedBusID].connection = self.request
                        try:
                            self.server.usbcontainer.usb_devices[self.attachedBusID].handle_usb_request(usb_req)
                        except:
                            colour_print(colour=bcolors.FAIL, component='USBIP', 
                                         msg='Connection with client ' + str(self.client_address) + ' ended')
                            break
                    elif(cmdVal == 0x00000002):
                        cmd = USBIPUnlinkReq()
                        data = self.request.recv(cmd.size())
                        cmd.unpack(data)
                        dump_bytes(command + cmd.pack(), colour=bcolors.WARNING, component='USBIP', msg='Unlink request')
                        #TODO have we actually sent a USBIP_RET_SUBMIT or not?
                        success = self.server.usbcontainer.usb_devices[self.attachedBusID].unlink(cmd)
                        status = 0x0;
                        if success == True:
                            status = 0xF
                        ret = USBIPUnlinkRet(command=0x04, seqnum=cmd.seqnum, devid=cmd.devid, direction=0, ep=cmd.ep,
                                             status=status, padding=b'\0' * 24)
                        dump_bytes(ret.pack(), colour=bcolors.WARNING, component='USBIP', msg='Unlink return')
                        self.request.sendall(ret.pack())

                    else:
                        raise Exception("Unknown USB/IP command recieved")
        self.request.close()
        self.server.server_close()
