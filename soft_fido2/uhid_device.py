#!/bin/python
#IBM Confidential
# Assisted by watsonx Code Assistant
# Copyright IBM Corp. 2025

import os, struct, fcntl, time, queue, threading, logging, re

from enum import Enum

try:
    from soft_fido2.message_queues import QueueMessageType, MessageQueue
except:
    from message_queues import QueueMessageType, MessageQueue

# Assisted by watsonx Code Assistant 
#logging.basicConfig(filename='passkey.log', filemode='a', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Thanks StackOverflow !
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
    logging.debug('[' + colour + component + bcolors.ENDC + '] ' + msg)


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
                logging.debug("\t" + result)
                result = ""
                count = 0
    logging.debug('\t' + result + '\n')

def dump_bytes(*args, colour=bcolors.OKPURPLE, component='UHID Device', msg=''):
    #Print bytes in nice format
    c = colour if colour != None else bcolors.OKPURPLE
    colour_print(colour=colour, component=component, msg=msg)
    print_bytes(*args)


UHID_EVENT_TYPE_SIZE = 4
'''
uint_32_t type;
'''

EV_MAX_SIZE = 4380
'''
/**
 * Fedora 40 test.
 * $ gcc -o ./uhid_test -Wall -I./include ./uhid-test.c
 *
 * $ ./uhid_test
 * 4380
 */
// uhid-test.c
#include <linux/uhid.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    struct uhid_event ev;
    size_t ev_size = sizeof(ev);
    fprintf(stderr, "%ld\n", ev_size);
    return 0;
}
'''


class UHIDEventType(Enum):
    CREATE = 0x00
    DESTROY = 0x01
    START = 0x02
    STOP = 0x03
    OPEN = 0x04
    CLOSE = 0x05
    OUTPUT = 0x06
    GET_REPORT = 0x09
    GET_REPORT_REPLY = 0x0A
    CREATE2 = 0x0B
    INPUT2 = 0x0C
    SET_REPORT = 0x0D
    SET_REPORT_REPLY = 0x0E


    @classmethod
    def from_bytes(cls, byte_data):
        if len(byte_data) != 4:
            raise ValueError("Expected 4 bytes to parse UHIDEventType")
        event_int = struct.unpack('I', byte_data)[0]
        try:
            return cls(event_int)
        except ValueError:
            raise ValueError(f"Unknown UHIDEventType value: {event_int}")

    def pack(self):
        return struct.pack('I', self.value)


class UHIDReportType(Enum):
    FEATURE_REPORT = 0x00
    OUTPUT_REPORT = 0x01
    INPUT_REPORT = 0x02

class BaseStructure(object):
    _fields_ = []
    base_pack_format = '<'

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
        pack_format = self.base_pack_format
        for field in self._fields_:
            if isinstance(field[1], BaseStructure):
                pack_format += str(field[1].size()) + 's'
            elif 'si' == field[1]:
                pack_format += 'c'
            elif '<' in field[1] or '>' in field[1]:
                pack_format += field[1][1:]
            else:
                pack_format += field[1]
        logging.debug(pack_format)
        return pack_format.encode('utf-8')

    def pack(self):
        values = []
        for field in self._fields_:
            #logging.debug("Field: {}".format(field))
            if isinstance(field[1], BaseStructure):
                values.append(getattr(self, field[0], field[1]).pack())
            elif re.match(r'\d*x', field[1]):
                #Skip padding
                continue
            else:
                if 'si' == field[1]:
                    values.append(chr(getattr(self, field[0], 0)))
                else:
                    values.append(getattr(self, field[0], 0))
        #Python 2 -> 3, str != bytestring so conditionally remap any strings we find.
        values = [bytes(v, 'utf-8') if isinstance(v, str) else v for v in values]
        logging.debug(values)
        packed = struct.pack(self.format(), *values)
        #logging.debug("packed [{}]".format(packed))
        return packed

    def unpack(self, buf):
        values = struct.unpack(self.format(), buf)
        i=0
        keys_vals = {}
        for val in values:
            if '<' in self._fields_[i][1][0]:
                val = struct.unpack('<' +self._fields_[i][1][1], struct.pack('>' + self._fields_[i][1][1], val))[0]
            keys_vals[self._fields_[i][0]]=val
            i+=1
        #logging.debug(keys_vals)
        self.init_from_dict(**keys_vals)


REPORT_DESCRIPTOR = bytes([
    0x06, 0xD0, 0xF1, # Usage Page (FIDO Alliance)
    0x09, 0x01, # Usage (U2F HID Authenticator)
    0xA1, 0x01, # Collection (Application)

    0x09, 0x20, # Usage (Input Report Data)
    0x15, 0x00, # Logical Minimum (0)
    0x26, 0xFF, 0x00, # Logical Maximum (255)
    0x75, 0x08,             # REPORT_SIZE (8)
    0x95, 0x40,             # REPORT_COUNT (64)
    0x81, 0x02, # Input (Data,Var,Abs)

    0x09, 0x21, # Usage (Output Report Data)
    0x15, 0x00, # Logical Minimum (0)
    0x26, 0xFF, 0x00, # Logical Maximum (255)
    0x75, 0x08,             # REPORT_SIZE (8)
    0x95, 0x40,             # REPORT_COUNT (64)
    0x91, 0x02, # Output (Data,Var,Abs)

    0xC0 # End Collection
])

DEVICE_NAME = b"EyeBeeKey"
PHYSICAL_ADDRESS = b"ibm-0101:01:01.0-1"
UNIQUE_ADDRESS = b"virtual-fido-uhid-01"

class UHIDCreate2Event(BaseStructure):
    _fields_ = [
            ('event', 'I', UHIDEventType.CREATE2.value),
            ('name', '128s', DEVICE_NAME.ljust(128, b'\x00')),
            ('phys', '64s', PHYSICAL_ADDRESS.ljust(64, b'\x00')),
            ('uniq', '64s', UNIQUE_ADDRESS.ljust(64, b'\x00')),
            ('rd_size', 'H', len(REPORT_DESCRIPTOR)),
            ('bus', 'H', 0x03), # USB HID
            ('vendor', 'I', 0x1337),
            ('product', 'I', 0x1337),
            ('version', 'I', 0x0100), # Version 1.00
            ('country', 'I', 0), # Not localized
            ('rd_data', '4096s', REPORT_DESCRIPTOR.ljust(4096, b'\x00'))
        ]

class UHIDStartEvent(BaseStructure):
    _fields_ = [
            ('event', 'I', UHIDEventType.START.value),
            ('dev_flags', 'Q')
        ]

class UHIDStopEvent(BaseStructure):
    _fields_ = [
            ('event', 'I', UHIDEventType.STOP.value)
        ]

class UHIDInput2Event(BaseStructure):

    _fields_ = [
            ('event', 'I', UHIDEventType.INPUT2.value),
            ('ev_len', 'H', 0),
            ('data', '4096s', b'\x00' * 4096 )
        ]

class UHIDOutputEvent(BaseStructure):
    ev_len = 0
    type = UHIDReportType.OUTPUT_REPORT.value
    data = b'\x00'

    _fields_ = [
            ('event', 'I', UHIDEventType.OUTPUT.value),
            ('data', '4096s', b'\x00' * 4096),
            ('ev_len', 'H', 0),
            ('type', 'B', UHIDReportType.OUTPUT_REPORT.value)
        ]


class UHIDOpenEvent(BaseStructure):
    _fields_ = [
            ('event', 'I', UHIDEventType.OPEN.value)
        ]

class UHIDCloseEvent(BaseStructure):
    _fields_ = [
            ('event', 'I', UHIDEventType.CLOSE.value)
        ]

class UHIDGetReport(BaseStructure):
    _fields_ = [
            ('event', 'I', UHIDEventType.GET_REPORT.value),
            ('id', 'I'),
            ('report_number', 'B'),
            ('report_type', 'B')
        ]

class UHIDGetReportReply(BaseStructure):
    _fields_ = [
            ('event', 'I', UHIDEventType.GET_REPORT_REPLY.value),
            ('id', 'I'),
            ('err', 'H'),
            ('ev_len', 'H'),
            ('data', '4096s')
        ]

class UHIDSetReport(BaseStructure):
    report_type = 0x01

    _fields_ = [
            ('event', 'I', UHIDEventType.SET_REPORT.value),
            ('id', 'I'),
            ('report_number', 'B'),
            ('report_type', 'B'),
            ('ev_len', 'H'),
            ('data', '4096s')
        ]

class UHIDSetReportReply(BaseStructure):
    _fields_ = [
            ('event', 'I', UHIDEventType.SET_REPORT_REPLY.value),
            ('id', 'I'),
            ('err', 'H')
        ]

class UserDevice(threading.Thread):


    #Pending input reports
    pending = queue.Queue(maxsize=100)
    events = []

    def __init__(self, devPath="/dev/uhid"):
        super().__init__()
        self.device_path = devPath
        self._interrupt = False
        #import signal
        #signal.signal(signal.SIGINT, self.stop_device)
        #signal.signal(signal.SIGTERM, self.stop_device)



    def stop_device(self, tid, frame):
        logging.error(f"Received interrupt from {tid}: frame {frame}")
        self._interrupt = True
        if MessageQueue.notify_sysapp is not None:
            MessageQueue.notify_sysapp.put(QueueMessageType.QUIT)

    # Assisted by watsonx Code Assistant 
    def format_bytes(self, byte_array):
        return ''.join(f'{byte:02x}' for byte in byte_array)

    # Assisted by watsonx Code Assistant 
    def log_received_bytes(self, byte_array, io_type="IN"):
        logging.debug("event byte count: {} DIR: {}".format( 
                            0 if byte_array is None else len(byte_array), io_type))
        formatted_bytes = self.format_bytes(byte_array)
        lines = [formatted_bytes[i:i+64] for i in range(0, len(formatted_bytes), 64)]
        for line in lines:
            logging.debug(line)

    def start_ev(self, ev_type, ev_bytes):
        logging.debug("Start event received!")
        ev = UHIDStartEvent()
        ev.unpack(ev_bytes[:len(ev.pack())])
        logging.debug(f"ev: {ev}")
        return

    def stop_ev(self, ev_type, ev_bytes):
        logging.debug("Stop event received")
        ev = UHIDStopEvent()
        ev.unpack(ev_bytes[:len(ev.pack())])
        logging.debug(f"ev: {ev}")
        return

    def open_ev(self, ev_type, ev_bytes):
        logging.debug("Open event received!")
        ev = UHIDOpenEvent()
        ev.unpack(ev_bytes[:len(ev.pack())])
        logging.debug(f"ev: {ev}")
        return

    def close_ev(self, ev_type, ev_bytes):
        logging.debug("Close event received!")
        ev = UHIDCloseEvent()
        ev.unpack(ev_bytes[:len(ev.pack())])
        logging.debug(f"ev: {ev}")
        MessageQueue.notify_auth.put(QueueMessageType.CLOSE_EVENT)
        return

    def process_output(self, event):
        raise NotImplementedError("override me")

    def output_ev(self, ev_type, ev_bytes):
        logging.debug("Output event received!")
        ev = UHIDOutputEvent()
        ev.unpack(ev_bytes[:len(ev.pack())])
        if ev.data:
            logging.debug(f"event : {ev.ev_len} {ev.type} {ev.data[:ev.ev_len]}")
        self.process_output(ev)

    def handle_unknown_control(self, ev_bytes):
        raise NotImplementedError("override me")

    def get_report_ev(self, ev_type, ev_bytes):
        logging.debug("Get report event received!")
        ev = UHIDGetReport()
        ev.unpack(ev_bytes[:len(ev.pack())])
        logging.debug(f"ev: {ev}")
        raise NotImplementedError("unexpected request")

    def set_report_ev(self, ev_type, ev_bytes):
        logging.debug("Set report event received!")
        ev = UHIDSetReport()
        ev.unpack(ev_bytes[:len(ev.pack())])
        logging.debug(f"ev: {ev}")
        if ev.report_type == UHIDReportType.FEATURE_REPORT:
            raise NotImplementedError("TODO")
        else:
            raise NotImplementedError("unexpected request")

    def error_ev(self, ev_type, ev_bytes):
        logging.debug("Unknown UHID event received")
        logging.debug(f"ev_bytes: {ev_bytes}")
        return

    def process_event(self, ev_type, ev_bytes):
        return {
                UHIDEventType.START: self.start_ev,
                UHIDEventType.STOP: self.stop_ev,
                UHIDEventType.OPEN: self.open_ev,
                UHIDEventType.CLOSE: self.close_ev,
                UHIDEventType.OUTPUT: self.output_ev,
                UHIDEventType.GET_REPORT: self.get_report_ev,
                UHIDEventType.SET_REPORT: self.set_report_ev
            }.get(ev_type, self.error_ev)(ev_type, ev_bytes)

    def destroy_ev(self, fd):
        ev = UHIDInput2Event(event=UHIDEventType.DESTROY.value, ev_len=0)
        os.write(fd, ev.pack())

    def _maybe_in(self, fd):
        try: #Poll for event
            eventBytes = os.read(fd, EV_MAX_SIZE)
            #self.log_received_bytes(eventBytes)
            if isinstance(eventBytes, bytes) \
                    and len(eventBytes) >= UHID_EVENT_TYPE_SIZE:
                eventType = UHIDEventType.from_bytes(
                                eventBytes[:UHID_EVENT_TYPE_SIZE])
                thread = threading.Thread(target=self.process_event, args=(eventType, eventBytes))
                thread.start()
                self.events.append(thread)
            else:
                logging.error(f"Invalid event read [{eventBytes}]")
        except BlockingIOError: #No event
            #logging.debug("No data available (non-blocking read)") #very very very verbose
            pass
        tempEvList = []
        for ev in self.events:
            if not ev.is_alive():
                ev.join()
                tempEvList.append(ev)
        for ev in tempEvList:
            self.events.remove(ev)

    def _maybe_out(self, fd):
        try:
            while self.pending.qsize() > 0: # uhid device sends output to kernel
                inData = self.pending.get(True, 0.00001) #10ns
                ev = UHIDInput2Event(ev_len=64, data=inData)
                inBytes = ev.pack()
                #self.log_received_bytes(inBytes, io_type="OUT")
                n = os.write(fd, bytearray(inBytes))
                if n != len(inBytes):
                    raise RuntimeError(f"invalid write length {n} != {len(ev.pack())}")
                else:
                    logging.debug("Event sent!")
                logging.debug(f"{self.pending.qsize()} events left in the queue")
        except queue.Empty:
            logging.debug("Failed to get more output events, not sending anything else.")


    def run(self):
        fd = None
        started = False
        try:
            fd = os.open('/dev/uhid', os.O_RDWR)  #| os.O_CLOEXEC| os.O_NONBLOCK
            fcntl.fcntl(fd, fcntl.F_SETFL, os.O_NONBLOCK)
        except OSError as e:
            logging.exception(f"OSError with uhid fd: {e}")
            return
        if fd == None:
            logging.error("udev fd is null")
            return
        try:
            #Send create
            create_2_req = UHIDCreate2Event().pack()
            n = os.write(fd, bytearray(create_2_req))
            if n != len(create_2_req):
                raise RuntimeError("invalid write length")
            while not self._interrupt:
                self._maybe_in(fd)
                self._maybe_out(fd)
                if not self._interrupt:
                    time.sleep(0.001) #poll respective queues every ms
                if MessageQueue.notify_udev.qsize() > 0:
                    sysTrayMsg = MessageQueue.notify_udev.get()
                    logging.debug(f"Event from systeray_app: {sysTrayMsg}") 
                    if sysTrayMsg == QueueMessageType.QUIT:
                        self._interrupt = True
                        break
        finally:
            if started:
                self.destroy_ev(fd)
            os.close(fd)
