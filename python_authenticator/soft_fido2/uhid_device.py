#!/bin/python
#IBM Confidential
# Assisted by watsonx Code Assistant
#Copyright IBM Corp. 2025

import os, struct, fcntl, errno, time, queue, threading

from enum import Enum

from .hid_device import CTAP2HIDevice

UHID_EVENT_TYPE_SIZE = 4

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
EV_MAX_SIZE = 4380


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

    def pack():
        return struct.pack('I', self.value)


class UHIDReportType(Enum):
    FEATURE_REPORT = 0x00
    OUTPUT_REPORT = 0x01
    INPUT_REPORT = 0x02

class BaseEvent(object):
    _fields = []

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
            if isinstance(field[1], BaseEvent):
                pack_format += str(field[1].size()) + 's'
            elif 'si' == field[1]:
                pack_format += 'c'
            elif '<' in field[1] or '>' in field[1]:
                pack_format += field[1][1:]
            else:
                pack_format += field[1]
        #print(pack_format)
        return pack_format.encode('utf-8')

    def pack(self):
        values = []
        for field in self._fields_:
            #print("Field: {}".format(field))
            if isinstance(field[1], BaseEvent):
                values.append(getattr(self, field[0], 0).pack())
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
        #print(values)
        packed = struct.pack(self.format(), *values)
        #print("packed [{}]".format(packed))
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
        #print(keys_vals)
        self.init_from_dict(**keys_vals)

REPORT_DESCRIPTOR = bytes([
    0x06, 0xD0, 0xF1, # Usage Page (FIDO Alliance)
    0x09, 0x01, # Usage (U2F HID Authenticator)
    0xA1, 0x01, # Collection (Application)

    0x85, 0x01, # Report ID (1)
    0x09, 0x20, # Usage (Input Report Data)
    0x15, 0x00, # Logical Minimum (0)
    0x26, 0xFF, 0x00, # Logical Maximum (255)
    0x75, 0x08, # Report Size (8)
    0x95, 0x40, # Report Count (64)
    0x81, 0x02, # Input (Data,Var,Abs)

    0x85, 0x01, # Report ID (1)
    0x09, 0x21, # Usage (Output Report Data)
    0x15, 0x00, # Logical Minimum (0)
    0x26, 0xFF, 0x00, # Logical Maximum (255)
    0x75, 0x08, # Report Size (8)
    0x95, 0x40, # Report Count (64)
    0x91, 0x02, # Output (Data,Var,Abs)
    0xC0 # End Collection
])

DEVICE_NAME = b"EyeBeeKey"
PHYSICAL_ADDRESS = b"ibm-0101:01:01.0-1"
UNIQUE_ADDRESS = b"virtual-fido-uhid-01"

class UHIDCreate2Event(BaseEvent):
    _fields_ = [
            ('event', 'I', UHIDEventType.CREATE2.value),
            ('name', '128s', DEVICE_NAME.ljust(128, b'\x00')),
            ('phys', '64s', PHYSICAL_ADDRESS.ljust(64, b'\x00')),
            ('uniq', '64s', UNIQUE_ADDRESS.ljust(64, b'\x00')),
            ('rd_size', 'H', len(REPORT_DESCRIPTOR)),
            ('bus', 'H', 0x03), #BUS_USB
            ('vendor', 'I', 0x3713),
            ('product', 'I', 0x3713),
            ('version', 'I', 0x0100), # Version 1.00
            ('country', 'I', 0), # Not localized
            ('rd_data', '4096s', REPORT_DESCRIPTOR.ljust(4096, b'\x00'))
        ]

class UHIDStartEvent(BaseEvent):
    _fields_ = [
            ('event', 'I', UHIDEventType.START.value),
            ('dev_flags', 'Q')
        ]

class UHIDInput2Event(BaseEvent):

    _fields_ = [
            ('event', 'I', UHIDEventType.INPUT2.value),
            ('size', 'H'),
            ('data', '4096s')
        ]

class UHIDOutputEvent(BaseEvent):
     _fields_ = [
            ('event', 'I', UHIDEventType.OUTPUT.value),
            ('data', '4096s'),
            ('size', 'H'),
            ('type', 'I')
        ]

class UHIDGetReportReq(BaseEvent):
    _fields_ = [
            ('event', 'I', UHIDEventType.GET_REPORT.value),
            ('id', 'I'),
            ('report_number', 'B'),
            ('report_type', 'B')
        ]

class UHIDGetReportReply(BaseEvent):
    _fields_ = [
            ('event', 'I', UHIDEventType.GET_REPORT_REPLY.value),
            ('id', 'I'),
            ('err', 'H'),
            ('size', 'H'),
            ('data', '4096s')
        ]

class UHIDSetReportReq(BaseEvent):
    _fields_ = [
            ('event', 'I', UHIDEventType.SET_REPORT.value),
            ('id', 'I'),
            ('report_number', 'B'),
            ('report_type', 'B'),
            ('size', 'H'),
            ('data', '4096s')
        ]

class UHIDSetReportReply(BaseEvent):
    _fields_ = [
            ('event', 'I', UHIDEventType.SET_REPORT_REPLY.value),
            ('id', 'I'),
            ('err', 'H')
        ]

class UserDevice(threading.Thread):

    def __init__(self, device_path="/dev/uhid"):
        self.devPath = device_path
        self.inQ = queue.LifoQueue()
        self.ctapDev= CTAP2HIDevice()

    def start_ev(self, ev_type, ev):
        print("Start event received!")
        return

    def stop_ev(self, ev_type, ev):
        print("Stop event received")
        return

    def open_ev(self, ev_type, ev):
        print("Open event received!")
        return

    def close_ev(self, ev_type, ev):
        print("Close event received!")
        return

    def output_ev(self, ev_type, ev):
        return ctapDev.handle_data(ev)

    def report_ev(self, ev_type, ev):
        print("Get report event received!")
        inQ.put(UHIDGetReportReply(
            id=req.id,
            err=0,
            size=len(report_data),
            data=report_data.ljust(4096, b'\x00')
        ).pack())
        return

    def error_ev(self, ev_type, ev):
        print("Unknown UHID event received")
        return

    def process_event(self, ev_type, ev):
        return {
                UHIDEventType.START: self.start_ev,
                UHIDEventType.STOP: self.stop_ev,
                UHIDEventType.OPEN: self.open_ev,
                UHIDEventType.CLOSE: self.close_ev,
                UHIDEventType.OUTPUT: self.output_ev,
                UHIDEventType.GET_REPORT: self.report_ev
            }.get(ev_type, self.error_ev)(ev_type, ev)

    def destroy_ev(self, fd):
        evBytes = bytes( UHIDInput2Event(type=UHIDEventType.DESTROY).pack() )
        fd.write(evBytes)

    def run(self):
        fd = None
        try:
            fd = os.open(self.device_path, os.O_RDWR | os.O_CLOEXEC)
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            interrupt = False
        except OSError as e:
            print("OSError with udev fd")
            return
        if fd == None:
            print("Error with udev fd")
            return
        try:
            #Send create
            create_2_req = bytes(UHIDCreate2Event().pack())
            os.write(create_2_req)
            while not interrupt:
                #Poll for event
                try:
                    eventBytes = os.read(fd, EV_MAX_SIZE)
                    if isinstance(eventBytes, list) and eventBytes.length >= UHID_EVENT_TYPE_SIZE:
                        eventType = UHIDEventType.from_bytes(
                                        eventBytes[:UHID_EVENT_TYPE_SIZE])
                        self.process_event(eventType, eventBytes)
                except BlockingIOError: #No event
                    print("No data available (non-blocking read)")
                if interrupt == True:
                    break
                #Send back queued events
                if not eventQueue.empty():
                    try:
                        inData = inQ.get(true, 0.0001) #10ns
                        ev = UHIDInput2Event(size=len(inData), data=inData)
                        os.write(ev.pack())
                    except queue.Empty:
                        print("Could not get output event, not sending anything")
            time.sleep(0.001) #poll every ms
        finally:
            if fd and fd.writable() == True:
                self.destroy_ev(fd)
            os.close(fd)

if __name__ == "__main__":
    print("#TODO")
    udev = UserDevice()
    udev.start()
    while udev.is_alive():
        time.sleep(1)