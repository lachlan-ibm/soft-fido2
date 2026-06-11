#!/usr/bin/env python3
# Copyright IBM Corp. 2022, 2025
# IBM Confidential
# Assisted by watsonx Code Assistant

"""CTAPHID packet structures and framing logic.

This module contains the packet structure definitions for the CTAP HID protocol,
which is transport-agnostic and can be used by both USB/IP and UHID implementations.
"""

import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from usbip_device import BaseStructure, bcolors, colour_print


class CTAPHIDInitPkt(BaseStructure):
    """CTAPHID initialization packet.
    
    This packet structure is used for the first frame of a CTAPHID message.
    It contains the channel ID (cid), command byte (cmd), byte count (bcnt),
    and up to 57 bytes of data.
    
    The data field is dynamically sized based on the actual data length.
    """
    
    _fields_ = [
        ('cid', 'I'),    # Channel identifier (4 bytes)
        ('cmd', 'B'),    # Command byte (1 byte)
        ('bcnt', 'H'),   # Byte count - total payload length (2 bytes)
    ]

    def __init__(self, **kwargs):
        if 'data' in kwargs:
            index = None
            for i, field in enumerate(self._fields_):
                if field[0] == 'data':
                    index = i
                    break
            if index == None:
                colour_print(colour=bcolors.OKGREEN, component='CTAPHIDInitPkt.__init__', 
                           msg='setting data field')
                self._fields_ += [('data', '%ds' % len(kwargs['data']))]
            else:
                colour_print(colour=bcolors.OKGREEN, component='CTAPHIDInitPkt.__init__', 
                           msg='data already exists as a field, updating it')
                self._fields_[index] = ('data', '%ds' % len(kwargs['data']))
            print(self._fields_)
        super().__init__(**kwargs)


class CTAPHIDSeqPkt(BaseStructure):
    """CTAPHID continuation packet.
    
    This packet structure is used for continuation frames of a CTAPHID message
    when the payload exceeds 57 bytes (the capacity of the init packet).
    It contains the channel ID (cid), sequence number (seq), and up to 59 bytes of data.
    
    The data field is dynamically sized based on the actual data length.
    """
    
    _fields_ = [
        ('cid', 'I'),    # Channel identifier (4 bytes)
        ('seq', 'B'),    # Sequence number (1 byte, 0-127)
    ]

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
                colour_print(colour=bcolors.OKPINK, component='CTAPHIDSeqPkt.__init__', 
                           msg='setting data field')
                self._fields_ += [('data', '%ds' % len(kwargs['data']))]
            else:
                colour_print(colour=bcolors.OKPINK, component='CTAPHIDSeqPkt.__init__', 
                           msg='data already exists as a field, updating it')
                self._fields_[index] = ('data', '%ds' % len(kwargs['data']))
            print(self._fields_)
        super(CTAPHIDSeqPkt, self).__init__(**kwargs)

# Made with Bob
