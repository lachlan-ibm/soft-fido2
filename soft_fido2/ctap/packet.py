#!/usr/bin/env python3
# Copyright IBM Corp. 2022, 2025
# IBM Confidential
# Assisted by watsonx Code Assistant

"""Shared primitives and CTAPHID packet structures.

BaseStructure, bcolors, and colour_print live here so that both
uhid_device and usbip_device can import them without creating a
circular dependency.  This module has no imports from other soft_fido2
modules, keeping it at the bottom of the dependency graph.
"""

import struct, re, logging


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


def colour_print(colour=bcolors.OKBLUE, component='CTAPHID', msg=''):
    logging.debug('[' + colour + component + bcolors.ENDC + '] ' + msg)


def print_bytes(*args):
    result = ""
    count = 0
    for ba in args:
        for x in ba:
            result += "%02X " % x
            count += 1
            if count == 8:
                result += " "
            elif count == 16:
                logging.debug("\t" + result)
                result = ""
                count = 0
    logging.debug('\t' + result + '\n')


def dump_bytes(*args, colour=bcolors.OKPURPLE, component='CTAPHID', msg=''):
    """Print bytes in a formatted hex dump via logging.debug."""
    colour_print(colour=colour, component=component, msg=msg)
    print_bytes(*args)


class BaseStructure(object):
    """Base class for binary protocol structures.

    Subclasses declare ``_fields_`` as a list of ``(name, fmt[, default])``
    tuples.  The default byte-order prefix is little-endian (``<``); override
    ``base_pack_format`` in a subclass when big-endian is required.
    """
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
        return pack_format.encode('utf-8')

    def pack(self):
        values = []
        for field in self._fields_:
            if isinstance(field[1], BaseStructure):
                values.append(getattr(self, field[0], field[1]).pack())
            elif re.match(r'\d*x', field[1]):
                continue  # skip padding
            else:
                if 'si' == field[1]:
                    values.append(chr(getattr(self, field[0], 0)))
                else:
                    values.append(getattr(self, field[0], 0))
        values = [bytes(v, 'utf-8') if isinstance(v, str) else v for v in values]
        return struct.pack(self.format(), *values)

    def unpack(self, buf):
        values = struct.unpack(self.format(), buf)
        i = 0
        keys_vals = {}
        for val in values:
            if '<' in self._fields_[i][1][0]:
                val = struct.unpack(
                    '<' + self._fields_[i][1][1],
                    struct.pack('>' + self._fields_[i][1][1], val)
                )[0]
            keys_vals[self._fields_[i][0]] = val
            i += 1
        self.init_from_dict(**keys_vals)


class CTAPHIDInitPkt(BaseStructure):
    """CTAPHID initialization packet (first frame of a CTAPHID message).

    Fields: channel ID (cid), command byte (cmd), total payload length (bcnt).
    A ``data`` field is appended dynamically when the caller supplies one.
    """

    _fields_ = [
        ('cid',  'I'),   # Channel identifier (4 bytes)
        ('cmd',  'B'),   # Command byte (1 byte)
        ('bcnt', 'H'),   # Byte count – total payload length (2 bytes)
    ]

    def __init__(self, **kwargs):
        self.base_pack_format = '>'
        if 'data' in kwargs:
            index = next(
                (i for i, f in enumerate(self._fields_) if f[0] == 'data'),
                None
            )
            data_field = ('data', '%ds' % len(kwargs['data']))
            if index is None:
                self._fields_ = list(self._fields_) + [data_field]
            else:
                self._fields_ = list(self._fields_)
                self._fields_[index] = data_field
        super().__init__(**kwargs)


class CTAPHIDSeqPkt(BaseStructure):
    """CTAPHID continuation packet (subsequent frames of a CTAPHID message).

    Fields: channel ID (cid), sequence number (seq, 0-127).
    A ``data`` field is appended dynamically when the caller supplies one.
    """

    _fields_ = [
        ('cid', 'I'),   # Channel identifier (4 bytes)
        ('seq', 'B'),   # Sequence number (1 byte, 0-127)
    ]

    def __init__(self, **kwargs):
        self.base_pack_format = '>'
        if 'data' in kwargs:
            index = next(
                (i for i, f in enumerate(self._fields_) if f[0] == 'data'),
                None
            )
            data_field = ('data', '%ds' % len(kwargs['data']))
            if index is None:
                self._fields_ = list(self._fields_) + [data_field]
            else:
                self._fields_ = list(self._fields_)
                self._fields_[index] = data_field
        super().__init__(**kwargs)
