# Copyright IBM Corp. 2022, 2025
# IBM Confidential

"""CTAP command and status code constants.

No runtime dependencies on other soft_fido2 modules.
"""

from enum import Enum, IntEnum

# Maximum USB HID data frame size in bytes
MAX_DATA_FRAME = 64


class CommandByte(Enum):
    MAKE_CREDENTIAL         = 0x01
    GET_NEXT_ASSERTION      = 0x02
    GET_INFO                = 0x04
    CLIENT_PIN              = 0x06
    RESET                   = 0x07
    CREDENTIAL_MANAGEMENT   = 0x09
    AUTHENTICATOR_SELECTION = 0x0B
    AUTHENTICATOR_CONFIG    = 0x0D

    def __repr__(self):
        return str(self.value)


class CBORStatusCode(IntEnum):
    CTAP2_OK                      = 0x00
    CTAP1_ERR_INVALID_COMMAND     = 0x01
    CTAP1_ERR_TIMEOUT             = 0x05
    CTAP2_ERR_INVALID_CBOR        = 0x12
    CTAP2_ERR_MISSING_PARAMETER   = 0x14
    CTAP2_ERR_CREDENTIAL_EXCLUDED = 0x19
    CTAP2_ERR_OPERATION_DENIED    = 0x27
    CTAP2_ERR_NO_CREDENTIALS      = 0x2E
    CTAP2_ERR_PIN_INVALID         = 0x31
    CTAP2_ERR_PIN_AUTH_INVALID    = 0x33
    CTAP2_ERR_PUAT_REQUIRED       = 0x36
    CTAP1_ERR_OTHER               = 0x7F
