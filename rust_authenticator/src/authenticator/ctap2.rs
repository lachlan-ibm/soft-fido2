use std:collections::HashMap;

pub enum CTAP_API {
    AUTHENTICATOR_MAKE_CRED = 0x01,
    AUTHENTICATOR_GET_ASSERT = 0x02,
    AUTHENTICATOR_CANCEL = 0x03,
    AUTHENTICATOR_GET_INFO = 0x04,
    AUTHENTICATOR_CLIENT_PIN = 0x06,
    AUTHENTICATOR_RESET = 0x07,
    AUTHENTICATOR_GET_NEXT_ASSERT = 0x08,
    AUTHENTICATOR_VENDOR_FIRST = 0x40,
    AUTHENTICATOR_VENDOR_LAST = 0xBF,
}

pub enum CTAP_ERROR {
    CTAP1_ERR_SUCCESS = 0x00 // Indicates
    CTAP1_ERR_INVALID_COMMAND = 0x01 // The
    CTAP1_ERR_INVALID_PARAMETER = 0x02 // The
    CTAP1_ERR_INVALID_LENGTH = 0x03 // Invalid
    CTAP1_ERR_INVALID_SEQ = 0x04 // Invalid
    CTAP1_ERR_TIMEOUT = 0x05 // Message
    CTAP1_ERR_CHANNEL_BUSY = 0x06 // Channel
    CTAP1_ERR_LOCK_REQUIRED = 0x0A // Command
    CTAP1_ERR_INVALID_CHANNEL = 0x0B // Command
    CTAP2_ERR_CBOR_PARSING = 0x10 // Error
    CTAP2_ERR_CBOR_UNEXPECTED_TYPE = 0x11 // Invalid/unexpected
    CTAP2_ERR_INVALID_CBOR = 0x12 // Error
    CTAP2_ERR_INVALID_CBOR_TYPE = 0x13 // Invalid
    CTAP2_ERR_MISSING_PARAMETER = 0x14 // Missing
    CTAP2_ERR_LIMIT_EXCEEDED = 0x15 // Limit
    CTAP2_ERR_UNSUPPORTED_EXTENSION = 0x16 // Unsupported
    CTAP2_ERR_TOO_MANY_ELEMENTS = 0x17 // Limit
    CTAP2_ERR_EXTENSION_NOT_SUPPORTED = 0x18 // Unsupported
    CTAP2_ERR_CREDENTIAL_EXCLUDED = 0x19 // Valid
    CTAP2_ERR_CREDENTIAL_NOT_VALID = 0x20 // Credential
    CTAP2_ERR_PROCESSING = 0x21 // Processing
    CTAP2_ERR_INVALID_CREDENTIAL = 0x22 // Credential
    CTAP2_ERR_USER_ACTION_PENDING = 0x23 // Authentication
    CTAP2_ERR_OPERATION_PENDING = 0x24 // Processing,
    CTAP2_ERR_NO_OPERATIONS = 0x25 // No
    CTAP2_ERR_UNSUPPORTED_ALGORITHM = 0x26 // Authenticator
    CTAP2_ERR_OPERATION_DENIED = 0x27 // Not
    CTAP2_ERR_KEY_STORE_FULL = 0x28 // Internal
    CTAP2_ERR_NOT_BUSY = 0x29 // Authenticator
    CTAP2_ERR_NO_OPERATION_PENDING = 0x2A // No
    CTAP2_ERR_UNSUPPORTED_OPTION = 0x2B // Unsupported
    CTAP2_ERR_INVALID_OPTION = 0x2C // Unsupported
    CTAP2_ERR_KEEPALIVE_CANCEL = 0x2D // Pending
    CTAP2_ERR_NO_CREDENTIALS = 0x2E // No
    CTAP2_ERR_USER_ACTION_TIMEOUT = 0x2F // Timeout
    CTAP2_ERR_NOT_ALLOWED = 0x30 // Continuation
    CTAP2_ERR_PIN_INVALID = 0x31 // PIN
    CTAP2_ERR_PIN_BLOCKED = 0x32 // PIN
    CTAP2_ERR_PIN_AUTH_INVALID = 0x33 // PIN
    CTAP2_ERR_PIN_AUTH_BLOCKED = 0x34 // PIN
    CTAP2_ERR_PIN_NOT_SET = 0x35 // No
    CTAP2_ERR_PIN_REQUIRED = 0x36 // PIN
    CTAP2_ERR_PIN_POLICY_VIOLATION = 0x37 // PIN
    CTAP2_ERR_PIN_TOKEN_EXPIRED = 0x38 // pinToken
    CTAP2_ERR_REQUEST_TOO_LARGE = 0x39 // Authenticator
    CTAP1_ERR_OTHER = 0x7F // Other
    CTAP2_ERR_SPEC_LAST = 0xDF // CTAP
    CTAP2_ERR_EXTENSION_FIRST = 0xE0 // Extension
    CTAP2_ERR_EXTENSION_LAST = 0xEF // Extension
    CTAP2_ERR_VENDOR_FIRST = 0xF0 // Vendor
    CTAP2_ERR_VENDOR_LAST = 0xFF // Vendor
}

pub enum MODE {
    PACKED,
    PACKED-SELF,
    TPM,
    U2F,
    ANDROID-KEY,
    ANDROID-SAFETYNET,
}


#[derive(Hash, Eq, PartialEq, Debug, Copy)]
struct Options {
    rk: bool,
    uv: bool,
    up: bool,
    plat: bool,
    clietnPin: bool
}


pub struct MakeCredential {
    clientDataHash: Vec<u8>,
    rp: String,
    user: String,
    pubKeyCredParams: Vec<u8>,
    excludeList: Vec<String>,
    options: Options,
    pinAuth: Vec<u8>,
    pimProtocal: Vec<u8>,
}

pub struct AttestationObject {
    authData: Vec<u8>,
    fmt: String,
    attStmt: Vec<u8>,
}

pub struct GetAssertion {
    rpId: String,
    clientDataHash: Vec<u8>,
    allowList: Vec<u8>,
    options: Options,
    pinAuth: Vec<u8>,
    pinProtocol: u8,
}

pub struct AssertionObject {
    credential: Vec<u8>,
    authData: Vec<u8>,
    signiture: Vec<u8>,
    user: Vec<u8>,
    numberOfCredentials: u8,
}

pub struct AuthenticatorInfo {
    versions: Vec<String>,
    extensions <Vec<String>,
    aaguid: Vec<u8>,
    options: Options,
    maxMsgSize: u8,
    pinProtocols: Vec<u8>,
}

pub struct ClientPin {
    pinProtocol: u8,
    subCommand: u8,
    keyAggreement: Vec<u8>,
    pinAuth: Vec<u8>,
    getKeyAggreement: bool,
    getRetries: bool,
}

pub struct PinInfo {
    keyAgreement: vec<u8>,
    pinToken: Vec<u8>,
    retries: u8,
}
