# USB/IP Integration Refactoring Plan

## Goal
Migrate USB/IP control and data request handling from `hid_device.py` to `usb_ip.py`, creating a clean architecture where:
- **`passkey_device.py`**: Contains all CTAP2 API commands and business logic
- **`usb_ip.py`**: Handles USB/IP protocol, device descriptors, and becomes `CTAP2USBIPDevice`
- **`hid_device.py`**: Deprecated/deleted after migration

## Current Architecture Problems

### Duplication Issues
1. **`CBORCommand`** exists in both:
   - [`passkey_device.py:536-813`](soft_fido2/passkey_device.py:536-813) - Full CTAP2 implementation
   - [`hid_device.py:118-323`](soft_fido2/hid_device.py:118-323) - Duplicate for USB/IP

2. **`CTAP2HIDevice`** exists in both:
   - [`passkey_device.py:898-1141`](soft_fido2/passkey_device.py:898-1141) - UHID transport
   - [`hid_device.py:378-738`](soft_fido2/hid_device.py:378-738) - USB/IP transport

3. **USB/IP Device Handling Split**:
   - [`usb_ip.py:411-521`](soft_fido2/usb_ip.py:411-521) - Base `USBDevice` class with:
     - [`handle_usb_control()`](soft_fido2/usb_ip.py:487-506) - USB control requests (ep=0)
     - [`handle_usb_request()`](soft_fido2/usb_ip.py:508-520) - Routes to control or data
     - [`handle_data()`](soft_fido2/usb_ip.py:508-520) - **Abstract method, not implemented**
   - [`hid_device.py:378-738`](soft_fido2/hid_device.py:378-738) - `CTAP2HIDevice(USBDevice)` implements:
     - [`handle_data()`](soft_fido2/hid_device.py:702-711) - HID interrupt endpoint handling
     - [`handle_unknown_control()`](soft_fido2/hid_device.py:714-738) - HID-specific control requests
     - All CTAPHID protocol methods (init, cbor, ping, msg, etc.)

## Critical Migration: USB/IP Request Handling

### Current Flow in `hid_device.py`

**USB/IP Socket → `USBDevice` → `CTAP2HIDevice`**

1. **Control Requests (ep=0)** - USB descriptor/configuration:
   ```
   USBDevice.handle_usb_request() 
   → USBDevice.handle_usb_control()
   → USBDevice.handle_get_descriptor() / handle_set_configuration()
   → CTAP2HIDevice.handle_unknown_control()  [HID-specific: Get Report Descriptor, Set Idle]
   ```

2. **Data Requests (ep=0x04, ep=0x0E)** - HID interrupt endpoints:
   ```
   USBDevice.handle_usb_request()
   → CTAP2HIDevice.handle_data()
   → _handle_incoming() [ep=0x04: HOST OUT, receives CTAPHID frames]
   → _handle_outgoing() [ep=0x0E: HOST IN, sends CTAPHID responses]
   ```

### What Needs to Move to `usb_ip.py`

#### Phase 1: Extend `USBDevice` → `CTAP2USBIPDevice`

**File: `soft_fido2/usb_ip.py`**

Add to existing `USBDevice` class (or create subclass):

```python
class CTAP2USBIPDevice(USBDevice):
    """USB/IP FIDO2 Authenticator Device"""
    
    # USB Device Configuration (from hid_device.py:379-393)
    speed = 2
    vendorID = 0x3713
    productID = 0x3713
    bcdDevice = 0x0
    bDeviceClass = 0x0
    bDeviceSubClass = 0x0
    bDeviceProtocol = 0x0
    configurations = [configuration]  # From hid_device.py:82
    
    # CTAPHID State (from hid_device.py:395-399)
    cids = {}  # Channel ID contexts
    pending = []  # Pending request queue for keep-alive
    
    def __init__(self):
        USBDevice.__init__(self)
        AuthenticatorAPI()  # Initialize CTAP2 API
    
    # === MIGRATE FROM hid_device.py ===
    
    def handle_data(self, usb_req):
        """Handle HID interrupt endpoint data (ep=0x04, ep=0x0E)"""
        # FROM: hid_device.py:702-711
        if usb_req.ep == 0xE:  # HOST IN endpoint
            return self._handle_outgoing(usb_req)
        else:  # HOST OUT endpoint
            return self._handle_incoming(usb_req)
    
    def handle_unknown_control(self, control_req, usb_req):
        """Handle HID-specific control requests"""
        # FROM: hid_device.py:714-738
        # - Get Report Descriptor (0x81, 0x06, wValue=0x22)
        # - Set Idle (0x21, 0x0a)
        ...
    
    def _handle_incoming(self, usb_req):
        """Process incoming CTAPHID frames from HOST OUT"""
        # FROM: hid_device.py:682-700
        ...
    
    def _handle_outgoing(self, usb_req):
        """Queue HOST IN requests for sending responses"""
        # FROM: hid_device.py:633-646
        ...
    
    def _handle_incoming_cmd(self, cmd, usb_req):
        """Route CTAPHID commands to handlers"""
        # FROM: hid_device.py:648-660
        return {
            1: self.ctaphid_ping,
            3: self.ctaphid_msg,
            6: self.ctaphid_init,
            16: self.ctaphid_cbor,
            ...
        }.get(ctapCmd, self.ctaphid_unknown)(usb_req)
    
    def _handle_incoming_sequence(self, cid, usb_req):
        """Handle CTAPHID continuation packets"""
        # FROM: hid_device.py:662-680
        ...
    
    # === CTAPHID Protocol Handlers ===
    
    def ctaphid_init(self, usb_req):
        """CTAPHID_INIT: Assign new channel ID"""
        # FROM: hid_device.py:566-592
        ...
    
    def ctaphid_cbor(self, usb_req):
        """CTAPHID_CBOR: Process CTAP2 commands"""
        # FROM: hid_device.py:594-618
        # Uses CBORCommand from passkey_device.py
        ...
    
    def ctaphid_msg(self, usb_req):
        """CTAPHID_MSG: Handle U2F legacy commands"""
        # FROM: hid_device.py:528-564
        ...
    
    def ctaphid_ping(self, usb_req):
        # FROM: hid_device.py:525-526
        ...
    
    def send_response_segment(self, cid, cbor_cmd):
        """Send CTAPHID response frames"""
        # FROM: hid_device.py:472-522
        # Uses send_usb_req() from base USBDevice
        ...
    
    class KeepAliveWorker:
        """Thread to send keep-alive if response takes >50ms"""
        # FROM: hid_device.py:441-469
        ...
    
    def generate_fido2_report(self):
        """Generate HID Report Descriptor for FIDO2"""
        # FROM: hid_device.py:418-435
        ...
```

#### Phase 2: USB Descriptor Configuration

**Keep in `usb_ip.py`** (already there, lines 37-83 in hid_device.py):

```python
# HID Class Descriptor
class CTAP2HIDClass(BaseStructure):
    _fields_ = [
        ('bLength', 'B', 9),
        ('bDescriptorType', 'B', 0x21),  # HID
        ('bcdHID', 'H'),
        ...
    ]

hid_class = CTAP2HIDClass(...)

# Interface Descriptor
interface_d = InterfaceDescriptor(
    bInterfaceClass=3,  # HID
    bNumEndpoints=2,
    ...
)

# Endpoints
end_point_one = EndPoint(bEndpointAddress=0x04, ...)  # HOST OUT
end_point_two = EndPoint(bEndpointAddress=0x8E, ...)  # HOST IN

# Configuration
configuration = DeviceConfigurations(...)
configuration.interfaces = [interface_d]
```

#### Phase 3: Remove from `hid_device.py`

**DELETE** these sections:
- Lines 37-83: USB descriptors → Move to `usb_ip.py`
- Lines 85-116: `Authenticator` wrapper → Delete (use `AuthenticatorAPI` directly)
- Lines 118-323: `CBORCommand` → Delete (use from `passkey_device.py`)
- Lines 325-375: `CTAPHIDInitPkt`, `CTAPHIDSeqPkt` → Move to new `ctaphid_protocol.py`
- Lines 378-738: `CTAP2HIDevice` → Becomes `CTAP2USBIPDevice` in `usb_ip.py`
- Lines 753-756: Entry point → Replace with thin launcher

## Detailed Migration Steps

### Step 1: Create Transport-Agnostic CTAPHID Protocol Layer

**NEW FILE: `soft_fido2/ctaphid_protocol.py`**

```python
"""CTAPHID packet structures and framing logic"""

class CTAPHIDInitPkt(BaseStructure):
    """CTAPHID initialization packet"""
    # FROM: hid_device.py:325-348
    _fields_ = [
        ('cid', 'I'),
        ('cmd', 'B'),
        ('bcnt', 'H'),
        ('data', '57s')
    ]

class CTAPHIDSeqPkt(BaseStructure):
    """CTAPHID continuation packet"""
    # FROM: hid_device.py:350-375
    _fields_ = [
        ('cid', 'I'),
        ('seq', 'B'),
        ('data', '59s')
    ]
```

### Step 2: Consolidate CBORCommand

**ACTION**: Delete duplicate from `hid_device.py:118-323`

**USE**: [`passkey_device.py:536-813`](soft_fido2/passkey_device.py:536-813) as single source

Both `CTAP2UHIDDevice` and `CTAP2USBIPDevice` import:
```python
from soft_fido2.passkey_device import CBORCommand
```

### Step 3: Migrate CTAP2HIDevice to usb_ip.py

**MOVE** from `hid_device.py:378-738` to `usb_ip.py`:

1. **Class definition and USB config** (lines 378-393)
2. **State management** (lines 395-399)
3. **`handle_data()` implementation** (lines 702-711)
4. **`handle_unknown_control()` for HID** (lines 714-738)
5. **CTAPHID protocol handlers**:
   - `ctaphid_init()` (lines 566-592)
   - `ctaphid_cbor()` (lines 594-618)
   - `ctaphid_msg()` (lines 528-564)
   - `ctaphid_ping()` (lines 525-526)
   - `ctaphid_cancel()`, `ctaphid_keepalive()`, `ctaphid_error()`, `ctaphid_unknown()`
6. **Frame handling**:
   - `_handle_incoming()` (lines 682-700)
   - `_handle_outgoing()` (lines 633-646)
   - `_handle_incoming_cmd()` (lines 648-660)
   - `_handle_incoming_sequence()` (lines 662-680)
7. **Response management**:
   - `send_response_segment()` (lines 472-522)
   - `KeepAliveWorker` class (lines 441-469)
8. **HID descriptor**:
   - `generate_fido2_report()` (lines 418-435)

### Step 4: Update usb_ip.py Base Class

**MODIFY** [`usb_ip.py:411-521`](soft_fido2/usb_ip.py:411-521):

```python
class USBDevice():
    """Base USB/IP device - handles USB protocol"""
    
    def __init__(self):
        self.generate_raw_configuration()
        self.start_time = datetime.datetime.now()
    
    def handle_usb_control(self, usb_req):
        """Handle standard USB control requests"""
        # KEEP: Lines 487-506
        # Handles: Get Descriptor, Set Configuration, Get Status
        ...
        if not handled:
            self.handle_unknown_control(control_req, usb_req)
    
    def handle_unknown_control(self, control_req, usb_req):
        """Override in subclass for device-specific control requests"""
        # MAKE ABSTRACT - subclass must implement
        raise NotImplementedError()
    
    def handle_data(self, usb_req):
        """Override in subclass for endpoint data handling"""
        # MAKE ABSTRACT - subclass must implement
        raise NotImplementedError()
```

### Step 5: Replace hid_device.py Entry Point

**REPLACE** `hid_device.py` (lines 753-756) with thin launcher:

```python
# soft_fido2/hid_device.py (NEW - 15 lines)
"""USB/IP transport entry point for FIDO2 authenticator"""

from soft_fido2.usb_ip import USBContainer, CTAP2USBIPDevice

if __name__ == '__main__':
    usb_dev = CTAP2USBIPDevice()
    usb_container = USBContainer()
    usb_container.add_usb_device(usb_dev)
    usb_container.run()
```

## File Structure After Refactoring

```
soft_fido2/
├── passkey_device.py          # AuthenticatorAPI + CBORCommand (CTAP2 logic)
├── ctaphid_protocol.py        # NEW: CTAPHIDInitPkt, CTAPHIDSeqPkt
├── usb_ip.py                  # USBDevice + CTAP2USBIPDevice (USB/IP + CTAPHID)
├── uhid_device.py             # UHID kernel interface (unchanged)
├── hid_device.py              # THIN LAUNCHER (15 lines) or DELETE
└── __main__.py                # Optional: Add --transport flag
```

## Migration Checklist

### Phase 1: Preparation (No Breaking Changes)
- [ ] Create `ctaphid_protocol.py` with packet structures
- [ ] Move `CTAPHIDInitPkt` and `CTAPHIDSeqPkt` from `hid_device.py`
- [ ] Update imports in `hid_device.py` to use new file
- [ ] Test USB/IP still works

### Phase 2: Consolidate CBORCommand
- [ ] Update `hid_device.py` to import `CBORCommand` from `passkey_device.py`
- [ ] Delete duplicate `CBORCommand` from `hid_device.py` (lines 118-323)
- [ ] Test USB/IP still works

### Phase 3: Migrate to usb_ip.py
- [ ] Copy USB descriptors (lines 37-83) to `usb_ip.py`
- [ ] Create `CTAP2USBIPDevice(USBDevice)` class in `usb_ip.py`
- [ ] Migrate `handle_data()` implementation
- [ ] Migrate `handle_unknown_control()` for HID
- [ ] Migrate all CTAPHID protocol handlers
- [ ] Migrate frame handling methods
- [ ] Migrate `send_response_segment()` and `KeepAliveWorker`
- [ ] Migrate `generate_fido2_report()`
- [ ] Test USB/IP with new class

### Phase 4: Clean Up
- [ ] Replace `hid_device.py` with thin launcher (15 lines)
- [ ] Delete `Authenticator` wrapper class (lines 85-116)
- [ ] Update documentation
- [ ] Final integration testing

### Phase 5: Optional Enhancements
- [ ] Add `--transport` flag to `__main__.py` for UHID/USB/IP selection
- [ ] Create `HIDTransport` abstraction for future transports (BLE, NFC)
- [ ] Extract common CTAPHID logic to base class

## Key Implementation Notes

### 1. USB/IP Request Flow
```
TCP Socket (port 3240)
  ↓
USBIPHandler (socketserver)
  ↓
USBContainer.handle_attach()
  ↓
CTAP2USBIPDevice.handle_usb_request()
  ├─ ep=0 → handle_usb_control() → handle_unknown_control()
  └─ ep≠0 → handle_data() → _handle_incoming() / _handle_outgoing()
```

### 2. CTAPHID Frame Processing
```
HOST OUT (ep=0x04): Receive CTAPHID frames
  ↓
_handle_incoming()
  ├─ Command frame (bit 7 set) → _handle_incoming_cmd()
  │   └─ Route to ctaphid_init/cbor/msg/ping/etc.
  └─ Sequence frame → _handle_incoming_sequence()
      └─ Append to CBORCommand.request_buffer

HOST IN (ep=0x0E): Send CTAPHID responses
  ↓
_handle_outgoing()
  └─ Check for ready responses → send_response_segment()
      ├─ First segment: CTAPHIDInitPkt
      └─ Continuation: CTAPHIDSeqPkt
```

### 3. Keep-Alive Mechanism
- USB/IP requires response within 50ms
- `KeepAliveWorker` thread monitors pending requests
- Sends CTAPHID_KEEPALIVE (0x3B) if CTAP2 processing takes >45ms
- Prevents USB timeout while authenticator processes PIN/biometric

### 4. Critical Dependencies
- `send_usb_req()` from base `USBDevice` - sends USB/IP responses
- `CBORCommand` from `passkey_device.py` - CTAP2 command processing
- `AuthenticatorAPI` from `passkey_device.py` - FIDO2 business logic
- `CTAPHIDInitPkt`/`CTAPHIDSeqPkt` from `ctaphid_protocol.py` - frame packing

## Effort Estimation

- **Phase 1** (Preparation): 1 day
- **Phase 2** (Consolidate CBORCommand): 1 day
- **Phase 3** (Migrate to usb_ip.py): 3-5 days
- **Phase 4** (Clean up): 1 day
- **Phase 5** (Optional): 2-3 days

**Total: 1-2 weeks** for core refactoring + testing

## Benefits

1. **Single CTAP2 Implementation**: All FIDO2 logic in `AuthenticatorAPI`
2. **Clear Separation**: USB/IP protocol vs CTAPHID protocol vs CTAP2 logic
3. **Eliminates Duplication**: One `CBORCommand`, one set of CTAPHID handlers
4. **Maintainability**: Changes to CTAP2 spec only touch `passkey_device.py`
5. **Extensibility**: Easy to add BLE/NFC transports using same CTAPHID layer
6. **Correct Architecture**: `usb_ip.py` owns USB/IP device implementation