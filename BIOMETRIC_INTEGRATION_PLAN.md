# Biometric User Verification Integration Plan

## Overview

Add fingerprint verification using Linux's `fprintd` D-Bus service. Authentication adapts based on credential type and UV requirements:

- **Passkey + UV Required/Preferred**: PIN + Fingerprint
- **UV Discouraged**: Fingerprint only
- **2nd Factor**: Fingerprint only

## Architecture

```mermaid
PasskeyDevice → FprintDevice → fprintd (D-Bus)
gather_user_presence() calls verify() which uses VerifyStart/Status/Stop
```

**Key Points:**
- D-Bus integration isolated in `fprint_device.py`
- Graceful fallback to GUI if biometric unavailable
- 30-second timeout with 3 retry attempts
- `dbus-python` is optional soft dependency

---

## Phase 1: Dependencies

**File**: `setup.py`

Mark `dbus-python` and `PyGObject` as optional in extras_require (not install_requires):

```python
extras_require={
    'biometric': ['dbus-python>=1.2.18', 'PyGObject>=3.42.0'],
    'tpm': ['tpm2-pytss>=2.0.0'],
}
```

**Note**: PyGObject is needed for GLib.MainLoop used in fprintd signal handling.

Users install with: `pip install soft-fido2[biometric]`

---

## Phase 2: Fingerprint Device Module

**File**: `soft_fido2/fprint_device.py` (NEW)

```python
# Copyright IBM 2025

import logging
import time
from typing import Optional, Tuple, Callable
from enum import Enum
from gi.repository import GLib

try:
    import dbus
    from dbus.mainloop.glib import DBusGMainLoop
    DBUS_AVAILABLE = True
except ImportError:
    DBUS_AVAILABLE = False


class BiometricResult(Enum):
    SUCCESS = "verify-match"
    NO_MATCH = "verify-no-match"
    RETRY = "verify-retry-scan"
    DISCONNECTED = "verify-disconnected"
    UNKNOWN_ERROR = "verify-unknown-error"
    NOT_AVAILABLE = "not-available"
    TIMEOUT = "timeout"


class FprintDevice:
    """Fingerprint authentication via fprintd D-Bus service.
    
    Correct fprintd verification flow:
    1. Claim() - claim the device for exclusive use
    2. VerifyStart('any') - start verification
    3. VerifyFingerSelected signal - tells which finger to scan (NOW prompt user)
    4. User places finger on scanner
    5. VerifyStatus signal - verification result
    6. VerifyStop() - stop verification
    7. Release() - release device
    """
    
    FPRINTD_BUS_NAME = 'net.reactivated.Fprint'
    FPRINTD_MANAGER_PATH = '/net/reactivated/Fprint/Manager'
    FPRINTD_MANAGER_IFACE = 'net.reactivated.Fprint.Manager'
    FPRINTD_DEVICE_IFACE = 'net.reactivated.Fprint.Device'
    
    def __init__(self):
        self._bus = None
        self._device_iface = None
        self._available = False
        self._mainloop = None
        
        if DBUS_AVAILABLE:
            self._initialize_dbus()
    
    def _initialize_dbus(self):
        """Initialize D-Bus connection and check fprintd availability."""
        try:
            DBusGMainLoop(set_as_default=True)
            self._bus = dbus.SystemBus()
            
            manager = self._bus.get_object(self.FPRINTD_BUS_NAME, self.FPRINTD_MANAGER_PATH)
            manager_iface = dbus.Interface(manager, self.FPRINTD_MANAGER_IFACE)
            
            device_path = manager_iface.GetDefaultDevice()
            device = self._bus.get_object(self.FPRINTD_BUS_NAME, device_path)
            self._device_iface = dbus.Interface(device, self.FPRINTD_DEVICE_IFACE)
            
            self._available = True
            logging.info("Biometric authentication available")
            
        except Exception as e:
            logging.info(f"fprintd not available: {e}")
            self._available = False
    
    def is_available(self) -> bool:
        """Check if biometric authentication is available."""
        return self._available
    
    def verify(self, username: Optional[str] = None,
               on_finger_needed: Optional[Callable[[str], None]] = None,
               timeout: float = 30.0) -> Tuple[BiometricResult, str]:
        """
        Verify fingerprint with proper fprintd flow.
        
        Args:
            username: Username to verify (empty string = current user)
            on_finger_needed: Callback when VerifyFingerSelected signal received
                             This is when you should prompt the user to place finger
            timeout: Maximum wait time in seconds
        
        Returns:
            (BiometricResult, message)
        """
        if not self._available:
            return (BiometricResult.NOT_AVAILABLE, "Biometric not available")
        
        result = None
        finger_selected = None
        
        try:
            # Step 1: Claim device
            if username is None:
                username = ""  # Empty string = current user
            self._device_iface.Claim(username)
            logging.info(f"Device claimed for user: {username or 'current'}")
            
            # Step 2: Set up signal handlers BEFORE starting verification
            def verify_finger_selected_handler(finger_name):
                nonlocal finger_selected
                finger_selected = finger_name
                logging.info(f"Finger selected: {finger_name}")
                # NOW prompt user to place finger on scanner
                if on_finger_needed:
                    on_finger_needed(finger_name)
            
            def verify_status_handler(result_code, done):
                nonlocal result
                result = result_code
                logging.info(f"Verify status: {result_code}, done: {done}")
                if done and self._mainloop:
                    self._mainloop.quit()
            
            self._device_iface.connect_to_signal('VerifyFingerSelected', verify_finger_selected_handler)
            self._device_iface.connect_to_signal('VerifyStatus', verify_status_handler)
            
            # Step 3: Start verification
            self._device_iface.VerifyStart('any')
            logging.info("Fingerprint verification started")
            
            # Step 4: Run mainloop with timeout
            self._mainloop = GLib.MainLoop()
            timeout_id = GLib.timeout_add_seconds(int(timeout), lambda: self._mainloop.quit())
            self._mainloop.run()
            GLib.source_remove(timeout_id)
            
            # Step 5: Stop verification
            try:
                self._device_iface.VerifyStop()
            except:
                pass
            
            # Step 6: Release device
            try:
                self._device_iface.Release()
            except:
                pass
            
            # Step 7: Process result
            if result is None:
                return (BiometricResult.TIMEOUT, "Verification timed out")
            
            result_map = {
                'verify-match': (BiometricResult.SUCCESS, "Fingerprint verified"),
                'verify-no-match': (BiometricResult.NO_MATCH, "Fingerprint does not match"),
                'verify-retry-scan': (BiometricResult.RETRY, "Retry fingerprint scan"),
                'verify-disconnected': (BiometricResult.DISCONNECTED, "Device disconnected"),
            }
            return result_map.get(result, (BiometricResult.UNKNOWN_ERROR, f"Unknown result: {result}"))
                
        except Exception as e:
            logging.error(f"Verification error: {e}")
            try:
                self._device_iface.Release()
            except:
                pass
            return (BiometricResult.UNKNOWN_ERROR, f"Error: {str(e)}")
    
    def verify_with_retries(self, username: Optional[str] = None,
                           on_finger_needed: Optional[Callable[[str], None]] = None,
                           max_retries: int = 3, timeout: float = 30.0) -> Tuple[BiometricResult, str]:
        """Verify fingerprint with automatic retries."""
        for attempt in range(max_retries):
            result, message = self.verify(username, on_finger_needed, timeout)
            
            if result == BiometricResult.SUCCESS:
                return (result, message)
            elif result == BiometricResult.RETRY:
                logging.info(f"Retry {attempt + 1}/{max_retries}")
                continue
            else:
                return (result, message)
        
        return (BiometricResult.NO_MATCH, f"Failed after {max_retries} attempts")


_fprint_device_instance: Optional[FprintDevice] = None


def get_fprint_device() -> FprintDevice:
    """Get singleton FprintDevice instance."""
    global _fprint_device_instance
    if _fprint_device_instance is None:
        _fprint_device_instance = FprintDevice()
    return _fprint_device_instance
```

---

## Phase 3: Update gather_user_presence()

**File**: `soft_fido2/passkey_device.py` (line 670)

**Current Implementation**: Lines 670-695 show the existing GUI-based user presence flow:
1. Sends `USER_REQUEST` to systray via MessageQueue
2. Systray shows notification
3. Waits for user click
4. Receives `USER_RESPONSE_ACCEPT` back

**New Implementation**: Integrate fprintd with proper signal handling:

```python
def gather_user_presence(self):
    """
    Gather user presence with fingerprint verification.
    
    Authentication adapts to credential type and UV requirements:
    - Passkey + UV Required/Preferred: PIN (already validated) + Fingerprint
    - UV Discouraged: Fingerprint only
    - 2nd Factor: Fingerprint only
    
    Fprintd flow:
    1. VerifyStart() - starts verification
    2. VerifyFingerSelected signal - NOW prompt user via systray
    3. User places finger
    4. VerifyStatus signal - collect result
    """
    from soft_fido2.fprint_device import get_fprint_device, BiometricResult
    from soft_fido2.message_queues import QueueMessageType, MessageQueue
    
    # Check skip flag
    if os.environ.get('SOFT_FIDO2_SKIP_UP', 'False').lower() in ['y', 'yes', '1', 'true', 't']:
        colour_print(colour=bcolors.WARNING, component='Authenticator.gather_user_presence',
                msg='Skipping user presence check')
        return True
    
    # Check cached presence
    if AuthenticatorAPI.has_cached_up(self.cid):
        return True
    
    # Configuration
    fprint_enabled = os.environ.get('SOFT_FIDO2_FPRINT_ENABLED', 'true').lower() in ['y', 'yes', '1', 'true', 't']
    fprint_timeout = float(os.environ.get('SOFT_FIDO2_FPRINT_TIMEOUT', '30'))
    fprint_retries = int(os.environ.get('SOFT_FIDO2_FPRINT_RETRIES', '3'))
    
    # Try fingerprint if enabled
    if fprint_enabled:
        fprint_device = get_fprint_device()
        if fprint_device.is_available():
            colour_print(colour=bcolors.OKBLUE, component='Authenticator.gather_user_presence',
                        msg='Starting fingerprint verification...')
            
            # Callback for when VerifyFingerSelected signal is received
            def on_finger_needed(finger_name):
                # This is called when fprintd is ready for finger scan
                # NOW send notification to systray
                colour_print(colour=bcolors.OKBLUE, component='Authenticator.gather_user_presence',
                            msg=f'Place {finger_name} finger on scanner')
                MessageQueue.notify_sysapp.put(QueueMessageType.USER_REQUEST)
            
            result, message = fprint_device.verify_with_retries(
                username=None,  # Current user
                on_finger_needed=on_finger_needed,
                timeout=fprint_timeout,
                max_retries=fprint_retries
            )
            
            # Cancel any pending notifications
            MessageQueue.notify_sysapp.put(QueueMessageType.AUTH_RESPONSE)
            
            if result == BiometricResult.SUCCESS:
                colour_print(colour=bcolors.OKGREEN, component='Authenticator.gather_user_presence',
                            msg='Fingerprint verified')
                AuthenticatorAPI.cache_up(self.cid, True)
                return True
            else:
                colour_print(colour=bcolors.FAIL, component='Authenticator.gather_user_presence',
                            msg=f'Fingerprint failed: {message}')
                # Fall through to GUI fallback
        else:
            colour_print(colour=bcolors.WARNING, component='Authenticator.gather_user_presence',
                        msg='Fingerprint not available, using GUI')
    
    # Fallback to GUI prompt (existing code)
    start_time = time.time()
    MessageQueue.notify_auth.queue.clear()
    MessageQueue.notify_sysapp.put(QueueMessageType.USER_REQUEST)
    msg = None
    worker = KeepAliveWorker(self._pending, self.cid)
    worker.start()
    current_time = time.time()
    while not msg and current_time - start_time < 60:
        time.sleep(0.002)
        current_time = time.time()
        if MessageQueue.notify_auth.qsize() > 0:
            msg = MessageQueue.notify_auth.get()
    worker.interrupt()
    worker.join()
    if msg == QueueMessageType.USER_RESPONSE_ACCEPT:
        AuthenticatorAPI.cache_up(self.cid, True)
        return True
    return False
```

**Key Changes:**
1. **Proper signal handling**: `on_finger_needed` callback triggered by `VerifyFingerSelected` signal
2. **Correct timing**: Systray notification sent AFTER fprintd is ready (not before)
3. **Notification cleanup**: Sends `AUTH_RESPONSE` to cancel notification after verification
4. **Fallback preserved**: Existing GUI prompt code unchanged for fallback

---

## Phase 4: System Tray App - No Changes Required

**File**: `soft_fido2/systray_app.py`

**Current State**:
- Already uses lazy imports for optional dependencies (e.g., TPM imported at line 771 inside `_try_load_tpm_key()`)
- Does NOT import dbus-python or tpm2-pytss at module level
- Does NOT need any biometric-related changes

**Why No Changes Needed**:
- All biometric logic is handled in `passkey_device.py` via `gather_user_presence()`
- Systray app only displays generic notifications and handles user clicks
- Current notification messages work for both biometric and non-biometric scenarios
- No need to check biometric availability in systray app

**Verification**: The systray app will work correctly whether or not dbus-python is installed, as it has no dependency on it.

---

## Phase 5: Testing

**File**: `tests/fprint_test.py` (NEW)

```python
import pytest
from soft_fido2.fprint_device import FprintDevice, BiometricResult

def test_fprint_availability():
    """Test availability check doesn't crash."""
    device = FprintDevice()
    assert isinstance(device.is_available(), bool)

def test_fprint_verify_not_available():
    """Test verification when unavailable."""
    device = FprintDevice()
    if not device.is_available():
        result, msg = device.verify()
        assert result == BiometricResult.NOT_AVAILABLE

@pytest.mark.skipif(not FprintDevice().is_available(), reason="fprintd not available")
def test_fprint_verify_with_timeout():
    """Test verification with timeout."""
    device = FprintDevice()
    result, msg = device.verify(timeout=5.0)
    assert result in [BiometricResult.SUCCESS, BiometricResult.NO_MATCH,
                     BiometricResult.TIMEOUT, BiometricResult.RETRY]
```

**Integration Test Scenarios:**
1. UV Required + Passkey: PIN + fingerprint
2. UV Discouraged: Fingerprint only
3. 2nd Factor: Fingerprint only
4. Fallback to GUI when fprintd unavailable
5. Fallback to GUI on fingerprint failure
6. Timeout handling
7. Retry logic
8. Cache behavior

---

## Phase 6: Documentation

**File**: `README.md`

Add section:

```markdown
## Biometric Authentication

Supports fingerprint verification via Linux's fprintd service.

### Requirements
- `fprintd` daemon running
- Fingerprint scanner hardware
- Enrolled fingerprints: `fprintd-enroll <username>`

### Installation
```bash
# Install with biometric support
pip install soft-fido2[biometric]

# Or install fprintd system package
sudo apt install fprintd  # Debian/Ubuntu
```

### Configuration
Environment variables:
- `SOFT_FIDO2_FPRINT_ENABLED`: Enable/disable (default: true)
- `SOFT_FIDO2_FPRINT_TIMEOUT`: Timeout in seconds (default: 30)
- `SOFT_FIDO2_FPRINT_RETRIES`: Max retries (default: 3)
- `SOFT_FIDO2_SKIP_UP`: Skip user presence (testing only)

### Authentication Flow
1. PIN authentication (if required by credential type)
2. Fingerprint verification
3. Fallback to GUI if biometric unavailable
```

---

## Key Design Decisions

**Soft Dependencies:**
- `dbus-python` is optional (extras_require, not install_requires)
- Systray app does NOT import dbus/tpm at module level
- Graceful degradation when dependencies missing

**Authentication Strategy:**
- PIN validated via CTAP2 protocol (before gather_user_presence)
- Fingerprint added in gather_user_presence()
- Both required for passkeys with UV Required/Preferred
- Fingerprint only for UV Discouraged or 2nd factor

**User Experience:**
- Automatic detection of fprintd availability
- Clear feedback via logs and notifications
- Fallback to GUI prompt if biometric fails
- 3 automatic retries on scan failures

**Security:**
- 30-second timeout prevents indefinite waiting
- User presence cached per CID (30-second expiry)
- No single-factor bypass

---

## Implementation Checklist

- [ ] Update `setup.py` with extras_require for biometric
- [ ] Create `soft_fido2/fprint_device.py`
- [ ] Update `gather_user_presence()` in `passkey_device.py`
- [ ] Update systray notifications (lazy import only)
- [ ] Create `tests/fprint_test.py`
- [ ] Update `README.md`
- [ ] Test with and without dbus-python installed
- [ ] Verify systray app works without dbus-python