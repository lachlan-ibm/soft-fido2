# Default Passkey Implementation Plan (Biometric + TPM Mode)

## Overview

**Prerequisites**: This implementation requires both:
- **Biometric device available** (fingerprint reader for runtime UV)
- **TPM device available** (platform key storage)

With these prerequisites met, the default passkey feature provides seamless authentication without requiring user unlocking. UV is prompted at runtime via biometric authentication, and the TPM key provides stable, secure key storage without file-based management.

## Use Cases

### 1. Make Credential (Runtime UV)
When biometric and TPM are available:
- UV prompted at runtime via fingerprint reader
- No resident credential needs to be stored
- TPM key used for credential generation
- No PIN unlock required

### 2. Get Assertion (2FA with Runtime UV)
When biometric and TPM are available:
- 2FA flow with runtime UV via biometric
- TPM key fulfills the assertion request
- No file-based passkey management needed
- Seamless user experience

## Architecture

### Key Components

```
┌─────────────────────────────────────────────────────────────┐
│                   Biometric Device                          │
│  - Provides runtime UV when needed                          │
│  - No unlock/lock state management                          │
│  - Direct integration with CTAP operations                  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      TPM Device                             │
│  - Stores platform key securely                             │
│  - More stable than file-based keys                         │
│  - No PIN management required                               │
│  - Persistent across sessions                               │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                Runtime Decision Logic                       │
│  _make_cred: Use TPM key with biometric UV                  │
│  _get_assertion: Use TPM key with biometric UV              │
│  _resolve_passkey: Return TPM-based key when appropriate    │
└─────────────────────────────────────────────────────────────┘
```

### Prerequisites Validation

The system must validate both prerequisites are available:

```python
def validate_biometric_tpm_mode() -> bool:
    """
    Validate that both biometric and TPM devices are available.
    
    Returns:
        True if both devices are available and functional
    """
    # Check biometric device
    if not BiometricDevice.is_available():
        return False
    
    # Check TPM device
    if not TPMDevice.is_available():
        return False
    
    # Verify TPM key exists
    try:
        tpm_key = KeyUtils._get_platform_kp()
        if tpm_key is None:
            return False
    except Exception:
        return False
    
    return True
```

## Implementation Tasks

### Task 1: Add Biometric + TPM Mode Detection

**File**: [`soft_fido2/passkey_device.py`](soft_fido2/passkey_device.py)

**Changes**:
```python
class AuthenticatorAPI(object):
    _biometric_tpm_mode_enabled = False
    _biometric_tpm_mode_lock = threading.Lock()
    
    @classmethod
    def initialize_biometric_tpm_mode(cls):
        """
        Initialize and validate biometric + TPM mode.
        
        This mode enables seamless authentication without user unlocking
        by leveraging runtime UV via biometric and stable TPM key storage.
        """
        with cls._biometric_tpm_mode_lock:
            # Check biometric device
            if not BiometricDevice.is_available():
                colour_print(colour=bcolors.WARNING,
                           component='AuthenticatorAPI.initialize_biometric_tpm_mode',
                           msg='Biometric device not available')
                cls._biometric_tpm_mode_enabled = False
                return False
            
            # Check TPM device
            if not TPMDevice.is_available():
                colour_print(colour=bcolors.WARNING,
                           component='AuthenticatorAPI.initialize_biometric_tpm_mode',
                           msg='TPM device not available')
                cls._biometric_tpm_mode_enabled = False
                return False
            
            # Verify TPM key exists
            try:
                tpm_key = KeyUtils._get_platform_kp()
                if tpm_key is None:
                    colour_print(colour=bcolors.FAIL,
                               component='AuthenticatorAPI.initialize_biometric_tpm_mode',
                               msg='TPM key not available')
                    cls._biometric_tpm_mode_enabled = False
                    return False
            except Exception as e:
                colour_print(colour=bcolors.FAIL,
                           component='AuthenticatorAPI.initialize_biometric_tpm_mode',
                           msg=f'TPM key check failed: {e}')
                cls._biometric_tpm_mode_enabled = False
                return False
            
            cls._biometric_tpm_mode_enabled = True
            colour_print(colour=bcolors.OKGREEN,
                       component='AuthenticatorAPI.initialize_biometric_tpm_mode',
                       msg='Biometric + TPM mode enabled')
            return True
    
    @classmethod
    def is_biometric_tpm_mode_enabled(cls) -> bool:
        """Check if biometric + TPM mode is enabled."""
        with cls._biometric_tpm_mode_lock:
            return cls._biometric_tpm_mode_enabled
```

**Testing**:
- Verify detection when both devices available
- Verify failure when biometric missing
- Verify failure when TPM missing
- Verify failure when TPM key not initialized

---

### Task 2: Modify `_make_cred` for Biometric + TPM Mode

**File**: [`soft_fido2/passkey_device.py`](soft_fido2/passkey_device.py:748-780)

**Current Logic**:
```python
def _make_cred(self, ba):
    # ... existing code ...
    result = (self.CBORStatusCode.CTAP2_ERR_PUAT_REQUIRED).to_bytes()
    # Request and validate pin-auth
    if not self._verify_pin_token(req.get(0x01), req.get(0x08)):
        if self.cid in AuthenticatorAPI._open_keys:
            result = (self.CBORStatusCode.CTAP2_ERR_PIN_AUTH_INVALID).to_bytes()
        return self._set_rsp_fields(list(result))
```

**Modified Logic**:
```python
def _make_cred(self, ba):
    # ... existing code ...
    
    # Check if pinAuth is provided
    pin_auth_provided = req.get(0x08) is not None
    
    # Check if UV is requested in options
    options = req.get(0x07, {})
    uv_requested = options.get('uv', False)
    
    if pin_auth_provided:
        # Original flow: validate pin token
        result = (self.CBORStatusCode.CTAP2_ERR_PUAT_REQUIRED).to_bytes()
        if not self._verify_pin_token(req.get(0x01), req.get(0x08)):
            if self.cid in AuthenticatorAPI._open_keys:
                result = (self.CBORStatusCode.CTAP2_ERR_PIN_AUTH_INVALID).to_bytes()
            return self._set_rsp_fields(list(result))
    elif uv_requested and AuthenticatorAPI.is_biometric_tpm_mode_enabled():
        # Biometric + TPM mode: prompt for UV at runtime
        colour_print(colour=bcolors.OKGREEN,
                   component='CBORCommand._make_cred',
                   msg='Using biometric + TPM mode (runtime UV)')
        
        # Prompt for biometric verification
        if not BiometricDevice.verify_user():
            colour_print(colour=bcolors.FAIL,
                       component='CBORCommand._make_cred',
                       msg='Biometric verification failed')
            result = (self.CBORStatusCode.CTAP2_ERR_OPERATION_DENIED).to_bytes()
            return self._set_rsp_fields(list(result))
        
        colour_print(colour=bcolors.OKGREEN,
                   component='CBORCommand._make_cred',
                   msg='Biometric verification successful')
    else:
        # No pinAuth and no biometric mode: require PUAT
        result = (self.CBORStatusCode.CTAP2_ERR_PUAT_REQUIRED).to_bytes()
        return self._set_rsp_fields(list(result))
    
    # Continue with attestation_out
    error, authData, attStmt = AuthenticatorAPI.attestation_out(
        req.get(0x01), req.get(0x02), req.get(0x03),
        req.get(0x04), req.get(0x05), req.get(0x06), 
        req.get(0x07, None), self.cid, 
        use_biometric_tpm=uv_requested and not pin_auth_provided
    )
    # ... rest of existing code ...
```

---

### Task 3: Modify `_get_assertion` for Biometric + TPM Mode

**File**: [`soft_fido2/passkey_device.py`](soft_fido2/passkey_device.py:783-815)

**Current Logic**:
```python
def _get_assertion(self, ba):
    # ... existing code ...
    result = (self.CBORStatusCode.CTAP1_ERR_OTHER).to_bytes()
    # Request and validate pin-auth
    if not self._verify_pin_token(req.get(0x02), req.get(0x06)):
        if self.cid in AuthenticatorAPI._open_keys:
            result = (self.CBORStatusCode.CTAP2_ERR_PIN_AUTH_INVALID).to_bytes()
        return self._set_rsp_fields(list(result))
```

**Modified Logic**:
```python
def _get_assertion(self, ba):
    # ... existing code ...
    
    # Check if pinAuth is provided
    pin_auth_provided = req.get(0x06) is not None
    
    # Check if UV is requested in options
    options = req.get(0x04, {})
    uv_requested = options.get('uv', False)
    
    if pin_auth_provided:
        # Original flow: validate pin token
        result = (self.CBORStatusCode.CTAP1_ERR_OTHER).to_bytes()
        if not self._verify_pin_token(req.get(0x02), req.get(0x06)):
            if self.cid in AuthenticatorAPI._open_keys:
                result = (self.CBORStatusCode.CTAP2_ERR_PIN_AUTH_INVALID).to_bytes()
            return self._set_rsp_fields(list(result))
    elif uv_requested and AuthenticatorAPI.is_biometric_tpm_mode_enabled():
        # Biometric + TPM mode: prompt for UV at runtime
        colour_print(colour=bcolors.OKGREEN,
                   component='CBORCommand._get_assertion',
                   msg='Using biometric + TPM mode (runtime UV)')
        
        # Prompt for biometric verification
        if not BiometricDevice.verify_user():
            colour_print(colour=bcolors.FAIL,
                       component='CBORCommand._get_assertion',
                       msg='Biometric verification failed')
            result = (self.CBORStatusCode.CTAP2_ERR_OPERATION_DENIED).to_bytes()
            return self._set_rsp_fields(list(result))
        
        colour_print(colour=bcolors.OKGREEN,
                   component='CBORCommand._get_assertion',
                   msg='Biometric verification successful')
    else:
        # No pinAuth and no biometric mode: return error
        result = (self.CBORStatusCode.CTAP1_ERR_OTHER).to_bytes()
        return self._set_rsp_fields(list(result))
    
    # Continue with assertion_out
    error, credential, authData, signature, userHandle = AuthenticatorAPI.assertion_out(
        req.get(0x01), req.get(0x02), req.get(0x03, []), 
        req.get(0x04, {}), self.cid,
        use_biometric_tpm=uv_requested and not pin_auth_provided
    )
    # ... rest of existing code ...
```

---

### Task 4: Update `_resolve_passkey` for Biometric + TPM Mode

**File**: [`soft_fido2/passkey_device.py`](soft_fido2/passkey_device.py:351-369)

**Current Implementation**:
```python
@classmethod
def _resolve_passkey(cls, options, cid):
    """
    Resolve passkey based on options (rk/uv flags).
    Returns: (passkey_dict, resident_creds, attestation_type, request_rk)
    """
    options = options or {}
    
    # Use platform key if rk or uv not requested
    if options.get('rk', False) == False and options.get('uv', False) == False:
        return {
            'kp': KeyUtils._get_platform_kp()
        }, None, 'packed-self', False

    # Use opened passkey
    passkey = cls._open_keys[cid]
    res_creds = KeyUtils._load_passkey(passkey['ph'], 
                                        passkey['file']).get('res.creds')
    return passkey, res_creds, 'packed', True
```

**Modified Implementation**:
```python
@classmethod
def _resolve_passkey(cls, options, cid, use_biometric_tpm=False):
    """
    Resolve passkey based on options (rk/uv flags) and biometric + TPM mode.
    
    Args:
        options: Options dict with 'rk' and 'uv' flags
        cid: Channel ID
        use_biometric_tpm: If True, use TPM key with biometric UV
        
    Returns: (passkey_dict, resident_creds, attestation_type, request_rk)
    """
    options = options or {}
    
    # Check if we should use biometric + TPM mode
    if use_biometric_tpm and cls.is_biometric_tpm_mode_enabled():
        tpm_key = KeyUtils._get_platform_kp()
        colour_print(colour=bcolors.OKGREEN,
                   component='AuthenticatorAPI._resolve_passkey',
                   msg='Using biometric + TPM mode')
        return {
            'kp': tpm_key
        }, None, 'packed-self', False
    
    # Use platform key if rk or uv not requested
    if options.get('rk', False) == False and options.get('uv', False) == False:
        return {
            'kp': KeyUtils._get_platform_kp()
        }, None, 'packed-self', False

    # Use opened passkey
    if cid not in cls._open_keys:
        raise KeyError(f"CID {cid} not found in open keys")
    
    passkey = cls._open_keys[cid]
    res_creds = KeyUtils._load_passkey(passkey['ph'], 
                                        passkey['file']).get('res.creds')
    return passkey, res_creds, 'packed', True
```

**Update `attestation_out` signature**:
```python
@classmethod
def attestation_out(cls, clientDataHash, rp, user, pkCredsParams, 
                   excludeList, exts, options, cid, use_biometric_tpm=False):
    # ... existing code ...
    passkey, res_creds, attestation, req_rk = cls._resolve_passkey(
        options, cid, use_biometric_tpm=use_biometric_tpm
    )
    # ... rest of existing code ...
```

**Update `assertion_out` signature**:
```python
@classmethod
def assertion_out(cls, rpId, clientDataHash, allowedList, exts, cid, 
                 use_biometric_tpm=False):
    # Handle biometric + TPM mode
    if use_biometric_tpm and cls.is_biometric_tpm_mode_enabled():
        tpm_key = KeyUtils._get_platform_kp()
        
        colour_print(colour=bcolors.OKGREEN,
                   component='AuthenticatorAPI.assertion_out',
                   msg='Using biometric + TPM mode for assertion')
        
        # Try to fulfill assertion with TPM key
        for cred in allowedList:
            try:
                return cls._maybe_next_assertion(rpId, tpm_key, None, 
                                                clientDataHash, cred)
            except Exception as e:
                colour_print(colour=bcolors.FAIL,
                           component='AuthenticatorAPI.assertion_out',
                           msg=f'Could not use credential {cred} with TPM key')
                continue
        
        # If no credentials work, return error
        return CBORCommand.CBORStatusCode.CTAP2_ERR_NO_CREDENTIALS, None, None, None, None
    
    # ... existing code for normal flow ...
```

---

### Task 5: Add Biometric Device Integration

**File**: [`soft_fido2/biometric_device.py`](soft_fido2/biometric_device.py) (new file)

**Implementation**:
```python
"""
Biometric device integration for runtime UV.
"""

import logging
from typing import Optional

class BiometricDevice:
    """
    Interface to biometric authentication device (fingerprint reader).
    
    This provides runtime user verification without requiring
    pre-unlocking of passkeys.
    """
    
    _device_available = None
    
    @classmethod
    def is_available(cls) -> bool:
        """
        Check if biometric device is available.
        
        Returns:
            True if fingerprint reader is available and functional
        """
        if cls._device_available is not None:
            return cls._device_available
        
        try:
            # Check for fingerprint device
            # This will be implemented based on the actual biometric
            # integration from BIOMETRIC_INTEGRATION_PLAN.md
            import subprocess
            result = subprocess.run(
                ['fprintd-verify'],
                capture_output=True,
                timeout=1
            )
            cls._device_available = result.returncode == 0
            return cls._device_available
        except Exception as e:
            logging.warning(f"Biometric device check failed: {e}")
            cls._device_available = False
            return False
    
    @classmethod
    def verify_user(cls) -> bool:
        """
        Prompt user for biometric verification.
        
        This blocks until user provides fingerprint or cancels.
        
        Returns:
            True if verification successful, False otherwise
        """
        if not cls.is_available():
            logging.error("Biometric device not available")
            return False
        
        try:
            # Prompt for fingerprint verification
            # This will be implemented based on the actual biometric
            # integration from BIOMETRIC_INTEGRATION_PLAN.md
            import subprocess
            result = subprocess.run(
                ['fprintd-verify'],
                capture_output=True,
                timeout=30
            )
            
            if result.returncode == 0:
                logging.info("Biometric verification successful")
                return True
            else:
                logging.warning("Biometric verification failed")
                return False
        except subprocess.TimeoutExpired:
            logging.warning("Biometric verification timed out")
            return False
        except Exception as e:
            logging.error(f"Biometric verification error: {e}")
            return False
    
    @classmethod
    def reset_cache(cls):
        """Reset the device availability cache."""
        cls._device_available = None
```

---

### Task 6: Update Systray App Initialization

**File**: [`soft_fido2/systray_app.py`](soft_fido2/systray_app.py)

**Changes**:
```python
class SystrayApp:
    def __init__(self):
        # ... existing code ...
        
        # Initialize biometric + TPM mode
        self._biometric_tpm_mode_enabled = False
        self._initialize_biometric_tpm_mode()
    
    def _initialize_biometric_tpm_mode(self):
        """Initialize biometric + TPM mode if prerequisites are met."""
        if AuthenticatorAPI.initialize_biometric_tpm_mode():
            self._biometric_tpm_mode_enabled = True
            logging.info("Biometric + TPM mode enabled")
            
            # Update UI to show mode is active
            self._update_mode_indicator()
        else:
            self._biometric_tpm_mode_enabled = False
            logging.info("Biometric + TPM mode not available")
    
    def _update_mode_indicator(self):
        """Update UI to show current authentication mode."""
        if self._biometric_tpm_mode_enabled:
            self.setToolTip("FIDO2 Authenticator (Biometric + TPM Mode)")
        else:
            self.setToolTip("FIDO2 Authenticator")
```

**Add to Settings Dialog**:
```python
class SettingsDialog(QDialog):
    def _create_mode_info_group(self):
        """Create mode information section."""
        group = QGroupBox("Authentication Mode:")
        layout = QVBoxLayout()
        
        # Check mode status
        if AuthenticatorAPI.is_biometric_tpm_mode_enabled():
            status_text = """
            <b>Biometric + TPM Mode: Enabled</b><br>
            <br>
            ✓ Biometric device available<br>
            ✓ TPM device available<br>
            <br>
            This mode provides seamless authentication with runtime UV
            via fingerprint reader and stable TPM key storage.
            """
            status_label = QLabel(status_text)
            status_label.setStyleSheet("color: green;")
        else:
            status_text = """
            <b>Biometric + TPM Mode: Not Available</b><br>
            <br>
            Prerequisites:<br>
            • Biometric device (fingerprint reader)<br>
            • TPM device with initialized key<br>
            <br>
            Standard passkey mode is active.
            """
            status_label = QLabel(status_text)
            status_label.setStyleSheet("color: orange;")
        
        layout.addWidget(status_label)
        group.setLayout(layout)
        return group
```

---

### Task 7: Add Validation and Error Handling

**Validation Points**:

1. **Mode Initialization**:
   - Verify biometric device is functional
   - Verify TPM device is accessible
   - Verify TPM key exists
   - Handle initialization failures gracefully

2. **Runtime UV**:
   - Handle biometric verification timeout
   - Handle biometric verification failure
   - Provide clear error messages
   - Log all verification attempts

3. **Fallback Behavior**:
   - Fall back to standard mode if biometric fails
   - Fall back to standard mode if TPM unavailable
   - Maintain compatibility with existing flows

**Error Messages**:
```python
# In passkey_device.py
class BiometricTPMError(Exception):
    """Base exception for biometric + TPM mode operations."""
    pass

class BiometricDeviceError(BiometricTPMError):
    """Biometric device not available or failed."""
    pass

class TPMDeviceError(BiometricTPMError):
    """TPM device not available or failed."""
    pass

class BiometricVerificationError(BiometricTPMError):
    """Biometric verification failed or timed out."""
    pass
```

---

### Task 8: Test Biometric + TPM Mode Scenarios

**Test Cases**:

1. **Make Credential with Biometric UV**:
   ```python
   # Setup: Biometric and TPM available
   # Action: Send makeCredential with uv=true, no pinAuth
   # Expected: Biometric prompt, credential created with TPM key
   # Verify: UV flag set in authData
   ```

2. **Get Assertion with Biometric UV**:
   ```python
   # Setup: Credential created, biometric and TPM available
   # Action: Send getAssertion with uv=true, no pinAuth
   # Expected: Biometric prompt, assertion successful with TPM key
   # Verify: UV flag set in authData
   ```

3. **Biometric Verification Failure**:
   ```python
   # Setup: Biometric available but user fails verification
   # Action: Send makeCredential with uv=true
   # Expected: CTAP2_ERR_OPERATION_DENIED
   ```

4. **Fallback to Standard Mode**:
   ```python
   # Setup: Biometric not available
   # Action: Send makeCredential with pinAuth
   # Expected: Standard passkey flow works normally
   ```

5. **TPM Key Stability**:
   ```python
   # Setup: Create credential with TPM key
   # Action: Restart application, perform assertion
   # Expected: Same TPM key used, assertion successful
   ```

**Test Script**:
```bash
#!/bin/bash
# tests/biometric_tpm_mode_test.sh

echo "Test 1: Verify biometric + TPM mode detection"
# ... test implementation ...

echo "Test 2: Make credential with biometric UV"
# ... test implementation ...

echo "Test 3: Get assertion with biometric UV"
# ... test implementation ...

echo "Test 4: Biometric verification failure handling"
# ... test implementation ...

echo "Test 5: TPM key stability across restarts"
# ... test implementation ...
```

---

### Task 9: Update Documentation

**Files to Update**:

1. **README.md**:
   ```markdown
   ## Biometric + TPM Mode
   
   When both a biometric device (fingerprint reader) and TPM device are available,
   the authenticator operates in a seamless mode that eliminates the need for
   passkey unlocking:
   
   ### Features
   - Runtime UV via fingerprint reader
   - Stable TPM key storage (no file management)
   - No PIN unlock required
   - Automatic mode detection
   
   ### Prerequisites
   - Fingerprint reader (fprintd compatible)
   - TPM 2.0 device with initialized key
   
   ### How It Works
   1. System detects biometric and TPM devices at startup
   2. When UV is requested, fingerprint prompt appears
   3. TPM key is used for credential operations
   4. No passkey file management needed
   
   ### Security Benefits
   - TPM key more stable than file-based keys
   - Biometric provides strong UV
   - No cached PINs or unlocked state
   - Each operation requires fresh UV
   ```

2. **Create `docs/BIOMETRIC_TPM_MODE.md`**:
   - Detailed architecture
   - Integration with BIOMETRIC_INTEGRATION_PLAN.md
   - TPM key management
   - Security model
   - Troubleshooting guide

3. **Update `TODO.md`**:
   - Mark biometric + TPM mode as completed
   - Link to BIOMETRIC_INTEGRATION_PLAN.md
   - Add any follow-up tasks

---

## Security Considerations

### Threat Model

1. **Biometric Spoofing**:
   - **Risk**: Attacker attempts to spoof fingerprint
   - **Mitigation**: Use hardware-backed biometric verification, liveness detection

2. **TPM Key Extraction**:
   - **Risk**: Attacker attempts to extract TPM key
   - **Mitigation**: TPM hardware protection, sealed keys

3. **Replay Attacks**:
   - **Risk**: Attacker replays biometric verification
   - **Mitigation**: Fresh UV required for each operation, no caching

### Best Practices

1. **Biometric Security**:
   - Use hardware-backed biometric verification
   - Implement liveness detection
   - Limit verification attempts
   - Log all verification attempts

2. **TPM Security**:
   - Use TPM 2.0 with proper key sealing
   - Verify TPM integrity at startup
   - Monitor TPM key stability
   - Handle TPM failures gracefully

3. **User Experience**:
   - Clear biometric prompts
   - Timeout handling
   - Fallback to standard mode if needed
   - Status indicators in UI

---

## Testing Strategy

### Unit Tests
- Biometric device detection
- TPM device detection
- Mode initialization
- Error handling

### Integration Tests
- Make credential flow with biometric UV
- Get assertion flow with biometric UV
- Fallback behavior
- TPM key stability

### End-to-End Tests
- Full authentication flow
- Multi-device scenarios
- Error recovery
- Performance testing

### Security Tests
- Biometric verification bypass attempts
- TPM key extraction attempts
- Replay attack prevention
- Timeout handling

---

## Rollout Plan

### Phase 1: Core Implementation (Tasks 1-4)
- Implement mode detection
- Modify make credential flow
- Modify get assertion flow
- Update passkey resolution logic
- **Milestone**: Biometric + TPM mode functional

### Phase 2: Integration (Tasks 5-6)
- Integrate biometric device
- Update systray app
- Add UI indicators
- **Milestone**: Full integration complete

### Phase 3: Quality & Documentation (Tasks 7-9)
- Add validation and error handling
- Write comprehensive tests
- Update documentation
- **Milestone**: Feature ready for production

### Phase 4: Deployment
- Beta testing with select users
- Monitor logs for issues
- Gather feedback
- Production rollout

---

## Integration with Existing Plans

### BIOMETRIC_INTEGRATION_PLAN.md
This implementation builds on the biometric integration plan:
- Uses the same biometric device interface
- Leverages fprintd integration
- Follows the same UV flow
- Compatible with existing biometric features

### TPM Device
This implementation uses the existing TPM device:
- [`soft_fido2/tpm_device.py`](soft_fido2/tpm_device.py)
- Platform key management
- Key sealing and unsealing
- Hardware-backed security

---

## Future Enhancements

1. **Multi-Factor Biometric**:
   - Support multiple biometric types
   - Fallback between biometric methods
   - User preference for biometric type

2. **TPM Key Rotation**:
   - Periodic key rotation
   - Secure key migration
   - Backward compatibility

3. **Advanced UV Options**:
   - Configurable UV timeout
   - UV strength levels
   - Context-aware UV requirements

4. **Audit Dashboard**:
   - UI for viewing biometric usage
   - TPM key status
   - Security alerts
   - Usage statistics

---

## References

- [FIDO2 CTAP Specification](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html)
- [WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
- [TPM 2.0 Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- Current implementation: [`soft_fido2/passkey_device.py`](soft_fido2/passkey_device.py)
- Key utilities: [`soft_fido2/key_pair.py`](soft_fido2/key_pair.py)
- TPM device: [`soft_fido2/tpm_device.py`](soft_fido2/tpm_device.py)
- Biometric integration: `BIOMETRIC_INTEGRATION_PLAN.md`
- UI implementation: [`soft_fido2/systray_app.py`](soft_fido2/systray_app.py)