Write a plan to replace the use of Fernet keys in @/soft_fido2/passkey_device.py  with Symmetric keys @/soft_fido2/symmetric_key.py



optimise how key is stored?
need custom asn.1 ? cbor? jsut need number of key



This plan should also add a small prefix to each of the ids so its simple to identify which credentials the app owns

however we must be careful as the maximum permitted credential id size is 1024 bytes and the size of the encrypted private key is fairly close to that

is there enough space to add this? make the prefix "1337C0D3." ? jsut remove the prefix when reconstructing the key?

```python
from soft_fido2.symmetric_key import SymmetricKey
from soft_fido2.key_pair import KeyPair
from cryptography.fernet import Fernet
import base64

# Generate a symmetric key (SymmetricKey)
skey_str = SymmetricKey.generate_key()
skey = SymmetricKey(skey_str)

# Generate a Fernet key
fkey = Fernet(Fernet.generate_key())

# Create a key pair (EC P-256) using the generate_ecdsa class method
kp = KeyPair.generate_ecdsa()
private_key_bytes = kp.get_private_bytes()

print(f"Private key size (PEM format): {len(private_key_bytes)} bytes")

# Encrypt with SymmetricKey
cred_id_skey = skey.encrypt(private_key_bytes)
print(f"\nSymmetricKey credential ID (base64): {len(cred_id_skey)} bytes")
print(f"SymmetricKey credential ID (raw): {len(base64.urlsafe_b64decode(cred_id_skey))} bytes")

# Encrypt with Fernet
cred_id_fkey = fkey.encrypt(private_key_bytes)
print(f"\nFernet credential ID (base64): {len(cred_id_fkey)} bytes")
print(f"Fernet credential ID (raw): {len(base64.urlsafe_b64decode(cred_id_fkey))} bytes")

# Breakdown of SymmetricKey token structure (raw bytes):
raw_token = base64.urlsafe_b64decode(cred_id_skey)
print(f"\nSymmetricKey token breakdown:")
print(f"  Version: 1 byte")
print(f"  Timestamp: 8 bytes")
print(f"  Nonce: 12 bytes")
print(f"  Tag: 16 bytes")
print(f"  Ciphertext: {len(raw_token) - 37} bytes")
print(f"  Total raw: {len(raw_token)} bytes")
```
"""
Private key size (PEM format): 241 bytes

SymmetricKey credential ID (base64): 372 bytes
SymmetricKey credential ID (raw): 278 bytes

Fernet credential ID (base64): 420 bytes
Fernet credential ID (raw): 313 bytes

SymmetricKey token breakdown:
  Version: 1 byte
  Timestamp: 8 bytes
  Nonce: 12 bytes
  Tag: 16 bytes
  Ciphertext: 241 bytes
  Total raw: 278 bytes

"""

I guess from this test its ok...






















# Plan: Replace Fernet with SymmetricKey in passkey_device.py

## Executive Summary

Replace [`Fernet`](soft_fido2/passkey_device.py:13) usage with [`SymmetricKey`](soft_fido2/symmetric_key.py:17) in [`passkey_device.py`](soft_fido2/passkey_device.py:1) while adding a credential ID prefix "1337C0D3." for app identification. Based on the test data provided, this is feasible within the 1024-byte CTAP2 limit.

## Size Analysis

**Current sizes (from test):**
- Private key (PEM): 241 bytes
- SymmetricKey credential ID (base64): 372 bytes
- SymmetricKey credential ID (raw): 278 bytes
- Fernet credential ID (base64): 420 bytes
- Fernet credential ID (raw): 313 bytes

**With prefix "1337C0D3." (9 bytes):**
- New credential ID size: 372 + 9 = **381 bytes** (base64)
- Raw size: 278 + 9 = **287 bytes**
- **Remaining headroom: 1024 - 381 = 643 bytes** ✅

**Conclusion:** Sufficient space exists for the prefix.

## Changes Required

### 1. Update Imports (Line 13)
**Current:**
```python
from cryptography.fernet import Fernet
```

**Action:** Remove this import (SymmetricKey already imported at line 21)

### 2. Modify [`_create_authenticator()`](soft_fido2/passkey_device.py:392-413)

**Current (lines 401-409):**
```python
seed = KeyUtils.get_passkey_seed(rp_id.encode(), ca_kp.get_private())
fkey = Fernet(seed)
kp = KeyPair.generate_ecdsa()

authenticator = Fido2Authenticator(
    keyPair=kp,
    caKeyPair=ca_kp,
    caCert=passkey.get('x5c'),
    fKey=fkey
)
```

**Replace with:**
```python
seed = KeyUtils.get_passkey_seed(rp_id.encode(), ca_kp.get_private())
skey = SymmetricKey(seed.decode())
kp = KeyPair.generate_ecdsa()

authenticator = Fido2Authenticator(
    keyPair=kp,
    caKeyPair=ca_kp,
    caCert=passkey.get('x5c'),
    sKey=skey
)
```

**Add prefix to credential ID (line 412):**
```python
cred_id = authenticator._get_credential_id_bytes(kp)
# Add prefix for app identification
PREFIX = b"1337C0D3."
cred_id = PREFIX + cred_id
return authenticator, kp, cred_id
```

### 3. Modify [`_maybe_next_assertion()`](soft_fido2/passkey_device.py:452-474)

**Current (lines 453-463):**
```python
seed = KeyUtils.get_passkey_seed(rpId.encode(), ca_kp.get_private())
fkey = Fernet(seed)
b64CredId = base64.urlsafe_b64encode(cred.get('id'))
decryptedKp = Fido2Authenticator._get_key_pair_from_credential_id(b64CredId, fkey)
# ...
_authenticator = Fido2Authenticator(keyPair=decryptedKp, credId=b64CredId, aaguid=[0] * 16,
                                    caKeyPair=ca_kp, caCert=ca_x5c, fKey=fkey)
```

**Replace with:**
```python
seed = KeyUtils.get_passkey_seed(rpId.encode(), ca_kp.get_private())
skey = SymmetricKey(seed.decode())

# Remove prefix before decryption
PREFIX = b"1337C0D3."
raw_cred_id = cred.get('id')
if raw_cred_id.startswith(PREFIX):
    raw_cred_id = raw_cred_id[len(PREFIX):]

b64CredId = base64.urlsafe_b64encode(raw_cred_id)
decryptedKp = Fido2Authenticator._get_key_pair_from_credential_id(b64CredId, skey)
# ...
_authenticator = Fido2Authenticator(keyPair=decryptedKp, credId=b64CredId, aaguid=[0] * 16,
                                    caKeyPair=ca_kp, caCert=ca_x5c, sKey=skey)
```

### 4. Modify [`_maybe_platform_assertion()`](soft_fido2/passkey_device.py:478-499)

**Current (lines 480-488):**
```python
seed = KeyUtils.get_passkey_seed(rpId.encode(), plat_key.get_private())
fkey = Fernet(seed)
for cred in allowedList:
    b64CredId = base64.urlsafe_b64encode(cred.get('id'))
    decryptedKp = Fido2Authenticator._get_key_pair_from_credential_id(b64CredId, fkey)
    # ...
    _authenticator = Fido2Authenticator(keyPair=decryptedKp, credId=b64CredId, aaguid=[0] * 16,
                                        caKeyPair=plat_key, caCert=None, fKey=fkey)
```

**Replace with:**
```python
seed = KeyUtils.get_passkey_seed(rpId.encode(), plat_key.get_private())
skey = SymmetricKey(seed.decode())
PREFIX = b"1337C0D3."

for cred in allowedList:
    raw_cred_id = cred.get('id')
    if raw_cred_id.startswith(PREFIX):
        raw_cred_id = raw_cred_id[len(PREFIX):]

    b64CredId = base64.urlsafe_b64encode(raw_cred_id)
    decryptedKp = Fido2Authenticator._get_key_pair_from_credential_id(b64CredId, skey)
    # ...
    _authenticator = Fido2Authenticator(keyPair=decryptedKp, credId=b64CredId, aaguid=[0] * 16,
                                        caKeyPair=plat_key, caCert=None, sKey=skey)
```

## Migration Strategy

### Backward Compatibility
The existing [`CredentialIdMigrator`](soft_fido2/credential_id_migrator.py:16) class already supports both Fernet and SymmetricKey decryption. For credentials without the prefix:

1. Try SymmetricKey decryption first
2. Fall back to Fernet if SymmetricKey fails
3. New credentials will have the prefix and use SymmetricKey only

### Prefix Handling
- **Registration:** Add prefix after encryption
- **Authentication:** Strip prefix before decryption
- **Legacy credentials:** No prefix = try both decryption methods via migrator

## Benefits

1. **Smaller credential IDs:** 372 vs 420 bytes (11% reduction)
2. **App identification:** "1337C0D3." prefix clearly marks app-owned credentials
3. **Modern crypto:** AES-GCM instead of AES-CBC + HMAC
4. **Backward compatible:** Existing credentials continue to work
5. **Within spec:** 381 bytes << 1024 byte CTAP2 limit

## Testing Requirements

1. Test new credential creation with prefix
2. Test authentication with prefixed credentials
4. Verify prefix stripping logic
5. Confirm size constraints (381 < 1024 bytes)
6. Test platform authenticator path


you do not need to implement backwards compatability
 