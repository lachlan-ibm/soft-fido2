# Post-Quantum Cryptography Migration Plan: ML-DSA Direct Migration

## Executive Summary

This document outlines the strategy for migrating the FIDO2 authenticator from classical EC256 keys to **ML-DSA (Module-Lattice-Based Digital Signature Algorithm)** post-quantum signatures. This is a **direct migration** with no backwards compatibility - all credentials will use ML-DSA going forward.

**Key Finding:** Direct encryption of ML-DSA private keys (2,560+ bytes) exceeds the credential ID size limit. The solution is **seed-based deterministic key derivation**, which is NIST FIPS 204-approved and reduces storage from 2,560+ bytes to just 32 bytes.

**Algorithm Choice:** ML-DSA-44 is selected as the primary target for:
- Smallest seed size (32 bytes vs 64 bytes for ML-KEM)
- Adequate security (NIST Level 2, ~128-bit quantum security)
- Existing partial implementation in codebase at [`load_mldsa_key()`](soft_fido2/key_pair.py:84)
- FIDO2 use case (digital signatures for authentication)

**Migration Approach:** Complete replacement - all new credentials use ML-DSA, no EC256 support.

---

## 1. Problem Analysis

### Current Implementation (To Be Replaced)
- **Algorithm:** EC256 (ECDSA with P-256 curve)
- **Private key size:** ~121 bytes (DER-encoded)
- **Credential ID structure:** `Version (1) + Timestamp (8) + Nonce (12) + Tag (16) + Encrypted_Key (121) = ~158 bytes`
- **Encryption:** AES-GCM via [`SymmetricKey.encrypt()`](soft_fido2/symmetric_key.py:61)
- **Location:** [`_get_credential_id_bytes()`](soft_fido2/authenticator.py:197) in authenticator.py

### ML-DSA Algorithm Size Comparison

| Algorithm | Private Key Size | Seed Size | After Encryption | Fits in 1024 bytes? | Security Level |
|-----------|-----------------|-----------|------------------|---------------------|----------------|
| **EC256 (legacy)** | ~121 bytes | N/A | ~158 bytes | ✅ Yes | Classical (obsolete) |
| **ML-DSA-44** | 2,560 bytes | **32 bytes** | **~70 bytes** | ✅ **Yes (seed-based)** | NIST Level 2 (~128-bit) |
| **ML-DSA-65** | 4,032 bytes | **32 bytes** | **~70 bytes** | ✅ **Yes (seed-based)** | NIST Level 3 (~192-bit) |
| **ML-DSA-87** | 4,896 bytes | **32 bytes** | **~70 bytes** | ✅ **Yes (seed-based)** | NIST Level 5 (~256-bit) |

**Key Insight:** While ML-DSA private keys are 2,560-4,896 bytes, the **32-byte seed** fits comfortably within the 1024-byte limit when encrypted (~70 bytes total).

**Comparison with other PQC options:**
- **sntrup761:** 1,763-byte private key, but not a signature algorithm (KEM only)
- **ML-KEM:** 1,632-3,168 byte private keys, 64-byte seeds (larger than ML-DSA)
- **Falcon:** 1,281-2,305 byte private keys, but complex implementation and floating-point operations

**Conclusion:** ML-DSA is optimal for FIDO2 because:
1. ✅ Smallest seed size (32 bytes vs 64 for ML-KEM)
2. ✅ Purpose-built for digital signatures (FIDO2's primary use case)
3. ✅ NIST FIPS 204 standardized
4. ✅ Already partially implemented in codebase

---

## 2. Proposed Solution: ML-DSA Seed-Based Key Derivation

### Core Concept

Instead of encrypting the full ML-DSA private key (2,560+ bytes), encrypt a **32-byte seed** and deterministically regenerate the key pair on-demand during authentication.

### NIST FIPS 204 Support

ML-DSA (FIPS 204) **explicitly supports** deterministic key generation from a seed:

**ML-DSA Deterministic Key Generation:**
```python
from oqs.oqs import Signature

# 32-byte seed for deterministic key generation
seed = b'\x00' * 32

# Generate ML-DSA key pair from seed
ml_key = Signature("ML-DSA-44", secret_key=seed)
pubkey = ml_key.generate_keypair_seed()

# Same seed always produces same key pair (deterministic)
```

**Your codebase already has this implemented at [`load_mldsa_key()`](soft_fido2/key_pair.py:84):**
```python
@classmethod
def load_mldsa_key(cls, alg, seed):
    from oqs.oqs import Signature
    ml_key: Signature = Signature(alg, seed)
    pubkey: bytes = ml_key.generate_keypair_seed()
    return KeyPair(ml_key, pubkey)
```

**Security Properties:**
- ✅ NIST FIPS 204 approved method
- ✅ Deterministic: Same seed → same key pair
- ✅ Cryptographically secure: Uses SHAKE-256 internally
- ✅ No key storage needed: Keys regenerated on-demand

### New Credential ID Structure for ML-DSA

```
Version (1) + Timestamp (8) + Nonce (12) + Tag (16) + Encrypted_Payload (33) = ~70 bytes

Encrypted Payload contains:
  AlgID (1) + Seed (32) = 33 bytes
```

**Size comparison:**
- EC256 legacy: ~158 bytes
- ML-DSA seed-based: **~70 bytes** (56% smaller!)
- ML-DSA direct encryption: ~2,597 bytes (would not fit)

**Benefits:**
- ✅ Fits comfortably in 1024-byte limit
- ✅ Actually smaller than legacy EC256 implementation
- ✅ Room for future metadata or algorithm upgrades

---

## 3. Implementation Design

### 3.1 ML-DSA Seed Derivation Function

```python
def _derive_mldsa_seed(self, rpId: bytes, alg: str = "ML-DSA-44") -> bytes:
    """
    Derive a deterministic 32-byte seed for ML-DSA key generation.
    
    Uses HKDF (HMAC-based Key Derivation Function) with:
    - Master secret: CA private key from passkey file
    - Salt: Fixed domain separator for version control
    - Info: RP ID for per-relying-party uniqueness
    
    Args:
        rpId: Relying Party identifier (e.g., b"example.com")
        alg: ML-DSA variant ("ML-DSA-44", "ML-DSA-65", or "ML-DSA-87")
        
    Returns:
        Deterministic 32-byte seed for ML-DSA key generation
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    
    master_secret = self.caKeyPair.get_private_bytes()
    
    # ML-DSA always uses 32-byte seeds (all security levels)
    seed_length = 32
    
    # Salt for ML-DSA seed derivation
    salt = b"FIDO2-ML-DSA-SEED-v1"
    
    # Derive seed using HKDF with SHA-256
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=seed_length,
        salt=salt,
        info=rpId,  # Ensures different seed per RP
    )
    
    return hkdf.derive(master_secret)
```

**Security Properties:**
- ✅ Deterministic: Same inputs → same 32-byte seed
- ✅ Unique per RP: Different rpId → different seed
- ✅ One-way: Cannot reverse to master secret
- ✅ Context binding: Seed includes RP ID
- ✅ FIPS 204 compatible: 32-byte seed format

**Why HKDF with SHA-256:**
- Industry standard for key derivation (RFC 5869, NIST SP 800-56C Rev. 2)
- Provides cryptographic separation between master secret and derived seeds
- SHA-256 output (32 bytes) matches ML-DSA seed requirement exactly
- Already in cryptography library (no new dependencies)

**KDF Alternatives Considered:**
- **SHAKE256 (SHA-3 XOF):** Valid alternative, used internally by ML-DSA, but HKDF is more standard for key derivation
- **PBKDF2/Argon2:** Rejected - designed for passwords (intentionally slow), unnecessary for high-entropy master secret
- **Direct HMAC:** Simpler but lacks HKDF's explicit extract-expand paradigm and salt/info separation

**Decision Rationale:**
HKDF chosen for industry-standard practice, better auditability, and explicit design with salt/info separation. No significant advantage from alternatives.

### 3.2 ML-DSA Credential ID Generation

```python
def _get_credential_id_bytes(self, keyPair, rpId: bytes, alg: str = "ML-DSA-44"):
    """
    Generate credential ID for ML-DSA keys using seed derivation.
    
    This replaces the EC256 implementation entirely.
    """
    if self.cib is not None:
        return self.cib
    
    # Derive 32-byte seed from RP ID
    seed = self._derive_mldsa_seed(rpId, alg)
    
    # Prepend algorithm identifier to seed
    alg_map = {
        "ML-DSA-44": 0x01,
        "ML-DSA-65": 0x02,
        "ML-DSA-87": 0x03,
    }
    alg_byte = bytes([alg_map.get(alg, 0x01)])
    payload = alg_byte + seed  # 33 bytes total
    
    # Encrypt the payload (algorithm ID + seed)
    key = self.sKey or self.fKey
    self.cib = key.encrypt(payload)
    
    return self.cib
```

**Credential ID Structure:**
```
Encrypted with SymmetricKey (AES-GCM):
  Version (1) + Timestamp (8) + Nonce (12) + Tag (16) + Ciphertext (33)
  = 70 bytes total

Ciphertext contains:
  AlgID (1) + Seed (32) = 33 bytes
```

### 3.3 ML-DSA Key Reconstruction

```python
@classmethod
def _get_key_pair_from_credential_id(cls, credId, decryptor):
    """
    Reconstruct ML-DSA key pair from encrypted seed in credential ID.
    
    This replaces the EC256 implementation entirely.
    
    Args:
        credId: URL-safe base64 encoded credential ID
        decryptor: SymmetricKey instance
        
    Returns:
        KeyPair: Regenerated ML-DSA key pair
        
    Raises:
        ValueError: If algorithm ID is invalid or key generation fails
    """
    # Decrypt to get payload (algorithm ID + seed)
    encBytes = cls._urlb64_decode(credId)
    payload = decryptor.decrypt(encBytes)
    
    # Extract algorithm identifier and seed
    if len(payload) != 33:
        raise ValueError(f"Invalid ML-DSA credential ID payload length: {len(payload)}")
    
    alg_byte = payload[0]
    seed = payload[1:]  # 32 bytes
    
    # Map algorithm byte to ML-DSA variant
    alg_map = {
        0x01: "ML-DSA-44",
        0x02: "ML-DSA-65",
        0x03: "ML-DSA-87",
    }
    
    alg = alg_map.get(alg_byte)
    if alg is None:
        raise ValueError(f"Unknown ML-DSA algorithm identifier: 0x{alg_byte:02x}")
    
    # Regenerate key pair from seed using existing function
    # This calls: Signature(alg, secret_key=seed).generate_keypair_seed()
    return KeyUtils.load_mldsa_key(alg, seed)
```

**Performance Characteristics:**
- ML-DSA-44 key generation: ~1-2ms
- ML-DSA-65 key generation: ~2-3ms
- ML-DSA-87 key generation: ~3-4ms

**Note:** Key regeneration happens during authentication, adding minimal latency compared to network round-trip times.

### 3.4 Integration Points

**Files to modify:**

1. **[`soft_fido2/authenticator.py`](soft_fido2/authenticator.py:197)**
   - Add `_derive_mldsa_seed()` method
   - Replace `_get_credential_id_bytes()` with ML-DSA implementation
   - Replace `_get_key_pair_from_credential_id()` with ML-DSA implementation
   - Remove all EC256-specific code paths

2. **[`soft_fido2/key_pair.py`](soft_fido2/key_pair.py:84)**
   - ✅ Already has `load_mldsa_key()` - no changes needed!
   - Remove EC256 key loading functions (if any)

3. **[`soft_fido2/passkey_device.py`](soft_fido2/passkey_device.py:42)**
   - Update credential creation flow to use ML-DSA
   - Add algorithm selection logic (default to ML-DSA-44)
   - Remove EC256 configuration options

**Minimal changes required:** The existing `load_mldsa_key()` function already provides the core functionality needed!

---

## 4. Algorithm Selection Strategy

**Decision:** Support all three ML-DSA variants with ML-DSA-44 as default

| Algorithm | Security Level | Seed Size | Key Gen Speed | Signature Size | Use Case |
|-----------|---------------|-----------|---------------|----------------|----------|
| **ML-DSA-44** | NIST Level 2 (~128-bit) | 32 bytes | Fast (~1ms) | 2,420 bytes | **Default** - Standard authentication |
| ML-DSA-65 | NIST Level 3 (~192-bit) | 32 bytes | Medium (~2ms) | 3,309 bytes | High-security applications |
| ML-DSA-87 | NIST Level 5 (~256-bit) | 32 bytes | Slow (~3ms) | 4,627 bytes | Maximum security requirements |

**Implementation Strategy:**
1. **Default:** ML-DSA-44 for all new credentials
2. **Configuration:** Allow users/RPs to request higher security levels
3. **Detection:** Algorithm byte in credential ID enables automatic variant selection

**Rationale:**
- ML-DSA-44 provides adequate quantum security for most use cases
- All variants use same 32-byte seed (no storage penalty)
- Algorithm byte allows seamless support for all three levels
- Users can upgrade security level without code changes

---

## 5. Implementation Phases

### Phase 1: Foundation (Week 1-2)
- [ ] Add `_derive_mldsa_seed()` function to authenticator.py using HKDF
- [ ] Replace `_get_credential_id_bytes()` with ML-DSA implementation
- [ ] Write unit tests for seed derivation with test vectors
- [ ] Remove EC256 credential generation code

**Deliverables:**
- Working seed derivation function
- Unit tests with 100% coverage
- Documentation of HKDF parameters

### Phase 2: Core Integration (Week 3-4)
- [ ] Replace `_get_key_pair_from_credential_id()` with ML-DSA implementation
- [ ] Update passkey_device.py to use ML-DSA by default
- [ ] Add configuration option for algorithm selection (44/65/87)
- [ ] Remove all EC256 key loading code

**Deliverables:**
- End-to-end ML-DSA credential creation and authentication
- Configuration system for algorithm selection
- Clean codebase with no EC256 remnants

### Phase 3: Testing & Validation (Week 5-6)
- [ ] Unit tests for all ML-DSA functions
- [ ] Integration tests with FIDO2 protocol (makeCredential + getAssertion)
- [ ] Test all three ML-DSA variants (44/65/87)
- [ ] Performance benchmarks on target hardware
- [ ] Security review of seed derivation implementation

**Deliverables:**
- Comprehensive test suite
- Performance benchmark report
- Security review documentation

### Phase 4: Deployment (Week 7-8)
- [ ] Update user documentation with ML-DSA information
- [ ] Deploy to test environment
- [ ] Monitor authentication success rates
- [ ] Collect performance metrics

**Deliverables:**
- Updated documentation
- Deployment guide
- Performance metrics report

**Note:** This is a breaking change - existing EC256 credentials will not work after migration.

---

## 6. Security Considerations

### ✅ Strengths
- NIST FIPS 204 approved algorithm (ML-DSA)
- Deterministic key generation is standard practice per FIPS 204
- HKDF provides cryptographic separation between master secret and seeds
- Quantum-resistant digital signatures
- 32-byte seed provides 256-bit entropy
- AES-GCM authenticated encryption protects seed confidentiality and integrity

### ⚠️ Risks & Mitigations

1. **Seed compromise = key compromise**
   - Risk: If seed is leaked, attacker can regenerate private key
   - Mitigation: AES-256-GCM encryption, secure passkey file storage
   - Impact: Same risk as legacy EC256 implementation
   
2. **Master secret is classical EC256**
   - Risk: CA key uses classical cryptography to derive quantum-safe seeds
   - Mitigation: Consider separate ML-DSA master key in future phase
   - Impact: Low - attacker needs both quantum computer AND compromised CA key
   
3. **Side-channel attacks during key regeneration**
   - Risk: Timing/power analysis during ML-DSA key generation
   - Mitigation: liboqs uses constant-time implementations
   - Impact: Low - key generation happens in secure environment

4. **Replay attacks**
   - Risk: Reuse of old credentials
   - Mitigation: FIDO2 protocol includes challenge-response, not affected by PQC
   - Impact: None - existing FIDO2 protections apply

### 🔒 Security Properties

**Confidentiality:**
- Seed encrypted with AES-256-GCM
- Master secret protected in passkey file
- Private keys never stored, only regenerated on-demand

**Integrity:**
- GCM authentication tag prevents tampering
- HKDF ensures seed derivation integrity
- ML-DSA signatures provide authentication

**Availability:**
- Deterministic regeneration ensures keys always recoverable from seed
- No key storage means no key loss risk

---

## 7. Performance Considerations

**Key regeneration overhead:**
- ML-DSA-44: ~1-2ms per authentication
- ML-DSA-65: ~2-3ms per authentication
- ML-DSA-87: ~3-4ms per authentication

**Impact Analysis:**
- ✅ Acceptable for FIDO2 use case (user authentication is not latency-critical)
- ✅ Negligible compared to network round-trip times (50-200ms)
- ✅ User won't notice the difference

**Comparison:**
- EC256 key loading: ~0.1ms (from encrypted storage)
- ML-DSA-44 regeneration: ~1-2ms (10-20x slower, but still fast)
- Total authentication time: Dominated by user interaction and network latency

---

## 8. Dependency Management

**Dependencies for ML-DSA:**
- ✅ Already have: `oqs` (liboqs) - provides ML-DSA implementation
- ✅ No new dependencies required!

**License:**
- liboqs: MIT License (permissive, compatible)

**Maintenance Status:**
- liboqs: Actively maintained by Open Quantum Safe project
- NIST FIPS 204 compliant implementation
- Regular security updates

---

## 9. References

### Standards
- [NIST FIPS 204: ML-DSA Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf) - Primary reference
- [NIST FIPS 203: ML-KEM Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) - For comparison
- [IETF Draft: Streamlined NTRU Prime](https://www.ietf.org/archive/id/draft-josefsson-ntruprime-streamlined-00.html) - Alternative considered

### Implementation
- [liboqs Documentation](https://github.com/open-quantum-safe/liboqs) - ML-DSA implementation used
- [Open Quantum Safe Project](https://openquantumsafe.org/) - PQC library ecosystem
- [RFC 5869: HKDF](https://datatracker.ietf.org/doc/html/rfc5869) - Key derivation function

### FIDO2 Specifications
- [FIDO2 CTAP Specification](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html)
- [WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)

---

## 10. Conclusion

ML-DSA seed-based deterministic key derivation is the **optimal solution** for implementing post-quantum cryptography in FIDO2 authenticators. This strategy:

- ✅ Fits comfortably within 1024-byte credential ID limit (~70 bytes vs ~158 bytes for EC256)
- ✅ Uses NIST FIPS 204 approved standard
- ✅ Provides quantum-resistant digital signatures
- ✅ Leverages existing `load_mldsa_key()` implementation
- ✅ Supports all three ML-DSA security levels (44/65/87)
- ✅ No new dependencies required (uses existing liboqs)
- ✅ Clean migration path with no legacy code

**Key Advantages over Alternatives:**
- **vs NTRUPrime:** ML-DSA is NIST standardized, smaller seed (32 vs 64 bytes)
- **vs ML-KEM:** ML-DSA is purpose-built for signatures (FIDO2's use case)
- **vs Falcon:** ML-DSA has simpler implementation, no floating-point operations
- **vs Direct Encryption:** 97% size reduction (70 bytes vs 2,597 bytes)

**Implementation Readiness:**
- 🟢 Algorithm selection: ML-DSA-44 default, support all variants
- 🟢 Performance: 1-4ms acceptable latency
- 🟢 Dependencies: No new dependencies needed
- 🟢 Migration: Direct replacement, no backwards compatibility

**Next Steps:**
1. Begin Phase 1 implementation (seed derivation)
2. Implement Phase 2 integration (credential ID generation/reconstruction)
3. Execute Phase 3 testing and validation
4. Deploy Phase 4

**Timeline:** 8 weeks to production-ready implementation

**Breaking Change Notice:** This is a complete migration - existing EC256 credentials will not work after deployment. Users will need to re-register their credentials.

---

*Document Version: 2.0*  
*Last Updated: 2026-03-19*  
*Author: Analysis by Bob (AI Assistant)*