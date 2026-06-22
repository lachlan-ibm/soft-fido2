# Soft FIDO2 Authenticator

A software-based FIDO2/WebAuthn passkey authenticator implemented in python. This project lets you use passwordless authentication (passkeys) on websites and applications without needing a physical USB security key.

This software implements the [W3C WebAuthn specification](https://www.w3.org/TR/webauthn/) and CTAP2 protocol, allowing your Linux system to act as a passkey authenticator.

Origianlly this code base was used as a test harness for a FIDO2 Relying Party implementation, however it has grown to support a large numbr of use cases. The authentictor is capable of generating all attestation formats, including TPM, Anndroid Keystore / SafetyNet, and even compound attestation statements. Some of the PKI/X509 requirements for these scenario's are quire complex and strict.

## Use Cases

- **Testing and Development**: Test FIDO2/WebAuthn implementations without physical hardware.  Supports various attestation formats for compatibility testing
- **Platform (OS) Authenticator**: Use passkeys for authentication on Linux systems/applications which support USB FIDO2/passkey authenticators.

> **Note**: This is experimental software. Use at your own risk.

## Quick Start

### System Dependencies
For some of the GUI features, you need to install additional system packages. The following packages are required for full functionality:
- **Python**: 3.10 or higher
- **OpenSSL**: 3.2+ with ML-DSA support (for post-quantum cryptography support)
- **tpm2-tss-devel**: TPM2 development headers (for TPM2 support)
- **tpm2-pytss**: TPM2 Python bindings (system package recommended - see note below)
- **dbus-devel**: D-Bus development headers (for D-Bus notifications)
- **dbus-glib-devel**: GLib development headers (for D-Bus support)
- **qt6**: Qt6 development headers (for Qt6 GUI bindings)


**Note on ML-DSA Support**: Post-quantum cryptography (ML-DSA) requires:
- Python `cryptography` library v47.0.0 or higher
- OpenSSL 3.2+ compiled with ML-DSA support enabled
- If ML-DSA is not available, the authenticator will still work with traditional algorithms (RSA, ECDSA, Ed25519)

### Installation

Install via pip:

```bash
pip3 install soft_fido2
```

Core python dependencies:
- `asn1 >= 2.2.0`
- `cryptography >= 47.0.0`
- `cbor2 >= 4.1.2`
- `PyJWT >= 0.6.1`

**Soft dependency targets**

```bash
# jeepney for dbus interfact to biometric device
pip3 install soft_fido2[bio]
# tpm2-pytss bindings
pip3 install soft_fido2[tpm]
# QT6 GUI
pip3 install soft_fido2[ux]
# All of the above
pip3 install soft_fido2[full]
```

## Module Usage

This module can be used to test WebAuthn Attestation and Assertion ceremonies. For information and examples on how to act as the client **or** authenticatior, see the [MODULE](MODULE.md) documentation.

A simple example of using this module to generate a self-signed attestation with an ES256 key:

```python
import soft_fido2, requests
attestation_options = requests.get("https://my.relying.party/attestation/options").json()
authenticator = soft_fido2.Fido2Authenticator()
attestation = authenticator.credential_create(attestation_options)
registration = requests.post("https://my.relying.party/attestation/result", json=attestation).json()
# Save the key
f = open("attestation.key", 'wb'); f.write(authenticator.kp.get_private_bytes()); f.close()
```

And to generate a self-signed assertion with the same key:

```python
import soft_fido2, requests
# Read the key
f = open("attestation.key", 'rb'); key = f.read(); f.close()
authenticator = soft_fido2.Fido2Authenticator(keyPair=soft_fido2.KeyPair.load_key_pair(key))
assertion_options = requests.get("https://my.relying.party/assertion/options").json()
assertion = authenticator.credential_request(assertion_options)
assertion_result = requests.post("https://my.relying.party/assertion/result", json=assertion).json()
```

## System Authenticator

This module can be run as main to provide a system CTAP2 authenticator service. This integrates with *nix systems via the UHID kernel module. For information on how to set up this python module as a system authenticator, see the [PASSKEY](PASSKEY.md) documentation.


## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Resources

- [W3C WebAuthn Specification](https://www.w3.org/TR/webauthn/)
- [FIDO Alliance CTAP 2 Specification](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.pdf)

## Support

For issues, questions, or contributions, please use the project's issue tracker.
