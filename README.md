# Soft FIDO2 Authenticator

A software-based FIDO2/WebAuthn passkey authenticator implemented in python. This project lets you use passwordless authentication (passkeys) on websites and applications without needing a physical USB security key.

This software implements the [W3C WebAuthn specification](https://www.w3.org/TR/webauthn/) and CTAP2 protocol, allowing your Linux system to act as a passkey authenticator.

Origianlly this code base was used as a test harness for a FIDO2 Relying Party implementation, however it has grown to support a large numbr of use cases. The authentictor is capable of generating all attestation formats, including TPM, Anndroid Keystore / SafetyNet, and even compound attestation statements. Some of the PKI/X509 requirements for these scenario's are quire complex and strict.

## Use Cases

- **Testing and Development**: Test FIDO2/WebAuthn implementations without physical hardware.  Supports various attestation formats for compatibility testing
- **Daily Use**: Use passkeys for authentication on Linux systems/applications which support USB FIDO2/passkey authenticators.

> **Note**: This is experimental software. Use at your own risk, especially for production systems.

## Quick Start


### Dependencies
- **Python**: 3.9 or higher
- **OpenSSL**: 3.2+ with ML-DSA support (for post-quantum cryptography support)
- **tpm2-tss-devel**: TPM2 development headers (for TPM2 support)
- **tpm2-pytss**: TPM2 Python bindings (system package recommended - see note below)

Automatically installed with pip:
- `asn1 >= 2.2.0`
- `cryptography >= 47.0.0` (ML-DSA support added in v47)
- `cbor2 >= 4.1.2`
- `PyJWT >= 0.6.1`

**Note on ML-DSA Support**: Post-quantum cryptography (ML-DSA) requires:
- Python `cryptography` library v47.0.0 or higher
- OpenSSL 3.2+ compiled with ML-DSA support enabled
- If ML-DSA is not available, the authenticator will still work with traditional algorithms (RSA, ECDSA, Ed25519)

### Installation

Install via pip:

```bash
pip3 install soft_fido2
```

### Using as a Python Module

```python
from soft_fido2 import Fido2Authenticator

# Create an authenticator instance
authenticator = Fido2Authenticator()

# Register with a website (attestation/registration)
attestation_options = {
  "rp": {
    "id": "www.myrp.ibm.com",
  },
  "user": {
    "id": "rOIpHRr9St-YqugsfyZgAw",
    "name": "testuser",
    "displayName": "testuser"
  },
  "timeout": 60000,
  "challenge": "Vi6gvN2yIvNRL9KVwo8FtR-fH3gR92LwCtneQueyawY",
  "excludeCredentials": [],
  "extensions": {},
  "authenticatorSelection": {
    "userVerification": "preferred"
  },
  "attestation": "direct",
  "pubKeyCredParams": [
    {
      "alg": -7,
      "type": "public-key"
    }
  ],
}

attestation_response = authenticator.credential_create(attestation_options, atteStmtFmt='packed-self')
print(json.dumps(attestation_response, indent=4)) # print not required but useful for debugging

rp_response = requests.post("https://www.myrp.ibm.com/attestation/result",
                        json=attestation_response)

##Assertion
assertion_options = {
  "rpId": "www.myrp.ibm.com",
  "timeout": 60000,
  "challenge": "kI9SKJRxv4zpICnG1Ls9FMwQ4t4Zq6t8HqKAJKzeyXI",
  "extensions": {},
}

# Get assertion (authentication)
auth_response = authenticator.credential_request(assertion_options)
print(json.dumps(assertion_response, indent=4))
```

### Testing with python-fido2 server library

For a simple testing environment, you can use the `python-fido2` library which provides a complete FIDO2 server implementation:

```python
from soft_fido2 import Fido2Authenticator
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity

# Initialize FIDO2 server
rp = PublicKeyCredentialRpEntity(id="example.com", name="Example RP")
server = Fido2Server(rp)

# Create user
user = PublicKeyCredentialUserEntity(
    id=b"user_id_123",
    name="testuser@example.com",
    display_name="Test User"
)

# Registration (Attestation)
attestation_options, state = server.register_begin(user)
attestation_options = dict(attestation_options)['publicKey']

# Create authenticator and generate credential
authenticator = Fido2Authenticator()
attestation_response = authenticator.credential_create(attestation_options)

# Verify registration with server
response = {
    'id': attestation_response['id'],
    'rawId': attestation_response['rawId'],
    'response': {
        'clientDataJSON': attestation_response['response']['clientDataJSON'],
        'attestationObject': attestation_response['response']['attestationObject']
    },
    'type': 'public-key'
}

auth_data = server.register_complete(state, response)
print(f"Registration successful! Credential ID: {auth_data.credential_data.credential_id.hex()}")

# Authentication (Assertion)
assertion_options, state = server.authenticate_begin()
assertion_options = dict(assertion_options)['publicKey']

# Generate authentication response
assertion_response = authenticator.credential_request(assertion_options)

# Verify authentication with server
response = {
    'id': assertion_response['id'],
    'rawId': assertion_response['rawId'],
    'response': {
        'clientDataJSON': assertion_response['response']['clientDataJSON'],
        'authenticatorData': assertion_response['response']['authenticatorData'],
        'signature': assertion_response['response']['signature']
    },
    'type': 'public-key'
}

server.authenticate_complete(state, [auth_data.credential_data], response)
print("Authentication successful!")
```

### Using from Command Line

1. Create a directory for your passkey files:

```bash
mkdir -p ~/.fido2
export FIDO_HOME="$HOME/.fido2"
```

2. The authenticator will automatically create encrypted passkey files in this directory when you register with websites.

> [!NOTE]
> The authenticator requires the `FIDO_HOME` environment variable to be set to read and write private key files.


#### Registration (Attestation)

```bash
# Create a registration response
python3 -m soft_fido2.authenticator attestation packed-self '{
  "rp": {
    "id": "www.myrp.ibm.com",
    "name": "ISAM_Unit_test"
  },
  "user": {
    "id": "3RH-c7d8Ss60BKau7mLKXA",
    "name": "testuser",
    "displayName": "testuser"
  },
  "timeout": 60000,
  "challenge": "mjqlXDT4RySLMyRCEePZgHpbgRCkFq9Gip4apBxcvTg",
  "excludeCredentials": [],
  "extensions": {},
  "authenticatorSelection": {
    "userVerification": "preferred"
  },
  "attestation": "direct",
  "pubKeyCredParams": [
    {
      "alg": -7,
      "type": "public-key"
    }
  ]
}'
```
Response:
```bash
 {
   "id": "EyOlQBLvCZUK96Z9DpCKYBw_aLOh4FikSd3h-1fKukk=",
   "rawId": "EyOlQBLvCZUK96Z9DpCKYBw_aLOh4FikSd3h-1fKukk=",
   "response": {
     "clientDataJSON": "eyJvcmlnaW4iOiAiaHR0cHM6Ly93d3cubXlpZHAuaWJtLmNvbSIsICJjaGFsbGVuZ2UiOiAiVmk2Z3ZOMnlJdk5STDlLVndvOEZ0Ui1mSDNnUjkyTHdDdG5lUXVleWF3WT0iLCAidHlwZSI6ICJ3ZWJhdXRobi5jcmVhdGUifQ==",
     "attestationObject": "o2hhdXRoRGF0YVkBbi-RrhkzFXpmZDWmVjlcmnlaWE_ET4cAHsNcOr-craCzRQAAAAAAAAAAAAAAAAAAAAAAAAAAACATI6VAEu8JlQr3pn0OkIpgHD9os6HgWKRJ3eH7V8q6SaRhMQNhMzkBAGItMVkBANNSB4BmS7RVWYwmuTyQmkmOZjiULIEgU_YpmgYX2yxTDgwf36TEwZDuoq-dfJiKGyPux5hnPSNia0iYGR8ABtO5pt9Ay5fHiHQ9Io5qcXw29gm8VPdHJhvcc0hMtctTCWy87QXiaI85MP-Uxd6fdEcGySnmhlUBjR5REJY89bql4BYLoK8wR90bohppGT0Dxh3kwY6QpXdZFVek2aGKA7YF4IM0lquRqMSvy9b_j2tl7NvNcoAU_-Kv-UufpyFqvWn1psjUMFyUvTBeP5dH_VWuuIINnbrgYuloei3IlA6DjIu7dvMuExXpFTTbILnstvOJGkrofboB8ELPnYK87P1iLTJEAAEAAWNmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzkBAGNzaWdZAQBPiPQ22-D-hqHKBDGtp6qKo8PuIttaD9qvXLU6IsfYVK9xUban1teHTqfCZ6bvubnSQc7SzR-DmrAGh4GvQA38ag__W-3uWQ3x2el_dvIWd5fZRtbYuf0n7v4WCIHru79AyIaNszECOIZu--0QoWRbrmcpjgsDQbS6Rm3eqqczKAWHUWAJuKtCp1Evv1V3ChYSmpMIKBTvDmOltF1YncY6goCt-Xa3auWm9VwbXi6LH_wAtSWCLrdyp6VcIS8n7w9m7fTiGALIi_y1xaiVJz5U5rYlHpTElKTvI4ceO23mlEqgi_O9Pfqg8dA1ejXxpc4yvTTMaihbZq_vtEgMup4h"
   },
   "type": "public-key",
   "getClientExtensionResults": "oA==",
   "nickname": "some_name"
}
```
#### Authentication (Assertion)

```bash
# Create an authentication response
python3 -m soft_fido2.authenticator assertion '{
  "rpId": "www.myrp.ibm.com",
  "timeout": 60000,
  "challenge": "kI9SKJRxv4zpICnG1Ls9FMwQ4t4Zq6t8HqKAJKzeyXI",
  "extensions": {},
}'
```

Response:

```bash
 {
     "id": "EyOlQBLvCZUK96Z9DpCKYBw_aLOh4FikSd3h-1fKukk=",
     "rawId": "EyOlQBLvCZUK96Z9DpCKYBw_aLOh4FikSd3h-1fKukk=",
     "response": {
         "clientDataJSON": "eyJvcmlnaW4iOiAiaHR0cHM6Ly93d3cubXlpZHAuaWJtLmNvbSIsICJjaGFsbGVuZ2UiOiAia0k5U0tKUnh2NHpwSUNuRzFMczlGTXdRNHQ0WnE2dDhIcUtBSkt6ZXlYST0iLCAidHlwZSI6ICJ3ZWJhdXRobi5nZXQifQ==",
         "authenticatorData": "L5GuGTMVemZkNaZWOVyaeVpYT8RPhwAew1w6v5ytoLMFAAAAAA==",
         "signature": "Tn1J7kTWVL_MmSVimB95r7MDhG8T18pm-CD7TQn5dsbcTec6M8E_4-TFS-U3xto6bYlmciw8YYXpINCag0KetdnCMhm0D23ElcUGcEbdJmpzuMdotjW6AZRnLMe6aZU7uSyzwvcustYeKlAtSziSAw7qHL4ucnJYQZhsaCpya325UgpNshAHXcG3an_nRbogvKd__zjg3Fr-2qltP8r9CneuOSpphnBTWTmNk8cC16Nluhi81rugjlMdDgP6_pyYcpxSR1FVN_fJnnqmwRyundR29C-SCe3-NGHcgKOdeZf6izpw1FXfET4LRKpxoPiIApWLGb7tg6jIVQieT_QXsQ=="
     },
     "type": "public-key"
 }
```

## Environment properties

### FIDO_HOME Directory

The `FIDO_HOME` directory stores your encrypted passkey files (`.passkey` files). Each file contains:
- Private keys for authentication
- Credential metadata
- User information

These files are encrypted and protected by your system.

```bash
export FIDO_HOME="$HOME/.fido2"
```

#### SOFT_FIDO2_SKIP_UP (Optional)
Skip user presence checks during authentication (for testing only).

```bash
export SOFT_FIDO2_SKIP_UP=true
```

#### SOFT_FIDO2_DEBUG_LEVEL (Optional)
Set logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR`

```bash
export SOFT_FIDO2_DEBUG_LEVEL=DEBUG
```

#### SOFT_FIDO2_LOG_FILE (Optional)
Log file path (relative to `FIDO_HOME`). Defaults to stdout.

```bash
export SOFT_FIDO2_LOG_FILE=authenticator.log
```

## Biometric Authentication

The authenticator supports fingerprint verification via Linux's fprintd D-Bus service, providing seamless user presence verification without GUI prompts.

**Note**: The fprintd command-line tools (fprintd-verify, etc.) are D-Bus clients themselves. If the D-Bus daemon is unavailable, the CLI tools will also fail. The system gracefully falls back to GUI prompts when fprintd is not available.

### Requirements

- `fprintd` daemon running
- Fingerprint scanner hardware
- Enrolled fingerprints: `fprintd-enroll <username>`
- Optional: `dbus-python` and `PyGObject` packages (see installation below)

### Installation

```bash
# Install with fprintd biometric support
pip install soft-fido2[bio]

# Install with TPM support
pip install soft-fido2[tpm]

# Install with both biometric and TPM
pip install soft-fido2[full]

# Or install fprintd system package
sudo apt install fprintd  # Debian/Ubuntu
sudo dnf install fprintd  # Fedora
```

### Configuration

Environment variables control biometric behavior:

```bash
# Timeout in seconds for fingerprint scan (default: 15)
export SOFT_FIDO2_FPRINT_TIMEOUT=15

# Maximum retry attempts for failed scans (default: 3)
export SOFT_FIDO2_FPRINT_RETRIES=3
```

### Troubleshooting

**Fingerprint not detected:**
```bash
# Check fprintd daemon status
systemctl status fprintd

# List enrolled fingerprints
fprintd-list $USER

# Enroll a new fingerprint
fprintd-enroll $USER
```

**D-Bus connection errors:**
```bash
# Verify D-Bus session is running
echo $DBUS_SESSION_BUS_ADDRESS

# Test fprintd availability
dbus-send --system --print-reply \
  --dest=net.reactivated.Fprint \
  /net/reactivated/Fprint/Manager \
  net.reactivated.Fprint.Manager.GetDefaultDevice
```

**Falls back to GUI despite fingerprint hardware:**
- Check `dbus-python` is installed: `python3 -c "import dbus"`
- Check `PyGObject` is installed: `python3 -c "from gi.repository import GLib"`
- Verify fprintd daemon is running: `systemctl status fprintd`
- Check logs: `journalctl -u fprintd -f`

## Advanced Usage
Advanced users can use the `soft-fido2` module to provide passkey authentication to 
applications that support USB HID authenticators.

### OS Integration with UHID

For system-wide passkey support, integrate the authenticator as a virtual USB device using UHID (User-space HID).

#### Prerequisites

- UHID kernel module
- Root or appropriate permissions for `/dev/uhid`
- install soft dependencies
  - Qt6
  - PyQt6
  - dbus-python (for interactive desktop notifications)

#### Setup

1. **Configure UHID permissions:**

```bash
# Load UHID module at boot
echo 'uhid' | sudo tee /etc/modules-load.d/uhid.conf

# Create uhid group (must be a system group for udev rules)
sudo groupadd -r uhid
sudo usermod -aG uhid $USER

# Set permissions
echo 'KERNEL=="uhid", GROUP="uhid", MODE="0660"' | sudo tee /etc/udev/rules.d/10-uhid.rules

# Apply changes
sudo udevadm control --reload-rules && sudo udevadm trigger
```

2. **Create encryption key:**

```bash
mkdir -p $HOME/.fido2
openssl ecparam -name prime256v1 -genkey -noout -out $HOME/.fido2/platform.key
```

3. **Install as systemd user service:**

```bash
# Create virtual environment in /opt
sudo mkdir -p /opt/soft_fido2
sudo chown $USER:$USER /opt/soft_fido2
virtualenv /opt/soft_fido2
/opt/soft_fido2/bin/python -m pip install --upgrade pip soft_fido2

# Create passkey storage directory
mkdir -p $HOME/.fido2

# Create environment file
echo "FIDO_HOME=${HOME}/.fido2" > /opt/soft_fido2/passkey.env

# Create user service directory
mkdir -p ~/.config/systemd/user

# Create systemd user service
tee ~/.config/systemd/user/passkey.service > /dev/null <<'EOF'
[Unit]
Description=Software FIDO2 Passkey Authenticator
PartOf=graphical-session.target
After=graphical-session.target

[Service]
Type=simple
ExecStart=/opt/soft_fido2/bin/python -m soft_fido2
Restart=on-failure
RestartSec=5
EnvironmentFile=/opt/soft_fido2/passkey.env
TimeoutStopSec=10
KillMode=mixed

[Install]
WantedBy=graphical-session.target
EOF

# Enable and start user service
systemctl --user daemon-reload
systemctl --user enable passkey
systemctl --user start passkey

# Check service status
systemctl --user status passkey
```

**Important Notes for User Services:**
- **User services run in your graphical session** - they start when you log in and stop when you log out
- **Requires `/dev/uhid` access** - ensure you're in the `uhid` group (log out/in after adding)
- **Service management commands:**
  - Check status: `systemctl --user status passkey`
  - View logs: `journalctl --user -u passkey -f`
  - Stop service: `systemctl --user stop passkey`
  - Restart service: `systemctl --user restart passkey`
  - Disable autostart: `systemctl --user disable passkey`

**Troubleshooting User Service Issues:**
- **GUI dialogs don't appear**: Ensure `graphical-session.target` is active: `systemctl --user list-units --type=target | grep graphical`
- **Service times out on stop**: The service includes `TimeoutStopSec=10` for graceful shutdown
- **Permission denied on /dev/uhid**: Run `groups` to verify you're in the `uhid` group, then log out and back in

4. **Verify the authenticator:**

```bash
# Check if the HID device is registered
hexdump -C "/sys/bus/hid/devices/$(ls /sys/bus/hid/devices | grep 1337:1337)/report_descriptor"
```

Expected output:
```
00000000  06 d0 f1 09 01 a1 01 09  20 15 00 26 ff 00 75 08  |........ ..&..u.|
00000010  95 40 81 02 09 21 15 00  26 ff 00 75 08 95 40 91  |.@...!..&..u..@.|
00000020  02 c0                                             |..|
```

### USB/IP Integration (Alternative)

For remote or networked authenticator access, you can use the USB/IP transport instead of UHID. This allows the authenticator to be accessed over the network without requiring kernel driver access.

#### Transport Selection

The authenticator now supports multiple transport layers via command-line flags:

```bash
# Run with UHID transport (default, requires /dev/uhid)
python -m soft_fido2
python -m soft_fido2 --transport uhid

# Run with USB/IP transport (network-based, requires vhci driver on client)
python -m soft_fido2 --transport usbip

# Run USB/IP on custom port
python -m soft_fido2 --transport usbip --port 3240

# Run in headless mode (no system tray)
python -m soft_fido2 --transport usbip --no-systray
```

#### USB/IP Server Setup

1. **Start the USB/IP server:**

```bash
# Using the main module with transport flag (recommended)
python -m soft_fido2 --transport usbip

# Or run the USB/IP module directly
python -m soft_fido2.usbip_device
# or
python soft_fido2/usbip_device.py
```

2. **Connect from client machine:**

```bash
# Load the vhci-hcd kernel module
sudo modprobe vhci-hcd

# List available USB/IP devices on the server
sudo usbip list -r <SERVER_IP>

# Attach the FIDO2 authenticator device
sudo usbip attach -r <SERVER_IP> -b 1-1.1

# Verify the device is attached
lsusb -v -d 3713:3713
```

#### Architecture Notes

The USB/IP implementation has been refactored for better maintainability:

- **`usbip_device.py`**: Contains all USB/IP protocol handling and CTAPHID frame processing in the `CTAP2USBIPDevice` class
- **`passkey_device.py`**: Contains CTAP2 business logic and command processing (shared by both UHID and USB/IP transports)
- **`ctaphid_protocol.py`**: Transport-agnostic CTAPHID packet structures
- **`__main__.py`**: Unified entry point with `--transport` flag for selecting UHID or USB/IP

This architecture eliminates code duplication and makes it easy to add new transport layers (e.g., BLE, NFC) in the future.

#### USB/IP vs UHID

**Use USB/IP when:**
- You need remote/networked authenticator access
- You are running in an OS that does not support the uhid kernel module
- You need to share one authenticator across multiple machines

**Use UHID when:**
- You want system-wide local integration
- You need the authenticator to appear as a native USB device
- You want the best performance and lowest latency
- You're setting up a permanent installation on a single machine

## Utility Scripts

The `util/` directory contains helper scripts:

### Generate Passkey

```bash
./util/generate_passkey.sh
```

Creates a new passkey file in `$FIDO_HOME`.

### Manage Credentials

```bash
python util/manage_creds.py
```

View and manage resident credentials (passwordless authentication).

### Verify Passkey

```bash
./util/verify_passkey.sh <passkey_file>
```

Verify the integrity of a passkey file.

## Development

### Local Development Setup

```bash
# Set up environment
export FIDO_HOME="$HOME/.fido2"
mkdir -p $FIDO_HOME

# Create virtual environment
virtualenv $FIDO_HOME
$FIDO_HOME/bin/python -m pip install --upgrade pip

# Install development dependencies
$FIDO_HOME/bin/python -m pip install -r dev-requirements.txt

# Build and install
export GITHUB_RUN_NUMBER=9999
$FIDO_HOME/bin/python -m build
$FIDO_HOME/bin/python -m pip install dist/soft_fido2-*-py3-none-any.whl

# Run the authenticator
$FIDO_HOME/bin/python -m soft_fido2
```

### Running Tests

```bash
# Run unit tests
./tests/unit_test.sh

# Run scenario tests
./tests/scenario_test.sh
```

### TPM2 Library Installation Note

The `tpm2_pytss` package may fail to build in virtual environments due to compatibility issues. If you encounter build errors:

**Recommended Solution:**
1. Install TPM2 development packages and `tpm2_pytss` via your system package manager first:
   ```bash
   # Fedora/RHEL
   sudo dnf install tpm2-tss-devel python3-tpm2-pytss
   
   # Ubuntu/Debian
   sudo apt install libtss2-dev python3-tpm2-pytss
   ```

2. Enable system site packages access in your virtual environment:
   ```bash
   # Create a virtual environment with system site packages access:

   virtualenv --system-site-packages $FIDO_HOME
   ```

3. Verify TPM2 library is accessible:
   ```bash
   $FIDO_HOME/bin/python -c "import tpm2_pytss; print('TPM2 library available')"
   ```

**Alternative Solution (Manual Copy):**
If you need an isolated virtual environment without system site packages, you can manually copy the TPM libraries:
```bash
# After installing system package, copy to venv
cp -r /usr/lib64/python3.*/site-packages/tpm2_pytss $FIDO_HOME/lib/python3.*/site-packages/
cp -r /usr/lib64/python3.*/site-packages/tpm2_pytss*.dist-info $FIDO_HOME/lib/python3.*/site-packages/
```

**Maybe Why This Happens:**
The `tpm2_pytss` package uses CFFI to build native extensions. GCC 15 introduced `nullptr_t` in `stddef.h`, which older versions of `pycparser` cannot parse. The system packages are pre-built and avoid this compilation issue.

### D-Bus Python Library Installation Note

The `dbus-python` package is an optional dependency that enables interactive desktop notifications with clickable action buttons. If not installed, the authenticator will fall back to Qt-based system tray notifications (without interactive buttons).

**Recommended Solution:**
1. Install `dbus-python` via your system package manager:
   ```bash
   # Fedora/RHEL
   sudo dnf install python3-dbus
   
   # Ubuntu/Debian
   sudo apt install python3-dbus
   
   # Arch Linux
   sudo pacman -S python-dbus
   
   # openSUSE
   sudo zypper install python3-dbus
   ```

2. Then create your virtual environment with system site packages access:
   ```bash
   virtualenv --system-site-packages $FIDO_HOME
   ```

**Alternative Solution (pip install):**
If you prefer to install via pip in an isolated virtual environment:
```bash
# Install system dependencies first
# Fedora/RHEL
sudo dnf install dbus-devel python3-devel

# Ubuntu/Debian
sudo apt install libdbus-1-dev python3-dev

# Then install via pip
pip install dbus-python
```

**Why D-Bus Notifications?**
- **Interactive buttons**: Accept/Decline authentication requests directly from notifications
- **Better UX**: No subprocess overhead, direct communication with notification daemon
- **Fingerprint fallback**: Provides UI when biometric authentication is unavailable
- **Standard protocol**: Works across all major Linux desktop environments (GNOME, KDE, XFCE, etc.)

**Graceful Degradation:**
If `dbus-python` is not available, the authenticator automatically falls back to Qt system tray notifications. Interactive features (clickable buttons) will not be available in fallback mode.

## Troubleshooting

### Common Issues

**"FIDO_HOME not set" error:**
```bash
export FIDO_HOME="$HOME/.fido2"
mkdir -p $FIDO_HOME
```

**Permission denied on `/dev/uhid`:**
- Ensure you're in the `udev` group
- Log out and back in after adding yourself to the group
- Check udev rules are properly configured

**No system tray icon on GNOME:**
- Install the AppIndicator extension
- Restart GNOME Shell (Alt+F2, type 'r', press Enter)

**Passkey not recognized by browser:**
- Ensure the UHID service is running: `systemctl status passkey`
- Check the HID device is registered: `ls /sys/bus/hid/devices/ | grep 1337`
- Verify browser supports WebAuthn (Chromium, Firefox, Edge all support it)

## Security Considerations

- Passkey files are encrypted but stored on disk
- The `SOFT_FIDO2_SKIP_UP` option bypasses user checks - use only for testing
- For production use, ensure proper file permissions on `$FIDO_HOME`
- This is experimental software - review the code before using for sensitive accounts

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

## Support

For issues, questions, or contributions, please use the project's issue tracker.
