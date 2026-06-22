# Platform Passkey
This document will giude a user through the requirements to use this python module as a system (platform) passkey authenticator; which emualtes an HID device; using the UHID kernel module.

At a high level this requires the following setup:
- UHID module loaded at boot with rw permissions for users set with udev rule
- soft_fido2 installed (with UX,tpm,biometric support)
  - Typically this requires **both** the system level bindings + the python API wrapper modules
- FIDO_HOME directory set
- User systemd service to start the passkey service when the user logs in to a graphical TTY

## System Setup

### FIDO_HOME Directory

The `FIDO_HOME` directory stores your encrypted passkey files (`.passkey` files). Each file contains:
- Private keys for authentication
- Credential metadata
- User information

These files are encrypted and protected by your system.

```bash
export FIDO_HOME="$HOME/.fido2"
```
### Environment properties
These properties are typically stored in `$FIDO_HAME/passkey.env` and are loaded by the systemd service.

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
### Biometric Authentication

The authenticator supports fingerprint verification via Linux's fprintd D-Bus service, providing user presence verification without system notifications.

**Note**: The passkey gracefully falls back to GUI prompts when fprintd is not available.

#### Requirements

- `fprintd` daemon running
- Fingerprint scanner hardware
- Enrolled fingerprints: `fprintd-enroll <username>`

#### Installation

Install the required system packages:

```bash
# Install fprintd system package
sudo apt install fprintd  # Debian/Ubuntu
sudo dnf install fprintd  # Fedora
```

Then install the package with the required target:

```bash
# Install with fprintd biometric support
pip install soft-fido2[bio]

# Install with full target
pip install soft-fido2[full]
```

#### Configuration

Environment variables control biometric behavior:

```bash
# Timeout in seconds for fingerprint scan (default: 15)
export SOFT_FIDO2_FPRINT_TIMEOUT=15

# Maximum retry attempts for failed scans (default: 3)
export SOFT_FIDO2_FPRINT_RETRIES=3
```

#### Troubleshooting

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


### Trusted Platform Module Key Storage:

The `tmp2_pytss` package provies a python API wrapper to the system TPM 2.0 library. This stack is required if you want to store the platform key in the TPM enclave attached to your device.

The `tpm2_pytss` package may fail to build in virtual environments due to system compatibility issues. If you encounter build errors:

**Recommended Install:**
1. Install TPM2 development packages and `tpm2_pytss` via your system package manager first:
   ```bash
   # Fedora/RHEL
   sudo dnf install tpm2-tss-devel python3-tpm2-pytss
   
   # Ubuntu/Debian
   sudo apt install libtss2-dev python3-tpm2-pytss
   ```

2. Enable system site packages access in your virtual environment (if required):
   ```bash
   # Create a virtual environment with system site packages access:

   virtualenv --system-site-packages $FIDO_HOME
   ```

3. Verify TPM2 library is accessible:
   ```bash
   python -c "import tpm2_pytss; print('TPM2 library available')"
   ```

**Alternative Solution (Manual Copy):**
If you need an isolated virtual environment without system site packages, you can manually copy the TPM libraries:
```bash
# After installing system package, copy to venv
cp -r /usr/lib64/python3.*/site-packages/tpm2_pytss $FIDO_HOME/lib/python3.*/site-packages/
cp -r /usr/lib64/python3.*/site-packages/tpm2_pytss*.dist-info $FIDO_HOME/lib/python3.*/site-packages/
```


### DBus Notifications:

The `dbus-python` package enables interactive desktop notifications with clickable action buttons. If not installed, the authenticator will fall back to Qt-based system tray notifications (without interactive buttons). DBus notifications are also used to request authentication ceremonies from the connected fingerprint device (biometric authentication).


**Recommended Install:**
1. Install `dbus-python` via your system package manager:
   ```bash
   # Fedora/RHEL
   sudo dnf install python3-dbus
   
   # Ubuntu/Debian
   sudo apt install python3-dbus
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

**Graceful Degradation:**
If `dbus-python` is not available, the authenticator automatically falls back to Qt system tray notifications. Interactive features (clickable buttons) will not be available in fallback mode.


### UHID kernel module and UDEV rules:

**Load UHID kernel module during boot:**

```bash
# Load UHID module at boot
echo 'uhid' | sudo tee /etc/modules-load.d/uhid.conf
```

**Create UHID group and UDEV set permissions:**

```bash
# Create uhid group (must be a system group for udev rules)
sudo groupadd -r uhid
sudo usermod -aG uhid $USER

# Set permissions
echo 'KERNEL=="uhid", GROUP="uhid", MODE="0660"' | sudo tee /etc/udev/rules.d/10-uhid.rules

# Apply changes
sudo udevadm control --reload-rules && sudo udevadm trigger
```


### User Systemd Service:
Create a systemd user service for the passkey authenticator.

```bash
# Install soft_fido2
pip install soft_fido2
# Create passkey storage directory
mkdir -p $HOME/.fido2
# Create environment file
echo "FIDO_HOME=${HOME}/.fido2" > $HOME/.fido2/passkey.env
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
ExecStart=/usr/bin/python -m soft_fido2
Restart=on-failure
RestartSec=5
EnvironmentFile=%h/.fido2/passkey.env
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



## Verification

4. **Verify the authenticator:**
Connect to the authenticator's hid file descriptor and read the device descriptor:


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





## Alternative model: USB/IP Integration

The authenticator also provide a USB/IP implementation. this may be useful in environments which do not support the UHID kernel module but do have access the VHCI kernel module.

```bash
modprob vhci
```

### Transport Selection

The authenticator supports multiple transport layers via command-line flags:

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

### USB/IP Server Start-up

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