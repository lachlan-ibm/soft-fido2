
# Soft FIDO2 (passkey)
Software implementation of the W3 WebAuthn specification. Project attempts to emulate all
known attestation types.

Use at your own risk.

## Prerequisites:
### System
 * libnotify >= 0.8.7
 * bcrypt >= 1.1
 * python3-virtualenv >= 20.29.1
### Python
 * >= Python 3.7
### Pip modules
 * asn1 >= 2.2.0
 * cryptography >= 38.0.1 
 * cbor2 >= 4.1.2
 * PyJwt >= 0.6.1
 * PyQt6 >= 6.9.1
### For GNOME Users (Tested on GNOME 48)
 * AppIndicator and KStatusNotifierItem Support (https://extensions.gnome.org/extension/615/appindicator-support/)

## Usage
### Command line
Attestation:
 * Basic usage  
Module will look for a `.fido2` folder in the home directory of the user. If it does not exist then the module will return a non-zero exit code.
If the directory exists, the `soft_fido2` module will then generate a key if required to generate an `attestation type` attestation response to the given `attestation options`:
```bash
FIDO_HOME=$HOME/.fido2 python3 -m soft_fido2.authenticator attestation <attestation type> <attestation options>
```  
The following example takes a JSON dictionary of attestation options provided by a FIDO2 relying party (RP) and prints a dictionary to stdout which contains the authenticator's response to the attestation request. The example uses 'packed-self' as the attestation format. Other attestation formats are supported; however, there is more complex setup required generating the required trust anchors and uploading them to your relying party.


```bash
ATTESTATION_OPTIONS='{
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
    },
    {
      "alg": -35,
      "type": "public-key"
    },
    {
      "alg": -36,
      "type": "public-key"
    },
    {
      "alg": -257,
      "type": "public-key"
    },
    {
      "alg": -258,
      "type": "public-key"
    },
    {
      "alg": -259,
      "type": "public-key"
    },
    {
      "alg": -65535,
      "type": "public-key"
    }
  ],
  "status": "ok",
  "errorMessage": ""
}'

python3 python_authenticator/soft_fido2/authenticator.py 'attestation' 'packed-self' ${ATTESTATION_OPTIONS}
> {
>   "id": "EyOlQBLvCZUK96Z9DpCKYBw_aLOh4FikSd3h-1fKukk=",
>   "rawId": "EyOlQBLvCZUK96Z9DpCKYBw_aLOh4FikSd3h-1fKukk=",
>   "response": {
>     "clientDataJSON": "eyJvcmlnaW4iOiAiaHR0cHM6Ly93d3cubXlpZHAuaWJtLmNvbSIsICJjaGFsbGVuZ2UiOiAiVmk2Z3ZOMnlJdk5STDlLVndvOEZ0Ui1mSDNnUjkyTHdDdG5lUXVleWF3WT0iLCAidHlwZSI6ICJ3ZWJhdXRobi5jcmVhdGUifQ==",
>     "attestationObject": "o2hhdXRoRGF0YVkBbi-RrhkzFXpmZDWmVjlcmnlaWE_ET4cAHsNcOr-craCzRQAAAAAAAAAAAAAAAAAAAAAAAAAAACATI6VAEu8JlQr3pn0OkIpgHD9os6HgWKRJ3eH7V8q6SaRhMQNhMzkBAGItMVkBANNSB4BmS7RVWYwmuTyQmkmOZjiULIEgU_YpmgYX2yxTDgwf36TEwZDuoq-dfJiKGyPux5hnPSNia0iYGR8ABtO5pt9Ay5fHiHQ9Io5qcXw29gm8VPdHJhvcc0hMtctTCWy87QXiaI85MP-Uxd6fdEcGySnmhlUBjR5REJY89bql4BYLoK8wR90bohppGT0Dxh3kwY6QpXdZFVek2aGKA7YF4IM0lquRqMSvy9b_j2tl7NvNcoAU_-Kv-UufpyFqvWn1psjUMFyUvTBeP5dH_VWuuIINnbrgYuloei3IlA6DjIu7dvMuExXpFTTbILnstvOJGkrofboB8ELPnYK87P1iLTJEAAEAAWNmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzkBAGNzaWdZAQBPiPQ22-D-hqHKBDGtp6qKo8PuIttaD9qvXLU6IsfYVK9xUban1teHTqfCZ6bvubnSQc7SzR-DmrAGh4GvQA38ag__W-3uWQ3x2el_dvIWd5fZRtbYuf0n7v4WCIHru79AyIaNszECOIZu--0QoWRbrmcpjgsDQbS6Rm3eqqczKAWHUWAJuKtCp1Evv1V3ChYSmpMIKBTvDmOltF1YncY6goCt-Xa3auWm9VwbXi6LH_wAtSWCLrdyp6VcIS8n7w9m7fTiGALIi_y1xaiVJz5U5rYlHpTElKTvI4ceO23mlEqgi_O9Pfqg8dA1ejXxpc4yvTTMaihbZq_vtEgMup4h"
>   },
>   "type": "public-key",
>   "getClientExtensionResults": "oA==",
>   "nickname": "some_name"
> }
```

Assertion:
 * Basic usage

`FIDO2_HOME=$HOME/.fido2 python3 -m soft_fido2.authenticator assertion <assertion options>`

The following example takes a JSON dictionary of assertion options provided by a FIDO2 RP and generates the assertion response. This example will only work if an attestation (registration) has previously been run for the required user against the target relying party.

```bash
ASSERTION_OPTIONS='{
  "rpId": "www.myrp.ibm.com",
  "timeout": 60000,
  "challenge": "kI9SKJRxv4zpICnG1Ls9FMwQ4t4Zq6t8HqKAJKzeyXI",
  "extensions": {},
}'

python3 -m soft_fido2.authenticator 'assertion' ${ASSERTION_OPTIONS}
> {
>     "id": "EyOlQBLvCZUK96Z9DpCKYBw_aLOh4FikSd3h-1fKukk=",
>     "rawId": "EyOlQBLvCZUK96Z9DpCKYBw_aLOh4FikSd3h-1fKukk=",
>     "response": {
>         "clientDataJSON": "eyJvcmlnaW4iOiAiaHR0cHM6Ly93d3cubXlpZHAuaWJtLmNvbSIsICJjaGFsbGVuZ2UiOiAia0k5U0tKUnh2NHpwSUNuRzFMczlGTXdRNHQ0WnE2dDhIcUtBSkt6ZXlYST0iLCAidHlwZSI6ICJ3ZWJhdXRobi5nZXQifQ==",
>         "authenticatorData": "L5GuGTMVemZkNaZWOVyaeVpYT8RPhwAew1w6v5ytoLMFAAAAAA==",
>         "signature": "Tn1J7kTWVL_MmSVimB95r7MDhG8T18pm-CD7TQn5dsbcTec6M8E_4-TFS-U3xto6bYlmciw8YYXpINCag0KetdnCMhm0D23ElcUGcEbdJmpzuMdotjW6AZRnLMe6aZU7uSyzwvcustYeKlAtSziSAw7qHL4ucnJYQZhsaCpya325UgpNshAHXcG3an_nRbogvKd__zjg3Fr-2qltP8r9CneuOSpphnBTWTmNk8cC16Nluhi81rugjlMdDgP6_pyYcpxSR1FVN_fJnnqmwRyundR29C-SCe3-NGHcgKOdeZf6izpw1FXfET4LRKpxoPiIApWLGb7tg6jIVQieT_QXsQ=="
>     },
>     "type": "public-key"
> }
```

### PIP module

First install from artifactory (requires IBM W3 login details)

* `pip3 install soft_fido2`

Once isntalled the FIDO2 authenticator can be imported like any other python module. The following example shows how to use the authenticator to generate an attestation (registration) with the 'packed-self' format then subsequently use the same authenticator to perform an assertion.

```python
import json
import requests
from soft_fido2 import Fido2Authenticator

#This will create a Fido2Authenticator with 2048-bit RSA key
authenticator = Fido2Authenticator()

##Attestation
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
    },
    {
      "alg": -35,
      "type": "public-key"
    },
    {
      "alg": -36,
      "type": "public-key"
    },
    {
      "alg": -257,
      "type": "public-key"
    },
    {
      "alg": -258,
      "type": "public-key"
    },
    {
      "alg": -259,
      "type": "public-key"
    },
    {
      "alg": -65535,
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

assertion_response = authenticator.credential_request(assertion_options)
print(json.dumps(assertion_response, indent=4))

rp_response = requests.post("https://www.myrp.ibm.com/assertion/result",
                        json=assertion_response)
```
## Environment properties

### FIDO_HOME
Property used for firectory which contains `.passkey` files which can be opened by suft_fido2 to
provide attestaiton and assertion responses.

Passkey files can be generated by the `util` scripts, or the system tray (if supported).


### SOFT_FIDO2_SKIP_UP
The `SOFT_FIDO2_SKIP_UP` property is used to skip the user presence check during attestation and assertion.

If this property is set to true then UV checks always immediatly return true for the
`get_info`, `make_cred` and `get_next_assert` authenticator commands.

### SOFT_FIDO2_DEBUG_LEVEL
The `SOFT_FIDO2_DEBUG_LEVEL` property is used to set the debug level for the soft_fido2 library.
The default debug level is `INFO`

### SOFT_FIDO2_LOG_FILE
The `SOFT_FIDO2_LOG_FILE` property is used to set the log file for the soft_fido2 library.
If this file is provided it will be created relative  to the `$FIDO_HOME` directory.
The default log file is `stdout`.

# USBIP OS Integration
Requires:
- USB/IP
- Python
  - usb_ip

Python server is hard coded to listen on the default USB/IP port (3240)

Users can use `lsusb` to list the devices known to the client.

Users can use `dmesg` to debug USB packed recieved by the client.

### Start the python usbip server
```bash
python hid_device.py
```

### List the device
```bash
usbip list -r 127.0.0.1
```

### Attach to a device
```
sudo modprobe vhci-hcd
usbip attach -r 127.0.0.1 -b <bus_id, 1-1.1>
```

# UHID OS Integration
Requires
- UHID (Fedora)
- Python3
- Notify Send (libnotify)

Users must set the `FIDO_HOME` environment property. This should be a directory which will contain
encrypted passkey files.

Virtual Passkey Device can be started by running the module as a user with sufficient permission to open
the `/dev/uhid` device:
```bash
# Root privileges are assumed
# Give sufficient permissions to open /dev/uhid:
# Create a rule in /etc/modules or /etc/modules-load.d so that the uhid module loads during boot
echo 'uhid' | tee /etc/modules-load.d/uhid.conf
# Create udev group and add a user to it
groupadd udev
usermod -aG udev $USER
# Create udev rule for uhid access with sufficient permissions
echo 'KERNEL=="uhid", GROUP="udev", MODE="0660"' | tee /etc/udev/rules.d/90-uhid.rules
# Apply rule
udevadm control --reload-rules && udevadm trigger
# Reboot to load uhid module during next boot

# Create key pair for encrypting half of the pin hash, this should be done for all users using software passkeys
openssl ecparam -name prime256v1 -genkey -noout -out $HOME/.fido/platform.key

# Create systemd daemon
export FIDO_HOME=/opt/soft_fido2
mkdir -p $FIDO_HOME
virtualenv $FIDO_HOME
$FIDO_HOME/bin/python -m pip install --upgrade pip soft_fido2
# In user's home directory
mkdir -p ${HOME}/.fido2
#FIDO_HOME=${HOME}/.fido2 $FIDO_HOME/bin/python -m soft_fido2
echo 'FIDO_HOME=${HOME}/.fido2' > $FIDO_HOME/passkey.env
cat <<EOF > /usr/lib/systemd/system/passkey.service
[Unit]
Description=Software FIDO2 Passkey
After=basic.target

[Service]
ExecStart=/opt/soft_fido2/bin/python -m soft_fido2
Type=simple
Restart=no
EnvironmentFile=/opt/soft_fido2/passkey.env

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable passkey
systemctl start passkey

# Confirm authenticator is running
hexdump -C "/sys/bus/hid/devices/$(ls /sys/bus/hid/devices | grep 1337:1337)/report_descriptor"
# Output of command should be identical to the sequence below
# 00000000  06 d0 f1 09 01 a1 01 09  20 15 00 26 ff 00 75 08  |........ ..&..u.|
# 00000010  95 40 81 02 09 21 15 00  26 ff 00 75 08 95 40 91  |.@...!..&..u..@.|
# 00000020  02 c0                                             |..|
# 00000022

```

# Development
Project can be build and installed locally using a python virtual environment.

Set up a python virtual environment as follows:
```bash
export FIDO_HOME="$HOME/.fido2"
mkdir -p $FIDO_HOME
virtualenv $FIDO_HOME
$FIDO_HOME/bin/python -m pip install --upgrade pip
$FIDO_HOME/bin/python -m pip install --upgrade -r dev-requirements.txt
export GITHUB_RUN_NUMBER=9999
$FIDO_HOME/bin/python -m build
$FIDO_HOME/bin/python -m pip install --upgrade dist/soft_fido2-*-py3-none-any.whl 
$FIDO_HOME/bin/python -m soft_fido2
```
