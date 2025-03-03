# Python

## Prerequisites:

### Python
    * >= Python 3.7

### Pip modules

    * asn1 >= 2.2.0
    * cryptography >= 38.0.1 
    * cbor2 >= 4.1.2
    * PyJwt >= 0.6.1

## Usage

### Command line

Attestation:
 * Basic usage

`python3 authenticator.py attestation <attestation type> <attestation options>`

The following example takes a JSON dictionary of attestation options provided by a FIDO2 relyingparty (RP) and prints a dictionary to stdout which contains the authenticator's response to the attestation request. The example uses 'packed-self' as the attestation format. Other attestation formats are supported however there is more complex setup required generating the required trust anchors and uploading them to your relying party.

```
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

`python3 authenticator.py assertion <assertion options>`

The following example takes a JSON dictionary of assertion options provided by a FIDO2 RP and generates the assertion response. This example will only work if an attestation (registration) has previously been run for the required user against the target relying party.

```
ASSERTION_OPTIONS='{
  "rpId": "www.myrp.ibm.com",
  "timeout": 60000,
  "challenge": "kI9SKJRxv4zpICnG1Ls9FMwQ4t4Zq6t8HqKAJKzeyXI",
  "extensions": {},
}'

python3 python_authenticator/soft_fido2/authenticator.py 'assertion' ${ASSERTION_OPTIONS}
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

* `pip3 install soft_fido2 --extra-index https://{username}:{password}@eu.artifactory.swg-devops.com/artifactory/api/pypi/sec-iam-components-pypi-virtual/simple`

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


# Python / USBIP
Requires:
- USB/IP
- Python
  - usb_ip

Python server is hard coded to listen on the default USB/IP port (3240)

Users can use `lsusb` to list the devices known to the client.

Users can use `dmesg` to debug USB packed recieved by the client.

### Start the python usbip server
```
python hid_device.py
```

### List the device
```
usbip list -r 127.0.0.1
```

### Attach to a device
```
sudo modprobe vhci-hcd
usbip attach -r 127.0.0.1 -b <bus_id, 1-1.1>
```

# Rust

## Not yet implemented
