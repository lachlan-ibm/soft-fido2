# Using soft_fido2 as a Python Module

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

## Testing with python-fido2 server library

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


## Using soft_fido2 from Command Line (no GUI/UX)

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

# More Attestation Formats
The above example generates a packed attestation statement using a self-signed X509 certificate. This is typically referred to as `packed-self`, as there is 
no external entity acting as a trust anchor.

There are several other attestation formats that can be used to provide a more trusted attestation statement. These formats require varying additional PKI (keys/certificates) to be provided to the authenticator when it is being constructed / generating the attestation statement.

## Anon-CA

## TPM

## Android Keystore and Safetynet