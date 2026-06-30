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

# Some Notes on Attestation Formats
The above example generates a packed attestation statement using a self-signed X509 certificate. This is typically referred to as `packed-self`, as there is no external entity acting as a trust anchor.

There are several other attestation formats that can be used to provide a more trusted attestation statement. These formats require varying additional PKI (keys/certificates) to be provided to the authenticator when it is being constructed / generating the attestation statement.

## Anon-CA
Anonymmous Certificate Authority Attestation; defined by Apple, requires the authenticator to add a nonce derrived from the attestation options to an X.509 Extension.

```python
from soft_fido2 import cert_utils, key_pair, authenticator
from cryptography import x509
#Generate Trust Root
fake_ca_kp = key_pair.KeyPair.generate_ecdsa()
fake_ca = cert_utils.CertUtils.gen_ca_cert(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Anonymous trust root")]), keyPair=fake_ca_kp)
#Create authenticator with claimed AAGUID
a = authenticator.Fido2Authenticator(aaguid=[0x17] * 16, keyPair=key_pair.KeyPair.generate_ecdsa(), caKeyPair=fake_ca_kp, caCert=fake_ca)
#Generate attestation response
attestation_options = {"rp":{"id":"myidp.ibm.com"},"user":{"id":"GwVWpXCCQ9ildXk-WbzvwQ"},"challenge":"aaiqW2gTbA2pX0Y4u4jdCIT1fjS0GF2psVj0JQTF5PQ"}
attestation = a.credential_create(attestation_options, atteStmtFmt='apple')
print(attestation)

>>> {'id': 'Umsolq67d0EMtEMeerUKSQ0szM6JH8wdnGExKiJH6n0', 'rawId': 'Umsolq67d0EMtEMeerUKSQ0szM6JH8wdnGExKiJH6n0', 'response': {'clientDataJSON': 'eyJvcmlnaW4iOiAiaHR0cHM6Ly9teWlkcC5pYm0uY29tIiwgImNoYWxsZW5nZSI6ICJhYWlxVzJnVGJBMnBYMFk0dTRqZENJVDFmalMwR0YycHNWajBKUVRGNVBRIiwgInR5cGUiOiAid2ViYXV0aG4uY3JlYXRlIn0=', 'attestationObject': 'o2hhdXRoRGF0YVik0oCMa7m4YmFOsMTakPy2jVVy5_BCq_H4YXU8RD_Sj_hFAAAAABcXFxcXFxcXFxcXFxcXFxcAIFJrKJauu3dBDLRDHnq1CkkNLMzOiR_MHZxhMSoiR-p9pQECAyYgASFYIMHEysDM6QoB1EOeYL2o5h-_qbd14wiB3HX6yJ7nlYu6IlggHKB_V2ev0lRhQdAz6KPstxbrBPLQMi5a0fSUEdf2WTRjZm10ZWFwcGxlZ2F0dFN0bXShY3g1Y4JZAaowggGmMIIBTaADAgECAhR-IiOQkVxHNnqVjd7Up-lXjwp_OzAKBggqhkjOPQQDAjAfMR0wGwYDVQQDDBRBbm9ueW1vdXMgdHJ1c3Qgcm9vdDAeFw0yNjA2MjEyMzQwNDFaFw0yNzA2MjIyMzQwNDFaME8xDjAMBgNVBAMMBWFwcGxlMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMQswCQYDVQQGEwJBVTEMMAoGA1UECgwDSUJNMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwcTKwMzpCgHUQ55gvajmH7-pt3XjCIHcdfrInueVi7ocoH9XZ6_SVGFB0DPoo-y3FusE8tAyLlrR9JQR1_ZZNKM3MDUwMwYJKoZIhvdjZAgCBCYwJKAiBCDAjm-wduOKpSWb3HNWaH47Y6zaGRtst5KgbJl_Znv_1TAKBggqhkjOPQQDAgNHADBEAiAUbyPK3S-u873WO-OH8sTLRSQi5aopioCEMPqxKJ7lowIgepVzwL6Ab3QHfxxmFzbHb4pB0HRhPht35vjg5y-3NXpZAYIwggF-MIIBJaADAgECAhQ_ZxRqC8jTZaHbfpUPVPpuT7pRXDAKBggqhkjOPQQDAjAfMR0wGwYDVQQDDBRBbm9ueW1vdXMgdHJ1c3Qgcm9vdDAeFw0yNjA2MjEyMzM4NDhaFw0yNzA2MjIyMzM4NDhaMB8xHTAbBgNVBAMMFEFub255bW91cyB0cnVzdCByb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEakBQmpTIzlqPmI0S5FRIV0PNMgfh2p3OlyI6YujEXojg3CwqMlOhpRWcF9zac3aal4Xu4pGkC8YfeL7ANDA5Z6M_MD0wHQYDVR0OBBYEFFMriNI_7WwXbao5PoNwuv-AENuaMA8GA1UdEwQIMAYBAf8CAQMwCwYDVR0PBAQDAgGGMAoGCCqGSM49BAMCA0cAMEQCIBvi5bPkD6YzVdIW3-Wgs6hSyA17I4pVNnBKg7XWzwcUAiAY3uWA5RzLd7D_uab8-jhn4Rfqaa4o6tCXO5dYwTecfw=='}, 'type': 'public-key', 'getClientExtensionResults': {}}
```


## TPM
Trused Platform Module Attestaion emulates the output of a TPM device. It requires the Autheticator to be constructed with a second Key and Certificate; which serves as the trusted root for the attestation.

```python
from soft_fido2 import cert_utils, key_pair, authenticator
from cryptography import x509
#Generate Trust Root
fake_ca_kp = key_pair.KeyPair.generate_ecdsa()
fake_ca = cert_utils.CertUtils.gen_ca_cert(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Fake tpm trust root")]), keyPair=fake_ca_kp)
#Create authenticator with claimed AAGUID
a = authenticator.Fido2Authenticator(aaguid=[0x18] * 16, keyPair=key_pair.KeyPair.generate_ecdsa(), caKeyPair=fake_ca_kp, caCert=fake_ca)
#Generate attestation response
attestation_options = {"rp":{"id":"myidp.ibm.com"},"user":{"id":"GwVWpXCCQ9ildXk-WbzvwQ"},"challenge":"aaiqW2gTbA2pX0Y4u4jdCIT1fjS0GF2psVj0JQTF5PQ","pubKeyCredParams":[{"alg":-7,"type":"public-key"}]}
attestation = a.credential_create(attestation_options, atteStmtFmt='tpm')
print(attestation)

>>> {'id': 'Ttdca33gtEIZgBdDFBy7ALxyd46wqNsSbLro5BG4xro', 'rawId': 'Ttdca33gtEIZgBdDFBy7ALxyd46wqNsSbLro5BG4xro', 'response': {'clientDataJSON': 'eyJvcmlnaW4iOiAiaHR0cHM6Ly9teWlkcC5pYm0uY29tIiwgImNoYWxsZW5nZSI6ICJhYWlxVzJnVGJBMnBYMFk0dTRqZENJVDFmalMwR0YycHNWajBKUVRGNVBRIiwgInR5cGUiOiAid2ViYXV0aG4uY3JlYXRlIn0=', 'attestationObject': 'o2hhdXRoRGF0YVik0oCMa7m4YmFOsMTakPy2jVVy5_BCq_H4YXU8RD_Sj_hFAAAAABgYGBgYGBgYGBgYGBgYGBgAIE7XXGt94LRCGYAXQxQcuwC8cneOsKjbEmy66OQRuMa6pQECAyYgASFYIK5VaxrW8QU2KzrKwWqefQVMMxBZ6DA7wm6wEgxL4nURIlggLWZJe_HXcjr2jKY8A0mCOHIW3rHssdo2VcK_6YmrFd1jZm10Y3RwbWdhdHRTdG10pmdwdWJBcmVhWFYAIwALAAAAAAAAABAAEAADABAAIK5VaxrW8QU2KzrKwWqefQVMMxBZ6DA7wm6wEgxL4nURACAtZkl78ddyOvaMpjwDSYI4chbeseyx2jZVwr_piasV3WhjZXJ0SW5mb1hp_1RDR4AXAAAAIDU9Akc9ja62Ru9rOVrdPNpjj8IgvwDg1kLkKXearpRYAAAAAAAAAAAAAAAAAAAAAAAAAAAA___x0AAiAAtKBVwiFRa01c5ZjyE0mQ3p_YggfPK1hNUa9jhsNa0aigAAY3NpZ1hIMEYCIQDlWXvXcbDMpnmgNUKXpbgGtudzMgnJk1ZDoam4CrJPuQIhAPCxi_A-zoG7xyoJvg_6Zb1dYHoUu_KBrXQtaeMNffQIY3ZlcmMyLjBjYWxnJmN4NWOCWQHDMIIBvzCCAWWgAwIBAgIUCzcFnFbquzORGMTrtnmvK9_Nn8owCgYIKoZIzj0EAwIwHjEcMBoGA1UEAwwTRmFrZSB0cG0gdHJ1c3Qgcm9vdDAeFw0yNjA2MjEyMzQ0NDFaFw0yNzA2MjIyMzQ0NDFaMAAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASuVWsa1vEFNis6ysFqnn0FTDMQWegwO8JusBIMS-J1ES1mSXvx13I69oymPANJgjhyFt6x7LHaNlXCv-mJqxXdo4GeMIGbMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgHWMBAGA1UdJQQJMAcGBWeBBQgDMEwGA1UdEQEB_wRCMECkPjA8MRYwFAYFZ4EFAgEMC2lkOmZmZmZmMWQwMREwDwYFZ4EFAgIMBklCTVRQTTEPMA0GBWeBBQIDDARpZDoxMCEGCysGAQQBguUcAQEEBBIEEBgYGBgYGBgYGBgYGBgYGBgwCgYIKoZIzj0EAwIDSAAwRQIgGkVChBwHplCuIlMMn14zRAoWMEfSiEcB5_zEzZ55WWQCIQDRuLqz8pat6qq0pt9r67RaBMA0xhPlPyszfSUxYRSiKlkBgDCCAXwwggEjoAMCAQICFHqgEhKV8mCkFTeMklnP8PQWfwbgMAoGCCqGSM49BAMCMB4xHDAaBgNVBAMME0Zha2UgdHBtIHRydXN0IHJvb3QwHhcNMjYwNjIxMjM0NDQxWhcNMjcwNjIyMjM0NDQxWjAeMRwwGgYDVQQDDBNGYWtlIHRwbSB0cnVzdCByb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENQehCS6GQTr681QNTg_ABkNAhfYHvXRlhUDyyZ2qUxdH-UBqFLK0tAX8WGSiXS8pSM8dud3fxNsY5qLuTE1nMqM_MD0wHQYDVR0OBBYEFMr2jGZKkI0JRX1vYNMws6b0WR3RMA8GA1UdEwQIMAYBAf8CAQMwCwYDVR0PBAQDAgGGMAoGCCqGSM49BAMCA0cAMEQCIBZsm-g3qR8S2Z55Q3jzg7GzCzbYZdOq_8YaBFxeuhkbAiB9kTGxfi9W3__lpyFgp9h7CZDyT9aLI3w9UxZCJNJHRw=='}, 'type': 'public-key', 'getClientExtensionResults': {}}
```

## Android Keystore and Safetynet

The android safetynet attestaion format is sometimes used by android applications. It is based on a JWT strucutre with some additional claims from the attestation ceremony. This format rerquires the authenticator to be constructed with a second Key and Certificate; which serves as the trusted root for the attestation.

```python
from soft_fido2 import cert_utils, key_pair, authenticator
from cryptography import x509
#Generate Trust Root
fake_ca_kp = key_pair.KeyPair.generate_rsa()
fake_ca = cert_utils.CertUtils.gen_ca_cert(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Fake android trust root")]), keyPair=fake_ca_kp)
#Create authenticator with claimed AAGUID
a = authenticator.Fido2Authenticator(aaguid=[0x19] * 16, keyPair=key_pair.KeyPair.generate_rsa(), caKeyPair=fake_ca_kp, caCert=fake_ca)
#Generate attestation response
attestation_options = {"rp":{"id":"myidp.ibm.com"},"user":{"id":"GwVWpXCCQ9ildXk-WbzvwQ"},"challenge":"aaiqW2gTbA2pX0Y4u4jdCIT1fjS0GF2psVj0JQTF5PQ","pubKeyCredParams":[{"alg":-7,"type":"public-key"}]}
attestation = a.credential_create(attestation_options, atteStmtFmt='android-safetynet')
print(attestation)

>>> {'id': '0ZAfgFRRHwaPaqKI94PNfdFed2nk5OHoFBQGRe35DMA', 'rawId': '0ZAfgFRRHwaPaqKI94PNfdFed2nk5OHoFBQGRe35DMA', 'response': {'clientDataJSON': 'eyJvcmlnaW4iOiAiaHR0cHM6Ly9teWlkcC5pYm0uY29tIiwgImNoYWxsZW5nZSI6ICJhYWlxVzJnVGJBMnBYMFk0dTRqZENJVDFmalMwR0YycHNWajBKUVRGNVBRIiwgInR5cGUiOiAid2ViYXV0aG4uY3JlYXRlIn0=', 'attestationObject': 'o2hhdXRoRGF0YVkBaNKAjGu5uGJhTrDE2pD8to1VcufwQqvx-GF1PEQ_0o_4RQAAAAAZGRkZGRkZGRkZGRkZGRkZACDRkB-AVFEfBo9qooj3g8190V53aeTk4egUFAZF7fkMwKQBAwM5AQAgWQEA3IiPeX7p5OYrk9F945EHuUl8RTaaNZIwwZD-rY4llMAC-_x_6aMJt6_f3GxK0iAMrHwH-_TEVMEKf01RC0UsEGOj6LZNB_1vSSTmnmpHjTFGLw0aERTRlRnoQxasu0CAnDQuHkMqXXh3OcUNZ33XQApoUuLbK6Sykhm-0ec6GIiUGgrJRHyCLyVGWyePtJZOwntSdcDleoLiIpD_TJSIwrd5zX4_WUTkFmPrZnxL3MDTuynqyEkSnf31PougbIJWbXdXpDaW4qXWmZaUlsfjLRJ5yJdGzlgrkygkI0ih7p5jjo_ONwP4o7N6JeE10UxIZ49zsBsjL9ynUqrudSXySyFEAAEAAWNmbXRxYW5kcm9pZC1zYWZldHluZXRnYXR0U3RtdKJjdmVybHNvbWUgdmVyc2lvbmhyZXNwb25zZVkOnmV5SmhiR2NpT2lKU1V6STFOaUlzSW5SNWNDSTZJa3BYVkNJc0luZzFZeUk2V3lKTlNVbEVhVlJEUTBGdVIyZEJkMGxDUVdkSlZXWXhWMUJrWlVkVmR6a3ZiRWxDVm5oQlJFNHhkV3A1TTBOU1dYZEVVVmxLUzI5YVNXaDJZMDVCVVVWTVFsRkJkMGxxUldkTlFqUkhRVEZWUlVGM2QxaFNiVVp5V2xOQ2FHSnRVbmxpTW14clNVaFNlV1JZVGpCSlNFcDJZak5SZDBob1kwNU5hbGwzVG1wSmVFMXFUVEJPZWtsM1YyaGpUazFxWTNkT2FrbDVUV3BOTUU1NlNYZFhha0pqVFZKemQwZFJXVVJXVVZGRVJFSkthR1JJVW14ak0xRjFXVmMxYTJOdE9YQmFRelZxWWpJd2VFbHFRV2RDWjA1V1FrRnpUVWRWUmpGa1IyaHNZbTVTY0ZreVJqQmlNMGxuVVZoU01GcFlUakJaV0ZKd1lqSTBlRU42UVVwQ1owNVdRa0ZaVkVGclJsWk5VWGQzUTJkWlJGWlJVVXRFUVU1S1VXc3dkMmRuUldsTlFUQkhRMU54UjFOSllqTkVVVVZDUVZGVlFVRTBTVUpFZDBGM1oyZEZTMEZ2U1VKQlVVUmphVWs1TldaMWJtczFhWFZVTUZnemFtdFJaVFZUV0hoR1RuQnZNV3RxUkVKclVEWjBhbWxYVlhkQlREY3ZTQzl3YjNkdE0zSTVMMk5pUlhKVFNVRjVjMlpCWmpjNVRWSlZkMUZ3TDFSV1JVeFNVM2RSV1RaUWIzUnJNRWd2VnpsS1NrOWhaV0ZyWlU1TlZWbDJSRkp2VWtaT1IxWkhaV2hFUm5GNU4xRkpRMk5PUXpSbFVYbHdaR1ZJWXpWNFVURnVabVJrUVVOdGFGTTBkSE55Y0V4TFUwZGlOMUkxZW05WmFVcFJZVU56YkVWbVNVbDJTbFZhWWtvMEt6QnNhemREWlRGS01YZFBWalpuZFVscGExQTVUV3hKYWtOME0yNU9abW81V2xKUFVWZFpLM1J0WmtWMlkzZE9UemRMWlhKSlUxSkxaQzltVlN0cE5rSnpaMnhhZEdReFpXdE9jR0pwY0dSaFdteHdVMWQ0SzAxMFJXNXVTV3d3WWs5WFEzVlVTME5SYWxOTFNIVnViVTlQYWpnME0wRXZhV3B6TTI5c05GUllVbFJGYUc1cU0wOTNSM2xOZGpOTFpGTnhkVFV4U21aS1RFRm5UVUpCUVVkcVpsUkNOMDFCYTBkQk1WVmtSWGRSUTAxQlFYZERkMWxFVmxJd1VFSkJVVVJCWjBoWFRVSkJSMEV4VldSS1VWRktUVUZqUjBKWFpVSkNVV2RFVFVVNFIwRXhWV1JGVVVWQ0wzZFNSazFGVDJ0UlZFRXZUVkUwZDBSQldVWmFORVZHUVdkRlRVRXdiRU5VVkVWalRVSnZSMEpYWlVKQ1VVbERSRUpHY0ZwRWNHbEtlVkptV0RFNVVsWkRRV2RKUm5oMVNucEZVRTFCTUVkQ1YyVkNRbEZKUkVSQlVuQmFSRzk0VFVFd1IwTlRjVWRUU1dJelJGRkZRa04zVlVGQk5FbENRVkZDUzFsTk0yTkJjRVI1Y25KTFEyaHNlVGN6UmxkRWQweE1lSEZFWld4VllrVmpZWGhaVkhCNVZFTXhUamxsYlZObGVVSlVabUoxVEVkM1ZGcG9hVmR0V0RoUVNrUXZlVkpoVG5SRU5WbFJiRGhpTUZwbWNVUTFUbFZXSzBZMGVIRkNNbVJZVm1GUWN6WkdOamx2VVN0dVpIVm9Oa2w1VjIwMlVucHNZa0V4ZUZOdFdWWnpXbmR0WkZBNFdqRkxiMmxGVEZoNGF6RkdNbVJJZVRCR01sVlRhRFJHTm5BNVVWZHZZV1JaVkdkd1UxTk5kekJ4Y0VSMVYwSTBWVGR2VldkMGNXNUdZMmxRV1hoaVNISktkMFpGYzFnMlFURnZhVWN4WldRM1dGQlpPSGhCYzFKWVptWjNPSE5JVGpZNFFVMVlLMFZOV0V3ckwwRktXbEZYU1hoRWNIUjJlSE5WTVRWbVpGSnVPVGgyTkhCb2VUVmFWVGR0VnpWQk5GVmtLMHBaVFRKNFMyVkZkMEp3TmtvdlltaHBkSHBYVVRSVFpuQkRkek15YlVKVVExZEZNMk5QWWs1V0t6bEhlakZ3UTJkSVdtdElVazhpTENKTlNVbEVSVlJEUTBGbWJXZEJkMGxDUVdkSlZVVlhNMUpSYUZNelUzbEthVlExYlUxalpYUnVhVk01ZVM5dlJYZEVVVmxLUzI5YVNXaDJZMDVCVVVWTVFsRkJkMGxxUldkTlFqUkhRVEZWUlVGM2QxaFNiVVp5V2xOQ2FHSnRVbmxpTW14clNVaFNlV1JZVGpCSlNFcDJZak5SZDBob1kwNU5hbGwzVG1wSmVFMXFUVEJPZWtsM1YyaGpUazFxWTNkT2FrbDVUV3BOTUU1NlNYZFhha0ZwVFZOQmQwaG5XVVJXVVZGRVJFSmtSMWxYZEd4SlIwWjFXa2hLZG1GWFVXZGtTRW94WXpOUloyTnRPWFprUkVORFFWTkpkMFJSV1VwTGIxcEphSFpqVGtGUlJVSkNVVUZFWjJkRlVFRkVRME5CVVc5RFoyZEZRa0ZKTkU5bVprUnNlRkp6VVdZck1XUkNhalV3S3poaWVFeEtiMFJyY0hOc1ZVbDRUMEZ1U25OcFZHMXRUbko0YTFaa2NFVjNaRVZCVDJoNVRESjJZazltSzJKTVYyWlJWRTVOYm1oSE9EWmtRaXR6WlZJd2JXUXpkelJKWVRsckwwWnhiVlpKV1dKQlJsUXhTR293UjFKT2NVZERXRW95YVc0NWRUTkxUek5PWjNwSFpqWklLM0l3Y0U4eFFXbzNTR0V5WTJneVNtSlRPWGxCVnpscmVIUkVLeTlzVm5GUVMxbE5URXhrY1V0NVZVdFRXa1p4ZUM5a1pUQTNOVWhKWlcxaFJDdHhPSGRFVUVsdVdVTlJTMHhZTUd0SlMyWnVUVFpETkVFeVJEQldTbUpCVGxrNVdUaFZUV2QxU2tsbldtNXFaM053VUc5UGQyaHhXVk16VFVoSGRVVXdOVk15VlhaSU1qUnJZMHhDS3pCWUwyODJiRnB4Y0UxSVVGRnFjbTUzZUdRNEwwVlJTVlJFYUVNNWRsaHBNVlY2UkhCeGFUUjBRVzlzYnk5TWRGUnpOSGRwY3psSk4yOUNiM0UxYmxock5YbFVRVVZEUVhkRlFVRmhUUzlOUkRCM1NGRlpSRlpTTUU5Q1FsbEZSa3NyYlUwemMwdHZSbmd3U0RoNU1HOHlNbFZFWW5KQmVsY3dTVTFCT0VkQk1WVmtSWGRSU1UxQldVSkJaamhEUVZGTmQwTjNXVVJXVWpCUVFrRlJSRUZuUjBkTlFUQkhRMU54UjFOSllqTkVVVVZDUTNkVlFVRTBTVUpCVVVKaVZub3dObnBGTVhSU1UxVjFUVGhqTDA1a1RrNVlSVE13VDNwSVlXaFBSbE5UY3pOWVJuZFBZVWRuVmtaMVYxaG9SMk5PUWxaak16azNkMDR6U0ZvelRXUnhOMWhRT0ZsaU9UYzJZMFZPYmpkRWRIRlhlVmRvZDA5VmVFSlBXWGxKYlZkT09Fc3lXa2xJUlVwM1JHNUVlbEZVU1VwM2VITTFSa3BqWTNKVWVWYzBWVWMwV1ZKQ01sQk9hVVpPUW1oYWNtdzNaamRMVEdWMmNHVm9RMmsxVEdwWU1GRjFOVnBQYjFWVmJqWjNlbVZNYUdkNGN6bFNkeXRNWVVKTWRGVmhXVVU0U2tFck16VnFWMjVqWkVONGREUm5aVlZzVWpKd1dGSmFNMmMwVWxndldrUTJhbEExY2toTlVWa3ZlbkExT0hSdk1tVkhObEJ4VjBaT1MxVmFaSEp0Y0d4WFVEazVjVXRGTlhOSFQxcFJVek5uUjJvcmVVRmtUbkEzVWpWb2VFbEhNVUZuWTFZM1VISlBSVXRRYldoS1pVZENWelY2TVhoRllXOXNSM1ZaTlRFNWQySjRSbms0ZVNzNWN6WktNWEpSTnlKZGZRLmV5SjBhVzFsYzNSaGJYQk5jeUk2TVRjNE1qRTNNakEwTURjNE5pd2libTl1WTJVaU9pSnJjVUpqWVd0amFVVnBiV2M0VVdkMFVHb3pXV3RDTUdkWVZYSm5TQ3QwTlVSdmRUUldRaXRaWVhCSlBTSXNJbUZ3YTFCaFkydGhaMlZPWVcxbElqb2lZMjl0TG5CaFkydGhaMlV1Ym1GdFpTNXZaaTV5WlhGMVpYTjBhVzVuTG1Gd2NDSXNJbUZ3YTBObGNuUnBabWxqWVhSbFJHbG5aWE4wVTJoaE1qVTJJanBiSW1JMk5DQmxibU52WkdWa0lITm9ZVEkxTmlCdlppQmpaWEowSWwwc0ltTjBjMUJ5YjJacGJHVk5ZWFJqYUNJNmRISjFaU3dpWW1GemFXTkpiblJsWjNKcGRIa2lPblJ5ZFdWOS5hNTdpbjAxcHEweC1DUFliNEoxNWYtZGhjdFBvOHp6VXoxeGRpWlZYTnZiQ0kwMnpJWUlubjVJbzdHcVBhMV9sWEx6V0toTFcxOEx1V1Z3eFNMQkQ1bmY4TENtellfSkp0WHVlTVNaMWYwMHBNbjR4OGN3OXpiRWE1c01ydlhybzNjd3JUREE0MV9fSWJHQ3RuT1h3X1pUelJzUTZNUExiSFl6WFJzTkhENXd1M05vNTNZREJBRE1ZcTlUa3NqR1pHcnI5dHN6aFFHaVR6ZW1KcDg5ci12M0oxQktXdDJzbkdXVjQ3TzVWQUdnSUR5MF8xa29Bd2hGcW5IeXFhbVhkaXJSSGUtWE9rUFhoWldyQTlhU2ZRc05YY2VpRkhxX1FDWjVyc0pPVEhrWGVyM2RQc0otZWx0c0syRXd6aEhzMUN4cWd5Z2NoMUs1QXp6andHWnpUYXc='}, 'type': 'public-key', 'getClientExtensionResults': {}}
```


The android key attestation format; which is very similar to the packed format

```python
from soft_fido2 import cert_utils, key_pair, authenticator
from cryptography import x509
#Generate Trust Root
fake_ca_kp = key_pair.KeyPair.generate_rsa()
fake_ca = cert_utils.CertUtils.gen_ca_cert(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Fake android trust root")]), keyPair=fake_ca_kp)
#Create authenticator with claimed AAGUID
a = authenticator.Fido2Authenticator(aaguid=[0x19] * 16, keyPair=key_pair.KeyPair.generate_rsa(), caKeyPair=fake_ca_kp, caCert=fake_ca)
#Generate attestation response
attestation_options = {"rp":{"id":"myidp.ibm.com"},"user":{"id":"GwVWpXCCQ9ildXk-WbzvwQ"},"challenge":"aaiqW2gTbA2pX0Y4u4jdCIT1fjS0GF2psVj0JQTF5PQ","pubKeyCredParams":[{"alg":-7,"type":"public-key"}]}
attestation = a.credential_create(attestation_options, atteStmtFmt='android-key')
print(attestation)

>>> {'id': 'VawFdtxzktuh0YFwwoZjW0oE9HFmfgfeAVcnReMCsvI', 'rawId': 'VawFdtxzktuh0YFwwoZjW0oE9HFmfgfeAVcnReMCsvI', 'response': {'clientDataJSON': 'eyJvcmlnaW4iOiAiaHR0cHM6Ly9teWlkcC5pYm0uY29tIiwgImNoYWxsZW5nZSI6ICJhYWlxVzJnVGJBMnBYMFk0dTRqZENJVDFmalMwR0YycHNWajBKUVRGNVBRIiwgInR5cGUiOiAid2ViYXV0aG4uY3JlYXRlIn0=', 'attestationObject': 'o2hhdXRoRGF0YVkBaNKAjGu5uGJhTrDE2pD8to1VcufwQqvx-GF1PEQ_0o_4RQAAAAAZGRkZGRkZGRkZGRkZGRkZACBVrAV23HOS26HRgXDChmNbSgT0cWZ-B94BVydF4wKy8qQBAwM5AQAgWQEAtmKGrAfzXIpJPFzPxmMT_CtDc1us75-ocNNLIGwARS8oRpQGLo_lCLpLAj5McCIpTCh-2UVQbucG59DWUE42oz-AM7cQA89wkHcdonVAVA86_SdbNwrI0NF97noLh_gdLutGrGwTth0TKQL-vymwzDcGxLlsVNLmCGTrVkn1AZ5Blk-om15WqnDeInRf4LiXrWFtNWcK75P0piyl8qE8T_pMQvX0JIQIybPBLkea4MIY0mTYEgxnB1YMvm8CR4Y0Cg4AmFNIB7xKozmtycFX4-U8eJuWnxpNgFFU7nVY_h7FPHMpNX8rJw75dumeonQwVm-mPnl514SaNAUcU2nZmSFEAAEAAWNmbXRrYW5kcm9pZC1rZXlnYXR0U3RtdKNjeDVjglkECzCCBAcwggLvoAMCAQICFCjIYZ8O4o0Im_iy4jAC-gUSnN1fMA0GCSqGSIb3DQEBCwUAMCIxIDAeBgNVBAMMF0Zha2UgYW5kcm9pZCB0cnVzdCByb290MB4XDTI2MDYyMTIzNTAxMloXDTI3MDYyMjIzNTAxMlowTjENMAsGA1UEAwwEbGVhZjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCQVUxDDAKBgNVBAoMA0lCTTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALZihqwH81yKSTxcz8ZjE_wrQ3NbrO-fqHDTSyBsAEUvKEaUBi6P5Qi6SwI-THAiKUwoftlFUG7nBufQ1lBONqM_gDO3EAPPcJB3HaJ1QFQPOv0nWzcKyNDRfe56C4f4HS7rRqxsE7YdEykC_r8psMw3BsS5bFTS5ghk61ZJ9QGeQZZPqJteVqpw3iJ0X-C4l61hbTVnCu-T9KYspfKhPE_6TEL19CSECMmzwS5HmuDCGNJk2BIMZwdWDL5vAkeGNAoOAJhTSAe8SqM5rcnBV-PlPHiblp8aTYBRVO51WP4exTxzKTV_KycO-XbpnqJ0MFZvpj55edeEmjQFHFNp2ZkCAwEAAaOCAQcwggEDMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgHWMBAGA1UdJQQJMAcGBWeBBQgDME8GA1UdEQEB_wRFMEOkQTA_MQ4wDAYFZ4EFAgEMA0lCTTEcMBoGBWeBBQICDBFpZDpiJyRfX19RVCAgIFxuJzEPMA0GBWeBBQIDDARpZDoxMIGFBgorBgEEAdZ5AgERBHcwdQIBAwoBAAIBAQoBAQQgZcw7l2U1kk19XN2t9fJ5Rp4t3uU9heBdKAzKAnapwpMEBDkwMDEwG7-DEAUCAwHiQL-DEQUCAwn78b-FPQUCAzAaKTAioQUxAwIBAqMEAgIBAL-DeAMCARe_g3kDAgEev4U-AwIBADANBgkqhkiG9w0BAQsFAAOCAQEAnMEAzWxR_qLnGgecn6ANgQpLDkqKWcPm__gxwUeiTY1EnyvchEeynM0Y7T5w7GPuVAHL4u2uIH-pllMnQRRoWcWe6U_3wNLsu6nApKS_NUDm9MHVUrzAGrROajptMQgaFr3U9wZGuFSdgu-F0EBW27AXNUr3YOOb7qSTuMK2xrAw9-CrXqg51s8AUvcAKE8dLSRpdmKZy6DBLZLZGEJm7aw87GNX0ysvJDHf7dO5sugwyx2JUqGwRj7_zVV7zCBI-v__OCu8WxEiQCWhkDUr96A4VnhWFdIceJQfpeDTw7MXZ9pGdClG-LGMnfDgtKJcqCngN9W3itxpOv6sHustBVkDFTCCAxEwggH5oAMCAQICFBS7kvOToLmW1SyuOdAPSBxFVJ_dMA0GCSqGSIb3DQEBCwUAMCIxIDAeBgNVBAMMF0Zha2UgYW5kcm9pZCB0cnVzdCByb290MB4XDTI2MDYyMTIzNTAxMloXDTI3MDYyMjIzNTAxMlowIjEgMB4GA1UEAwwXRmFrZSBhbmRyb2lkIHRydXN0IHJvb3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDrB9NJAS2GfVx_2U4ezwWOspXzKLDjg_hZjQaVl6hmio3U8tQXAZ9eF4D4EQl8q4rvs3Sc2Uu_AgZjfl1UAoxRisFLJENYSsQksLLSPqLL61a-wnT-7FhcucFL5nnPtTR5gHe4zBSwqhJevl3itI9Y_otr9QkDgFy__bxA3VNtSDO_ecfU0N5Wrp8jOgo9GmiG-Gd4bUVaNOm0636PTfmhvah3ZkUTKeoH8xSG_NZTKcjJkerfyASqpouZgsQ1Qg7T3HU_-vHp7ucgQ2tRBHHdJvL80jKX698IWl3YfRT9NoMXADWProqT4jrN5SN6njnU0RuDeeoc-cde8HX_gKSZAgMBAAGjPzA9MB0GA1UdDgQWBBQwuFLzV4TI-NvCFadUrqhqFy5PejAPBgNVHRMECDAGAQH_AgEDMAsGA1UdDwQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAQEA0YG6VpSOJeU3_jod6HoH3e9B8RySHiHmoGW_SgILfTapXlReg0TcmYWJyrGugGUUPAQ-QuEv0f0uQe9dQ6KMQCAOTao0Cfg2CcGBPlFMg6HiLQ1IrP_RPWJdUthmHIxLIJFz0f3FqGhRxWenmiSv6B9Wv3TM6YiZCNgtfJqPHNemuHqYzY78FHE3Zr_2WskPP-NjTiEprZ6fBGm5S4hqKqdJx8QNR-R_peziaz-nZGkJrTn3ceqqLXjzOw2Qn4N7w7f0QuJ3ukb6lwNeWQob99fusxrzxkVdIZU1u7sNWoxD7aYv4jUq6ilBhG4C6cfyfZ1zNCwH0Ni9nN66E8FKwmNzaWdZAQA4mRk7Rj0iwzE0xAda6R0uVPZCeGKOqG6KzhTyw5jEDcORGyo_OyrdAr1yms0zlSeEahJYGhmnXDXkN1Qo5g6n47UEV_bqoiYRg_ANdvTdovMv4JM94roSukEcwTPuU3ISYIEsYYG2IHZMtY3IbSiaT_CDS5WVMxDLS3E5S6wuy-61d1Q9fmOs3rR-O2o1NGk5Yi-fLqkPr8BKuwFCS7mhlz5DbRJFfXKQnQ3En0JkCoXRR3r4nVVVNtzCoZrGEULhriF8LY3lWLQnnkF8Vboe15DjnqdMzprH_l1TGHtN8stUUWmDfWz3rY_wW6zRTacF8OoAxebT_pdLhAtLlp6gY2FsZzkBAA=='}, 'type': 'public-key', 'getClientExtensionResults': {}}
```