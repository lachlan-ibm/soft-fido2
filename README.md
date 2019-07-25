* Prerequisites:
  * Python libraries:
    * cryptography
    * cbor2

Using soft_fido2.py

From the cmd line:

attestation:
`python3 soft_fido2.py 'attestation' 'attestation_format' 'attestation_options(as json string)'`

prints a json string with the attestation response

assertion:
`python3 soft_fido2.py 'assertion' 'assertion_optsion(as json string)'`

prints a json string with the assertion response



As a python module:
First install from artifactory (requires artifactory API key, can be generates @ https://eu.artifactory.swg-devops.com/artifactory)
* `pip3 install fido2_authenticator --extra-index https://eu.artifactory.swg-devops.com/artifactory/api/pypi/sec-iam-components-pypi-virtual/simple`
```python
from fiod2_authenticator.soft_fido2 import Fido2Authenticatior
#This will create a Fido2Authenticator with 2048-bit RSA key
authenticator = Fido2Authenticator()
##Attestation
#attestation_options should be either a python dictionary or a JSON string
rsp = authenticator.credential_create(attestation_options)


##Assertion
#assertion_options should be either a python dictionary or a JSON string
rsp = authenticator.credential_request(assertion_options)
```
