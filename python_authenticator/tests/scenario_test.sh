#!/bin/bash

set -e

#compile
python setup.py sdist bdist_wheel

#run tests
PYTHONPATH="$PYTHONPATH:./build/lib" python3 << EOF
import json
import requests
from soft_FIDO2 import Fido2Authenticator

#This will create a Fido2Authenticator with 2048-bit RSA key
authenticator = Fido2Authenticator()

attestation_options = {
                        "rp": {
                            "id": "runtime.scenario.tests",
                            "name": "Runtime Scenario Tests"
                        },
                        "user": {
                            "id": "NTBOMU5WUUtHMA",
                            "name": "jessica",
                            "displayName": "super trusted authenticator"
                        },
                        "timeout": 240000,
                        "challenge": "R8MuBfC52gc1RD2quII5qPfvIH4rVDZOnXuEgL3wIAo",
                        "excludeCredentials": [
                            {
                                "id": "2QqNtNAQqIT1wRyrHNn9iOYIC6rYh30D7BCDlPv3ypY",
                                "type": "public-key"
                            }
                        ],
                        "authenticatorSelection": {
                            "requireResidentKey": True,
                            "authenticatorAttachment": "cross-platform",
                            "userVerification": "preferred"
                        },
                        "attestation": "direct",
                        "pubKeyCredParams": [
                            {
                                "alg": -7,
                                "type": "public-key"
                            },
                            {
                                "alg": -257,
                                "type": "public-key"
                            }
                        ]
                    }
# Credentail Create Options
cco = authenticator.attestation_options_response_to_credential_create_options(attestation_options).get('publicKey', {})
assert cco.get('rp', {}).get('id') == attestation_options['rp']['id'], "rpId invalid;\n got [{}] expected [{}]".format(
        cco.get('rp', {}).get('id'), attestation_options['rp']['id'])
assert authenticator._urlb64_encode( cco.get('user', {}).get('id') ) == attestation_options['user']['id'], "userId invalid;\n got [{}] expected [{}]".format(
        authenticator._urlb64_encode( cco.get('user', {}).get('id') ), attestation_options['user']['id'])
assert authenticator._urlb64_encode( cco.get('challenge') ) == attestation_options['challenge'], "challenge invalid\n Got [{}] expected [{}]".format(
        authenticator._urlb64_encode( cco.get('challenge') ), attestation_options['challenge'])

# Client Data JSON
clientDataJSON = json.loads( authenticator.build_client_data_JSON( cco ) )
assert clientDataJSON.get('origin') == 'https://' + cco.get('rp', {}).get('id', ''), "origin not correct"
assert clientDataJSON.get('challenge') == attestation_options['challenge'], "challenge incorrect\n Got [{}] expected [{}]".format(
        clientDataJSON.get('challenge'), attestation_options['challenge'])
assert clientDataJSON.get('type') == 'webauthn.create'

# Authenticator Data
auth_data = authenticator.build_authenticator_data( cco, 'packed-self', authenticator.kp, False )


EOF

PYTHONPATH="$PYTHONPATH:./build/lib" python3 << EOF
import json
import requests
from soft_FIDO2 import Fido2Authenticator

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

##Assertion
assertion_options = {
  "rpId": "www.myrp.ibm.com",
  "timeout": 60000,
  "challenge": "kI9SKJRxv4zpICnG1Ls9FMwQ4t4Zq6t8HqKAJKzeyXI",
  "extensions": {},
}

assertion_response = authenticator.credential_request(assertion_options)
print(json.dumps(assertion_response, indent=4))

EOF
