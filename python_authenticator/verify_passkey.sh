#!/bin/bash

#Read password/pin
echo -n "Pin [0000]: "
read -s READ_PIN
PIN="${READ_PIN:-"0000"}"
#Get file name
echo -n -e "\nPasskey filename [default]: "
read READ_PASSKEY
PASSKEY="${READ_PASSKEY:-"default"}"
FIDO2_DIR="$HOME/.fido2"
AUTHENTICATOR_FILE="$HOME/.fido2/$PASSKEY.passkey"
mkdir -p $FIDO2_DIR

export PASSKEYSRCDIR="`dirname $0`/soft_FIDO2/"
echo $PASSKEYSRCDIR
echo -e "$PIN\n$AUTHENTICATOR_FILE" | python <(cat <<EOF
import os, sys, secrets
import cbor2 as cbor
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
sys.path.append(os.path.realpath(os.environ.get("PASSKEYSRCDIR")))
from key_pair import KeyUtils, KeyPair
from cert_utils import CertUtils

pin, passkey = sys.stdin.read().splitlines()
digest = hashes.Hash(hashes.SHA256())
digest.update(pin.encode())
pinHash = digest.finalize()[:16]
aesKey = algorithms.AES128(pinHash)
with open(passkey, 'rb') as f:
    everything = f.read()
    iv = everything[:16]
    tag = everything[16:32]
    encKeyAndCert = everything[32:]
    decryptor = Cipher(aesKey, modes.GCM(iv, tag)).decryptor()
    cborKeyAndPem = decryptor.update(encKeyAndCert) + decryptor.finalize()
    d = cbor.loads(cborKeyAndPem)
    ca = d['ca']
    pk = d['pk']
    seed = d['seed']
    f.close()
EOF
)

echo "Passkey $PASSKEY.passkey in $FIDO2_DIR van be validated with the provided pin! :)"
