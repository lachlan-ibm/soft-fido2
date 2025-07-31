#!/bin/bash

#Read password/pin
echo -n "Pin [00000000]: "
read -s READ_PIN
PIN="${READ_PIN:-"00000000"}"
#Get file name
echo -n -e "\nPasskey filename [default]: "
read READ_PASSKEY
PASSKEY="${READ_PASSKEY:-"default"}"
FIDO2_DIR="$HOME/.fido2"
AUTHENTICATOR_FILE="$HOME/.fido2/$PASSKEY.passkey"
mkdir -p $FIDO2_DIR

echo -e "$PIN\n$AUTHENTICATOR_FILE" | python <(cat <<EOF
import sys
from soft_fido2.key_pair import KeyUtils
from cryptography.hazmat.primitives import hashes

pin, passkey = sys.stdin.read().splitlines()
digest = hashes.Hash(hashes.SHA256())
digest.update(pin.encode())
pinHash = digest.finalize()[:16]

d = KeyUtils._load_passkey(pinHash, passkey)
resCreds = d.get('res_creds', [])
print("Resident creds: {}".format(resCreds))
EOF
)
echo "Passkey $PASSKEY.passkey in $FIDO2_DIR can be validated with the provided pin! :)"
