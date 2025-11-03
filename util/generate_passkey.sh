#!/bin/bash

#Read password/pin
echo -n "Pin [00000000]: "
read -s READ_PIN
READ_PIN="${READ_PIN:-"00000000"}"
if [[ ${#READ_PIN} -lt 8 ]]; then
        echo -e "\nMinimum pin length (8) not met"
        exit 1
fi

#Get file name
echo -n -e "\nPasskey filename [default]: "
read READ_PASSKEY
PASSKEY="${READ_PASSKEY:-"default"}"
FIDO2_DIR="$HOME/.fido2"
AUTHENTICATOR_FILE="$HOME/.fido2/$PASSKEY.passkey"
mkdir -p $FIDO2_DIR

echo -e "$READ_PIN\n$AUTHENTICATOR_FILE" | python <(cat <<EOF
import sys
from cryptography.hazmat.primitives import hashes
from soft_fido2.key_pair import KeyUtils

pin, passkey = sys.stdin.read().splitlines()

KeyUtils._save_passkey(KeyUtils.generate_passkey(), KeyUtils.get_pin_hash(pin), passkey)
EOF
)

echo "Passkey $PASSKEY.passkey created in $FIDO2_DIR directory; don't loose your pin!"
