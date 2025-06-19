#!/bin/bash

#Read password/pin
echo -n "Pin [0000]: "
read -s READ_PIN
#Get file name
echo -n -e "\nPasskey filename [default]: "
read READ_PASSKEY
PASSKEY="${READ_PASSKEY:-"default"}"
FIDO2_DIR="$HOME/.fido2"
AUTHENTICATOR_FILE="$HOME/.fido2/$PASSKEY.passkey"
mkdir -p $FIDO2_DIR

echo -e "${READ_PIN:-"0000"}\n$AUTHENTICATOR_FILE" | python <(cat <<EOF
import sys, secrets, base64
import cbor2 as cbor
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from soft_fido2.key_pair import KeyUtils, KeyPair
from soft_fido2.cert_utils import CertUtils

pin, passkey = sys.stdin.read().splitlines()
digest = hashes.Hash(hashes.SHA256())
digest.update(pin.encode())
pinHash = digest.finalize()[:16]
kp = KeyPair.generate_ecdsa()
subj = x509.Name([ x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'Pirate Passkey'),
                   x509.NameAttribute(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME, u'IBM Security') ])
pem = CertUtils.gen_ca_cert(subject=subj, lifetime=9999, keyPair=kp)
d = {'ca': pem.public_bytes(encoding=serialization.Encoding.DER),
     'pk': { 'pv': kp.get_private().private_numbers().private_value,
             'c': kp.get_private().curve.name},
     'seed': base64.urlsafe_b64encode(secrets.token_bytes(32))
}
KeyUtils._save_passkey(d, passkey, pinHash)
EOF
)

echo "Passkey $PASSKEY.passkey created in $FIDO2_DIR directory; don't loose your pin!"
