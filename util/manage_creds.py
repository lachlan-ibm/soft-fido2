import os, sys
from soft_fido2.key_pair import KeyUtils
from cryptography.hazmat.primitives import hashes
from getpass import getpass

if "FIDO_HOME" not in os.environ:
    print("FIDO_HOME not set")
    sys.exit(1)
if not "FIDO_HOME" in os.environ:
    raise ValueError("FIDO_HOME not set")
pin = getpass(prompt="Pin [00000000]: ")
pin = "00000000" if pin == None or len(pin) == 0 else pin
passkey = input("Passkey filename [default]: ")
passkey = "default" if passkey == None or len(passkey) == 0 else passkey
passkey = os.path.join(os.environ["FIDO_HOME"], passkey + '.passkey')
pinHash = KeyUtils.get_pin_hash(pin)
lowerPinHash = pinHash[:16]

try:
    d = KeyUtils._load_passkey(lowerPinHash, passkey) #Throws if invalid
except Exception as e:
    print("Pin is invalid or passkey does not exist")
    exit(1)
ca = d['x5c']
pk = d['key']
resCreds = d.get('res.creds', [])
print(f"Passkey {passkey} in {os.environ.get("FIDO_HOME")} "\
        "can be validated with the provided pin! :)")
newCreds = []
prompt = "Remove credential for user {} on {}? Y:[N]"
for cred in resCreds:
    rpId = cred['rp.id']
    userId = cred['user.id']
    credId = cred['cred.id']
    print("\nCredential for user \"{}\" on \"{}\"\n{}".format(userId, rpId, credId))
    rsp = input(prompt.format(userId, rpId))
    if rsp.upper() != 'Y':
        newCreds += [cred]
d['res.creds'] = newCreds
KeyUtils._save_passkey(
    d['key'],
    d['x5c'],
    d['res.creds'],
    pinHash,
    passkey
)
