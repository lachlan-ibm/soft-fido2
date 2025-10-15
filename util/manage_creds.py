import os, sys
from soft_fido2.key_pair import KeyUtils
from cryptography.hazmat.primitives import hashes
from getpass import getpass

if "FIDO_HOME" not in os.environ:
    print("FIDO_HOME not set")
    sys.exit(1)

pin = getpass(prompt="Pin [00000000]: ")
pin = "00000000" if pin == None or len(pin) == 0 else pin
passkey = input("Passkey filename [default]: ")
passkey = "default" if passkey == None or len(passkey) == 0 else passkey
passkey = os.path.join(os.environ.get("FIDO_HOME"), passkey + '.passkey')
digest = hashes.Hash(hashes.SHA256())
digest.update(pin.encode())
pinHash = digest.finalize()[:16]

try:
    d = KeyUtils._load_passkey(pinHash, passkey) #Throws if invalid
except Exception as e:
    print("Pin is invalid or passkey does not exist")
    exit(1)
ca = d['ca']
pk = d['pk']
seed = d['seed']
resCreds = d.get('res_creds', [])
print(f"Passkey {passkey} in {os.environ.get("FIDO_HOME")} "\
        "can be validated with the provided pin! :)")
newCreds = []
prompt = "Remove credential for user {} on {}? Y:[N]"
for cred in resCreds:
    for k, v in cred.items():
        if k != 'user': #rpID
            rpID = k
            rp, userID = cred[rpID], cred['user']
            print("\nCredential for user \"{}\" on \"{}\"\n{}".format(userID, rpID, rp))
            rsp = input(prompt.format(userID, rpID))
            if rsp.upper() != 'Y':
                newCreds += [cred]
d['res_creds'] = newCreds
KeyUtils._save_passkey(d, pinHash, passkey)
