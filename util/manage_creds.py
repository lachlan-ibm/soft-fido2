import os, sys
from soft_fido2.key_pair import KeyUtils
from cryptography.hazmat.primitives import hashes

if "FIDO_HOME" not in os.environ:
    print("FIDO_HOME not set")
    sys.exit(1)

pin = input("Pin [0000]: ")
pin = "0000" if pin == None or len(pin) == 0 else pin
passkey = input("Passkey filename [default]: ")
passkey = "default" if passkey == None or len(passkey) == 0 else passkey
passkey = os.path.join(os.environ.get("FIDO_HOME"), passkey + '.passkey')
digest = hashes.Hash(hashes.SHA256())
digest.update(pin.encode())
pinHash = digest.finalize()[:16]

d = KeyUtils._load_passkey(pinHash, passkey) #Throws if invalid
ca = d['ca']
pk = d['pk']
seed = d['seed']
resCreds = d.get('res_creds', [])
print(f"Passkey {passkey} in {os.environ.get("FIDO_HOME")} "\
        "can be validated with the provided pin! :)")
newCreds = []
prompt = "Remove credential for {} Y:[N]"
for cred in resCreds:
    print("Credential: {}".format(cred))
    for k, v in cred.items():
        if k != 'user': #rpId
            rsp = input(prompt.format(k))
            if rsp.upper() != 'Y':
                newCreds += [cred]
d['res_creds'] = newCreds
KeyUtils._save_passkey(d, pinHash, passkey)