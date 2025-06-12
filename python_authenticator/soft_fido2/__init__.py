from .authenticator import Fido2Authenticator
from .cert_utils import CertUtils
from .key_pair import KeyPair
from .passkey_device import CTAP2HIDevice


if __name__ == "__main__":
    logging.debug("Starting the BeeKey Passkey UHID Service")
    import os, sys
    if os.environ.get("FIDO_HOME") == None:
        logging.debug("Cannot find passkey home \"FIDO_HOME\"")
        sys.exit(1)
    udev = CTAP2HIDevice('/dev/uhid')
    udev.start()
    while udev.is_alive():
        time.sleep(0.25)
    udev.join()