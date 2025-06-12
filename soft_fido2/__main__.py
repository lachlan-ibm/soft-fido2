from .passkey_device import CTAP2HIDevice
import logging, sys, os, time
if os.environ.get("FIDO_HOME") == None:
    sys.exit(1)
logPath = os.path.join(os.environ.get("FIDO_HOME"), 'passkey.log')
logging.basicConfig(filename=logPath, filemode='a', level=logging.DEBUG, format='%(message)s')
logging.debug("Starting the EyeBeeKey Passkey UHID Service")
udev = CTAP2HIDevice('/dev/uhid')
udev.start()
while udev.is_alive():
    time.sleep(0.25)
udev.join()