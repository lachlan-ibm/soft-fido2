#!/bin/python
import logging, sys, os, time
try:
    from .passkey_device import CTAP2HIDevice
except:
    try:
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
        from passkey_device import CTAP2HIDevice
    except Exception as e:
        logging.debug("Module load error")
        logging.exception(e)
        raise e


if os.environ.get("FIDO_HOME") == None:
    sys.exit(1)
ll = logging.INFO
if "SOFT_FIDO2_DEBUG_LEVEL" in os.environ:
    ll = os.environ.get("SOFT_FIDO2_DEBUG_LEVEL")

#logPath = os.path.join(os.environ.get("FIDO_HOME"), 'passkey.log')
logging.basicConfig(level=ll, format='%(message)s')
logging.info("Starting the EyeBeeKey Passkey UHID Service")
print("Starting the EyeBeeKey Passkey UHID Service")
udev = CTAP2HIDevice('/dev/uhid')
udev.start()
while udev.is_alive():
    time.sleep(0.25)
udev.join()
