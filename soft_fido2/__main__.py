#!/bin/python
# Copyrite IBM 2022, 2025
# IBM Confidential

import logging, sys, os
try:
    from .passkey_device import CTAP2HIDevice
    from .systray_app import SysTrayApp
except:
    try:
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
        from passkey_device import CTAP2HIDevice
        from systray_app import SysTrayApp
    except Exception as e:
        logging.debug("Module load error")
        logging.exception(e)
        raise e


if os.environ.get("FIDO_HOME") == None:
    sys.exit(1)
ll = logging.INFO
if "SOFT_FIDO2_DEBUG_LEVEL" in os.environ:
    ll = os.environ.get("SOFT_FIDO2_DEBUG_LEVEL")
logFile = None # > stdout/stderr
if "SOFT_FIDO2_LOG_FILE" in os.environ:
    logFile = os.path.join(
                        os.environ["FIDO_HOME"], os.environ["SOFT_FIDO2_LOG_FILE"])

#logPath = os.path.join(os.environ.get("FIDO_HOME"), 'passkey.log')
logging.basicConfig(level=ll, format='%(message)s', filename=logFile)
#logging.basicConfig(level=logging.DEBUG, format='%(message)s')
logging.info("Starting the EyeBeeKey Passkey UHID Service")
print("Starting the EyeBeeKey Passkey UHID Service")


udev = CTAP2HIDevice('/dev/uhid')
udev.start()
app = SysTrayApp() # runs until quit
udev.join()
