#!/bin/python
import logging, sys, os, time, queue
try:
    from .passkey_device import CTAP2HIDevice
    from .systray_app import SysTrayIcon
except:
    try:
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
        from passkey_device import CTAP2HIDevice
        from systray_app import SysTrayIcon
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
#logging.basicConfig(level=logging.DEBUG, format='%(message)s')
logging.info("Starting the EyeBeeKey Passkey UHID Service")
print("Starting the EyeBeeKey Passkey UHID Service")

uts_msg_queue = queue.Queue(maxsize=100)
stu_msg_queue = queue.Queue(maxsize=100)
udev = CTAP2HIDevice('/dev/uhid', uts_msg_queue, stu_msg_queue)
udev.start()
systrayapp = SysTrayIcon(uts_msg_queue, stu_msg_queue)
udev.join()
