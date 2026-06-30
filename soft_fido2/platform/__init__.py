# Copyright IBM 2025
# IBM Confidential

"""Platform backend dispatch.

Selects the correct biometric, TPM, and notification implementations based on
the current platform.  Call sites import from here rather than from the
concrete Linux modules directly, so adding a Windows (or other) backend
requires no changes outside this package.

Usage::

    from soft_fido2.platform import BiometricDevice, BiometricResult
    from soft_fido2.platform import get_biometric_device
    from soft_fido2.platform import TPMBackend
    from soft_fido2.platform import Notifier, NotificationListener
"""

import sys

from soft_fido2.platform.types import BiometricResult

if sys.platform == 'win32':
    from soft_fido2.platform.win_biometric import WinBiometricDevice as BiometricDevice
    from soft_fido2.platform.win_biometric import get_biometric_device
    from soft_fido2.platform.win_tpm       import WinTPMDevice       as TPMBackend
    from soft_fido2.platform.win_notify    import WinToastNotifier   as Notifier
    from soft_fido2.platform.win_notify    import WinNotificationListener as NotificationListener
else:
    from soft_fido2.platform.fprint_device import FprintDevice       as BiometricDevice
    from soft_fido2.platform.fprint_device import get_fprint_device  as get_biometric_device
    from soft_fido2.platform.tpm_device    import TPMDevice           as TPMBackend
    from soft_fido2.platform.dbus_notify   import DBusNotifier        as Notifier
    from soft_fido2.platform.dbus_notify   import DBusNotificationListener as NotificationListener
