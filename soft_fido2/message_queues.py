# Copyrite IBM 2022, 2025
# IBM Confidential

import queue


class PlatformKeyRequest:
    def __init__(self, request_id: str):
        self.request_id = request_id


class PlatformKeyResponse:
    def __init__(self, request_id: str, key_pair=None, error=None):
        self.request_id = request_id
        self.key_pair = key_pair  # KeyPair object or None
        self.error = error  # Error message or None


class QueueMessageType:
    USER_REQUEST = 0
    USER_RESPONSE_ACCEPT = 1
    USER_RESPONSE_REJECT = 2
    USER_RESPONSE_TIMEOUT = 3
    AUTH_REQUEST = 4
    AUTH_RESPONSE = 5
    KEEPALIVE = 6
    KEEPALIVE_CANCEL = 7
    QUIT = 8
    CLOSE_EVENT = 9
    PLATFORM_KEY_REQUEST = 10
    PLATFORM_KEY_RESPONSE = 11
    PLATFORM_KEY_ERROR = 12


class MessageQueue:
    ''' read by uhid_device.py '''
    notify_udev = queue.Queue(maxsize=10)
    ''' read by systray_app.py '''
    notify_sysapp = queue.Queue(maxsize=10)
    ''' read by passkey_device.py.Authenticator '''
    notify_auth = queue.Queue(maxsize=10)
    ''' read by systray_app.py for platform key requests '''
    platform_key_requests = queue.Queue(maxsize=10)
    ''' read by passkey_device.py for platform key responses '''
    platform_key_responses = queue.Queue(maxsize=10)