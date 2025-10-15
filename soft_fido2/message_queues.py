# Copyrite IBM 2022, 2025
# IBM Confidential

import queue


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


class MessageQueue:
    notify_udev = queue.Queue(maxsize=100)
    notify_sysapp = queue.Queue(maxsize=100)
    notify_auth = queue.Queue(maxsize=100)
    sysapp_get = queue.Queue(maxsize=100)
    udev_get = queue.Queue(maxsize=100)
