# Copyright IBM 2025
# IBM Confidential

"""
D-Bus notification module for interactive desktop notifications.

This module provides direct D-Bus communication with org.freedesktop.Notifications
for reliable, interactive desktop notifications on Linux systems.
"""

import logging
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from jeepney import DBusAddress, HeaderFields, MatchRule, MessageType, new_method_call
    from jeepney.io.blocking import open_dbus_connection
    from jeepney.wrappers import new_method_call as wrappers_new_method_call
    _JEEPNEY_AVAILABLE = True
except ImportError:
    _JEEPNEY_AVAILABLE = False


class DBusNotifier:
    """Direct D-Bus notification with interactive action support"""

    URGENCY_LOW = 0
    URGENCY_NORMAL = 1
    URGENCY_CRITICAL = 2

    APP_NAME = 'AyeBeKey'
    DEFAULT_ICON = 'dialog-password'
    NEW_NOTIFICATION_ID = 0
    NOTIFICATIONS_PATH = '/org/freedesktop/Notifications'
    NOTIFICATIONS_BUS_NAME = 'org.freedesktop.Notifications'
    NOTIFICATIONS_INTERFACE = 'org.freedesktop.Notifications'

    def __init__(self):
        """Initialize D-Bus connection to org.freedesktop.Notifications."""
        self._available = False
        self._connection = None
        self._notifications = DBusAddress(
            self.NOTIFICATIONS_PATH,
            bus_name=self.NOTIFICATIONS_BUS_NAME,
            interface=self.NOTIFICATIONS_INTERFACE
        )

        try:
            self._connection = open_dbus_connection(bus='SESSION')
            self._install_signal_matches()
            self._available = True
            logging.info("D-Bus notification service initialized")
        except Exception as e:
            self._available = False
            self._connection = None
            logging.warning(f"D-Bus notifications unavailable: {e}")

    def is_available(self) -> bool:
        """Check if D-Bus notification service is available."""
        return self._available

    def get_capabilities(self) -> List[str]:
        """Query server capabilities (check for 'actions' support)."""
        if not self._available or self._connection is None:
            return []

        try:
            msg = new_method_call(self._notifications, 'GetCapabilities')
            reply = self._connection.send_and_get_reply(msg)
            return list(reply.body[0])
        except Exception as e:
            logging.error(f"Failed to get notification capabilities: {e}")
            return []

    def _install_signal_matches(self) -> None:
        """Subscribe to notification signals on the session bus."""
        if self._connection is None:
            return

        for member in ('ActionInvoked', 'NotificationClosed'):
            rule = MatchRule(
                type='signal',
                interface=self.NOTIFICATIONS_INTERFACE,
                member=member,
                path=self.NOTIFICATIONS_PATH
            )
            msg = wrappers_new_method_call(
                DBusAddress(
                    '/org/freedesktop/DBus',
                    bus_name='org.freedesktop.DBus',
                    interface='org.freedesktop.DBus'
                ),
                'AddMatch',
                signature='s',
                body=(rule.serialise(),)
            )
            self._connection.send_and_get_reply(msg)

    def _build_action_array(self, actions: Optional[List[Tuple[str, str]]]) -> List[str]:
        """Flatten action tuples into D-Bus action array format."""
        if not actions:
            return []
        return [item for pair in actions for item in pair]

    def _build_hints_dict(
        self,
        hints: Optional[Dict[str, Any]],
        urgency: int
    ) -> Dict[str, Tuple[str, Any]]:
        """Build D-Bus hints dictionary with urgency level."""
        result: Dict[str, Tuple[str, Any]] = {}
        for key, value in dict(hints or {}).items():
            if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], str):
                result[key] = value
            elif isinstance(value, bool):
                result[key] = ('b', value)
            elif isinstance(value, int):
                result[key] = ('i', value)
            elif isinstance(value, str):
                result[key] = ('s', value)
            else:
                raise TypeError(f"Unsupported D-Bus hint type for '{key}': {type(value).__name__}")

        result['urgency'] = ('y', urgency)
        return result

    def send_notification(
        self,
        title: str,
        message: str,
        urgency: int = URGENCY_NORMAL,
        timeout: int = 5000,
        actions: Optional[List[Tuple[str, str]]] = None,
        hints: Optional[Dict[str, Any]] = None,
        icon: Optional[str] = None
    ) -> Optional[int]:
        """Send interactive notification with action buttons."""
        if not self._available or self._connection is None:
            return None

        try:
            action_array = self._build_action_array(actions)
            hint_dict = self._build_hints_dict(hints, urgency)

            msg = new_method_call(
                self._notifications,
                'Notify',
                'susssasa{sv}i',
                (
                    self.APP_NAME,
                    self.NEW_NOTIFICATION_ID,
                    icon or self.DEFAULT_ICON,
                    title or self.APP_NAME,
                    message,
                    action_array,
                    hint_dict,
                    timeout
                )
            )

            reply = self._connection.send_and_get_reply(msg)
            notification_id = int(reply.body[0])

            logging.info(f"Sent D-Bus notification ID {notification_id}: {title}")
            return notification_id

        except (Exception, TypeError, ValueError) as e:
            logging.error(f"Failed to send notification ({type(e).__name__}): {e}")
            return None

    def close_notification(self, notification_id: Optional[int]) -> None:
        """Close notification via D-Bus CloseNotification method."""
        if not self._available or self._connection is None or notification_id is None:
            return

        try:
            msg = new_method_call(
                self._notifications,
                'CloseNotification',
                'u',
                (notification_id,)
            )
            self._connection.send(msg)
            logging.info(f"Closed D-Bus notification ID {notification_id}")
        except Exception as e:
            logging.error(f"Failed to close notification {notification_id}: {e}")

    def receive_signal(self, timeout: float = 0.01):
        """Receive a single D-Bus signal message if available."""
        if not self._available or self._connection is None:
            return None

        try:
            msg = self._connection.receive(timeout=timeout)
        except TimeoutError:
            return None

        if msg is None or msg.header.message_type != MessageType.signal:
            return None

        return msg


class DBusNotificationListener:
    """Listen for user interactions with notifications via polled D-Bus signals."""

    def __init__(self, notifier: DBusNotifier, on_action_callback: Callable[[int, str], None],
                 on_closed_callback: Callable[[int, int], None]):
        """Initialize listener using the notifier's shared D-Bus connection."""
        self._notifier = notifier
        self.on_action_callback = on_action_callback
        self.on_closed_callback = on_closed_callback
        self._available = notifier.is_available()

        if self._available:
            logging.info("D-Bus notification listener initialized")

    def is_available(self) -> bool:
        """Check if listener is available."""
        return self._available

    def poll(self) -> None:
        """Poll for pending notification signals and dispatch callbacks."""
        if not self._available:
            return

        while True:
            msg = self._notifier.receive_signal(timeout=0.0)
            if msg is None:
                return

            if msg.header.fields.get(HeaderFields.member) == 'ActionInvoked':
                notification_id, action_key = msg.body
                self._handle_action_invoked(int(notification_id), str(action_key))
            elif msg.header.fields.get(HeaderFields.member) == 'NotificationClosed':
                notification_id, reason = msg.body
                self._handle_notification_closed(int(notification_id), int(reason))

    def _handle_action_invoked(self, notification_id: int, action_key: str) -> None:
        """Called when user clicks an action button."""
        logging.info(f"Notification {notification_id} action invoked: {action_key}")
        if self.on_action_callback:
            self.on_action_callback(notification_id, action_key)

    def _handle_notification_closed(self, notification_id: int, reason: int) -> None:
        """Called when notification is closed."""
        reason_map = {1: 'expired', 2: 'dismissed', 3: 'closed by app', 4: 'undefined'}
        reason_str = reason_map.get(reason, f'unknown({reason})')
        logging.info(f"Notification {notification_id} closed: {reason_str}")

        if self.on_closed_callback:
            self.on_closed_callback(notification_id, reason)

