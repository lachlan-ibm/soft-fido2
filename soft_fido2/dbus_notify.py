# Copyright IBM 2025
# IBM Confidential

"""
D-Bus notification module for interactive desktop notifications.

This module provides direct D-Bus communication with org.freedesktop.Notifications
for reliable, interactive desktop notifications on Linux systems.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

import dbus
from dbus.mainloop.glib import DBusGMainLoop


class DBusNotifier:
    """Direct D-Bus notification with interactive action support"""
    
    URGENCY_LOW = 0
    URGENCY_NORMAL = 1
    URGENCY_CRITICAL = 2
    
    # Configuration constants
    APP_NAME = 'AyeBeKey'
    DEFAULT_ICON = 'dialog-password'
    NEW_NOTIFICATION_ID = 0
    
    def __init__(self):
        """Initialize D-Bus connection to org.freedesktop.Notifications"""
        self._available = False
            
        try:
            # Initialize D-Bus main loop integration BEFORE creating connection
            DBusGMainLoop(set_as_default=True)
            
            self.bus = dbus.SessionBus()
            self.notify_service = self.bus.get_object(
                'org.freedesktop.Notifications',
                '/org/freedesktop/Notifications'
            )
            self.notify_interface = dbus.Interface(
                self.notify_service,
                'org.freedesktop.Notifications'
            )
            self._available = True
            logging.info("D-Bus notification service initialized")
        except Exception as e:
            self._available = False
            logging.warning(f"D-Bus notifications unavailable: {e}")
    
    def is_available(self):
        """Check if D-Bus notification service is available"""
        return self._available
    
    def get_capabilities(self):
        """Query server capabilities (check for 'actions' support)"""
        if not self._available:
            return []
        try:
            return self.notify_interface.GetCapabilities()
        except Exception as e:
            logging.error(f"Failed to get notification capabilities: {e}")
            return []
    
    def _build_action_array(self, actions: Optional[List[Tuple[str, str]]]) -> List[str]:
        """
        Flatten action tuples into D-Bus action array format.
        
        Args:
            actions: List of (action_key, button_label) tuples
        
        Returns:
            Flat list: ['key1', 'label1', 'key2', 'label2', ...]
        
        Example:
            >>> _build_action_array([('accept', 'Accept'), ('decline', 'Decline')])
            ['accept', 'Accept', 'decline', 'Decline']
        """
        if not actions:
            return []
        return [item for pair in actions for item in pair]
    
    def _build_hints_dict(
        self,
        hints: Optional[Dict[str, Any]],
        urgency: int
    ) -> Dict[str, Any]:
        """
        Build D-Bus hints dictionary with urgency level.
        
        Args:
            hints: User-provided hints (not mutated)
            urgency: Urgency level (0=low, 1=normal, 2=critical)
        
        Returns:
            New dictionary with urgency as dbus.Byte
        """
        result = dict(hints or {})
        result['urgency'] = dbus.Byte(urgency)
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
        """
        Send interactive notification with action buttons
        
        Args:
            title: Notification title
            message: Notification body text
            urgency: URGENCY_LOW, URGENCY_NORMAL, or URGENCY_CRITICAL
            timeout: Milliseconds before auto-dismiss (0 = never, -1 = default)
            actions: List of (action_key, button_label) tuples
                    e.g., [('accept', 'Accept'), ('decline', 'Decline')]
            hints: Dictionary of additional hints
            icon: Icon name or path (default: 'dialog-password')
        
        Returns:
            notification_id for tracking callbacks, or None on failure
            
        Example:
            >>> notifier.send_notification(
            ...     "Auth Request",
            ...     "Accept authentication?",
            ...     urgency=DBusNotifier.URGENCY_CRITICAL,
            ...     actions=[('accept', 'Accept'), ('decline', 'Decline')]
            ... )
        """
        if not self._available:
            return None
        
        try:
            action_array = self._build_action_array(actions)
            hint_dict = self._build_hints_dict(hints, urgency)
            
            # Send notification via D-Bus
            notification_id = self.notify_interface.Notify(self.APP_NAME, self.NEW_NOTIFICATION_ID,
                icon or self.DEFAULT_ICON, title or self.APP_NAME, message, action_array, hint_dict, timeout)
            
            logging.info(f"Sent D-Bus notification ID {notification_id}: {title}")
            return notification_id
            
        except (Exception, TypeError, ValueError) as e:
            logging.error(f"Failed to send notification ({type(e).__name__}): {e}")
            return None
    
    def close_notification(self, notification_id):
        """Close notification via D-Bus CloseNotification method"""
        if not self._available or notification_id is None:
            return
        
        try:
            self.notify_interface.CloseNotification(notification_id)
            logging.info(f"Closed D-Bus notification ID {notification_id}")
        except Exception as e:
            logging.error(f"Failed to close notification {notification_id}: {e}")


class DBusNotificationListener:
    """Listen for user interactions with notifications via D-Bus signals"""
    
    def __init__(self, on_action_callback, on_closed_callback):
        """
        Set up D-Bus signal receivers
        
        Args:
            on_action_callback: Function(notification_id, action_key)
            on_closed_callback: Function(notification_id, reason)
        """
        self.on_action_callback = on_action_callback
        self.on_closed_callback = on_closed_callback
        self._available = False
        
        try:
            self.bus = dbus.SessionBus()
            
            # Connect to ActionInvoked signal
            self.bus.add_signal_receiver(
                self._handle_action_invoked,
                signal_name='ActionInvoked',
                dbus_interface='org.freedesktop.Notifications',
                path='/org/freedesktop/Notifications'
            )
            
            # Connect to NotificationClosed signal
            self.bus.add_signal_receiver(
                self._handle_notification_closed,
                signal_name='NotificationClosed',
                dbus_interface='org.freedesktop.Notifications',
                path='/org/freedesktop/Notifications'
            )
            
            self._available = True
            logging.info("D-Bus notification listener initialized")
            
        except Exception as e:
            logging.warning(f"D-Bus notification listener unavailable: {e}")
    
    def is_available(self):
        """Check if listener is available"""
        return self._available
    
    def _handle_action_invoked(self, notification_id, action_key):
        """
        Called when user clicks an action button
        
        Args:
            notification_id: ID of the notification
            action_key: Key of the clicked action (e.g., 'accept', 'decline')
        """
        logging.info(f"Notification {notification_id} action invoked: {action_key}")
        if self.on_action_callback:
            self.on_action_callback(notification_id, action_key)
    
    def _handle_notification_closed(self, notification_id, reason):
        """
        Called when notification is closed
        
        Args:
            notification_id: ID of the notification
            reason: 1=expired, 2=dismissed by user, 3=closed by app, 4=undefined
        """
        reason_map = {1: 'expired', 2: 'dismissed', 3: 'closed by app', 4: 'undefined'}
        reason_str = reason_map.get(reason, f'unknown({reason})')
        logging.info(f"Notification {notification_id} closed: {reason_str}")
        
        if self.on_closed_callback:
            self.on_closed_callback(notification_id, reason)

# Made with Bob
