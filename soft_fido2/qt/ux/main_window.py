"""System tray icon and main window UI components.

This module handles:
- System tray icon display and state management
- Menu creation and actions
- Notification display (Qt and DBus)

Communicates with parent app via Qt signals/slots and message queues.
"""

import os
import logging
from typing import Optional, List, Tuple

from PyQt6.QtGui import QIcon, QAction
from PyQt6.QtWidgets import QSystemTrayIcon, QMenu
from PyQt6.QtCore import QTimer

try:
    from soft_fido2.message_queues import QueueMessageType, MessageQueue
    from soft_fido2.qt.ux.settings_dialog import SettingsDialog
except ImportError:
    from message_queues import QueueMessageType, MessageQueue
    from qt.ux.settings_dialog import SettingsDialog

try:
    from soft_fido2.platform import Notifier as DBusNotifier
    from soft_fido2.platform import NotificationListener as DBusNotificationListener
except ImportError:
    DBusNotifier = None
    DBusNotificationListener = None


class SysTrayMainWindow:
    """System tray icon and main window UI components.
    
    This class handles:
    - System tray icon display and state
    - Menu creation and actions
    - Notification display (Qt and DBus)
    
    Communicates with parent app via Qt signals/slots and message queues.
    """
    
    class NotificationFramework:
        """Notification framework types."""
        DBUS = 0           # Direct D-Bus (primary)
        QT = 1             # Qt system tray (fallback only)
    
    def __init__(self, parent_app):
        """Initialize with reference to parent SysTrayApp.
        
        Args:
            parent_app: Reference to the parent SysTrayApp instance
        """
        self.app = parent_app
        
        # Load all icon variants
        self.main_icon = self._generate_icon('main_icon.svg', QIcon.ThemeIcon.DialogPassword)
        self.locked_icon = self._generate_icon('main_icon_locked.svg', QIcon.ThemeIcon.DialogPassword)
        self.unlocked_icon = self._generate_icon('main_icon_unlocked.svg', QIcon.ThemeIcon.DialogPassword)
        self.auth_icon = self._generate_icon('auth_request.png', QIcon.ThemeIcon.DialogWarning)
        
        # Create the tray icon
        self._tray_icon = QSystemTrayIcon(self.main_icon, parent_app)
        self._tray_icon.setToolTip('AyeBeeKey')
        
        # Set up notifications
        self.notification_fw = self._setup_notifications()
        
        # Create a timer to reset the icon after a period of time
        self.icon_reset_timer = QTimer(parent_app)
        self.icon_reset_timer.setSingleShot(True)
        self.icon_reset_timer.timeout.connect(self._reset_icon)
        
        # Set up menu
        self.menu = self._menu_setup()
        self._tray_icon.setContextMenu(self.menu)
        self._tray_icon.show()
    
    # === Icon Management ===
    
    def _generate_icon(self, path: str, fallback) -> QIcon:
        """Generate icon from path or fallback to theme icon.
        
        Args:
            path: Relative path to icon file
            fallback: Fallback theme icon
            
        Returns:
            QIcon instance
        """
        icon = None
        # Try to find icon relative to the module directory
        # __file__ is soft_fido2/qt/ux/main_window.py → go up 3 levels to reach soft_fido2/
        module_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        icon_path = os.path.join(module_dir, 'icons', path)
        if os.path.exists(icon_path):
            icon = QIcon(icon_path)
        else:
            # Fallback to theme icon
            icon = QIcon.fromTheme(fallback)
        return icon
    
    def _update_icon_for_state(self):
        """Update the tray icon based on current state."""
        if self.app._current_state == self.app.AppState.LOCKED:
            self._tray_icon.setIcon(self.locked_icon)
            self._tray_icon.setToolTip('AyeBeKey - Locked')
        else:
            self._tray_icon.setIcon(self.unlocked_icon)
            self._tray_icon.setToolTip('AyeBeKey - Unlocked')
    
    def _set_ceremony_icon(self):
        """Set tray icon to main_icon.svg during authentication ceremony."""
        icon_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'icons', 'main_icon.svg')
        if os.path.exists(icon_path):
            self._tray_icon.setIcon(QIcon(icon_path))
            logging.info("Set ceremony icon: main_icon.svg")
    
    def _restore_status_icon(self):
        """Restore tray icon to locked/unlocked status after ceremony."""
        self._update_icon_for_state()
        logging.info("Restored status icon")
    
    def start_icon_reset_timer(self):
        """Start the icon reset timer from the main thread."""
        # Start the timer to reset the icon after 15 seconds (15000 ms)
        self.icon_reset_timer.start(15000)
    
    def _reset_icon(self):
        """Reset the tray icon to the state-appropriate icon and update the tooltip."""
        self._update_icon_for_state()
    
    def set_auth_icon(self):
        """Set the authentication icon and tooltip."""
        self._tray_icon.setIcon(self.auth_icon)
        self._tray_icon.setToolTip('Aye.Be.Key UV')
    
    # === Menu Management ===
    
    def _menu_setup(self) -> QMenu:
        """Set up the system tray menu.
        
        Returns:
            QMenu instance with actions
        """
        menu = QMenu()
        action_setup = [
            self.__settings_action_setup,
            self.__exit_action_setup
        ]
        for action in action_setup:
            menu.addAction(action())
        return menu
    
    def __settings_action_setup(self) -> QAction:
        """Create the Settings menu action.
        
        Returns:
            QAction for settings
        """
        action = QAction('Settings', self.app.app)
        action.triggered.connect(self.app._SysTrayApp__open_settings)
        return action
    
    def __exit_action_setup(self) -> QAction:
        """Create the Exit menu action.
        
        Returns:
            QAction for exit
        """
        action = QAction('Exit', self.app.app)
        action.triggered.connect(self.app._exit)
        return action
    
    # === Notification Management ===
    
    def _setup_notifications(self) -> int:
        """Determine which notification framework to use - D-Bus first, Qt fallback.
        
        Returns:
            NotificationFramework constant (DBUS or QT)
        """
        # Initialize instance variables for D-Bus notification tracking
        self._current_notification_id = None
        self._dbus_notifier = None
        self._dbus_listener = None
        
        # Try D-Bus notification service (primary method with full interactivity)
        if DBusNotifier is not None and DBusNotificationListener is not None:
            self._dbus_notifier = DBusNotifier()
            if self._dbus_notifier.is_available():
                self._dbus_listener = DBusNotificationListener(
                    self._dbus_notifier,
                    on_action_callback=self._handle_notification_action,
                    on_closed_callback=self._handle_notification_closed
                )
                if self._dbus_listener.is_available():
                    self._dbus_poll_timer = QTimer(self.app.app)
                    self._dbus_poll_timer.timeout.connect(self._poll_dbus_notifications)
                    self._dbus_poll_timer.start(100)
                    logging.info("Using D-Bus notifications with interactive support")
                    return self.NotificationFramework.DBUS
                else:
                    logging.warning("D-Bus listener unavailable, falling back to Qt")
            else:
                logging.warning("D-Bus notifier unavailable, falling back to Qt")
        else:
            logging.info("D-Bus module not available, using Qt fallback")
        
        self._dbus_poll_timer = None

        # Fallback to Qt system tray notifications (limited functionality)
        self._tray_icon.messageClicked.connect(self.on_message_clicked)
        logging.info("Using Qt system tray notifications (no interactive buttons)")
        return self.NotificationFramework.QT
    
    def launch_notification(self):
        """Smart startup notification - only show if user action needed.
        
        - If locked: Show "get started" message (needs platform key setup)
        - If unlocked: No notification (app in good state)
        """
        if self.app._current_state == self.app.AppState.LOCKED:
            self._show_notification(
                title=SettingsDialog.TITLE,
                message="Create or unlock the platform key",
                urgency="normal",
                timeout=5000
            )
        # else: No notification when app is in good state
    
    def prompt_notification(self, fprint_pending: bool = False):
        """Show authentication request notification.
        
        Args:
            fprint_pending: Whether fingerprint authentication is pending
        """
        self._show_notification(
            title=SettingsDialog.TITLE + ": UV",
            message="User Verification request: accept" + ("? or scan your fingerprint!" if fprint_pending else "?"),
            urgency="critical",
            timeout=15000,
            actions=[
                ('accept', 'Accept'),
                ('accept_u2f', 'Accept [U2F]'),
                ('decline', 'Decline')
            ] if self.notification_fw == self.NotificationFramework.DBUS else None
        )
    
    def cancel_notification(self):
        """Cancel active notification."""
        if self.notification_fw == self.NotificationFramework.DBUS:
            self._cancel_notification_dbus()
        # Qt notifications don't need explicit cancellation
    
    def _show_notification(self, title: str, message: str, urgency: str = "normal", 
                          timeout: int = 3000, actions: Optional[List[Tuple[str, str]]] = None):
        """Unified notification display - routes to Qt or D-Bus based on framework.
        
        Args:
            title: Notification title
            message: Notification message
            urgency: "low", "normal", or "critical"
            timeout: Display duration in milliseconds
            actions: List of (action_key, button_label) tuples for D-Bus only
        """
        if self.notification_fw == self.NotificationFramework.DBUS:
            self._show_notification_dbus(title, message, urgency, timeout, actions)
        else:
            self._show_notification_qt(title, message, urgency, timeout)
    
    def _show_notification_qt(self, title: str, message: str, urgency: str, timeout: int):
        """Display notification using Qt system tray.
        
        Args:
            title: Notification title
            message: Notification message
            urgency: "low", "normal", or "critical"
            timeout: Display duration in milliseconds
        """
        icon_map = {
            "low": QSystemTrayIcon.MessageIcon.Information,
            "normal": QSystemTrayIcon.MessageIcon.Information,
            "critical": QSystemTrayIcon.MessageIcon.Critical
        }
        self._tray_icon.showMessage(
            title, message, 
            icon_map.get(urgency, QSystemTrayIcon.MessageIcon.Information), 
            timeout
        )
    
    def _show_notification_dbus(self, title: str, message: str, urgency: str, 
                               timeout: int, actions: Optional[List[Tuple[str, str]]] = None):
        """Display notification using D-Bus.
        
        Args:
            title: Notification title
            message: Notification message
            urgency: "low", "normal", or "critical"
            timeout: Display duration in milliseconds
            actions: List of (action_key, button_label) tuples
        """
        if not self._dbus_notifier:
            return
        
        urgency_map = {
            "low": self._dbus_notifier.URGENCY_LOW,
            "normal": self._dbus_notifier.URGENCY_NORMAL,
            "critical": self._dbus_notifier.URGENCY_CRITICAL
        }
        
        # Set ceremony icon for authentication requests
        if urgency == "critical" and actions:
            self._set_ceremony_icon()
            icon_path = os.path.abspath(os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'icons', 'main_icon.svg'
            ))
        else:
            icon_path = 'dialog-password'
        
        self._current_notification_id = self._dbus_notifier.send_notification(
            title=title,
            message=message,
            urgency=urgency_map.get(urgency, self._dbus_notifier.URGENCY_NORMAL),
            timeout=timeout,
            actions=actions or [],
            hints={'category': 'device'} if actions else {},
            icon=icon_path
        )
    
    def _cancel_notification_dbus(self):
        """Cancel active D-Bus notification."""
        if self._dbus_notifier and self._current_notification_id is not None:
            self._dbus_notifier.close_notification(self._current_notification_id)
            self._current_notification_id = None

    def _poll_dbus_notifications(self):
        """Poll pending D-Bus notification signals via the shared notifier connection."""
        if self._dbus_listener is not None:
            self._dbus_listener.poll()
    
    def _handle_notification_action(self, notification_id: int, action_key: str):
        """Handle D-Bus notification action callback.
        
        Args:
            notification_id: ID of the notification
            action_key: Key of the action that was triggered
        """
        logging.info(f"Notification action: {action_key}")
        
        if action_key == 'accept':
            # User clicked Accept button (verified)
            MessageQueue.notify_auth.put(QueueMessageType.USER_RESPONSE_ACCEPT)
            # Restore status icon after user response
            self._restore_status_icon()
        elif action_key == 'accept_u2f':
            # User clicked Accept [U2F] button (U2F mode)
            MessageQueue.notify_auth.put(QueueMessageType.USER_RESPONSE_ACCEPT_U2F)
            # Restore status icon after user response
            self._restore_status_icon()
        elif action_key == 'decline':
            # User clicked Decline button (authentication)
            MessageQueue.notify_auth.put(QueueMessageType.USER_RESPONSE_REJECT)
            # Restore status icon after user response
            self._restore_status_icon()
        elif action_key == 'unlock':
            # User clicked Unlock button (platform key)
            self.app._SysTrayApp__open_settings()
        elif action_key == 'later':
            # User clicked Later button (platform key)
            logging.info("User chose to unlock platform key later")
    
    def _handle_notification_closed(self, notification_id: int, reason: int):
        """Handle notification closed event.
        
        Args:
            notification_id: ID of the notification
            reason: Reason code for closure (1=expired, 2=dismissed, 3=closed by app, 4=undefined)
        """
        reason_map = {1: 'expired', 2: 'dismissed', 3: 'closed by app', 4: 'undefined'}
        reason_str = reason_map.get(reason, f'unknown({reason})')
        logging.info(f"Notification closed: {reason_str}")

        if notification_id == self._current_notification_id:
            self._current_notification_id = None
       
        # Restore status icon when notification expires or is dismissed
        if reason in (1, 2):  # 1=expired, 2=dismissed by user
            self._restore_status_icon()
            if reason == 1:  # Expired - treat as rejection
                MessageQueue.notify_auth.put(QueueMessageType.USER_RESPONSE_REJECT)
    
    def on_message_clicked(self):
        """Handle Qt notification message clicked event."""
        MessageQueue.notify_auth.put(QueueMessageType.USER_RESPONSE_ACCEPT)
    
    def is_visible(self) -> bool:
        """Check if the tray icon is visible.
        
        Returns:
            True if tray icon is visible, False otherwise
        """
        return self._tray_icon.isVisible()
