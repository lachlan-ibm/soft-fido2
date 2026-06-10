"""
Qt UX Components Package

This package contains all PyQt6 UI components for the FIDO2 authenticator
system tray application. Components are organized by responsibility:

- config: Configuration management (PlatformConfig)
- workers: Threading utilities (Worker, WorkerSignals)
- settings_dialog: Settings dialog UI
- advanced_dialog: Advanced configuration dialog UI
- main_window: System tray icon and main window UI
"""

from .config import PlatformConfig
from .workers import Worker, WorkerSignals
from .settings_dialog import SettingsDialog
from .advanced_dialog import AdvancedConfigDialog
from .main_window import SysTrayMainWindow

__all__ = [
    'PlatformConfig',
    'Worker',
    'WorkerSignals',
    'SettingsDialog',
    'AdvancedConfigDialog',
    'SysTrayMainWindow',
]
