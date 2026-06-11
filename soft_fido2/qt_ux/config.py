"""
Configuration Management Module.

This module provides the PlatformConfig class for managing platform-level
configuration with JSON-based persistent storage.

The configuration includes:
- Key type selection (TPM or file-based)
- Info string for HKDF derivation
- Automatic timestamp tracking for modifications
"""

import json
import os
import logging
from datetime import datetime


class PlatformConfig:
    """Manages platform configuration with JSON storage"""

    VERSION = "1.0"
    DEFAULT_INFO = "FIDO2-PASSKEY-SEED"

    def __init__(self, fido_home):
        self.fido_home = fido_home
        self.config_path = os.path.join(fido_home, 'platform.cfg')
        self._config = self._load_config()

    def _load_config(self):
        """Load config from JSON"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    return loaded
                logging.error("Failed to load config: platform.cfg must contain a JSON object")
            except Exception as e:
                logging.error(f"Failed to load config: {e}")

        return self._get_default_config()

    def _get_default_config(self):
        """Get default configuration"""
        return {
            'key_type': None,
            'info_string': self.DEFAULT_INFO
        }

    def save(self):
        """Save configuration to JSON file"""
        self._config['last_modified'] = datetime.utcnow().isoformat() + 'Z'
        try:
            os.makedirs(self.fido_home, exist_ok=True)
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(self._config, f, indent=2)
            logging.info("Configuration saved")
        except Exception as e:
            logging.error(f"Failed to save config: {e}")

    @property
    def key_type(self):
        return self._config.get('key_type')

    @key_type.setter
    def key_type(self, value):
        if value not in ('tpm', 'file', None):
            raise ValueError(f"Invalid key type: {value}")
        self._config['key_type'] = value
        self.save()

    @property
    def info_string(self):
        return self._config.get('info_string', self.DEFAULT_INFO)

    @info_string.setter
    def info_string(self, value):
        if not isinstance(value, str) or not value:
            raise ValueError("Info string must be non-empty string")
        self._config['info_string'] = value
        self.save()
