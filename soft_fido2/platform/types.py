# Copyright IBM 2025
# IBM Confidential

"""Platform-neutral types shared across all platform backend implementations."""

from enum import Enum


class BiometricResult(Enum):
    SUCCESS = "verify-match"
    NO_MATCH = "verify-no-match"
    RETRY = "verify-retry-scan"
    DISCONNECTED = "verify-disconnected"
    UNKNOWN_ERROR = "verify-unknown-error"
    NOT_AVAILABLE = "not-available"
    TIMEOUT = "timeout"
