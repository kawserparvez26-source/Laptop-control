"""Laptop Control - Secure AI-powered remote computer control system.

A modular, extensible platform using Google Gemini as the central AI coordinator
for secure remote computer management via Telegram.
"""

__version__ = "0.1.0"
__author__ = "Kawser Parvez"
__email__ = "kawserparvez26@gmail.com"

from laptop_control.core.exceptions import (
    AuditLogError,
    AuthorizationError,
    CommandValidationError,
    ConfigurationError,
    EmergencyStopTriggered,
    LaptopControlException,
    SecurityError,
    ToolExecutionError,
    ToolNotFoundError,
    ToolRuntimeError,
)

__all__ = [
    "LaptopControlException",
    "ConfigurationError",
    "AuthorizationError",
    "ToolExecutionError",
    "ToolNotFoundError",
    "CommandValidationError",
    "ToolRuntimeError",
    "SecurityError",
    "EmergencyStopTriggered",
    "AuditLogError",
]
