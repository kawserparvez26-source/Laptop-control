"""Core types, protocols, and exceptions for Laptop Control."""

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
from laptop_control.core.protocols import (
    AIInterface,
    CommandHandler,
    MessageInterface,
    Tool,
)
from laptop_control.core.types import (
    Command,
    CommandResult,
    OperationStatus,
    RiskLevel,
    ToolRequest,
    ToolResult,
)

__all__ = [
    # Exceptions
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
    # Types
    "OperationStatus",
    "RiskLevel",
    "Command",
    "CommandResult",
    "ToolRequest",
    "ToolResult",
    # Protocols
    "Tool",
    "AIInterface",
    "CommandHandler",
    "MessageInterface",
]
