"""Core data types and models for Laptop Control.

Defines typed dataclasses and enums used throughout the system
for consistency and type safety.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class OperationStatus(Enum):
    """Status of an operation or tool execution.

    Attributes:
        PENDING: Operation queued but not started
        RUNNING: Operation currently executing
        SUCCESS: Operation completed successfully
        FAILED: Operation failed with error
        TIMEOUT: Operation exceeded time limit
        CANCELLED: Operation was cancelled by user or system
    """

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class RiskLevel(Enum):
    """Risk level associated with an operation.

    Higher risk operations may require additional authorization
    or approval before execution.

    Attributes:
        LOW: Safe operation with minimal system impact
        MEDIUM: Normal operation, standard authorization sufficient
        HIGH: Significant system impact, may require approval
        CRITICAL: System-critical operation, requires explicit approval
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Command:
    """A user command to be executed.

    Attributes:
        user_id: Telegram user ID who issued the command
        tool_name: Name of the tool to use (e.g., "filesystem", "terminal")
        operation: Specific operation within the tool
        parameters: Dict of parameters for the operation
        timestamp: Unix timestamp when command was issued
        request_id: Unique identifier for tracking this request
        risk_level: Risk level of this command
    """

    user_id: int
    tool_name: str
    operation: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0
    request_id: str = ""
    risk_level: RiskLevel = RiskLevel.MEDIUM


@dataclass
class CommandResult:
    """Result of a command execution.

    Attributes:
        command: Original Command that was executed
        status: Execution status
        output: Command output/result
        error: Error message if status is FAILED
        execution_time: Time taken to execute in seconds
        tool_metadata: Additional metadata from the tool
    """

    command: Command
    status: OperationStatus
    output: str = ""
    error: Optional[str] = None
    execution_time: float = 0.0
    tool_metadata: Dict[str, Any] = field(default_factory=dict)

    def is_successful(self) -> bool:
        """Check if command executed successfully.

        Returns:
            True if status is SUCCESS, False otherwise.
        """
        return self.status == OperationStatus.SUCCESS

    def is_error(self) -> bool:
        """Check if command failed.

        Returns:
            True if status is FAILED or TIMEOUT, False otherwise.
        """
        return self.status in (OperationStatus.FAILED, OperationStatus.TIMEOUT)


@dataclass
class ToolRequest:
    """Request to execute a tool.

    Represents a request sent to a tool for execution, with all
    necessary context for authorization and execution.

    Attributes:
        tool_name: Name of tool to execute
        user_id: User requesting execution
        command: Command string/parameters
        risk_level: Risk level of this request
        requires_approval: Whether operation needs approval before execution
        timeout_seconds: Maximum execution time in seconds
        metadata: Additional context (e.g., conversation_id, message_id)
    """

    tool_name: str
    user_id: int
    command: str
    risk_level: RiskLevel = RiskLevel.MEDIUM
    requires_approval: bool = False
    timeout_seconds: int = 30
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolResult:
    """Result from tool execution.

    Attributes:
        tool_name: Name of tool that executed
        success: Whether execution was successful
        output: Output or result from the tool
        error: Error message if unsuccessful
        execution_time: Seconds taken to execute
        status: Overall status of execution
        metadata: Additional data from tool execution
    """

    tool_name: str
    success: bool
    output: str = ""
    error: Optional[str] = None
    execution_time: float = 0.0
    status: OperationStatus = OperationStatus.SUCCESS
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate status is consistent with success flag."""
        if self.success and self.status == OperationStatus.FAILED:
            raise ValueError("Cannot have success=True with status=FAILED")
        if not self.success and self.status == OperationStatus.SUCCESS:
            raise ValueError("Cannot have success=False with status=SUCCESS")
