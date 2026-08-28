"""Base tool abstraction and interfaces.

Provides BaseTool abstract base class that all system tools must inherit from.
Establishes the contract for tool behavior, validation, and execution.
"""

import logging
import re
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from laptop_control.core.exceptions import CommandValidationError, ToolRuntimeError
from laptop_control.core.types import OperationStatus, RiskLevel, ToolResult
from laptop_control.security.audit import AuditLogger
from laptop_control.security.authorization import AuthorizationManager

logger = logging.getLogger(__name__)


class BaseTool(ABC):
    """Abstract base class for all tools in Laptop Control.

    All tools must inherit from BaseTool and implement the required
    abstract methods. BaseTool handles common functionality like:
    - Authorization checking
    - Audit logging
    - Error handling
    - Result formatting

    Attributes:
        name: Unique tool identifier
        description: Human-readable tool description
        risk_level: Risk level for operations in this tool
        authorizer: Authorization manager for permission checks
        audit_logger: Audit logger for operation logging
    """

    def __init__(
        self,
        name: str,
        description: str,
        risk_level: RiskLevel = RiskLevel.MEDIUM,
        authorizer: Optional[AuthorizationManager] = None,
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        """Initialize a tool.

        Args:
            name: Unique tool name (alphanumeric + underscore)
            description: Human-readable description
            risk_level: Risk level of this tool's operations
            authorizer: AuthorizationManager for permission checks
            audit_logger: AuditLogger for operation logging

        Raises:
            ValueError: If name is invalid format
            TypeError: If authorizer or audit_logger wrong type
        """
        # Validate tool name
        if not self._is_valid_tool_name(name):
            raise ValueError(
                f"Tool name '{name}' is invalid. "
                "Must be lowercase alphanumeric with underscores only."
            )

        if not isinstance(description, str) or not description.strip():
            raise ValueError("Description must be non-empty string")

        if not isinstance(risk_level, RiskLevel):
            raise TypeError(f"risk_level must be RiskLevel, got {type(risk_level)}")

        if authorizer is not None and not isinstance(authorizer, AuthorizationManager):
            raise TypeError(
                f"authorizer must be AuthorizationManager, got {type(authorizer)}"
            )

        if audit_logger is not None and not isinstance(audit_logger, AuditLogger):
            raise TypeError(f"audit_logger must be AuditLogger, got {type(audit_logger)}")

        self.name = name
        self.description = description
        self.risk_level = risk_level
        self.authorizer = authorizer
        self.audit_logger = audit_logger

        logger.debug(
            f"Tool '{self.name}' initialized with risk_level={self.risk_level.value}"
        )

    @staticmethod
    def _is_valid_tool_name(name: str) -> bool:
        """Check if tool name is valid format.

        Valid tool names are lowercase alphanumeric with underscores,
        between 1 and 63 characters.

        Args:
            name: Tool name to validate

        Returns:
            True if name is valid, False otherwise
        """
        if not isinstance(name, str):
            return False
        # Pattern: lowercase letters, numbers, underscores only
        # Must be 1-63 chars
        pattern = r"^[a-z0-9_]{1,63}$"
        return bool(re.match(pattern, name))

    @abstractmethod
    async def validate(self, command: str) -> bool:
        """Validate a command before execution.

        Subclasses should override this to implement tool-specific
        validation logic. This is called before execute() to catch
        errors early.

        Must not have side effects or access external resources.

        Args:
            command: Command string to validate

        Returns:
            True if command is valid, False otherwise
        """
        ...

    @abstractmethod
    async def _execute_impl(
        self,
        command: str,
        user_id: int,
        **kwargs: Any,
    ) -> ToolResult:
        """Execute tool-specific logic.

        Subclasses must implement this to perform the actual tool
        operation. This is called after all security checks pass.

        Should handle all errors and return appropriate ToolResult.

        Args:
            command: Validated command string
            user_id: User ID of requester
            **kwargs: Additional tool-specific parameters

        Returns:
            ToolResult with execution outcome
        """
        ...

    async def execute(
        self,
        command: str,
        user_id: int,
        **kwargs: Any,
    ) -> ToolResult:
        """Execute a command with authorization and auditing.

        This is the main entry point. It handles:
        1. Authorization check
        2. Command validation
        3. Tool execution
        4. Audit logging
        5. Error handling

        Args:
            command: Command string to execute
            user_id: User requesting execution
            **kwargs: Additional parameters for tool

        Returns:
            ToolResult with execution outcome
        """
        # Log the execution attempt
        if self.audit_logger:
            self.audit_logger.log_operation(
                user_id=user_id,
                operation="tool_execute_attempt",
                tool=self.name,
                status=OperationStatus.PENDING,
                risk_level=self.risk_level,
                details={
                    "command": command[:100],  # Truncate for logging
                },
            )

        # Step 1: Check authorization
        if self.authorizer:
            if not self.authorizer.is_authorized(user_id):
                # Log authorization failure
                if self.audit_logger:
                    self.audit_logger.log_authorization_failure(
                        user_id=user_id,
                        reason=f"Not authorized for tool '{self.name}'",
                    )
                logger.warning(f"Unauthorized tool access: user={user_id}, tool={self.name}")
                return ToolResult(
                    tool_name=self.name,
                    success=False,
                    error=f"User {user_id} is not authorized",
                    status=OperationStatus.FAILED,
                )

        # Step 2: Validate command
        try:
            is_valid = await self.validate(command)
            if not is_valid:
                # Log validation failure
                if self.audit_logger:
                    self.audit_logger.log_operation(
                        user_id=user_id,
                        operation="validation_failed",
                        tool=self.name,
                        status=OperationStatus.FAILED,
                        risk_level=self.risk_level,
                        details={"reason": "Command validation failed"},
                    )
                logger.warning(
                    f"Command validation failed: tool={self.name}, "
                    f"user={user_id}, command={command[:50]}"
                )
                return ToolResult(
                    tool_name=self.name,
                    success=False,
                    error="Command validation failed",
                    status=OperationStatus.FAILED,
                )
        except Exception as e:
            # Validation error
            if self.audit_logger:
                self.audit_logger.log_operation(
                    user_id=user_id,
                    operation="validation_error",
                    tool=self.name,
                    status=OperationStatus.FAILED,
                    risk_level=self.risk_level,
                    details={"error": str(e)},
                )
            logger.error(
                f"Validation error in {self.name}: {e}",
                exc_info=True,
            )
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=f"Validation error: {e}",
                status=OperationStatus.FAILED,
            )

        # Step 3: Execute tool
        try:
            result = await self._execute_impl(command, user_id, **kwargs)

            # Ensure result is ToolResult
            if not isinstance(result, ToolResult):
                logger.error(f"Tool {self.name} returned non-ToolResult: {type(result)}")
                result = ToolResult(
                    tool_name=self.name,
                    success=False,
                    error="Internal error: invalid result type",
                    status=OperationStatus.FAILED,
                )

            # Log successful execution
            if self.audit_logger:
                self.audit_logger.log_operation(
                    user_id=user_id,
                    operation="tool_execute_success" if result.success else "tool_execute_failed",
                    tool=self.name,
                    status=result.status,
                    risk_level=self.risk_level,
                    details={
                        "output_length": len(result.output),
                        "execution_time": result.execution_time,
                    },
                )

            return result

        except Exception as e:
            # Execution error
            logger.error(
                f"Execution error in {self.name}: {e}",
                exc_info=True,
            )

            if self.audit_logger:
                self.audit_logger.log_operation(
                    user_id=user_id,
                    operation="tool_execute_error",
                    tool=self.name,
                    status=OperationStatus.FAILED,
                    risk_level=self.risk_level,
                    details={"error": str(e)},
                )

            return ToolResult(
                tool_name=self.name,
                success=False,
                error=f"Execution error: {e}",
                status=OperationStatus.FAILED,
            )

    def get_metadata(self) -> Dict[str, Any]:
        """Get tool metadata.

        Returns metadata about this tool without executing it.
        Useful for registration and discovery.

        Returns:
            Dict with tool information
        """
        return {
            "name": self.name,
            "description": self.description,
            "risk_level": self.risk_level.value,
        }

    def __repr__(self) -> str:
        """Return string representation.

        Returns:
            String representation of tool
        """
        return f"{self.__class__.__name__}(name='{self.name}')"
