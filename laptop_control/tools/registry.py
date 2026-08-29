"""Tool registry and discovery system.

Manages tool registration, lookup, and execution with integrated
security checks (authorization, emergency stop, audit logging).
"""

import logging
import time
from typing import Any, Dict, Optional

from laptop_control.core.exceptions import (
    AuthorizationError,
    CommandValidationError,
    EmergencyStopTriggered,
    ToolExecutionError,
    ToolNotFoundError,
)
from laptop_control.core.types import OperationStatus, ToolRequest, ToolResult
from laptop_control.security.audit import AuditLogger
from laptop_control.security.authorization import AuthorizationManager
from laptop_control.security.emergency_stop import EmergencyStop
from laptop_control.tools.base import BaseTool

logger = logging.getLogger(__name__)


class ToolRegistry:
    """Registry for discovering and executing tools.

    Manages tool registration and execution with full security integration:
    - Authorization checking via AuthorizationManager
    - Emergency stop enforcement
    - Audit logging of all operations
    - Secure execution pipeline

    The execution pipeline enforces this order:
    1. Verify user authorization
    2. Check EmergencyStop is not active
    3. Find and validate tool exists
    4. Validate command syntax
    5. Execute tool
    6. Audit result
    7. Return typed ToolResult

    Attributes:
        tools: Dict mapping tool names to BaseTool instances
        authorizer: Authorization manager
        audit_logger: Audit logger
        emergency_stop: Emergency stop mechanism
    """

    def __init__(
        self,
        authorizer: AuthorizationManager,
        audit_logger: AuditLogger,
        emergency_stop: EmergencyStop,
    ) -> None:
        """Initialize tool registry.

        Args:
            authorizer: AuthorizationManager instance
            audit_logger: AuditLogger instance
            emergency_stop: EmergencyStop instance

        Raises:
            TypeError: If arguments wrong type
        """
        if not isinstance(authorizer, AuthorizationManager):
            raise TypeError(
                f"authorizer must be AuthorizationManager, got {type(authorizer)}"
            )
        if not isinstance(audit_logger, AuditLogger):
            raise TypeError(f"audit_logger must be AuditLogger, got {type(audit_logger)}")
        if not isinstance(emergency_stop, EmergencyStop):
            raise TypeError(
                f"emergency_stop must be EmergencyStop, got {type(emergency_stop)}"
            )

        self.tools: Dict[str, BaseTool] = {}
        self.authorizer = authorizer
        self.audit_logger = audit_logger
        self.emergency_stop = emergency_stop

        logger.debug("ToolRegistry initialized")

    def register(self, tool: BaseTool) -> None:
        """Register a tool.

        Args:
            tool: BaseTool instance to register

        Raises:
            TypeError: If tool is not BaseTool
            ToolExecutionError: If tool name already registered
        """
        if not isinstance(tool, BaseTool):
            raise TypeError(f"tool must be BaseTool, got {type(tool)}")

        if tool.name in self.tools:
            raise ToolExecutionError(f"Tool '{tool.name}' is already registered")

        # Inject the registry's authorizer and audit_logger into the tool so that
        # BaseTool.execute can log and use the same authorization/audit objects.
        try:
            setattr(tool, "authorizer", self.authorizer)
            setattr(tool, "audit_logger", self.audit_logger)
        except Exception:
            logger.warning(f"Failed to inject authorizer/audit_logger into tool {tool.name}")

        self.tools[tool.name] = tool
        logger.info(f"Tool registered: {tool.name}")

    def unregister(self, name: str) -> None:
        """Unregister a tool by name.

        Args:
            name: Tool name to unregister
        """
        if name in self.tools:
            del self.tools[name]
            logger.info(f"Tool unregistered: {name}")

    def has(self, name: str) -> bool:
        """Check if a tool is registered.

        Args:
            name: Tool name to check

        Returns:
            True if tool is registered, False otherwise
        """
        return name in self.tools

    def get(self, name: str) -> Optional[BaseTool]:
        """Get a tool by name.

        Args:
            name: Tool name to retrieve

        Returns:
            BaseTool instance or None if not found
        """
        return self.tools.get(name)

    def list_tools(self) -> Dict[str, Dict[str, Any]]:
        """List all registered tools with metadata.

        Returns metadata for each tool without executing anything.

        Returns:
            Dict mapping tool names to their metadata
        """
        result = {}
        for name, tool in self.tools.items():
            result[name] = tool.get_metadata()
        return result

    async def execute(
        self,
        request: ToolRequest,
    ) -> ToolResult:
        """Execute a tool with full security pipeline.

        Execution pipeline:
        1. Verify user authorization
        2. Check EmergencyStop is not active
        3. Find requested tool
        4. Validate the tool request
        5. Execute the tool
        6. Audit the result
        7. Return typed ToolResult

        Args:
            request: ToolRequest with execution details

        Returns:
            ToolResult with execution outcome
        """
        start_time = time.time()
        user_id = request.user_id
        tool_name = request.tool_name
        command = request.command

        logger.debug(f"Execute request: tool={tool_name}, user={user_id}")

        # STEP 1: Verify user authorization
        try:
            self.authorizer.require_authorized(user_id)
        except AuthorizationError as e:
            # Log authorization failure
            self.audit_logger.log_authorization_failure(
                user_id=user_id,
                reason=f"Unauthorized tool execution attempt: {tool_name}",
            )
            logger.warning(f"Authorization failed: user={user_id}, tool={tool_name}")
            return ToolResult(
                tool_name=tool_name,
                success=False,
                error=f"Authorization failed: {e}",
                status=OperationStatus.FAILED,
                execution_time=time.time() - start_time,
            )

        # STEP 2: Check EmergencyStop
        try:
            self.emergency_stop.require_not_stopped()
        except EmergencyStopTriggered as e:
            # Log emergency stop block
            self.audit_logger.log_operation(
                user_id=user_id,
                operation="tool_blocked_by_emergency_stop",
                tool=tool_name,
                status=OperationStatus.FAILED,
                risk_level=request.risk_level,
                details={"reason": str(e)},
            )
            logger.warning(f"Tool execution blocked by emergency stop: {tool_name}")
            return ToolResult(
                tool_name=tool_name,
                success=False,
                error="System is in emergency stop mode",
                status=OperationStatus.FAILED,
                execution_time=time.time() - start_time,
            )

        # STEP 3: Find and validate tool exists
        tool = self.get(tool_name)
        if not tool:
            # Log tool not found
            self.audit_logger.log_operation(
                user_id=user_id,
                operation="tool_not_found",
                tool=tool_name,
                status=OperationStatus.FAILED,
                risk_level=request.risk_level,
                details={"available_tools": list(self.tools.keys())},
            )
            logger.warning(f"Tool not found: {tool_name}")
            return ToolResult(
                tool_name=tool_name,
                success=False,
                error=f"Tool '{tool_name}' not found",
                status=OperationStatus.FAILED,
                execution_time=time.time() - start_time,
            )

        # STEP 4-7: Delegate to tool's execute method
        # The tool handles: validation, execution, error handling, and returns ToolResult
        try:
            result = await tool.execute(
                command=command,
                user_id=user_id,
                **request.metadata,
            )

            # Ensure it's a ToolResult
            if not isinstance(result, ToolResult):
                logger.error(f"Tool returned invalid result type: {type(result)}")
                return ToolResult(
                    tool_name=tool_name,
                    success=False,
                    error="Internal error: invalid result type",
                    status=OperationStatus.FAILED,
                    execution_time=time.time() - start_time,
                )

            return result

        except Exception as e:
            # Unexpected error during execution
            logger.error(
                f"Unexpected error executing tool: {tool_name}",
                exc_info=True,
            )
            self.audit_logger.log_operation(
                user_id=user_id,
                operation="tool_execute_unexpected_error",
                tool=tool_name,
                status=OperationStatus.FAILED,
                risk_level=request.risk_level,
                details={"error": str(e)},
            )
            return ToolResult(
                tool_name=tool_name,
                success=False,
                error=f"Unexpected error: {e}",
                status=OperationStatus.FAILED,
                execution_time=time.time() - start_time,
            )

    def __repr__(self) -> str:
        """Return string representation.

        Returns:
            String representation showing registered tools
        """
        return f"ToolRegistry(tools={len(self.tools)}, names={list(self.tools.keys())})"
