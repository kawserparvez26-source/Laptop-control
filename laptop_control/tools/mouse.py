"""Secure mouse control tool.

Provides safe mouse control with strict security boundaries:
- Explicit coordinate validation and bounds checking
- Only controlled operations (move, click)
- No screen capture or GUI automation
- No mouse event monitoring
- No arbitrary button/parameter injection
- Full audit logging and authorization integration

Supported operations (Phase 2 - backend pending):
- move: Move mouse to specified (x, y) coordinates
- click: Left-click at specified (x, y) coordinates

This is NOT a GUI automation or screen interaction tool. It provides
only explicitly controlled mouse operations with strong input validation.

Note: This implementation requires an external mouse backend
(e.g., pynput) which is not currently a project dependency.
Without a backend, the tool validates inputs correctly but returns
a safe "unavailable" error for execution.
"""

import json
import logging
import math
import time
from typing import Any, Dict, Optional

from laptop_control.core.exceptions import ToolRuntimeError
from laptop_control.core.types import OperationStatus, RiskLevel, ToolResult
from laptop_control.security.audit import AuditLogger
from laptop_control.security.authorization import AuthorizationManager
from laptop_control.tools.base import BaseTool

logger = logging.getLogger(__name__)


class MouseTool(BaseTool):
    """Secure mouse control tool.

    Provides controlled mouse operations with strict coordinate bounds
    and explicit operation allowlist.

    This implementation prioritizes security over functionality:
    - Operations must be explicitly allowed (move, click only)
    - Coordinates must be numeric, non-negative, within bounds
    - Click supports only single left-click (no buttons, no counts)
    - No arbitrary automation parameters
    - No mouse event monitoring or recording
    - Comprehensive audit logging of operations

    Supported operations:
    - move: Move cursor to (x, y)
    - click: Left-click at (x, y)

    Command validation:
    - Valid JSON format
    - Operation must be move or click
    - Coordinates must be numeric integers
    - No boolean coordinates (False=0, True=1 exploitation)
    - No NaN or infinity values
    - No negative coordinates
    - Coordinates within configured bounds
    - No arbitrary button names
    - No arbitrary parameter injection

    Coordinate bounds:
    - Configurable max X and max Y (no unbounded desktop access)
    - Default: 1024x768 (safe for testing, easily adjusted)
    - Can be configured per instance if display size known

    Attributes:
        max_x: Maximum allowed X coordinate
        max_y: Maximum allowed Y coordinate
    """

    # Default maximum coordinates (safe testing bounds)
    # These are intentionally conservative and can be configured
    DEFAULT_MAX_X = 1024
    DEFAULT_MAX_Y = 768

    def __init__(
        self,
        max_x: int = DEFAULT_MAX_X,
        max_y: int = DEFAULT_MAX_Y,
        authorizer: Optional[AuthorizationManager] = None,
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        """Initialize mouse tool.

        Args:
            max_x: Maximum allowed X coordinate
            max_y: Maximum allowed Y coordinate
            authorizer: AuthorizationManager for permission checks
            audit_logger: AuditLogger for operation logging

        Raises:
            ValueError: If parameters invalid
            TypeError: If parameters wrong type
        """
        super().__init__(
            name="mouse",
            description="Secure mouse control with coordinate bounds (Phase 2 - backend pending)",
            risk_level=RiskLevel.HIGH,
            authorizer=authorizer,
            audit_logger=audit_logger,
        )

        # Validate coordinate bounds
        if not isinstance(max_x, int) or max_x <= 0:
            raise ValueError(f"max_x must be positive integer, got {max_x}")

        if not isinstance(max_y, int) or max_y <= 0:
            raise ValueError(f"max_y must be positive integer, got {max_y}")

        self.max_x = max_x
        self.max_y = max_y

        logger.debug(
            f"MouseTool initialized: max_x={self.max_x}, max_y={self.max_y}"
        )

    @staticmethod
    def _is_valid_coordinate(value: Any) -> bool:
        """Check if a coordinate value is valid.

        Valid coordinates are:
        - Numeric integers
        - Non-negative
        - Not NaN or infinity

        Rejects:
        - Booleans (False=0, True=1)
        - Floats (including NaN, inf, -inf)
        - Strings
        - None

        Args:
            value: Coordinate value to validate

        Returns:
            True if valid, False otherwise
        """
        # Reject booleans explicitly (bool is subclass of int in Python)
        if isinstance(value, bool):
            return False

        # Must be an integer
        if not isinstance(value, int):
            return False

        # Must be non-negative
        if value < 0:
            return False

        return True

    async def validate(self, command: str) -> bool:
        """Validate mouse command format.

        Command must be valid JSON with structure:
        {
            "operation": "move" or "click",
            "x": <integer>,
            "y": <integer>
        }

        Validation checks:
        - Valid JSON format
        - Has 'operation' field
        - Operation is move or click
        - Has x and y fields
        - x and y are numeric integers (not booleans, floats, strings)
        - No NaN or infinity
        - No negative coordinates
        - Coordinates within configured bounds
        - No arbitrary extra parameters for click

        Args:
            command: JSON command string to validate

        Returns:
            True if command is valid, False otherwise
        """
        try:
            if not isinstance(command, str) or not command.strip():
                logger.warning("Empty or non-string mouse command")
                return False

            cmd_data = json.loads(command)

            if not isinstance(cmd_data, dict):
                logger.warning("Mouse command must be JSON object")
                return False

            # Check required field
            if "operation" not in cmd_data:
                logger.warning("Mouse command missing 'operation' field")
                return False

            operation = cmd_data.get("operation")
            if not isinstance(operation, str):
                logger.warning("Operation must be string")
                return False

            # Both move and click require x and y
            if operation not in ("move", "click"):
                logger.warning(f"Unsupported mouse operation: {operation}")
                return False

            # Validate x coordinate
            if "x" not in cmd_data:
                logger.warning("Mouse command missing 'x' field")
                return False

            x = cmd_data.get("x")
            if not self._is_valid_coordinate(x):
                logger.warning(f"Invalid x coordinate: {x} (type: {type(x).__name__})")
                return False

            if x > self.max_x:
                logger.warning(f"x coordinate exceeds maximum: {x} > {self.max_x}")
                return False

            # Validate y coordinate
            if "y" not in cmd_data:
                logger.warning("Mouse command missing 'y' field")
                return False

            y = cmd_data.get("y")
            if not self._is_valid_coordinate(y):
                logger.warning(f"Invalid y coordinate: {y} (type: {type(y).__name__})")
                return False

            if y > self.max_y:
                logger.warning(f"y coordinate exceeds maximum: {y} > {self.max_y}")
                return False

            # For click operation, verify no arbitrary parameters
            if operation == "click":
                # Only allow operation, x, y
                allowed_fields = {"operation", "x", "y"}
                extra_fields = set(cmd_data.keys()) - allowed_fields
                if extra_fields:
                    logger.warning(f"Click operation has unexpected fields: {extra_fields}")
                    return False

            return True

        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON mouse command: {e}")
            return False
        except Exception as e:
            logger.error(f"Mouse command validation error: {e}", exc_info=True)
            return False

    async def _execute_impl(
        self,
        command: str,
        user_id: int,
        **kwargs: Any,
    ) -> ToolResult:
        """Execute mouse operation.

        NOTE: This implementation validates commands but returns
        "unavailable" for execution because no mouse backend
        (e.g., pynput) is available in the project dependencies.

        To enable execution, add a mouse backend to pyproject.toml:
        - pynput (cross-platform)
        - python-mouse (simple, cross-platform)
        - pyautogui (more features, requires additional deps)

        Args:
            command: JSON command string (validated)
            user_id: User requesting operation
            **kwargs: Additional parameters (unused)

        Returns:
            ToolResult with unavailable status
        """
        start_time = time.time()

        try:
            cmd_data = json.loads(command)
            operation = cmd_data.get("operation")
            x = cmd_data.get("x")
            y = cmd_data.get("y")

            logger.debug(f"Executing mouse operation: {operation} at ({x}, {y})")

            # Log operation metadata
            if self.audit_logger:
                self.audit_logger.log_operation(
                    user_id=user_id,
                    operation="mouse_operation_requested",
                    tool=self.name,
                    status=OperationStatus.FAILED,
                    risk_level=self.risk_level,
                    details={
                        "operation": operation,
                        "x": x,
                        "y": y,
                    },
                )

            # Mouse backend is not available
            logger.warning(
                "Mouse operation requested but no backend available. "
                "Install pynput or compatible mouse library and rebuild."
            )

            return ToolResult(
                tool_name=self.name,
                success=False,
                error=(
                    "Mouse backend not available. "
                    "Install pynput or compatible mouse library to enable this tool."
                ),
                status=OperationStatus.FAILED,
                execution_time=time.time() - start_time,
                metadata={
                    "operation": operation,
                    "reason": "backend_unavailable",
                },
            )

        except json.JSONDecodeError as e:
            logger.error(f"Mouse JSON parsing error: {e}", exc_info=True)
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=f"JSON parsing error: {e}",
                status=OperationStatus.FAILED,
                execution_time=time.time() - start_time,
            )

        except Exception as e:
            logger.error(f"Unexpected mouse error: {e}", exc_info=True)
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=f"Unexpected error: {e}",
                status=OperationStatus.FAILED,
                execution_time=time.time() - start_time,
            )
