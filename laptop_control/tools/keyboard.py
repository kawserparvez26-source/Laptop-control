"""Secure keyboard input tool.

Provides safe keyboard input with strict security controls:
- Explicit key allowlist (not arbitrary key injection)
- No keyboard monitoring or logging of input
- No keystroke recording
- Controlled operations only (press_key, type_text)
- Strict text input limits
- Full audit logging and authorization integration

Supported operations (Phase 2 - backend pending):
- press_key: Simulate pressing a single key from the allowlist
- type_text: Type limited text (with strict safety boundaries)

This is NOT a keyboard automation or monitoring tool. It provides
only explicitly allowed operations with strong input validation.

Note: This implementation requires an external keyboard backend
(e.g., pynput) which is not currently a project dependency.
Without a backend, the tool validates inputs correctly but returns
a safe "unavailable" error for execution.
"""

import json
import logging
import re
import time
from typing import Any, Dict, Optional, Set

from laptop_control.core.exceptions import ToolRuntimeError
from laptop_control.core.types import OperationStatus, RiskLevel, ToolResult
from laptop_control.security.audit import AuditLogger
from laptop_control.security.authorization import AuthorizationManager
from laptop_control.tools.base import BaseTool

logger = logging.getLogger(__name__)


class KeyboardTool(BaseTool):
    """Secure keyboard input tool.

    Provides controlled keyboard input operations with an explicit
    allowlist for keys and strict limits on text input.

    This implementation prioritizes security over functionality:
    - Operations must be explicitly allowed
    - Only safe key names permitted (no arbitrary keys)
    - Text input strictly limited in length and character set
    - No keyboard monitoring or input capture
    - No keystroke logging (only metadata logged)
    - Comprehensive audit logging of operations

    Supported operations:
    - press_key: Press a single key from the allowlist
    - type_text: Type limited text with safety restrictions

    Command validation:
    - Valid JSON format with required fields
    - Operation must be press_key or type_text
    - Key must be in allowlist
    - Text must not exceed max_text_length
    - No control characters in text
    - No escape sequences in text

    Attributes:
        allowed_keys: Set of permitted key names
        max_text_length: Maximum length for type_text operations (default 256)
    """

    # Maximum text length for type_text operations
    DEFAULT_MAX_TEXT_LENGTH = 256

    # Phase 2 - backend pending: minimal safe keys for basic control
    DEFAULT_ALLOWED_KEYS = frozenset([
        "enter",      # Return/Enter key
        "escape",     # Escape key
        "tab",        # Tab key
        "space",      # Space bar
        "backspace",  # Backspace key
        "up",         # Up arrow
        "down",       # Down arrow
        "left",       # Left arrow
        "right",      # Right arrow
    ])

    def __init__(
        self,
        allowed_keys: Optional[Set[str]] = None,
        max_text_length: int = DEFAULT_MAX_TEXT_LENGTH,
        authorizer: Optional[AuthorizationManager] = None,
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        """Initialize keyboard tool.

        Args:
            allowed_keys: Set of permitted key names.
                         Uses DEFAULT_ALLOWED_KEYS if None.
            max_text_length: Maximum length for type_text operations
            authorizer: AuthorizationManager for permission checks
            audit_logger: AuditLogger for operation logging

        Raises:
            ValueError: If parameters invalid
            TypeError: If parameters wrong type
        """
        super().__init__(
            name="keyboard",
            description="Secure keyboard input with operation allowlist (Phase 2 - backend pending)",
            risk_level=RiskLevel.HIGH,
            authorizer=authorizer,
            audit_logger=audit_logger,
        )

        # Validate and store allowed_keys
        if allowed_keys is None:
            allowed_keys = set(self.DEFAULT_ALLOWED_KEYS)

        if not isinstance(allowed_keys, (set, frozenset)):
            raise TypeError(f"allowed_keys must be set, got {type(allowed_keys)}")

        if len(allowed_keys) == 0:
            raise ValueError("allowed_keys cannot be empty")

        # Validate each key name
        for key in allowed_keys:
            if not isinstance(key, str):
                raise TypeError(f"Key must be string, got {type(key)}")
            if not self._is_valid_key_name(key):
                raise ValueError(
                    f"Key '{key}' is invalid. "
                    "Must be lowercase alphanumeric with underscores only."
                )

        self.allowed_keys = frozenset(allowed_keys)
        self.max_text_length = max_text_length

        if not isinstance(max_text_length, int) or max_text_length <= 0:
            raise ValueError(f"max_text_length must be positive integer, got {max_text_length}")

        logger.debug(
            f"KeyboardTool initialized: allowed_keys={sorted(self.allowed_keys)}, "
            f"max_text_length={self.max_text_length}"
        )

    @staticmethod
    def _is_valid_key_name(name: str) -> bool:
        """Check if a key name is valid format.

        Valid key names are lowercase alphanumeric with underscores.

        Args:
            name: Key name to validate

        Returns:
            True if name is valid, False otherwise
        """
        if not isinstance(name, str):
            return False
        pattern = r"^[a-z0-9_]{1,63}$"
        return bool(re.match(pattern, name))

    @staticmethod
    def _has_control_characters(text: str) -> bool:
        """Check if text contains control characters.

        Args:
            text: Text to check

        Returns:
            True if control characters found, False otherwise
        """
        # Check for common control characters (0x00-0x1f, 0x7f-0x9f)
        for char in text:
            code = ord(char)
            if (code < 0x20 and code not in (0x09, 0x0a, 0x0d)) or (0x7f <= code <= 0x9f):
                return True
        return False

    @staticmethod
    def _has_escape_sequences(text: str) -> bool:
        """Check if text contains escape sequences.

        Args:
            text: Text to check

        Returns:
            True if escape sequences found, False otherwise
        """
        # Check for common escape patterns
        escape_patterns = [
            r"\\[0-9]",      # Octal escape
            r"\\x[0-9a-fA-F]",  # Hex escape
            r"\\[nrtvfab\\]",   # Common escapes
            r"\x1b\[",        # ANSI escape sequences
        ]

        for pattern in escape_patterns:
            if re.search(pattern, text):
                return True

        return False

    async def validate(self, command: str) -> bool:
        """Validate keyboard command format.

        Command must be valid JSON with structure:
        {
            "operation": "press_key" or "type_text",
            "key": "enter" (for press_key),
            "text": "hello" (for type_text)
        }

        Validation checks:
        - Valid JSON format
        - Has 'operation' field
        - Operation is press_key or type_text
        - For press_key: has key field, key is in allowlist
        - For type_text: has text field, text within length limit, no control chars

        Args:
            command: JSON command string to validate

        Returns:
            True if command is valid, False otherwise
        """
        try:
            if not isinstance(command, str) or not command.strip():
                logger.warning("Empty or non-string keyboard command")
                return False

            cmd_data = json.loads(command)

            if not isinstance(cmd_data, dict):
                logger.warning("Keyboard command must be JSON object")
                return False

            # Check required field
            if "operation" not in cmd_data:
                logger.warning("Keyboard command missing 'operation' field")
                return False

            operation = cmd_data.get("operation")
            if not isinstance(operation, str):
                logger.warning("Operation must be string")
                return False

            # Validate press_key operation
            if operation == "press_key":
                if "key" not in cmd_data:
                    logger.warning("press_key operation missing 'key' field")
                    return False

                key = cmd_data.get("key")
                if not isinstance(key, str):
                    logger.warning("Key must be string")
                    return False

                if key not in self.allowed_keys:
                    logger.warning(f"Key not in allowlist: {key}")
                    return False

                return True

            # Validate type_text operation
            elif operation == "type_text":
                if "text" not in cmd_data:
                    logger.warning("type_text operation missing 'text' field")
                    return False

                text = cmd_data.get("text")
                if not isinstance(text, str):
                    logger.warning("Text must be string")
                    return False

                if len(text) == 0:
                    logger.warning("Text cannot be empty")
                    return False

                if len(text) > self.max_text_length:
                    logger.warning(
                        f"Text exceeds maximum length: {len(text)} > {self.max_text_length}"
                    )
                    return False

                if self._has_control_characters(text):
                    logger.warning("Text contains control characters")
                    return False

                if self._has_escape_sequences(text):
                    logger.warning("Text contains escape sequences")
                    return False

                return True

            else:
                logger.warning(f"Unknown keyboard operation: {operation}")
                return False

        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON keyboard command: {e}")
            return False
        except Exception as e:
            logger.error(f"Keyboard command validation error: {e}", exc_info=True)
            return False

    async def _execute_impl(
        self,
        command: str,
        user_id: int,
        **kwargs: Any,
    ) -> ToolResult:
        """Execute keyboard operation.

        NOTE: This implementation validates commands but returns
        "unavailable" for execution because no keyboard backend
        (e.g., pynput) is available in the project dependencies.

        To enable execution, add a keyboard backend to pyproject.toml:
        - pynput (cross-platform)
        - python-keyboard (Linux/Windows)
        - PyObjC (macOS)

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

            logger.debug(f"Executing keyboard operation: {operation}")

            # Log operation metadata (without actual key/text content)
            if self.audit_logger:
                details = {"operation": operation}
                if operation == "press_key":
                    key = cmd_data.get("key")
                    details["key"] = key
                elif operation == "type_text":
                    text = cmd_data.get("text", "")
                    details["text_length"] = len(text)

                self.audit_logger.log_operation(
                    user_id=user_id,
                    operation="keyboard_operation_requested",
                    tool=self.name,
                    status=OperationStatus.FAILED,
                    risk_level=self.risk_level,
                    details=details,
                )

            # Keyboard backend is not available
            logger.warning(
                "Keyboard operation requested but no backend available. "
                "Install pynput or compatible keyboard library and rebuild."
            )

            return ToolResult(
                tool_name=self.name,
                success=False,
                error=(
                    "Keyboard backend not available. "
                    "Install pynput or compatible keyboard library to enable this tool."
                ),
                status=OperationStatus.FAILED,
                execution_time=time.time() - start_time,
                metadata={
                    "operation": operation,
                    "reason": "backend_unavailable",
                },
            )

        except json.JSONDecodeError as e:
            logger.error(f"Keyboard JSON parsing error: {e}", exc_info=True)
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=f"JSON parsing error: {e}",
                status=OperationStatus.FAILED,
                execution_time=time.time() - start_time,
            )

        except Exception as e:
            logger.error(f"Unexpected keyboard error: {e}", exc_info=True)
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=f"Unexpected error: {e}",
                status=OperationStatus.FAILED,
                execution_time=time.time() - start_time,
            )
