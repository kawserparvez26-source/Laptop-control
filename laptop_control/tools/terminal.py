"""Secure terminal command execution tool.

Provides safe terminal access with strict security controls:
- Explicit command allowlist (not arbitrary shell execution)
- No shell=True execution
- No command chaining, pipes, or redirects
- Structured argv execution via subprocess
- Strict output/timing limits
- Full audit logging and authorization integration

Supported operations (Phase 2B foundation - read-only safe commands):
- pwd: Print working directory
- ls: List directory contents
- whoami: Print current user
- uname: Print system information

This is NOT an arbitrary shell execution tool. It uses an explicit
allowlist and rejects shell metacharacters and unsafe patterns.
"""

import json
import logging
import re
import shlex
import subprocess
import time
from typing import Any, Dict, List, Optional, Set

from laptop_control.core.exceptions import ToolRuntimeError
from laptop_control.core.types import OperationStatus, RiskLevel, ToolResult
from laptop_control.security.audit import AuditLogger
from laptop_control.security.authorization import AuthorizationManager
from laptop_control.tools.base import BaseTool

logger = logging.getLogger(__name__)


class TerminalTool(BaseTool):
    """Secure terminal command execution tool.

    Provides controlled access to terminal operations with an explicit
    command allowlist. Commands are executed via subprocess.run() with
    shell=False to prevent shell injection.

    This implementation prioritizes security over functionality:
    - Commands must be explicitly allowed via allowlist
    - No shell interpretation or metacharacters
    - No command chaining, pipes, or redirects
    - Structured argument passing (argv list, not shell string)
    - Subprocess execution with shell=False only
    - Output and execution time limits
    - Comprehensive audit logging

    Command validation:
    - Rejects shell metacharacters: | ; & $ ( ) < > ` ' " \ etc.
    - Rejects shell operators: &&, ||, ;, |, >, <, >>
    - Rejects redirection operators: >, >>, <, 2>, 2>>
    - Rejects command substitution: $(...), `...`
    - Rejects environment variables in arguments: $VAR, ${VAR}
    - Only allows alphanumeric, hyphen, underscore, dot in arguments

    Attributes:
        allowed_commands: Set of permitted command names (executable names)
        max_output_bytes: Maximum stdout output size (default 1MB)
        max_execution_seconds: Maximum command execution time (default 30s)
    """

    # Maximum output from a single command (1 MB)
    DEFAULT_MAX_OUTPUT_BYTES = 1 * 1024 * 1024

    # Maximum execution time (30 seconds)
    DEFAULT_MAX_EXECUTION_SECONDS = 30

    # Phase 2B foundation: minimal read-only safe commands
    DEFAULT_ALLOWED_COMMANDS = frozenset([
        "pwd",      # Print working directory
        "ls",       # List directory contents
        "whoami",   # Print current user
        "uname",    # Print system information
    ])

    # Patterns that indicate shell metacharacters or dangerous syntax
    DANGEROUS_PATTERNS = [
        r"\|",           # Pipe
        r";",            # Command separator
        r"&",            # Background/AND
        r"\$\(",         # Command substitution $()
        r"`",            # Command substitution backticks
        r"[<>]",         # Redirects
        r"\|\|",         # OR operator
        r"&&",           # AND operator
        r">>",           # Append redirect
        r"2>",           # Stderr redirect
        r"\$\{",         # Variable expansion ${...}
        r"\$[A-Z_]",     # Environment variable $VAR
        r"'",            # Single quote
        r'"',            # Double quote (outer level)
    ]

    def __init__(
        self,
        allowed_commands: Optional[Set[str]] = None,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
        max_execution_seconds: int = DEFAULT_MAX_EXECUTION_SECONDS,
        authorizer: Optional[AuthorizationManager] = None,
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        """Initialize terminal tool.

        Args:
            allowed_commands: Set of permitted executable names.
                             Uses DEFAULT_ALLOWED_COMMANDS if None.
            max_output_bytes: Maximum stdout size in bytes
            max_execution_seconds: Maximum execution time in seconds
            authorizer: AuthorizationManager for permission checks
            audit_logger: AuditLogger for operation logging

        Raises:
            ValueError: If parameters invalid
            TypeError: If parameters wrong type
        """
        super().__init__(
            name="terminal",
            description="Secure terminal execution with command allowlist (Phase 2B foundation)",
            risk_level=RiskLevel.HIGH,
            authorizer=authorizer,
            audit_logger=audit_logger,
        )

        # Validate and store allowed_commands
        if allowed_commands is None:
            allowed_commands = set(self.DEFAULT_ALLOWED_COMMANDS)

        if not isinstance(allowed_commands, (set, frozenset)):
            raise TypeError(f"allowed_commands must be set, got {type(allowed_commands)}")

        if len(allowed_commands) == 0:
            raise ValueError("allowed_commands cannot be empty")

        # Validate each command name
        for cmd in allowed_commands:
            if not isinstance(cmd, str):
                raise TypeError(f"Command must be string, got {type(cmd)}")
            if not self._is_valid_command_name(cmd):
                raise ValueError(
                    f"Command '{cmd}' is invalid. "
                    "Must be lowercase alphanumeric with hyphens/underscores only."
                )

        self.allowed_commands = frozenset(allowed_commands)
        self.max_output_bytes = max_output_bytes
        self.max_execution_seconds = max_execution_seconds

        if not isinstance(max_output_bytes, int) or max_output_bytes <= 0:
            raise ValueError(f"max_output_bytes must be positive integer, got {max_output_bytes}")

        if not isinstance(max_execution_seconds, int) or max_execution_seconds <= 0:
            raise ValueError(
                f"max_execution_seconds must be positive integer, got {max_execution_seconds}"
            )

        logger.debug(
            f"TerminalTool initialized: allowed_commands={sorted(self.allowed_commands)}, "
            f"max_output_bytes={self.max_output_bytes}, "
            f"max_execution_seconds={self.max_execution_seconds}"
        )

    @staticmethod
    def _is_valid_command_name(name: str) -> bool:
        """Check if a command name is valid format.

        Valid command names are lowercase alphanumeric with hyphens and underscores.

        Args:
            name: Command name to validate

        Returns:
            True if name is valid, False otherwise
        """
        if not isinstance(name, str):
            return False
        pattern = r"^[a-z0-9_-]{1,63}$"
        return bool(re.match(pattern, name))

    async def validate(self, command: str) -> bool:
        """Validate terminal command format.

        Command must be valid JSON with structure:
        {
            "command": "pwd",
            "args": ["arg1", "arg2"]  (optional, default [])
        }

        Validation checks:
        - Valid JSON format
        - Has 'command' field
        - Command is in allowlist
        - No dangerous patterns in command or args
        - Args are safe (alphanumeric, hyphens, underscores, dots, slashes)

        Args:
            command: JSON command string to validate

        Returns:
            True if command is valid, False otherwise
        """
        try:
            if not isinstance(command, str) or not command.strip():
                logger.warning("Empty or non-string terminal command")
                return False

            cmd_data = json.loads(command)

            if not isinstance(cmd_data, dict):
                logger.warning("Terminal command must be JSON object")
                return False

            # Check required field
            if "command" not in cmd_data:
                logger.warning("Terminal command missing 'command' field")
                return False

            cmd_name = cmd_data.get("command")
            if not isinstance(cmd_name, str):
                logger.warning("Command must be string")
                return False

            # Check command is in allowlist
            if cmd_name not in self.allowed_commands:
                logger.warning(f"Command not in allowlist: {cmd_name}")
                return False

            # Check for dangerous patterns in command name
            if self._has_dangerous_patterns(cmd_name):
                logger.warning(f"Command has dangerous patterns: {cmd_name}")
                return False

            # Validate args if present
            args = cmd_data.get("args", [])
            if not isinstance(args, list):
                logger.warning("Args must be list")
                return False

            for arg in args:
                if not isinstance(arg, str):
                    logger.warning(f"Arg must be string, got {type(arg)}")
                    return False

                # Check for dangerous patterns
                if self._has_dangerous_patterns(arg):
                    logger.warning(f"Arg has dangerous patterns: {arg}")
                    return False

                # Check arg is safe (alphanumeric, hyphens, underscores, dots, slashes)
                if not self._is_safe_arg(arg):
                    logger.warning(f"Arg contains unsafe characters: {arg}")
                    return False

            return True

        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON terminal command: {e}")
            return False
        except Exception as e:
            logger.error(f"Terminal command validation error: {e}", exc_info=True)
            return False

    @staticmethod
    def _has_dangerous_patterns(text: str) -> bool:
        """Check if text contains dangerous shell patterns.

        Args:
            text: Text to check

        Returns:
            True if dangerous patterns found, False otherwise
        """
        for pattern in TerminalTool.DANGEROUS_PATTERNS:
            if re.search(pattern, text):
                return True
        return False

    @staticmethod
    def _is_safe_arg(arg: str) -> bool:
        """Check if argument contains only safe characters.

        Safe characters: alphanumeric, hyphens, underscores, dots, slashes, colons
        (restricted set for file paths and flags)

        Args:
            arg: Argument to check

        Returns:
            True if argument is safe, False otherwise
        """
        # Allow: a-z, A-Z, 0-9, -, _, ., /, :
        # This permits: file paths, flags, simple arguments
        pattern = r"^[a-zA-Z0-9_.\-/:]+$"
        return bool(re.match(pattern, arg))

    async def _execute_impl(
        self,
        command: str,
        user_id: int,
        **kwargs: Any,
    ) -> ToolResult:
        """Execute terminal command.

        Args:
            command: JSON command string (validated)
            user_id: User requesting execution
            **kwargs: Additional parameters (unused)

        Returns:
            ToolResult with execution outcome
        """
        start_time = time.time()

        try:
            cmd_data = json.loads(command)
            cmd_name = cmd_data.get("command")
            args = cmd_data.get("args", [])

            logger.debug(f"Executing terminal command: {cmd_name} with args={args}")

            # Build argv list (command + args)
            argv = [cmd_name] + args

            # Execute with subprocess (shell=False for safety)
            try:
                result = subprocess.run(
                    argv,
                    capture_output=True,
                    timeout=self.max_execution_seconds,
                    text=True,
                    shell=False,  # SECURITY: Never use shell=True
                )

                # Check output size
                output = result.stdout
                if len(output) > self.max_output_bytes:
                    output = output[:self.max_output_bytes] + "\n[OUTPUT TRUNCATED]"

                # Log successful operation (without output content)
                if self.audit_logger:
                    self.audit_logger.log_operation(
                        user_id=user_id,
                        operation="terminal_execute",
                        tool=self.name,
                        status=OperationStatus.SUCCESS if result.returncode == 0 else OperationStatus.FAILED,
                        risk_level=self.risk_level,
                        details={
                            "command": cmd_name,
                            "return_code": result.returncode,
                            "output_length": len(output),
                            "stderr_present": bool(result.stderr),
                        },
                    )

                # If exit code is non-zero, treat as failure but still return output
                if result.returncode != 0:
                    return ToolResult(
                        tool_name=self.name,
                        success=False,
                        output=output,
                        error=f"Command exited with code {result.returncode}",
                        status=OperationStatus.FAILED,
                        execution_time=time.time() - start_time,
                        metadata={
                            "return_code": result.returncode,
                            "stderr": result.stderr[:500] if result.stderr else "",
                        },
                    )

                return ToolResult(
                    tool_name=self.name,
                    success=True,
                    output=output,
                    status=OperationStatus.SUCCESS,
                    execution_time=time.time() - start_time,
                    metadata={
                        "return_code": result.returncode,
                        "command": cmd_name,
                    },
                )

            except subprocess.TimeoutExpired:
                # Execution timeout
                if self.audit_logger:
                    self.audit_logger.log_operation(
                        user_id=user_id,
                        operation="terminal_timeout",
                        tool=self.name,
                        status=OperationStatus.TIMEOUT,
                        risk_level=self.risk_level,
                        details={
                            "command": cmd_name,
                            "timeout_seconds": self.max_execution_seconds,
                        },
                    )

                logger.warning(
                    f"Terminal command timeout: {cmd_name} (max {self.max_execution_seconds}s)"
                )
                return ToolResult(
                    tool_name=self.name,
                    success=False,
                    error=f"Command timeout: exceeded {self.max_execution_seconds} seconds",
                    status=OperationStatus.TIMEOUT,
                    execution_time=time.time() - start_time,
                )

            except FileNotFoundError as e:
                # Executable not found
                if self.audit_logger:
                    self.audit_logger.log_operation(
                        user_id=user_id,
                        operation="terminal_not_found",
                        tool=self.name,
                        status=OperationStatus.FAILED,
                        risk_level=self.risk_level,
                        details={"command": cmd_name, "error": "Executable not found"},
                    )

                logger.warning(f"Terminal command not found: {cmd_name}")
                return ToolResult(
                    tool_name=self.name,
                    success=False,
                    error=f"Executable not found: {cmd_name}",
                    status=OperationStatus.FAILED,
                    execution_time=time.time() - start_time,
                )

            except PermissionError as e:
                # Permission denied
                if self.audit_logger:
                    self.audit_logger.log_operation(
                        user_id=user_id,
                        operation="terminal_permission_denied",
                        tool=self.name,
                        status=OperationStatus.FAILED,
                        risk_level=self.risk_level,
                        details={"command": cmd_name, "error": "Permission denied"},
                    )

                logger.warning(f"Terminal permission denied: {cmd_name}")
                return ToolResult(
                    tool_name=self.name,
                    success=False,
                    error=f"Permission denied executing: {cmd_name}",
                    status=OperationStatus.FAILED,
                    execution_time=time.time() - start_time,
                )

            except Exception as e:
                # Execution error
                if self.audit_logger:
                    self.audit_logger.log_operation(
                        user_id=user_id,
                        operation="terminal_execution_error",
                        tool=self.name,
                        status=OperationStatus.FAILED,
                        risk_level=self.risk_level,
                        details={
                            "command": cmd_name,
                            "error_type": type(e).__name__,
                        },
                    )

                logger.error(f"Terminal execution error: {e}", exc_info=True)
                return ToolResult(
                    tool_name=self.name,
                    success=False,
                    error=f"Execution error: {e}",
                    status=OperationStatus.FAILED,
                    execution_time=time.time() - start_time,
                )

        except json.JSONDecodeError as e:
            # JSON parsing error (shouldn't happen if validate passed)
            logger.error(f"Terminal JSON parsing error: {e}", exc_info=True)
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=f"JSON parsing error: {e}",
                status=OperationStatus.FAILED,
                execution_time=time.time() - start_time,
            )

        except Exception as e:
            # Unexpected error
            logger.error(f"Unexpected terminal execution error: {e}", exc_info=True)
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=f"Unexpected error: {e}",
                status=OperationStatus.FAILED,
                execution_time=time.time() - start_time,
            )
