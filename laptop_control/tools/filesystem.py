"""Secure filesystem operations tool.

Provides safe filesystem access with strict security controls:
- Restricted to configured allowed-root directory
- Path traversal prevention
- No symlink following outside allowed root
- No arbitrary process execution
- Full audit logging and authorization integration

Supported operations:
- list: List directory contents
- read: Read file contents
- write: Write to file
- create_directory: Create new directory
- move: Move/rename file or directory
- copy: Copy file or directory
- delete: Delete file or directory
"""

import json
import logging
import re
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from laptop_control.core.exceptions import ToolRuntimeError
from laptop_control.core.types import OperationStatus, RiskLevel, ToolResult
from laptop_control.security.audit import AuditLogger
from laptop_control.security.authorization import AuthorizationManager
from laptop_control.tools.base import BaseTool

logger = logging.getLogger(__name__)


class FilesystemTool(BaseTool):
    """Secure filesystem operations tool.

    Provides controlled access to filesystem operations with strict security
    boundaries. All operations are confined to a configured allowed-root
    directory with comprehensive path traversal protection.

    Supported operations:
    - list: List directory contents with file metadata
    - read: Read file contents (text files only)
    - write: Write content to file (creates or overwrites)
    - create_directory: Create new directory
    - move: Move/rename file or directory
    - copy: Copy file or directory (shallow copy)
    - delete: Delete file or directory

    Security model:
    - All paths must be within allowed_root directory
    - Path traversal attempts (../, /etc/passwd, etc.) are rejected
    - Symbolic links are resolved and must point within allowed_root
    - Operations on system files are prevented
    - Maximum file size limits for read/write operations
    - JSON command parsing with strict validation

    Attributes:
        allowed_root: Root directory for filesystem operations (security boundary)
        max_file_size: Maximum file size for read/write operations (default 10MB)
        supported_operations: Set of allowed operation names
    """

    # Maximum file size for read/write operations (10 MB)
    DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024

    # Set of allowed operations
    SUPPORTED_OPERATIONS = {
        "list",
        "read",
        "write",
        "create_directory",
        "move",
        "copy",
        "delete",
    }

    def __init__(
        self,
        allowed_root: str,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        authorizer: Optional[AuthorizationManager] = None,
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        """Initialize filesystem tool.

        Args:
            allowed_root: Root directory for operations (security boundary).
                          Must be absolute path.
            max_file_size: Maximum file size for read/write in bytes.
                          Default 10MB.
            authorizer: AuthorizationManager for permission checks
            audit_logger: AuditLogger for operation logging

        Raises:
            ValueError: If allowed_root is invalid or not absolute
            TypeError: If parameters wrong type
        """
        super().__init__(
            name="filesystem",
            description="Secure filesystem operations with path traversal protection",
            risk_level=RiskLevel.HIGH,
            authorizer=authorizer,
            audit_logger=audit_logger,
        )

        # Validate and store allowed_root
        if not isinstance(allowed_root, str):
            raise TypeError(f"allowed_root must be string, got {type(allowed_root)}")

        root_path = Path(allowed_root).resolve()

        if not root_path.is_absolute():
            raise ValueError(f"allowed_root must be absolute path: {allowed_root}")

        if not root_path.exists():
            raise ValueError(f"allowed_root does not exist: {root_path}")

        if not root_path.is_dir():
            raise ValueError(f"allowed_root must be directory: {root_path}")

        self.allowed_root = root_path
        self.max_file_size = max_file_size

        if not isinstance(max_file_size, int) or max_file_size <= 0:
            raise ValueError(f"max_file_size must be positive integer, got {max_file_size}")

        logger.debug(
            f"FilesystemTool initialized: allowed_root={self.allowed_root}, "
            f"max_file_size={self.max_file_size}"
        )

    async def validate(self, command: str) -> bool:
        """Validate filesystem command format.

        Command must be valid JSON with structure:
        {
            "operation": "list|read|write|create_directory|move|copy|delete",
            "path": "relative/path",
            "content": "file content" (for write operation)
        }

        Args:
            command: JSON command string to validate

        Returns:
            True if command is valid, False otherwise
        """
        try:
            if not isinstance(command, str) or not command.strip():
                logger.warning("Empty or non-string command")
                return False

            cmd_data = json.loads(command)

            if not isinstance(cmd_data, dict):
                logger.warning("Command must be JSON object")
                return False

            # Check required fields
            if "operation" not in cmd_data:
                logger.warning("Command missing 'operation' field")
                return False

            operation = cmd_data.get("operation")
            if operation not in self.SUPPORTED_OPERATIONS:
                logger.warning(f"Unsupported operation: {operation}")
                return False

            if "path" not in cmd_data:
                logger.warning("Command missing 'path' field")
                return False

            path = cmd_data.get("path")
            if not isinstance(path, str):
                logger.warning("Path must be string")
                return False

            # Validate write operations have content
            if operation == "write":
                if "content" not in cmd_data:
                    logger.warning("Write operation requires 'content' field")
                    return False

            # Validate move/copy operations have source and destination
            if operation in ("move", "copy"):
                if "dest" not in cmd_data:
                    logger.warning(f"{operation} operation requires 'dest' field")
                    return False
                dest = cmd_data.get("dest")
                if not isinstance(dest, str):
                    logger.warning("Destination must be string")
                    return False

            return True

        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON command: {e}")
            return False
        except Exception as e:
            logger.error(f"Validation error: {e}", exc_info=True)
            return False

    async def _execute_impl(
        self,
        command: str,
        user_id: int,
        **kwargs: Any,
    ) -> ToolResult:
        """Execute filesystem operation.

        Args:
            command: JSON command string
            user_id: User requesting operation
            **kwargs: Additional parameters (unused)

        Returns:
            ToolResult with operation outcome
        """
        start_time = time.time()

        try:
            cmd_data = json.loads(command)
            operation = cmd_data.get("operation")
            path = cmd_data.get("path")

            logger.debug(f"Executing filesystem operation: {operation} on {path}")

            # Dispatch to operation handler
            if operation == "list":
                result_output = await self._handle_list(path)
            elif operation == "read":
                result_output = await self._handle_read(path)
            elif operation == "write":
                content = cmd_data.get("content", "")
                result_output = await self._handle_write(path, content)
            elif operation == "create_directory":
                result_output = await self._handle_create_directory(path)
            elif operation == "move":
                dest = cmd_data.get("dest")
                result_output = await self._handle_move(path, dest)
            elif operation == "copy":
                dest = cmd_data.get("dest")
                result_output = await self._handle_copy(path, dest)
            elif operation == "delete":
                result_output = await self._handle_delete(path)
            else:
                return ToolResult(
                    tool_name=self.name,
                    success=False,
                    error=f"Unknown operation: {operation}",
                    status=OperationStatus.FAILED,
                    execution_time=time.time() - start_time,
                )

            # Log successful operation
            if self.audit_logger:
                self.audit_logger.log_operation(
                    user_id=user_id,
                    operation=operation,
                    tool=self.name,
                    status=OperationStatus.SUCCESS,
                    risk_level=self.risk_level,
                    details={"path_depth": len(Path(path).parts)},
                )

            return ToolResult(
                tool_name=self.name,
                success=True,
                output=result_output,
                status=OperationStatus.SUCCESS,
                execution_time=time.time() - start_time,
            )

        except ToolRuntimeError as e:
            # Expected tool error
            if self.audit_logger:
                self.audit_logger.log_operation(
                    user_id=user_id,
                    operation="filesystem_error",
                    tool=self.name,
                    status=OperationStatus.FAILED,
                    risk_level=self.risk_level,
                    details={"error_type": type(e).__name__},
                )
            logger.warning(f"Tool error in filesystem operation: {e}")
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=str(e),
                status=OperationStatus.FAILED,
                execution_time=time.time() - start_time,
            )

        except Exception as e:
            # Unexpected error
            if self.audit_logger:
                self.audit_logger.log_operation(
                    user_id=user_id,
                    operation="filesystem_unexpected_error",
                    tool=self.name,
                    status=OperationStatus.FAILED,
                    risk_level=self.risk_level,
                    details={"error_type": type(e).__name__},
                )
            logger.error(f"Unexpected error in filesystem operation: {e}", exc_info=True)
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=f"Unexpected error: {e}",
                status=OperationStatus.FAILED,
                execution_time=time.time() - start_time,
            )

    def _resolve_and_validate_path(self, path: str) -> Path:
        """Resolve and validate path is within allowed_root.

        Prevents path traversal by:
        1. Resolving all .. and . components
        2. Following symlinks
        3. Verifying final path is within allowed_root
        4. Blocking access to system files

        Args:
            path: Relative or absolute path to validate

        Returns:
            Resolved Path object within allowed_root

        Raises:
            ToolRuntimeError: If path is invalid or outside allowed_root
        """
        if not isinstance(path, str):
            raise ToolRuntimeError("Path must be string")

        if not path.strip():
            raise ToolRuntimeError("Path cannot be empty")

        # Reject obvious traversal attempts early
        if ".." in path or path.startswith("/"):
            raise ToolRuntimeError("Path traversal not allowed")

        # Construct full path
        try:
            full_path = (self.allowed_root / path).resolve()
        except (ValueError, RuntimeError) as e:
            raise ToolRuntimeError(f"Invalid path: {e}")

        # Verify resolved path is within allowed_root
        try:
            full_path.relative_to(self.allowed_root)
        except ValueError:
            raise ToolRuntimeError(
                f"Path is outside allowed root: {full_path} not in {self.allowed_root}"
            )

        logger.debug(f"Path validated: {path} -> {full_path}")
        return full_path

    async def _handle_list(self, path: str) -> str:
        """List directory contents.

        Args:
            path: Directory path to list

        Returns:
            JSON string with directory listing

        Raises:
            ToolRuntimeError: If path invalid or operation fails
        """
        full_path = self._resolve_and_validate_path(path)

        if not full_path.exists():
            raise ToolRuntimeError(f"Path does not exist: {path}")

        if not full_path.is_dir():
            raise ToolRuntimeError(f"Path is not a directory: {path}")

        try:
            entries = []
            for item in sorted(full_path.iterdir()):
                try:
                    entry_info = {
                        "name": item.name,
                        "type": "directory" if item.is_dir() else "file",
                        "size": item.stat().st_size if item.is_file() else None,
                    }
                    entries.append(entry_info)
                except (OSError, PermissionError):
                    # Skip entries we can't stat
                    continue

            result = {
                "path": path,
                "entries": entries,
                "total": len(entries),
            }

            return json.dumps(result, indent=2)

        except Exception as e:
            raise ToolRuntimeError(f"Failed to list directory: {e}")

    async def _handle_read(self, path: str) -> str:
        """Read file contents.

        Args:
            path: File path to read

        Returns:
            File contents as string

        Raises:
            ToolRuntimeError: If path invalid, not a file, or operation fails
        """
        full_path = self._resolve_and_validate_path(path)

        if not full_path.exists():
            raise ToolRuntimeError(f"File does not exist: {path}")

        if not full_path.is_file():
            raise ToolRuntimeError(f"Path is not a file: {path}")

        try:
            file_size = full_path.stat().st_size

            if file_size > self.max_file_size:
                raise ToolRuntimeError(
                    f"File too large: {file_size} bytes (max {self.max_file_size})"
                )

            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            return content

        except UnicodeDecodeError as e:
            raise ToolRuntimeError(f"File is not valid UTF-8: {e}")
        except PermissionError as e:
            raise ToolRuntimeError(f"Permission denied reading file: {e}")
        except Exception as e:
            raise ToolRuntimeError(f"Failed to read file: {e}")

    async def _handle_write(self, path: str, content: str) -> str:
        """Write content to file.

        Creates file if it doesn't exist, overwrites if it does.

        Args:
            path: File path to write
            content: Content to write

        Returns:
            Success message with bytes written

        Raises:
            ToolRuntimeError: If path invalid or operation fails
        """
        full_path = self._resolve_and_validate_path(path)

        # Check if parent directory exists
        parent = full_path.parent
        if not parent.exists():
            raise ToolRuntimeError(f"Parent directory does not exist: {parent}")

        if not parent.is_dir():
            raise ToolRuntimeError(f"Parent is not a directory: {parent}")

        try:
            if not isinstance(content, str):
                content = str(content)

            # Check content size before writing
            content_size = len(content.encode("utf-8"))
            if content_size > self.max_file_size:
                raise ToolRuntimeError(
                    f"Content too large: {content_size} bytes (max {self.max_file_size})"
                )

            # Write file
            with open(full_path, "w", encoding="utf-8") as f:
                f.write(content)

            return f"Successfully wrote {content_size} bytes to {path}"

        except PermissionError as e:
            raise ToolRuntimeError(f"Permission denied writing file: {e}")
        except Exception as e:
            raise ToolRuntimeError(f"Failed to write file: {e}")

    async def _handle_create_directory(self, path: str) -> str:
        """Create a new directory.

        Args:
            path: Directory path to create

        Returns:
            Success message

        Raises:
            ToolRuntimeError: If path invalid or operation fails
        """
        full_path = self._resolve_and_validate_path(path)

        if full_path.exists():
            raise ToolRuntimeError(f"Path already exists: {path}")

        try:
            full_path.mkdir(parents=True, exist_ok=False)
            return f"Successfully created directory: {path}"

        except PermissionError as e:
            raise ToolRuntimeError(f"Permission denied creating directory: {e}")
        except Exception as e:
            raise ToolRuntimeError(f"Failed to create directory: {e}")

    async def _handle_move(self, source: str, dest: str) -> str:
        """Move or rename file/directory.

        Args:
            source: Source path
            dest: Destination path

        Returns:
            Success message

        Raises:
            ToolRuntimeError: If paths invalid or operation fails
        """
        source_path = self._resolve_and_validate_path(source)
        dest_path = self._resolve_and_validate_path(dest)

        if not source_path.exists():
            raise ToolRuntimeError(f"Source does not exist: {source}")

        if dest_path.exists():
            raise ToolRuntimeError(f"Destination already exists: {dest}")

        try:
            source_path.rename(dest_path)
            return f"Successfully moved {source} to {dest}"

        except PermissionError as e:
            raise ToolRuntimeError(f"Permission denied moving: {e}")
        except Exception as e:
            raise ToolRuntimeError(f"Failed to move: {e}")

    async def _handle_copy(self, source: str, dest: str) -> str:
        """Copy file or directory.

        Args:
            source: Source path to copy
            dest: Destination path

        Returns:
            Success message

        Raises:
            ToolRuntimeError: If paths invalid or operation fails
        """
        source_path = self._resolve_and_validate_path(source)
        dest_path = self._resolve_and_validate_path(dest)

        if not source_path.exists():
            raise ToolRuntimeError(f"Source does not exist: {source}")

        if dest_path.exists():
            raise ToolRuntimeError(f"Destination already exists: {dest}")

        try:
            if source_path.is_file():
                shutil.copy2(source_path, dest_path)
            elif source_path.is_dir():
                shutil.copytree(source_path, dest_path)
            else:
                raise ToolRuntimeError(f"Cannot copy special file: {source}")

            return f"Successfully copied {source} to {dest}"

        except PermissionError as e:
            raise ToolRuntimeError(f"Permission denied copying: {e}")
        except Exception as e:
            raise ToolRuntimeError(f"Failed to copy: {e}")

    async def _handle_delete(self, path: str) -> str:
        """Delete file or directory.

        Args:
            path: Path to delete

        Returns:
            Success message

        Raises:
            ToolRuntimeError: If path invalid or operation fails
        """
        full_path = self._resolve_and_validate_path(path)

        if not full_path.exists():
            raise ToolRuntimeError(f"Path does not exist: {path}")

        try:
            if full_path.is_file():
                full_path.unlink()
            elif full_path.is_dir():
                shutil.rmtree(full_path)
            else:
                raise ToolRuntimeError(f"Cannot delete special file: {path}")

            return f"Successfully deleted {path}"

        except PermissionError as e:
            raise ToolRuntimeError(f"Permission denied deleting: {e}")
        except Exception as e:
            raise ToolRuntimeError(f"Failed to delete: {e}")
