"""Comprehensive security boundary tests for FilesystemTool.

Tests verify 25 security scenarios:
1. allowed_root must be absolute.
2. allowed_root must exist and be a directory.
3. Relative paths inside allowed_root work.
4. Absolute paths are rejected.
5. ../ traversal is rejected.
6. ../../ traversal is rejected.
7. Resolved paths outside allowed_root are rejected.
8. Symlink pointing outside allowed_root is rejected.
9. Symlink pointing inside allowed_root behaves safely.
10. Missing files return a safe ToolResult failure.
11. Permission errors return a safe ToolResult failure.
12. Unsupported operations are rejected.
13. Invalid JSON is rejected.
14. Missing required fields are rejected.
15. write respects max_file_size.
16. read respects max_file_size.
17. move cannot overwrite an existing destination.
18. copy cannot overwrite an existing destination.
19. delete works only inside allowed_root.
20. Recursive directory operations cannot escape allowed_root through symlinks.
21. File contents are never written to AuditLogger details.
22. Audit records do not contain file contents.
23. Tool execution returns the existing ToolResult type.
24. Unauthorized users cannot execute the tool through BaseTool.execute().
25. EmergencyStop blocks execution through the existing ToolRegistry execution path.
"""

import asyncio
import json
import logging
import tempfile
from pathlib import Path
from typing import Dict, Set
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from laptop_control.core.exceptions import (
    EmergencyStopTriggered,
    AuthorizationError,
    ToolRuntimeError,
)
from laptop_control.core.types import OperationStatus, RiskLevel, ToolResult, ToolRequest
from laptop_control.security.audit import AuditLogger
from laptop_control.security.authorization import AuthorizationManager
from laptop_control.security.emergency_stop import EmergencyStop
from laptop_control.tools.filesystem import FilesystemTool
from laptop_control.tools.registry import ToolRegistry


class TestFilesystemToolPathValidation:
    """Tests for path validation and traversal prevention (scenarios 1-7)."""

    @pytest.fixture
    def temp_root(self):
        """Create a temporary root directory for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_allowed_root_must_be_absolute(self, temp_root):
        """Scenario 1: allowed_root must be absolute."""
        relative_path = "relative/path"
        with pytest.raises(ValueError, match="must be absolute path"):
            FilesystemTool(allowed_root=relative_path)

    def test_allowed_root_must_exist(self, temp_root):
        """Scenario 2a: allowed_root must exist."""
        nonexistent = str(temp_root / "does_not_exist")
        with pytest.raises(ValueError, match="does not exist"):
            FilesystemTool(allowed_root=nonexistent)

    def test_allowed_root_must_be_directory(self, temp_root):
        """Scenario 2b: allowed_root must be a directory."""
        file_path = temp_root / "file.txt"
        file_path.write_text("test")
        with pytest.raises(ValueError, match="must be directory"):
            FilesystemTool(allowed_root=str(file_path))

    def test_relative_paths_inside_allowed_root_work(self, temp_root):
        """Scenario 3: Relative paths inside allowed_root work."""
        tool = FilesystemTool(allowed_root=str(temp_root))
        subdir = temp_root / "subdir"
        subdir.mkdir()
        test_file = subdir / "test.txt"
        test_file.write_text("content")

        # This should not raise
        result = tool._resolve_and_validate_path("subdir/test.txt")
        assert result == test_file

    def test_absolute_paths_are_rejected(self, temp_root):
        """Scenario 4: Absolute paths are rejected."""
        tool = FilesystemTool(allowed_root=str(temp_root))
        with pytest.raises(ToolRuntimeError, match="Path traversal not allowed"):
            tool._resolve_and_validate_path("/etc/passwd")

    def test_dot_dot_traversal_is_rejected(self, temp_root):
        """Scenario 5: ../ traversal is rejected."""
        tool = FilesystemTool(allowed_root=str(temp_root))
        with pytest.raises(ToolRuntimeError, match="Path traversal not allowed"):
            tool._resolve_and_validate_path("subdir/../../../etc/passwd")

    def test_double_dot_traversal_is_rejected(self, temp_root):
        """Scenario 6: ../../ traversal is rejected."""
        tool = FilesystemTool(allowed_root=str(temp_root))
        with pytest.raises(ToolRuntimeError, match="Path traversal not allowed"):
            tool._resolve_and_validate_path("a/../../etc/passwd")

    def test_resolved_paths_outside_allowed_root_are_rejected(self, temp_root):
        """Scenario 7: Resolved paths outside allowed_root are rejected.
        
        Tests that even if we create a structure like subdir/../../parent,
        the resolution check catches it.
        """
        # Create allowed_root/subdir
        subdir = temp_root / "subdir"
        subdir.mkdir()

        tool = FilesystemTool(allowed_root=str(temp_root))

        # Path that resolves outside allowed_root
        # This tests the ValueError.relative_to() check
        with pytest.raises(ToolRuntimeError, match="outside allowed root"):
            # Create a path that when resolved, escapes the root
            tool._resolve_and_validate_path("subdir/../../..")


class TestFilesystemToolSymlinks:
    """Tests for symlink handling (scenarios 8-9, 20)."""

    @pytest.fixture
    def temp_root(self):
        """Create a temporary root directory for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_symlink_pointing_outside_allowed_root_is_rejected(self, temp_root):
        """Scenario 8: Symlink pointing outside allowed_root is rejected."""
        # Create external directory
        with tempfile.TemporaryDirectory() as external_tmp:
            external_dir = Path(external_tmp)
            external_file = external_dir / "external.txt"
            external_file.write_text("external content")

            # Create symlink inside allowed_root pointing outside
            symlink = temp_root / "external_link"
            try:
                symlink.symlink_to(external_file)
            except (OSError, NotImplementedError):
                # Skip on systems that don't support symlinks
                pytest.skip("Symlinks not supported")

            tool = FilesystemTool(allowed_root=str(temp_root))

            # Attempting to access the symlink should fail
            with pytest.raises(ToolRuntimeError, match="outside allowed root"):
                tool._resolve_and_validate_path("external_link")

    def test_symlink_pointing_inside_allowed_root_behaves_safely(self, temp_root):
        """Scenario 9: Symlink pointing inside allowed_root behaves safely."""
        # Create a file inside allowed_root
        test_file = temp_root / "target.txt"
        test_file.write_text("target content")

        # Create a symlink to it
        symlink = temp_root / "link"
        try:
            symlink.symlink_to(test_file)
        except (OSError, NotImplementedError):
            pytest.skip("Symlinks not supported")

        tool = FilesystemTool(allowed_root=str(temp_root))

        # This should resolve safely
        result = tool._resolve_and_validate_path("link")
        # resolve() follows symlinks, so result should be the target
        assert result.is_file()
        assert result.read_text() == "target content"

    def test_symlink_directory_cannot_escape_allowed_root(self, temp_root):
        """Scenario 20: Recursive directory operations cannot escape allowed_root through symlinks."""
        # Create structure inside allowed_root
        safe_dir = temp_root / "safe"
        safe_dir.mkdir()
        (safe_dir / "file.txt").write_text("content")

        # Create external directory
        with tempfile.TemporaryDirectory() as external_tmp:
            external_dir = Path(external_tmp)
            (external_dir / "external_file.txt").write_text("external")

            # Create symlink inside safe_dir pointing outside
            symlink = safe_dir / "external_link"
            try:
                symlink.symlink_to(external_dir)
            except (OSError, NotImplementedError):
                pytest.skip("Symlinks not supported")

            tool = FilesystemTool(allowed_root=str(temp_root))

            # Trying to access the symlink should fail path validation
            with pytest.raises(ToolRuntimeError, match="outside allowed root"):
                tool._resolve_and_validate_path("safe/external_link")


class TestFilesystemToolOperations:
    """Tests for file operations and error handling (scenarios 10-11, 15-20)."""

    @pytest.fixture
    def temp_root(self):
        """Create a temporary root directory for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def tool(self, temp_root):
        """Create a FilesystemTool instance."""
        return FilesystemTool(allowed_root=str(temp_root))

    @pytest.mark.asyncio
    async def test_missing_files_return_safe_tool_result_failure(self, tool, temp_root):
        """Scenario 10: Missing files return a safe ToolResult failure."""
        command = json.dumps({"operation": "read", "path": "nonexistent.txt"})
        result = await tool._execute_impl(command, user_id=123)

        assert isinstance(result, ToolResult)
        assert result.success is False
        assert "does not exist" in result.error
        assert result.status == OperationStatus.FAILED

    @pytest.mark.asyncio
    async def test_permission_errors_return_safe_tool_result_failure(self, tool, temp_root):
        """Scenario 11: Permission errors return a safe ToolResult failure."""
        # Create a file with no read permissions
        test_file = temp_root / "noaccess.txt"
        test_file.write_text("secret")
        test_file.chmod(0o000)

        try:
            command = json.dumps({"operation": "read", "path": "noaccess.txt"})
            result = await tool._execute_impl(command, user_id=123)

            assert isinstance(result, ToolResult)
            assert result.success is False
            assert result.status == OperationStatus.FAILED
        finally:
            # Restore permissions for cleanup
            test_file.chmod(0o644)

    @pytest.mark.asyncio
    async def test_write_respects_max_file_size(self, tool, temp_root):
        """Scenario 15: write respects max_file_size."""
        large_content = "x" * (tool.max_file_size + 1)
        command = json.dumps({
            "operation": "write",
            "path": "large.txt",
            "content": large_content
        })
        result = await tool._execute_impl(command, user_id=123)

        assert result.success is False
        assert "too large" in result.error

    @pytest.mark.asyncio
    async def test_read_respects_max_file_size(self, tool, temp_root):
        """Scenario 16: read respects max_file_size."""
        # Create a file larger than max_file_size
        large_file = temp_root / "large.txt"
        large_file.write_text("x" * (tool.max_file_size + 1))

        command = json.dumps({"operation": "read", "path": "large.txt"})
        result = await tool._execute_impl(command, user_id=123)

        assert result.success is False
        assert "too large" in result.error

    @pytest.mark.asyncio
    async def test_move_cannot_overwrite_existing_destination(self, tool, temp_root):
        """Scenario 17: move cannot overwrite an existing destination."""
        source = temp_root / "source.txt"
        source.write_text("source content")
        dest = temp_root / "dest.txt"
        dest.write_text("dest content")

        command = json.dumps({
            "operation": "move",
            "path": "source.txt",
            "dest": "dest.txt"
        })
        result = await tool._execute_impl(command, user_id=123)

        assert result.success is False
        assert "already exists" in result.error

    @pytest.mark.asyncio
    async def test_copy_cannot_overwrite_existing_destination(self, tool, temp_root):
        """Scenario 18: copy cannot overwrite an existing destination."""
        source = temp_root / "source.txt"
        source.write_text("source content")
        dest = temp_root / "dest.txt"
        dest.write_text("dest content")

        command = json.dumps({
            "operation": "copy",
            "path": "source.txt",
            "dest": "dest.txt"
        })
        result = await tool._execute_impl(command, user_id=123)

        assert result.success is False
        assert "already exists" in result.error

    @pytest.mark.asyncio
    async def test_delete_works_only_inside_allowed_root(self, tool, temp_root):
        """Scenario 19: delete works only inside allowed_root."""
        test_file = temp_root / "delete_me.txt"
        test_file.write_text("content")

        # Delete should work inside allowed_root
        command = json.dumps({"operation": "delete", "path": "delete_me.txt"})
        result = await tool._execute_impl(command, user_id=123)
        assert result.success is True
        assert not test_file.exists()

        # Attempting to delete outside allowed_root should fail
        command = json.dumps({"operation": "delete", "path": "/etc/passwd"})
        result = await tool._execute_impl(command, user_id=123)
        assert result.success is False


class TestFilesystemToolValidation:
    """Tests for JSON validation and command parsing (scenarios 12-14)."""

    @pytest.fixture
    def temp_root(self):
        """Create a temporary root directory for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def tool(self, temp_root):
        """Create a FilesystemTool instance."""
        return FilesystemTool(allowed_root=str(temp_root))

    @pytest.mark.asyncio
    async def test_unsupported_operations_are_rejected(self, tool):
        """Scenario 12: Unsupported operations are rejected."""
        command = json.dumps({"operation": "invalid_op", "path": "file.txt"})
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_invalid_json_is_rejected(self, tool):
        """Scenario 13: Invalid JSON is rejected."""
        command = "{ not valid json }"
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_missing_required_fields_are_rejected(self, tool):
        """Scenario 14: Missing required fields are rejected."""
        # Missing 'operation' field
        command = json.dumps({"path": "file.txt"})
        is_valid = await tool.validate(command)
        assert is_valid is False

        # Missing 'path' field
        command = json.dumps({"operation": "read"})
        is_valid = await tool.validate(command)
        assert is_valid is False

        # Write operation missing 'content' field
        command = json.dumps({"operation": "write", "path": "file.txt"})
        is_valid = await tool.validate(command)
        assert is_valid is False

        # Move operation missing 'dest' field
        command = json.dumps({"operation": "move", "path": "src.txt"})
        is_valid = await tool.validate(command)
        assert is_valid is False


class TestFilesystemToolAuditLogging:
    """Tests for audit logging and secret sanitization (scenarios 21-22)."""

    @pytest.fixture
    def temp_root(self):
        """Create a temporary root directory for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def audit_log_file(self, temp_root):
        """Create an audit log file path."""
        return str(temp_root / "audit.log")

    @pytest.fixture
    def audit_logger(self, audit_log_file):
        """Create an AuditLogger instance."""
        return AuditLogger(log_file=audit_log_file, fail_on_write=False)

    @pytest.fixture
    def tool_with_audit(self, temp_root, audit_logger):
        """Create a FilesystemTool with audit logging."""
        return FilesystemTool(
            allowed_root=str(temp_root),
            audit_logger=audit_logger
        )

    @pytest.mark.asyncio
    async def test_file_contents_never_written_to_audit_logger_details(
        self, tool_with_audit, temp_root, audit_log_file
    ):
        """Scenario 21: File contents are never written to AuditLogger details."""
        # Create and write a file
        test_file = temp_root / "test.txt"
        sensitive_content = "SUPER_SECRET_PASSWORD"
        test_file.write_text(sensitive_content)

        # Read the file through the tool
        command = json.dumps({"operation": "read", "path": "test.txt"})
        result = await tool_with_audit._execute_impl(command, user_id=123)

        # Check audit logs
        audit_logger = tool_with_audit.audit_logger
        records = audit_logger.read_records()

        # File contents should not be in any audit record
        for record in records:
            details_str = json.dumps(record.get("details", {}))
            assert sensitive_content not in details_str

    @pytest.mark.asyncio
    async def test_audit_records_do_not_contain_file_contents(
        self, tool_with_audit, temp_root, audit_log_file
    ):
        """Scenario 22: Audit records do not contain file contents."""
        test_file = temp_root / "sensitive.txt"
        sensitive_data = "api_key=sk_live_1234567890"
        test_file.write_text(sensitive_data)

        # Write a file
        write_command = json.dumps({
            "operation": "write",
            "path": "newfile.txt",
            "content": sensitive_data
        })
        await tool_with_audit._execute_impl(write_command, user_id=123)

        # Read the audit log
        audit_logger = tool_with_audit.audit_logger
        records = audit_logger.read_records()

        # Verify sensitive_data doesn't appear in audit details
        for record in records:
            details = record.get("details", {})
            assert sensitive_data not in str(details)


class TestFilesystemToolResultType:
    """Tests for ToolResult type consistency (scenario 23)."""

    @pytest.fixture
    def temp_root(self):
        """Create a temporary root directory for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def tool(self, temp_root):
        """Create a FilesystemTool instance."""
        return FilesystemTool(allowed_root=str(temp_root))

    @pytest.mark.asyncio
    async def test_tool_execution_returns_tool_result_type(self, tool, temp_root):
        """Scenario 23: Tool execution returns the existing ToolResult type."""
        test_file = temp_root / "test.txt"
        test_file.write_text("test content")

        # Test successful operation
        command = json.dumps({"operation": "read", "path": "test.txt"})
        result = await tool._execute_impl(command, user_id=123)

        assert isinstance(result, ToolResult)
        assert hasattr(result, "tool_name")
        assert hasattr(result, "success")
        assert hasattr(result, "output")
        assert hasattr(result, "error")
        assert hasattr(result, "status")
        assert hasattr(result, "execution_time")

        # Test failed operation
        command = json.dumps({"operation": "read", "path": "nonexistent.txt"})
        result = await tool._execute_impl(command, user_id=123)

        assert isinstance(result, ToolResult)
        assert result.success is False
        assert result.status == OperationStatus.FAILED


class TestFilesystemToolAuthorization:
    """Tests for authorization integration (scenario 24)."""

    @pytest.fixture
    def temp_root(self):
        """Create a temporary root directory for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def authorizer(self):
        """Create an AuthorizationManager."""
        return AuthorizationManager(authorized_users={123})

    @pytest.fixture
    def tool(self, temp_root, authorizer):
        """Create a FilesystemTool with authorization."""
        return FilesystemTool(
            allowed_root=str(temp_root),
            authorizer=authorizer
        )

    @pytest.mark.asyncio
    async def test_unauthorized_users_cannot_execute_through_base_tool(
        self, tool, temp_root
    ):
        """Scenario 24: Unauthorized users cannot execute the tool through BaseTool.execute()."""
        test_file = temp_root / "test.txt"
        test_file.write_text("content")

        # Authorized user should succeed
        command = json.dumps({"operation": "read", "path": "test.txt"})
        result = await tool.execute(command, user_id=123)
        assert result.success is True

        # Unauthorized user should fail
        result = await tool.execute(command, user_id=999)
        assert result.success is False
        assert "not authorized" in result.error
        assert result.status == OperationStatus.FAILED


class TestFilesystemToolEmergencyStop:
    """Tests for EmergencyStop integration (scenario 25)."""

    @pytest.fixture
    def temp_root(self):
        """Create a temporary root directory for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def emergency_stop(self, temp_root):
        """Create an EmergencyStop instance."""
        stop_file = str(temp_root / "stop")
        return EmergencyStop(stop_file=stop_file)

    @pytest.fixture
    def authorizer(self):
        """Create an AuthorizationManager."""
        return AuthorizationManager(authorized_users={123})

    @pytest.fixture
    def audit_logger(self, temp_root):
        """Create an AuditLogger instance."""
        return AuditLogger(
            log_file=str(temp_root / "audit.log"),
            fail_on_write=False
        )

    @pytest.fixture
    def registry(self, authorizer, audit_logger, emergency_stop):
        """Create a ToolRegistry instance."""
        return ToolRegistry(
            authorizer=authorizer,
            audit_logger=audit_logger,
            emergency_stop=emergency_stop
        )

    @pytest.mark.asyncio
    async def test_emergency_stop_blocks_execution_through_registry(
        self, registry, temp_root
    ):
        """Scenario 25: EmergencyStop blocks execution through the existing ToolRegistry execution path."""
        # Create a FilesystemTool and register it
        tool = FilesystemTool(allowed_root=str(temp_root))
        registry.register(tool)

        # Create a test file
        test_file = temp_root / "test.txt"
        test_file.write_text("content")

        # Verify normal operation works
        request = ToolRequest(
            tool_name="filesystem",
            user_id=123,
            command=json.dumps({"operation": "read", "path": "test.txt"}),
            risk_level=RiskLevel.HIGH
        )
        result = await registry.execute(request)
        assert result.success is True

        # Activate emergency stop
        registry.emergency_stop.activate(reason="Test emergency stop")

        # Execution should now fail
        request = ToolRequest(
            tool_name="filesystem",
            user_id=123,
            command=json.dumps({"operation": "read", "path": "test.txt"}),
            risk_level=RiskLevel.HIGH
        )
        result = await registry.execute(request)
        assert result.success is False
        assert "emergency stop" in result.error.lower()
        assert result.status == OperationStatus.FAILED


class TestFilesystemToolInitialization:
    """Tests for initialization and configuration validation."""

    def test_initialization_with_invalid_type_for_allowed_root(self):
        """Test that non-string allowed_root raises TypeError."""
        with pytest.raises(TypeError, match="must be string"):
            FilesystemTool(allowed_root=123)

    def test_initialization_with_invalid_max_file_size(self):
        """Test that invalid max_file_size raises ValueError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(ValueError, match="must be positive integer"):
                FilesystemTool(
                    allowed_root=tmpdir,
                    max_file_size=-1
                )

    def test_initialization_with_invalid_max_file_size_zero(self):
        """Test that zero max_file_size raises ValueError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(ValueError, match="must be positive integer"):
                FilesystemTool(
                    allowed_root=tmpdir,
                    max_file_size=0
                )

    def test_initialization_with_invalid_authorizer_type(self):
        """Test that invalid authorizer type raises TypeError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(TypeError, match="must be AuthorizationManager"):
                FilesystemTool(
                    allowed_root=tmpdir,
                    authorizer="not_an_authorizer"
                )

    def test_initialization_with_invalid_audit_logger_type(self):
        """Test that invalid audit_logger type raises TypeError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(TypeError, match="must be AuditLogger"):
                FilesystemTool(
                    allowed_root=tmpdir,
                    audit_logger="not_an_audit_logger"
                )


class TestFilesystemToolEdgeCases:
    """Tests for edge cases and special scenarios."""

    @pytest.fixture
    def temp_root(self):
        """Create a temporary root directory for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def tool(self, temp_root):
        """Create a FilesystemTool instance."""
        return FilesystemTool(allowed_root=str(temp_root))

    @pytest.mark.asyncio
    async def test_empty_path_is_rejected(self, tool):
        """Test that empty path is rejected."""
        with pytest.raises(ToolRuntimeError, match="cannot be empty"):
            tool._resolve_and_validate_path("")

    @pytest.mark.asyncio
    async def test_whitespace_only_path_is_rejected(self, tool):
        """Test that whitespace-only path is rejected."""
        with pytest.raises(ToolRuntimeError, match="cannot be empty"):
            tool._resolve_and_validate_path("   ")

    @pytest.mark.asyncio
    async def test_validate_with_non_string_command(self, tool):
        """Test that validation rejects non-string commands."""
        is_valid = await tool.validate(None)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_validate_with_empty_string_command(self, tool):
        """Test that validation rejects empty string commands."""
        is_valid = await tool.validate("")
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_validate_command_is_not_dict(self, tool):
        """Test that validation rejects non-dict JSON commands."""
        command = json.dumps(["operation", "read"])  # JSON array, not object
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_list_operation_works(self, tool, temp_root):
        """Test that list operation works correctly."""
        (temp_root / "file1.txt").write_text("content1")
        (temp_root / "file2.txt").write_text("content2")
        subdir = temp_root / "subdir"
        subdir.mkdir()

        command = json.dumps({"operation": "list", "path": "."})
        result = await tool._execute_impl(command, user_id=123)

        assert result.success is True
        output = json.loads(result.output)
        assert "entries" in output
        assert len(output["entries"]) == 3

    @pytest.mark.asyncio
    async def test_create_directory_operation_works(self, tool, temp_root):
        """Test that create_directory operation works correctly."""
        command = json.dumps({"operation": "create_directory", "path": "newdir"})
        result = await tool._execute_impl(command, user_id=123)

        assert result.success is True
        assert (temp_root / "newdir").is_dir()

    @pytest.mark.asyncio
    async def test_write_and_read_roundtrip(self, tool, temp_root):
        """Test writing and reading a file."""
        test_content = "Hello, World!"

        write_command = json.dumps({
            "operation": "write",
            "path": "test.txt",
            "content": test_content
        })
        write_result = await tool._execute_impl(write_command, user_id=123)
        assert write_result.success is True

        read_command = json.dumps({"operation": "read", "path": "test.txt"})
        read_result = await tool._execute_impl(read_command, user_id=123)
        assert read_result.success is True
        assert read_result.output == test_content

    @pytest.mark.asyncio
    async def test_move_operation_works(self, tool, temp_root):
        """Test that move operation works correctly."""
        source = temp_root / "source.txt"
        source.write_text("content")

        command = json.dumps({
            "operation": "move",
            "path": "source.txt",
            "dest": "dest.txt"
        })
        result = await tool._execute_impl(command, user_id=123)

        assert result.success is True
        assert not source.exists()
        assert (temp_root / "dest.txt").exists()

    @pytest.mark.asyncio
    async def test_copy_operation_works(self, tool, temp_root):
        """Test that copy operation works correctly."""
        source = temp_root / "source.txt"
        source.write_text("content")

        command = json.dumps({
            "operation": "copy",
            "path": "source.txt",
            "dest": "copy.txt"
        })
        result = await tool._execute_impl(command, user_id=123)

        assert result.success is True
        assert source.exists()
        assert (temp_root / "copy.txt").exists()
        assert source.read_text() == (temp_root / "copy.txt").read_text()
