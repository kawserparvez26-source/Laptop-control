"""Tests for core types and data models."""

import pytest
from laptop_control.core.types import (
    OperationStatus,
    RiskLevel,
    Command,
    CommandResult,
    ToolRequest,
    ToolResult,
)


class TestOperationStatus:
    """Test OperationStatus enum."""

    def test_all_statuses_exist(self):
        """Test that all expected statuses exist."""
        assert OperationStatus.PENDING.value == "pending"
        assert OperationStatus.RUNNING.value == "running"
        assert OperationStatus.SUCCESS.value == "success"
        assert OperationStatus.FAILED.value == "failed"
        assert OperationStatus.TIMEOUT.value == "timeout"
        assert OperationStatus.CANCELLED.value == "cancelled"

    def test_status_comparison(self):
        """Test status enum comparison."""
        assert OperationStatus.SUCCESS == OperationStatus.SUCCESS
        assert OperationStatus.SUCCESS != OperationStatus.FAILED


class TestRiskLevel:
    """Test RiskLevel enum."""

    def test_all_levels_exist(self):
        """Test that all expected risk levels exist."""
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.CRITICAL.value == "critical"

    def test_risk_level_comparison(self):
        """Test risk level enum comparison."""
        assert RiskLevel.LOW == RiskLevel.LOW
        assert RiskLevel.LOW != RiskLevel.CRITICAL


class TestCommand:
    """Test Command dataclass."""

    def test_command_creation(self):
        """Test creating a Command."""
        cmd = Command(
            user_id=123,
            tool_name="filesystem",
            operation="list_files",
            parameters={"path": "/home"},
            timestamp=1234567890.0,
            request_id="req_123",
            risk_level=RiskLevel.LOW,
        )

        assert cmd.user_id == 123
        assert cmd.tool_name == "filesystem"
        assert cmd.operation == "list_files"
        assert cmd.parameters == {"path": "/home"}
        assert cmd.timestamp == 1234567890.0
        assert cmd.request_id == "req_123"
        assert cmd.risk_level == RiskLevel.LOW

    def test_command_default_values(self):
        """Test Command default values."""
        cmd = Command(
            user_id=456,
            tool_name="terminal",
            operation="execute",
        )

        assert cmd.parameters == {}
        assert cmd.timestamp == 0.0
        assert cmd.request_id == ""
        assert cmd.risk_level == RiskLevel.MEDIUM

    def test_command_empty_parameters(self):
        """Test Command with empty parameters."""
        cmd = Command(
            user_id=789,
            tool_name="test",
            operation="test_op",
            parameters={},
        )

        assert cmd.parameters == {}


class TestCommandResult:
    """Test CommandResult dataclass."""

    def test_command_result_creation(self):
        """Test creating a CommandResult."""
        cmd = Command(
            user_id=123,
            tool_name="filesystem",
            operation="list_files",
        )

        result = CommandResult(
            command=cmd,
            status=OperationStatus.SUCCESS,
            output="file1.txt\nfile2.txt",
            error=None,
            execution_time=1.5,
        )

        assert result.command == cmd
        assert result.status == OperationStatus.SUCCESS
        assert result.output == "file1.txt\nfile2.txt"
        assert result.error is None
        assert result.execution_time == 1.5

    def test_command_result_default_values(self):
        """Test CommandResult default values."""
        cmd = Command(
            user_id=456,
            tool_name="terminal",
            operation="execute",
        )

        result = CommandResult(
            command=cmd,
            status=OperationStatus.FAILED,
        )

        assert result.output == ""
        assert result.error is None
        assert result.execution_time == 0.0
        assert result.tool_metadata == {}

    def test_is_successful(self):
        """Test is_successful method."""
        cmd = Command(user_id=1, tool_name="test", operation="test")

        # Successful result
        result_success = CommandResult(
            command=cmd,
            status=OperationStatus.SUCCESS,
        )
        assert result_success.is_successful() is True

        # Failed result
        result_failed = CommandResult(
            command=cmd,
            status=OperationStatus.FAILED,
        )
        assert result_failed.is_successful() is False

    def test_is_error(self):
        """Test is_error method."""
        cmd = Command(user_id=1, tool_name="test", operation="test")

        # Failed result
        result_failed = CommandResult(
            command=cmd,
            status=OperationStatus.FAILED,
        )
        assert result_failed.is_error() is True

        # Timeout result
        result_timeout = CommandResult(
            command=cmd,
            status=OperationStatus.TIMEOUT,
        )
        assert result_timeout.is_error() is True

        # Success result
        result_success = CommandResult(
            command=cmd,
            status=OperationStatus.SUCCESS,
        )
        assert result_success.is_error() is False


class TestToolRequest:
    """Test ToolRequest dataclass."""

    def test_tool_request_creation(self):
        """Test creating a ToolRequest."""
        req = ToolRequest(
            tool_name="filesystem",
            user_id=123,
            command="ls /home",
            risk_level=RiskLevel.MEDIUM,
            requires_approval=True,
            timeout_seconds=60,
            metadata={"msg_id": "msg_123"},
        )

        assert req.tool_name == "filesystem"
        assert req.user_id == 123
        assert req.command == "ls /home"
        assert req.risk_level == RiskLevel.MEDIUM
        assert req.requires_approval is True
        assert req.timeout_seconds == 60
        assert req.metadata == {"msg_id": "msg_123"}

    def test_tool_request_default_values(self):
        """Test ToolRequest default values."""
        req = ToolRequest(
            tool_name="test",
            user_id=456,
            command="test",
        )

        assert req.risk_level == RiskLevel.MEDIUM
        assert req.requires_approval is False
        assert req.timeout_seconds == 30
        assert req.metadata == {}


class TestToolResult:
    """Test ToolResult dataclass."""

    def test_tool_result_creation(self):
        """Test creating a ToolResult."""
        result = ToolResult(
            tool_name="filesystem",
            success=True,
            output="file1.txt",
            error=None,
            execution_time=0.5,
            status=OperationStatus.SUCCESS,
            metadata={"files": 1},
        )

        assert result.tool_name == "filesystem"
        assert result.success is True
        assert result.output == "file1.txt"
        assert result.error is None
        assert result.execution_time == 0.5
        assert result.status == OperationStatus.SUCCESS
        assert result.metadata == {"files": 1}

    def test_tool_result_default_values(self):
        """Test ToolResult default values."""
        result = ToolResult(
            tool_name="test",
            success=True,
        )

        assert result.output == ""
        assert result.error is None
        assert result.execution_time == 0.0
        assert result.status == OperationStatus.SUCCESS
        assert result.metadata == {}

    def test_tool_result_success_failed_validation(self):
        """Test ToolResult validation of success and status."""
        # Valid: success=True with SUCCESS status
        result = ToolResult(
            tool_name="test",
            success=True,
            status=OperationStatus.SUCCESS,
        )
        assert result.success is True

        # Invalid: success=True with FAILED status
        with pytest.raises(ValueError, match="Cannot have success=True with status=FAILED"):
            ToolResult(
                tool_name="test",
                success=True,
                status=OperationStatus.FAILED,
            )

        # Invalid: success=False with SUCCESS status
        with pytest.raises(ValueError, match="Cannot have success=False with status=SUCCESS"):
            ToolResult(
                tool_name="test",
                success=False,
                status=OperationStatus.SUCCESS,
            )

        # Valid: success=False with FAILED status
        result = ToolResult(
            tool_name="test",
            success=False,
            status=OperationStatus.FAILED,
        )
        assert result.success is False
