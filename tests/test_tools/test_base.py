"""Tests for base tool abstraction."""

import pytest
from typing import Any
from laptop_control.tools.base import BaseTool
from laptop_control.core.types import OperationStatus, RiskLevel, ToolResult
from laptop_control.security.authorization import AuthorizationManager
from laptop_control.security.audit import AuditLogger


class TestTool(BaseTool):
    """Test tool for testing base functionality."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.validation_count = 0
        self.execution_count = 0
        self.last_command = None

    async def validate(self, command: str) -> bool:
        """Test validation logic."""
        self.validation_count += 1
        if not command or command.startswith("invalid"):
            return False
        return True

    async def _execute_impl(
        self,
        command: str,
        user_id: int,
        **kwargs: Any,
    ) -> ToolResult:
        """Test execution logic."""
        self.execution_count += 1
        self.last_command = command

        if command == "error":
            return ToolResult(
                tool_name=self.name,
                success=False,
                error="Test error",
                status=OperationStatus.FAILED,
            )

        return ToolResult(
            tool_name=self.name,
            success=True,
            output=f"Executed: {command}",
            status=OperationStatus.SUCCESS,
        )


class TestBaseTool:
    """Test BaseTool functionality."""

    def test_valid_tool_creation(self):
        """Test creating a valid tool."""
        tool = TestTool(
            name="test_tool",
            description="Test tool",
            risk_level=RiskLevel.LOW,
        )
        assert tool.name == "test_tool"
        assert tool.description == "Test tool"
        assert tool.risk_level == RiskLevel.LOW

    def test_invalid_tool_name_uppercase(self):
        """Test that uppercase tool names are rejected."""
        with pytest.raises(ValueError, match="Tool name.*invalid"):
            TestTool(
                name="TestTool",
                description="Test tool",
            )

    def test_invalid_tool_name_with_dash(self):
        """Test that dashes in tool names are rejected."""
        with pytest.raises(ValueError, match="Tool name.*invalid"):
            TestTool(
                name="test-tool",
                description="Test tool",
            )

    def test_invalid_tool_name_with_space(self):
        """Test that spaces in tool names are rejected."""
        with pytest.raises(ValueError, match="Tool name.*invalid"):
            TestTool(
                name="test tool",
                description="Test tool",
            )

    def test_invalid_description_empty(self):
        """Test that empty description is rejected."""
        with pytest.raises(ValueError, match="Description must be non-empty"):
            TestTool(
                name="test_tool",
                description="",
            )

    def test_invalid_risk_level_type(self):
        """Test that invalid risk_level type is rejected."""
        with pytest.raises(TypeError, match="risk_level must be RiskLevel"):
            TestTool(
                name="test_tool",
                description="Test",
                risk_level="high",
            )

    def test_tool_metadata(self):
        """Test getting tool metadata."""
        tool = TestTool(
            name="test_tool",
            description="Test tool",
            risk_level=RiskLevel.MEDIUM,
        )
        metadata = tool.get_metadata()

        assert metadata["name"] == "test_tool"
        assert metadata["description"] == "Test tool"
        assert metadata["risk_level"] == "medium"

    def test_tool_repr(self):
        """Test tool string representation."""
        tool = TestTool(
            name="test_tool",
            description="Test tool",
        )
        repr_str = repr(tool)
        assert "test_tool" in repr_str
        assert "TestTool" in repr_str

    @pytest.mark.asyncio
    async def test_successful_execution(self):
        """Test successful tool execution."""
        tool = TestTool(
            name="test_tool",
            description="Test tool",
        )

        result = await tool.execute("echo hello", user_id=123)

        assert result.success is True
        assert result.status == OperationStatus.SUCCESS
        assert "hello" in result.output
        assert result.error is None

    @pytest.mark.asyncio
    async def test_failed_execution(self):
        """Test failed tool execution."""
        tool = TestTool(
            name="test_tool",
            description="Test tool",
        )

        result = await tool.execute("error", user_id=123)

        assert result.success is False
        assert result.status == OperationStatus.FAILED
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_validation_failure(self):
        """Test validation failure blocks execution."""
        tool = TestTool(
            name="test_tool",
            description="Test tool",
        )

        result = await tool.execute("invalid command", user_id=123)

        assert result.success is False
        assert result.status == OperationStatus.FAILED
        assert "validation failed" in result.error.lower()
        # Execution should not be called
        assert tool.execution_count == 0

    @pytest.mark.asyncio
    async def test_authorization_failure_blocks_execution(self, auth_manager):
        """Test that authorization failure blocks execution."""
        tool = TestTool(
            name="test_tool",
            description="Test tool",
            authorizer=auth_manager,
        )

        # Unauthorized user
        result = await tool.execute("echo hello", user_id=999999999)

        assert result.success is False
        assert result.status == OperationStatus.FAILED
        assert "not authorized" in result.error.lower()
        # Execution should not be called
        assert tool.execution_count == 0

    @pytest.mark.asyncio
    async def test_authorization_success_allows_execution(self, auth_manager):
        """Test that authorized user can execute."""
        tool = TestTool(
            name="test_tool",
            description="Test tool",
            authorizer=auth_manager,
        )

        # Authorized user
        result = await tool.execute("echo hello", user_id=123456789)

        assert result.success is True
        assert tool.execution_count == 1

    @pytest.mark.asyncio
    async def test_audit_logging_on_success(self, auth_manager, audit_logger):
        """Test that successful execution is audited."""
        tool = TestTool(
            name="test_tool",
            description="Test tool",
            authorizer=auth_manager,
            audit_logger=audit_logger,
        )

        result = await tool.execute("echo hello", user_id=123456789)

        assert result.success is True
        # Check audit records
        records = audit_logger.read_records()
        assert len(records) > 0

    @pytest.mark.asyncio
    async def test_audit_logging_on_authorization_failure(self, auth_manager, audit_logger):
        """Test that authorization failure is audited."""
        tool = TestTool(
            name="test_tool",
            description="Test tool",
            authorizer=auth_manager,
            audit_logger=audit_logger,
        )

        result = await tool.execute("echo hello", user_id=999999999)

        # Check audit records
        records = audit_logger.read_records()
        assert len(records) > 0
        assert any("authorization_failure" in r.get("operation", "") for r in records)
