"""Tests for tool registry."""

import pytest
from laptop_control.tools.registry import ToolRegistry
from laptop_control.tools.base import BaseTool
from laptop_control.core.types import OperationStatus, RiskLevel, ToolRequest, ToolResult
from laptop_control.core.exceptions import EmergencyStopTriggered
from laptop_control.security.authorization import AuthorizationManager
from laptop_control.security.audit import AuditLogger
from laptop_control.security.emergency_stop import EmergencyStop
from typing import Any


class DummyTool(BaseTool):
    """Dummy tool for testing."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.execution_count = 0

    async def validate(self, command: str) -> bool:
        return not command.startswith("invalid")

    async def _execute_impl(
        self,
        command: str,
        user_id: int,
        **kwargs: Any,
    ) -> ToolResult:
        self.execution_count += 1
        return ToolResult(
            tool_name=self.name,
            success=True,
            output="success",
            status=OperationStatus.SUCCESS,
        )


class TestToolRegistry:
    """Test ToolRegistry functionality."""

    def test_registry_starts_empty(self, auth_manager, audit_logger, emergency_stop):
        """Test that registry starts empty."""
        registry = ToolRegistry(auth_manager, audit_logger, emergency_stop)
        assert len(registry.tools) == 0
        assert registry.list_tools() == {}

    def test_register_tool(self, auth_manager, audit_logger, emergency_stop):
        """Test registering a tool."""
        registry = ToolRegistry(auth_manager, audit_logger, emergency_stop)
        tool = DummyTool(name="test_tool", description="Test")

        registry.register(tool)

        assert registry.has("test_tool")
        assert registry.get("test_tool") is tool

    def test_duplicate_registration_rejected(self, auth_manager, audit_logger, emergency_stop):
        """Test that duplicate registrations are rejected."""
        from laptop_control.core.exceptions import ToolExecutionError

        registry = ToolRegistry(auth_manager, audit_logger, emergency_stop)
        tool1 = DummyTool(name="test_tool", description="Test")
        tool2 = DummyTool(name="test_tool", description="Test")

        registry.register(tool1)

        with pytest.raises(ToolExecutionError, match="already registered"):
            registry.register(tool2)

    def test_unregister_tool(self, auth_manager, audit_logger, emergency_stop):
        """Test unregistering a tool."""
        registry = ToolRegistry(auth_manager, audit_logger, emergency_stop)
        tool = DummyTool(name="test_tool", description="Test")

        registry.register(tool)
        assert registry.has("test_tool")

        registry.unregister("test_tool")
        assert not registry.has("test_tool")

    def test_get_nonexistent_tool(self, auth_manager, audit_logger, emergency_stop):
        """Test getting a tool that doesn't exist."""
        registry = ToolRegistry(auth_manager, audit_logger, emergency_stop)
        assert registry.get("nonexistent") is None

    def test_list_tools(self, auth_manager, audit_logger, emergency_stop):
        """Test listing all tools."""
        registry = ToolRegistry(auth_manager, audit_logger, emergency_stop)
        tool1 = DummyTool(name="tool1", description="Tool 1")
        tool2 = DummyTool(name="tool2", description="Tool 2", risk_level=RiskLevel.HIGH)

        registry.register(tool1)
        registry.register(tool2)

        tools = registry.list_tools()
        assert len(tools) == 2
        assert "tool1" in tools
        assert "tool2" in tools
        assert tools["tool1"]["risk_level"] == "medium"
        assert tools["tool2"]["risk_level"] == "high"

    @pytest.mark.asyncio
    async def test_authorized_execution(self, auth_manager, audit_logger, emergency_stop):
        """Test tool execution by authorized user."""
        registry = ToolRegistry(auth_manager, audit_logger, emergency_stop)
        tool = DummyTool(name="test_tool", description="Test")
        registry.register(tool)

        request = ToolRequest(
            tool_name="test_tool",
            user_id=123456789,  # Authorized user
            command="test",
        )

        result = await registry.execute(request)

        assert result.success is True
        assert tool.execution_count == 1

    @pytest.mark.asyncio
    async def test_unauthorized_execution_blocked(self, auth_manager, audit_logger, emergency_stop):
        """Test that unauthorized users cannot execute."""
        registry = ToolRegistry(auth_manager, audit_logger, emergency_stop)
        tool = DummyTool(name="test_tool", description="Test")
        registry.register(tool)

        request = ToolRequest(
            tool_name="test_tool",
            user_id=999999999,  # Unauthorized user
            command="test",
        )

        result = await registry.execute(request)

        assert result.success is False
        assert "Authorization failed" in result.error
        # Tool should not be executed
        assert tool.execution_count == 0

    @pytest.mark.asyncio
    async def test_emergency_stop_blocks_execution(self, auth_manager, audit_logger, emergency_stop):
        """Test that emergency stop blocks tool execution."""
        registry = ToolRegistry(auth_manager, audit_logger, emergency_stop)
        tool = DummyTool(name="test_tool", description="Test")
        registry.register(tool)

        # Activate emergency stop
        emergency_stop.activate(reason="Test")

        request = ToolRequest(
            tool_name="test_tool",
            user_id=123456789,
            command="test",
        )

        result = await registry.execute(request)

        assert result.success is False
        assert "emergency stop" in result.error.lower()
        # Tool should not be executed
        assert tool.execution_count == 0

    @pytest.mark.asyncio
    async def test_tool_not_found(self, auth_manager, audit_logger, emergency_stop):
        """Test execution of non-existent tool."""
        registry = ToolRegistry(auth_manager, audit_logger, emergency_stop)

        request = ToolRequest(
            tool_name="nonexistent",
            user_id=123456789,
            command="test",
        )

        result = await registry.execute(request)

        assert result.success is False
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_execution_audit_on_success(self, auth_manager, audit_logger, emergency_stop):
        """Test that successful executions are audited."""
        registry = ToolRegistry(auth_manager, audit_logger, emergency_stop)
        tool = DummyTool(name="test_tool", description="Test")
        registry.register(tool)

        request = ToolRequest(
            tool_name="test_tool",
            user_id=123456789,
            command="test",
        )

        result = await registry.execute(request)

        assert result.success is True
        records = audit_logger.read_records()
        assert len(records) > 0

    @pytest.mark.asyncio
    async def test_execution_audit_on_authorization_failure(self, auth_manager, audit_logger, emergency_stop):
        """Test that authorization failures are audited."""
        registry = ToolRegistry(auth_manager, audit_logger, emergency_stop)
        tool = DummyTool(name="test_tool", description="Test")
        registry.register(tool)

        request = ToolRequest(
            tool_name="test_tool",
            user_id=999999999,
            command="test",
        )

        result = await registry.execute(request)

        records = audit_logger.read_records()
        assert len(records) > 0
        assert any("authorization_failure" in r.get("operation", "") for r in records)

    @pytest.mark.asyncio
    async def test_execution_audit_on_emergency_stop(self, auth_manager, audit_logger, emergency_stop):
        """Test that emergency stop blocks are audited."""
        registry = ToolRegistry(auth_manager, audit_logger, emergency_stop)
        tool = DummyTool(name="test_tool", description="Test")
        registry.register(tool)

        emergency_stop.activate(reason="Test")

        request = ToolRequest(
            tool_name="test_tool",
            user_id=123456789,
            command="test",
        )

        result = await registry.execute(request)

        records = audit_logger.read_records()
        assert len(records) > 0
        assert any("emergency_stop" in r.get("operation", "") for r in records)
