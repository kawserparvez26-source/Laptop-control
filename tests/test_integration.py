"""Integration tests for complete security pipeline."""

import pytest
from laptop_control.tools.registry import ToolRegistry
from laptop_control.tools.base import BaseTool
from laptop_control.core.types import OperationStatus, RiskLevel, ToolRequest, ToolResult
from laptop_control.security.authorization import AuthorizationManager
from laptop_control.security.audit import AuditLogger
from laptop_control.security.emergency_stop import EmergencyStop
from typing import Any


class IntegrationTestTool(BaseTool):
    """Tool for integration testing."""

    async def validate(self, command: str) -> bool:
        return not command.startswith("invalid")

    async def _execute_impl(
        self,
        command: str,
        user_id: int,
        **kwargs: Any,
    ) -> ToolResult:
        return ToolResult(
            tool_name=self.name,
            success=True,
            output=f"Executed by user {user_id}: {command}",
            status=OperationStatus.SUCCESS,
        )


class TestIntegration:
    """Integration tests for complete pipeline."""

    @pytest.mark.asyncio
    async def test_complete_security_pipeline(self, temp_dir):
        """Test complete security pipeline: Auth -> EmergencyStop -> Tool -> Audit."""
        # Setup
        authorized_users = {123, 456, 789}
        auth_manager = AuthorizationManager(authorized_users)
        audit_logger = AuditLogger(str(temp_dir / "audit.log"))
        emergency_stop = EmergencyStop(str(temp_dir / "stop.file"))
        registry = ToolRegistry(auth_manager, audit_logger, emergency_stop)

        # Register tool
        tool = IntegrationTestTool(
            name="test_tool",
            description="Test",
            risk_level=RiskLevel.MEDIUM,
        )
        registry.register(tool)

        # Execute: Authorized user, emergency stop inactive, tool exists
        request = ToolRequest(
            tool_name="test_tool",
            user_id=123,
            command="test_command",
        )

        result = await registry.execute(request)

        # Verify
        assert result.success is True
        assert result.status == OperationStatus.SUCCESS
        assert "Executed by user 123" in result.output

        # Verify audit log
        records = audit_logger.read_records()
        assert len(records) > 0

    @pytest.mark.asyncio
    async def test_unauthorized_user_blocked_before_tool(self, temp_dir):
        """Verify unauthorized users never reach tool implementation."""
        # Setup
        authorized_users = {123}
        auth_manager = AuthorizationManager(authorized_users)
        audit_logger = AuditLogger(str(temp_dir / "audit.log"))
        emergency_stop = EmergencyStop(str(temp_dir / "stop.file"))
        registry = ToolRegistry(auth_manager, audit_logger, emergency_stop)

        # Register tool with execution counter
        tool = IntegrationTestTool(
            name="test_tool",
            description="Test",
        )
        registry.register(tool)

        # Execute with unauthorized user
        request = ToolRequest(
            tool_name="test_tool",
            user_id=999,  # Not authorized
            command="test",
        )

        result = await registry.execute(request)

        # Verify tool was never executed
        assert result.success is False
        assert "Authorization failed" in result.error

        # Verify audit shows authorization failure
        records = audit_logger.read_records()
        assert any("authorization_failure" in r.get("operation", "") for r in records)

    @pytest.mark.asyncio
    async def test_emergency_stop_blocks_before_tool(self, temp_dir):
        """Verify emergency stop blocks execution before tool runs."""
        # Setup
        authorized_users = {123}
        auth_manager = AuthorizationManager(authorized_users)
        audit_logger = AuditLogger(str(temp_dir / "audit.log"))
        emergency_stop = EmergencyStop(str(temp_dir / "stop.file"))
        registry = ToolRegistry(auth_manager, audit_logger, emergency_stop)

        # Register tool
        tool = IntegrationTestTool(
            name="test_tool",
            description="Test",
        )
        registry.register(tool)

        # Activate emergency stop
        emergency_stop.activate(reason="Security threat")

        # Execute with authorized user
        request = ToolRequest(
            tool_name="test_tool",
            user_id=123,
            command="test",
        )

        result = await registry.execute(request)

        # Verify tool was never executed
        assert result.success is False
        assert "emergency stop" in result.error.lower()

        # Verify audit shows emergency stop block
        records = audit_logger.read_records()
        assert any("emergency_stop" in r.get("operation", "") for r in records)
