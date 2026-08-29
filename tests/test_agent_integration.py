import pytest
from laptop_control.agent.integration import SecureDispatcher, AgentLoopStub
from laptop_control.security.authorization import AuthorizationManager
from laptop_control.security.audit import AuditLogger
from laptop_control.security.emergency_stop import EmergencyStop
from laptop_control.tools.registry import ToolRegistry

@pytest.fixture
def secure_dispatcher():
    auth = AuthorizationManager(authorized_users={123})
    audit = AuditLogger(log_file="/tmp/test_audit.log", fail_on_write=False)
    emergency = EmergencyStop(stop_file="/tmp/test_emergency.stop")
    registry = ToolRegistry(authorizer=auth, audit_logger=audit, emergency_stop=emergency)
    
    agent_stub = AgentLoopStub(registry=registry, require_human_approval=True)
    # Only ScreenTool is allowed
    return SecureDispatcher(agent_loop=agent_stub, allowed_tools=["ScreenTool"])


def test_dispatcher_allows_whitelisted_tool(secure_dispatcher):
    ai_text = '{"tool": "ScreenTool", "kwargs": {"quality": "high"}}'
    result = secure_dispatcher.process_ai_message(ai_text)
    assert result is not None
    assert result["status"] == "queued_for_human_approval"
    assert result["tool"] == "ScreenTool"


def test_dispatcher_rejects_non_whitelisted_tool(secure_dispatcher):
    ai_text = '{"tool": "DeleteSystem32", "kwargs": {"force": true}}'
    result = secure_dispatcher.process_ai_message(ai_text)
    # Should drop the request and return None
    assert result is None


def test_dispatcher_rejects_invalid_kwargs(secure_dispatcher):
    # kwargs is a list instead of a dict
    ai_text = '{"tool": "ScreenTool", "kwargs": ["high_quality"]}'
    result = secure_dispatcher.process_ai_message(ai_text)
    assert result is None
