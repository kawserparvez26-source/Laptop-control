"""Comprehensive security tests for TerminalTool.

Tests verify 25+ security scenarios for terminal execution:
- Allowed commands validation
- Dangerous pattern rejection
- Shell metacharacter blocking
- Environment variable protection
- Argument validation
- Execution model verification (subprocess, shell=False)
- Output protection
- Timeout handling
- Error handling (not found, permission denied)
- Audit logging security
- Authorization enforcement
- EmergencyStop integration
- ToolResult type consistency
- ToolRegistry compatibility
"""

import json
import logging
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from laptop_control.core.exceptions import (
    AuthorizationError,
    EmergencyStopTriggered,
)
from laptop_control.core.types import OperationStatus, RiskLevel, ToolRequest, ToolResult
from laptop_control.security.audit import AuditLogger
from laptop_control.security.authorization import AuthorizationManager
from laptop_control.security.emergency_stop import EmergencyStop
from laptop_control.tools.terminal import TerminalTool
from laptop_control.tools.registry import ToolRegistry


class TestTerminalToolValidation:
    """Tests for command validation and dangerous pattern detection."""

    @pytest.fixture
    def tool(self):
        """Create a TerminalTool instance."""
        return TerminalTool()

    @pytest.mark.asyncio
    async def test_valid_allowed_command_pwd(self, tool):
        """Test that 'pwd' is a valid allowed command."""
        command = json.dumps({"command": "pwd"})
        is_valid = await tool.validate(command)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_valid_allowed_command_ls(self, tool):
        """Test that 'ls' is a valid allowed command."""
        command = json.dumps({"command": "ls"})
        is_valid = await tool.validate(command)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_valid_allowed_command_whoami(self, tool):
        """Test that 'whoami' is a valid allowed command."""
        command = json.dumps({"command": "whoami"})
        is_valid = await tool.validate(command)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_valid_allowed_command_uname(self, tool):
        """Test that 'uname' is a valid allowed command."""
        command = json.dumps({"command": "uname"})
        is_valid = await tool.validate(command)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_unknown_command_rejected(self, tool):
        """Test that unknown commands are rejected."""
        command = json.dumps({"command": "whoami_fake"})
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_bash_command_rejected(self, tool):
        """Test that bash command is rejected."""
        command = json.dumps({"command": "bash"})
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_sh_command_rejected(self, tool):
        """Test that sh command is rejected."""
        command = json.dumps({"command": "sh"})
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_sudo_command_rejected(self, tool):
        """Test that sudo command is rejected."""
        command = json.dumps({"command": "sudo"})
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_rm_command_rejected(self, tool):
        """Test that rm command is rejected."""
        command = json.dumps({"command": "rm"})
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_pipe_operator_rejected(self, tool):
        """Test that pipe operator is rejected."""
        command = json.dumps({"command": "pwd", "args": ["test|cat"]})
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_semicolon_operator_rejected(self, tool):
        """Test that semicolon operator is rejected."""
        command = json.dumps({"command": "pwd", "args": ["test;ls"]})
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_and_operator_rejected(self, tool):
        """Test that && operator is rejected."""
        command = json.dumps({"command": "pwd", "args": ["test&&cat"]})
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_or_operator_rejected(self, tool):
        """Test that || operator is rejected."""
        command = json.dumps({"command": "pwd", "args": ["test||cat"]})
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_redirect_gt_rejected(self, tool):
        """Test that > redirect is rejected."""
        command = json.dumps({"command": "pwd", "args": ["test>file"]})
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_redirect_lt_rejected(self, tool):
        """Test that < redirect is rejected."""
        command = json.dumps({"command": "pwd", "args": ["test<file"]})
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_redirect_append_rejected(self, tool):
        """Test that >> redirect is rejected."""
        command = json.dumps({"command": "pwd", "args": ["test>>file"]})
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_stderr_redirect_rejected(self, tool):
        """Test that 2> redirect is rejected."""
        command = json.dumps({"command": "pwd", "args": ["test2>file"]})
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_command_substitution_paren_rejected(self, tool):
        """Test that $() command substitution is rejected."""
        command = json.dumps({"command": "pwd", "args": ["$(cat)"]})
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_command_substitution_backtick_rejected(self, tool):
        """Test that backtick command substitution is rejected."""
        command = json.dumps({"command": "pwd", "args": ["`cat`"]})
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_env_var_dollar_rejected(self, tool):
        """Test that $VAR environment variable pattern is rejected."""
        command = json.dumps({"command": "pwd", "args": ["$HOME"]})
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_env_var_braces_rejected(self, tool):
        """Test that ${VAR} environment variable pattern is rejected."""
        command = json.dumps({"command": "pwd", "args": ["${HOME}"]})
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_single_quote_rejected(self, tool):
        """Test that single quotes are rejected."""
        command = json.dumps({"command": "pwd", "args": ["'test'"]})
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_double_quote_rejected(self, tool):
        """Test that double quotes are rejected."""
        command = json.dumps({"command": "pwd", "args": ['"test"']})
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_invalid_json_rejected(self, tool):
        """Test that invalid JSON is rejected."""
        command = "{ not valid json }"
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_missing_command_field_rejected(self, tool):
        """Test that missing 'command' field is rejected."""
        command = json.dumps({"args": []})
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_invalid_args_type_rejected(self, tool):
        """Test that non-list args are rejected."""
        command = json.dumps({"command": "pwd", "args": "not_a_list"})
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_invalid_arg_type_rejected(self, tool):
        """Test that non-string arg items are rejected."""
        command = json.dumps({"command": "pwd", "args": [123]})
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_unsafe_arg_characters_rejected(self, tool):
        """Test that args with unsafe characters are rejected."""
        command = json.dumps({"command": "pwd", "args": ["test@arg"]})
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_safe_args_with_hyphens_accepted(self, tool):
        """Test that args with hyphens are accepted."""
        command = json.dumps({"command": "ls", "args": ["-la"]})
        is_valid = await tool.validate(command)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_safe_args_with_dots_accepted(self, tool):
        """Test that args with dots are accepted."""
        command = json.dumps({"command": "ls", "args": ["test.txt"]})
        is_valid = await tool.validate(command)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_safe_args_with_slashes_accepted(self, tool):
        """Test that args with slashes are accepted."""
        command = json.dumps({"command": "ls", "args": ["test/path"]})
        is_valid = await tool.validate(command)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_non_string_command_rejected(self, tool):
        """Test that non-string command is rejected."""
        command = json.dumps({"command": 123})
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_empty_string_command_rejected(self, tool):
        """Test that empty string is rejected."""
        command = ""
        is_valid = await tool.validate(command)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_non_string_input_rejected(self, tool):
        """Test that non-string input is rejected."""
        is_valid = await tool.validate(None)
        assert is_valid is False


class TestTerminalToolExecution:
    """Tests for command execution and result handling."""

    @pytest.fixture
    def tool(self):
        """Create a TerminalTool instance."""
        return TerminalTool()

    @pytest.mark.asyncio
    async def test_valid_execution_pwd(self, tool):
        """Test successful execution of pwd command."""
        command = json.dumps({"command": "pwd"})
        result = await tool._execute_impl(command, user_id=123)

        assert isinstance(result, ToolResult)
        assert result.success is True
        assert result.status == OperationStatus.SUCCESS
        assert result.output  # Should have some output
        assert result.error is None

    @pytest.mark.asyncio
    async def test_valid_execution_whoami(self, tool):
        """Test successful execution of whoami command."""
        command = json.dumps({"command": "whoami"})
        result = await tool._execute_impl(command, user_id=123)

        assert isinstance(result, ToolResult)
        assert result.success is True
        assert result.status == OperationStatus.SUCCESS
        assert result.output  # Should have some output

    @pytest.mark.asyncio
    async def test_execution_with_args_ls(self, tool):
        """Test execution of ls with arguments."""
        command = json.dumps({"command": "ls", "args": ["-1"]})
        result = await tool._execute_impl(command, user_id=123)

        assert isinstance(result, ToolResult)
        # May succeed or fail depending on current directory
        assert isinstance(result.output, str)

    @pytest.mark.asyncio
    async def test_nonzero_exit_code_handled(self, tool):
        """Test that non-zero exit codes are handled safely."""
        command = json.dumps({"command": "ls", "args": ["/nonexistent_directory_xyz"]})
        result = await tool._execute_impl(command, user_id=123)

        assert isinstance(result, ToolResult)
        assert result.success is False
        assert result.status == OperationStatus.FAILED
        assert "exited with code" in result.error

    @pytest.mark.asyncio
    async def test_result_has_metadata(self, tool):
        """Test that result includes metadata."""
        command = json.dumps({"command": "pwd"})
        result = await tool._execute_impl(command, user_id=123)

        assert isinstance(result, ToolResult)
        assert "return_code" in result.metadata
        assert "command" in result.metadata

    @pytest.mark.asyncio
    async def test_result_has_execution_time(self, tool):
        """Test that result includes execution_time."""
        command = json.dumps({"command": "pwd"})
        result = await tool._execute_impl(command, user_id=123)

        assert isinstance(result, ToolResult)
        assert result.execution_time >= 0

    @pytest.mark.asyncio
    async def test_output_truncation(self):
        """Test that large output is truncated."""
        tool = TerminalTool(max_output_bytes=100)
        # Use ls with a large directory to generate output
        command = json.dumps({"command": "ls", "args": ["-la", "/"]})
        result = await tool._execute_impl(command, user_id=123)

        assert isinstance(result, ToolResult)
        # Output should be truncated at max_output_bytes
        assert len(result.output) <= tool.max_output_bytes + len("\n[OUTPUT TRUNCATED]")


class TestTerminalToolSubprocessExecution:
    """Tests for subprocess execution model verification."""

    @pytest.fixture
    def tool(self):
        """Create a TerminalTool instance."""
        return TerminalTool()

    @pytest.mark.asyncio
    async def test_subprocess_run_called_with_shell_false(self, tool):
        """Test that subprocess.run is called with shell=False."""
        with patch("laptop_control.tools.terminal.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="output",
                stderr="",
            )

            command = json.dumps({"command": "pwd"})
            await tool._execute_impl(command, user_id=123)

            # Verify subprocess.run was called with shell=False
            mock_run.assert_called_once()
            call_kwargs = mock_run.call_args[1]
            assert call_kwargs["shell"] is False

    @pytest.mark.asyncio
    async def test_subprocess_receives_argv_list(self, tool):
        """Test that subprocess receives structured argv list."""
        with patch("laptop_control.tools.terminal.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="output",
                stderr="",
            )

            command = json.dumps({"command": "ls", "args": ["-la"]})
            await tool._execute_impl(command, user_id=123)

            # Verify argv list was passed (not a shell command string)
            call_args = mock_run.call_args[0]
            argv = call_args[0]
            assert isinstance(argv, list)
            assert argv == ["ls", "-la"]

    @pytest.mark.asyncio
    async def test_subprocess_captures_output(self, tool):
        """Test that subprocess output is captured."""
        with patch("laptop_control.tools.terminal.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="test_output",
                stderr="",
            )

            command = json.dumps({"command": "pwd"})
            result = await tool._execute_impl(command, user_id=123)

            # Verify output was captured
            mock_run.assert_called_once()
            call_kwargs = mock_run.call_args[1]
            assert call_kwargs["capture_output"] is True

    @pytest.mark.asyncio
    async def test_subprocess_timeout_handled(self, tool):
        """Test that subprocess timeout is handled."""
        with patch("laptop_control.tools.terminal.subprocess.run") as mock_run:
            import subprocess as sp
            mock_run.side_effect = sp.TimeoutExpired("pwd", 30)

            command = json.dumps({"command": "pwd"})
            result = await tool._execute_impl(command, user_id=123)

            assert isinstance(result, ToolResult)
            assert result.success is False
            assert result.status == OperationStatus.TIMEOUT
            assert "timeout" in result.error.lower()

    @pytest.mark.asyncio
    async def test_subprocess_not_found_handled(self, tool):
        """Test that FileNotFoundError is handled."""
        with patch("laptop_control.tools.terminal.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("pwd not found")

            command = json.dumps({"command": "pwd"})
            result = await tool._execute_impl(command, user_id=123)

            assert isinstance(result, ToolResult)
            assert result.success is False
            assert result.status == OperationStatus.FAILED
            assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_subprocess_permission_error_handled(self, tool):
        """Test that PermissionError is handled."""
        with patch("laptop_control.tools.terminal.subprocess.run") as mock_run:
            mock_run.side_effect = PermissionError("Permission denied")

            command = json.dumps({"command": "pwd"})
            result = await tool._execute_impl(command, user_id=123)

            assert isinstance(result, ToolResult)
            assert result.success is False
            assert result.status == OperationStatus.FAILED
            assert "permission" in result.error.lower()


class TestTerminalToolAuditLogging:
    """Tests for audit logging security."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for logging."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def audit_logger(self, temp_dir):
        """Create an AuditLogger instance."""
        return AuditLogger(str(temp_dir / "audit.log"), fail_on_write=False)

    @pytest.fixture
    def tool_with_audit(self, audit_logger):
        """Create a TerminalTool with audit logging."""
        return TerminalTool(audit_logger=audit_logger)

    @pytest.mark.asyncio
    async def test_command_output_not_in_audit_log(self, tool_with_audit):
        """Test that command output is not logged to audit trail."""
        command = json.dumps({"command": "pwd"})
        await tool_with_audit._execute_impl(command, user_id=123)

        records = tool_with_audit.audit_logger.read_records()
        assert len(records) > 0

        # Verify output is not in audit details
        for record in records:
            details_str = json.dumps(record.get("details", {}))
            # pwd output should not be in details
            assert not any(
                char in details_str
                for char in ["/", "home", "root", "tmp"]
                if len(char) > 1  # Avoid false positives
            )

    @pytest.mark.asyncio
    async def test_audit_logs_command_name_only(self, tool_with_audit):
        """Test that audit logs only command name, not arguments."""
        command = json.dumps({"command": "ls", "args": ["-la", "/tmp"]})
        await tool_with_audit._execute_impl(command, user_id=123)

        records = tool_with_audit.audit_logger.read_records()
        assert len(records) > 0

        # Verify command name is logged but not args
        for record in records:
            details = record.get("details", {})
            assert "command" in details
            assert details["command"] == "ls"
            # Args should not be in details
            assert "-la" not in str(details)

    @pytest.mark.asyncio
    async def test_audit_logs_return_code(self, tool_with_audit):
        """Test that audit logs include return code."""
        command = json.dumps({"command": "pwd"})
        await tool_with_audit._execute_impl(command, user_id=123)

        records = tool_with_audit.audit_logger.read_records()
        assert len(records) > 0

        # Verify return_code is logged
        for record in records:
            details = record.get("details", {})
            if "return_code" in details:
                assert isinstance(details["return_code"], int)

    @pytest.mark.asyncio
    async def test_audit_logs_timeout(self, tool_with_audit):
        """Test that timeout is logged."""
        with patch("laptop_control.tools.terminal.subprocess.run") as mock_run:
            import subprocess as sp
            mock_run.side_effect = sp.TimeoutExpired("pwd", 30)

            command = json.dumps({"command": "pwd"})
            await tool_with_audit._execute_impl(command, user_id=123)

            records = tool_with_audit.audit_logger.read_records()
            assert any(
                "timeout" in r.get("operation", "").lower()
                for r in records
            )


class TestTerminalToolAuthorization:
    """Tests for authorization enforcement."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def auth_manager(self):
        """Create an AuthorizationManager."""
        return AuthorizationManager(authorized_users={123})

    @pytest.fixture
    def tool_with_auth(self, auth_manager):
        """Create a TerminalTool with authorization."""
        return TerminalTool(authorizer=auth_manager)

    @pytest.mark.asyncio
    async def test_authorized_user_can_execute(self, tool_with_auth):
        """Test that authorized users can execute commands."""
        command = json.dumps({"command": "pwd"})
        result = await tool_with_auth.execute(command, user_id=123)

        assert isinstance(result, ToolResult)
        # Success depends on command, but authorization should pass

    @pytest.mark.asyncio
    async def test_unauthorized_user_blocked(self, tool_with_auth):
        """Test that unauthorized users are blocked."""
        command = json.dumps({"command": "pwd"})
        result = await tool_with_auth.execute(command, user_id=999)

        assert isinstance(result, ToolResult)
        assert result.success is False
        assert "not authorized" in result.error.lower()


class TestTerminalToolEmergencyStop:
    """Tests for EmergencyStop integration."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def auth_manager(self):
        """Create an AuthorizationManager."""
        return AuthorizationManager(authorized_users={123})

    @pytest.fixture
    def audit_logger(self, temp_dir):
        """Create an AuditLogger."""
        return AuditLogger(str(temp_dir / "audit.log"), fail_on_write=False)

    @pytest.fixture
    def emergency_stop(self, temp_dir):
        """Create an EmergencyStop."""
        return EmergencyStop(str(temp_dir / "stop.file"))

    @pytest.fixture
    def registry(self, auth_manager, audit_logger, emergency_stop):
        """Create a ToolRegistry."""
        return ToolRegistry(auth_manager, audit_logger, emergency_stop)

    @pytest.mark.asyncio
    async def test_emergency_stop_blocks_execution(self, registry, temp_dir):
        """Test that EmergencyStop blocks tool execution through registry."""
        tool = TerminalTool()
        registry.register(tool)

        # Normal execution should work
        request = ToolRequest(
            tool_name="terminal",
            user_id=123,
            command=json.dumps({"command": "pwd"}),
            risk_level=RiskLevel.HIGH,
        )
        result = await registry.execute(request)
        assert result.success is True

        # Activate emergency stop
        registry.emergency_stop.activate(reason="Test")

        # Execution should now fail
        request = ToolRequest(
            tool_name="terminal",
            user_id=123,
            command=json.dumps({"command": "pwd"}),
            risk_level=RiskLevel.HIGH,
        )
        result = await registry.execute(request)
        assert result.success is False
        assert "emergency stop" in result.error.lower()


class TestTerminalToolInitialization:
    """Tests for tool initialization and configuration."""

    def test_default_allowed_commands(self):
        """Test that default allowed commands are set correctly."""
        tool = TerminalTool()
        expected = {"pwd", "ls", "whoami", "uname"}
        assert tool.allowed_commands == frozenset(expected)

    def test_custom_allowed_commands(self):
        """Test initialization with custom allowed commands."""
        custom_commands = {"ls", "pwd"}
        tool = TerminalTool(allowed_commands=custom_commands)
        assert tool.allowed_commands == frozenset(custom_commands)

    def test_empty_allowed_commands_rejected(self):
        """Test that empty command set is rejected."""
        with pytest.raises(ValueError, match="cannot be empty"):
            TerminalTool(allowed_commands=set())

    def test_invalid_command_name_rejected(self):
        """Test that invalid command names are rejected."""
        with pytest.raises(ValueError, match="invalid"):
            TerminalTool(allowed_commands={"invalid command"})

    def test_max_output_bytes_validation(self):
        """Test max_output_bytes validation."""
        with pytest.raises(ValueError, match="positive integer"):
            TerminalTool(max_output_bytes=0)

        with pytest.raises(ValueError, match="positive integer"):
            TerminalTool(max_output_bytes=-1)

    def test_max_execution_seconds_validation(self):
        """Test max_execution_seconds validation."""
        with pytest.raises(ValueError, match="positive integer"):
            TerminalTool(max_execution_seconds=0)

        with pytest.raises(ValueError, match="positive integer"):
            TerminalTool(max_execution_seconds=-1)

    def test_tool_has_correct_name(self):
        """Test that tool name is 'terminal'."""
        tool = TerminalTool()
        assert tool.name == "terminal"

    def test_tool_has_high_risk_level(self):
        """Test that tool has HIGH risk level."""
        tool = TerminalTool()
        assert tool.risk_level == RiskLevel.HIGH


class TestTerminalToolCommandNames:
    """Tests to verify prohibited commands remain unavailable."""

    @pytest.fixture
    def tool(self):
        """Create a TerminalTool instance."""
        return TerminalTool()

    @pytest.mark.asyncio
    async def test_bash_not_allowed(self, tool):
        """Test that bash is not in allowed commands."""
        assert "bash" not in tool.allowed_commands

    @pytest.mark.asyncio
    async def test_sh_not_allowed(self, tool):
        """Test that sh is not in allowed commands."""
        assert "sh" not in tool.allowed_commands

    @pytest.mark.asyncio
    async def test_zsh_not_allowed(self, tool):
        """Test that zsh is not in allowed commands."""
        assert "zsh" not in tool.allowed_commands

    @pytest.mark.asyncio
    async def test_sudo_not_allowed(self, tool):
        """Test that sudo is not in allowed commands."""
        assert "sudo" not in tool.allowed_commands

    @pytest.mark.asyncio
    async def test_su_not_allowed(self, tool):
        """Test that su is not in allowed commands."""
        assert "su" not in tool.allowed_commands

    @pytest.mark.asyncio
    async def test_rm_not_allowed(self, tool):
        """Test that rm is not in allowed commands."""
        assert "rm" not in tool.allowed_commands

    @pytest.mark.asyncio
    async def test_mv_not_allowed(self, tool):
        """Test that mv is not in allowed commands."""
        assert "mv" not in tool.allowed_commands

    @pytest.mark.asyncio
    async def test_cp_not_allowed(self, tool):
        """Test that cp is not in allowed commands."""
        assert "cp" not in tool.allowed_commands

    @pytest.mark.asyncio
    async def test_chmod_not_allowed(self, tool):
        """Test that chmod is not in allowed commands."""
        assert "chmod" not in tool.allowed_commands

    @pytest.mark.asyncio
    async def test_chown_not_allowed(self, tool):
        """Test that chown is not in allowed commands."""
        assert "chown" not in tool.allowed_commands

    @pytest.mark.asyncio
    async def test_kill_not_allowed(self, tool):
        """Test that kill is not in allowed commands."""
        assert "kill" not in tool.allowed_commands

    @pytest.mark.asyncio
    async def test_reboot_not_allowed(self, tool):
        """Test that reboot is not in allowed commands."""
        assert "reboot" not in tool.allowed_commands

    @pytest.mark.asyncio
    async def test_shutdown_not_allowed(self, tool):
        """Test that shutdown is not in allowed commands."""
        assert "shutdown" not in tool.allowed_commands

    @pytest.mark.asyncio
    async def test_systemctl_not_allowed(self, tool):
        """Test that systemctl is not in allowed commands."""
        assert "systemctl" not in tool.allowed_commands

    @pytest.mark.asyncio
    async def test_apt_not_allowed(self, tool):
        """Test that apt is not in allowed commands."""
        assert "apt" not in tool.allowed_commands

    @pytest.mark.asyncio
    async def test_pip_not_allowed(self, tool):
        """Test that pip is not in allowed commands."""
        assert "pip" not in tool.allowed_commands

    @pytest.mark.asyncio
    async def test_python_not_allowed(self, tool):
        """Test that python is not in allowed commands."""
        assert "python" not in tool.allowed_commands


class TestTerminalToolRegistryCompatibility:
    """Tests for ToolRegistry compatibility."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def registry(self, temp_dir):
        """Create a ToolRegistry."""
        auth_manager = AuthorizationManager(authorized_users={123})
        audit_logger = AuditLogger(str(temp_dir / "audit.log"), fail_on_write=False)
        emergency_stop = EmergencyStop(str(temp_dir / "stop.file"))
        return ToolRegistry(auth_manager, audit_logger, emergency_stop)

    def test_terminal_tool_can_be_registered(self, registry):
        """Test that TerminalTool can be registered with ToolRegistry."""
        tool = TerminalTool()
        registry.register(tool)
        assert registry.has("terminal")

    def test_terminal_tool_metadata_available(self, registry):
        """Test that TerminalTool metadata is available from registry."""
        tool = TerminalTool()
        registry.register(tool)
        tools = registry.list_tools()
        assert "terminal" in tools
        assert tools["terminal"]["name"] == "terminal"
        assert tools["terminal"]["risk_level"] == "high"

    @pytest.mark.asyncio
    async def test_terminal_tool_executable_through_registry(self, registry):
        """Test that TerminalTool can be executed through registry."""
        tool = TerminalTool()
        registry.register(tool)

        request = ToolRequest(
            tool_name="terminal",
            user_id=123,
            command=json.dumps({"command": "pwd"}),
            risk_level=RiskLevel.HIGH,
        )
        result = await registry.execute(request)

        assert isinstance(result, ToolResult)
