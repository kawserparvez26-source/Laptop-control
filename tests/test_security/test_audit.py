"""Tests for audit logging."""

import json
from pathlib import Path

import pytest
from laptop_control.core.types import OperationStatus, RiskLevel
from laptop_control.security import AuditLogger


class TestAuditLogger:
    """Test AuditLogger functionality."""

    def test_audit_file_created(self, audit_logger):
        """Test that audit log file is created."""
        audit_logger.log_operation(
            user_id=123,
            operation="test_op",
            tool="test_tool",
            status=OperationStatus.SUCCESS,
        )
        assert audit_logger.log_file.exists()

    def test_valid_json_records_written(self, audit_logger):
        """Test that audit records are valid JSON."""
        audit_logger.log_operation(
            user_id=123,
            operation="test_op",
            tool="test_tool",
            status=OperationStatus.SUCCESS,
        )

        with open(audit_logger.log_file, "r") as f:
            line = f.readline()
            record = json.loads(line)  # Should not raise
            assert isinstance(record, dict)

    def test_required_fields_exist(self, audit_logger):
        """Test that audit records contain required fields."""
        audit_logger.log_operation(
            user_id=456,
            operation="file_read",
            tool="filesystem",
            status=OperationStatus.SUCCESS,
            risk_level=RiskLevel.LOW,
        )

        records = audit_logger.read_records()
        assert len(records) == 1
        record = records[0]

        required_fields = {
            "timestamp",
            "user_id",
            "operation",
            "tool",
            "status",
            "risk_level",
            "details",
        }
        assert required_fields.issubset(set(record.keys()))

    def test_secrets_not_logged_in_keys(self, audit_logger):
        """Test that secrets in key names are masked."""
        audit_logger.log_operation(
            user_id=789,
            operation="test",
            tool="test",
            status=OperationStatus.SUCCESS,
            details={
                "api_key": "secret_key_12345",
                "token": "secret_token_xyz",
                "password": "super_secret",
            },
        )

        records = audit_logger.read_records()
        record = records[0]
        details = record["details"]

        assert details["api_key"] == "***MASKED***"
        assert details["token"] == "***MASKED***"
        assert details["password"] == "***MASKED***"

    def test_secrets_not_logged_in_values(self, audit_logger):
        """Test that secrets in values are masked."""
        audit_logger.log_operation(
            user_id=789,
            operation="test",
            tool="test",
            status=OperationStatus.SUCCESS,
            details={
                "api_key": "api_key=sk_test_1234567890",
                "auth_header": "Authorization: Bearer sk_live_xyz123",
            },
        )

        records = audit_logger.read_records()
        record = records[0]
        details = record["details"]

        assert details["api_key"] == "***MASKED***"
        assert details["auth_header"] == "***MASKED***"

    def test_nested_details_sanitized(self, audit_logger):
        """Test that nested details are recursively sanitized."""
        audit_logger.log_operation(
            user_id=789,
            operation="test",
            tool="test",
            status=OperationStatus.SUCCESS,
            details={
                "nested": {
                    "api_key": "secret123",
                    "safe_field": "value",
                },
                "list_field": [
                    {"token": "secret456"},
                    {"password": "secret789"},
                ],
            },
        )

        records = audit_logger.read_records()
        record = records[0]
        details = record["details"]

        assert details["nested"]["api_key"] == "***MASKED***"
        assert details["nested"]["safe_field"] == "value"
        assert details["list_field"][0]["token"] == "***MASKED***"
        assert details["list_field"][1]["password"] == "***MASKED***"

    def test_read_records_returns_all(self, audit_logger):
        """Test reading audit records."""
        for i in range(5):
            audit_logger.log_operation(
                user_id=i,
                operation=f"op_{i}",
                tool="test",
                status=OperationStatus.SUCCESS,
            )

        records = audit_logger.read_records()
        assert len(records) == 5

    def test_read_records_with_limit(self, audit_logger):
        """Test reading audit records with limit."""
        for i in range(10):
            audit_logger.log_operation(
                user_id=i,
                operation=f"op_{i}",
                tool="test",
                status=OperationStatus.SUCCESS,
            )

        records = audit_logger.read_records(limit=3)
        assert len(records) == 3

    def test_authorization_failure_logged(self, audit_logger):
        """Test logging authorization failures."""
        audit_logger.log_authorization_failure(
            user_id=999,
            reason="User not in authorized list",
        )

        records = audit_logger.read_records()
        record = records[0]

        assert record["operation"] == "authorization_failure"
        assert record["risk_level"] == RiskLevel.HIGH.value
        assert record["status"] == OperationStatus.FAILED.value

    def test_emergency_stop_logged(self, audit_logger):
        """Test logging emergency stop events."""
        audit_logger.log_emergency_stop(reason="Security threat detected")

        records = audit_logger.read_records()
        record = records[0]

        assert record["operation"] == "emergency_stop_activated"
        assert record["risk_level"] == RiskLevel.CRITICAL.value

    def test_logging_failure_doesnt_crash(self, temp_dir):
        """Test that audit logging failure doesn't crash application."""
        # Create logger with non-writable path
        audit_logger = AuditLogger("/root/not_writable/audit.log")
        # This should not raise (logs warning instead)
        audit_logger.log_operation(
            user_id=123,
            operation="test",
            tool="test",
            status=OperationStatus.SUCCESS,
        )

    def test_read_records_handles_invalid_json(self, audit_logger):
        """Test that invalid JSON in log file is skipped."""
        # Write valid record
        audit_logger.log_operation(
            user_id=1,
            operation="op1",
            tool="test",
            status=OperationStatus.SUCCESS,
        )

        # Manually write invalid JSON
        with open(audit_logger.log_file, "a") as f:
            f.write("invalid json line\n")

        # Write another valid record
        audit_logger.log_operation(
            user_id=2,
            operation="op2",
            tool="test",
            status=OperationStatus.SUCCESS,
        )

        records = audit_logger.read_records()
        # Should only get 2 valid records
        assert len(records) == 2
