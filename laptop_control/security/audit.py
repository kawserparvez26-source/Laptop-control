"""Audit logging for security events and operations.

Provides AuditLogger for recording all significant operations
for forensics and compliance.
"""

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from laptop_control.core.exceptions import AuditLogError
from laptop_control.core.types import OperationStatus, RiskLevel

logger = logging.getLogger(__name__)


class AuditLogger:
    """Records audit trails of all significant operations.

    Writes structured JSON records to an audit log file for
    forensics and compliance auditing.

    Attributes:
        log_file: Path to audit log file
        fail_on_write: If True, write failures raise AuditLogError (fail-closed).
                       If False, write failures are logged as warnings (safe for
                       development/testing).
    """

    # Patterns for secrets that should never appear in audit logs
    SECRET_PATTERNS = [
        r"(?i)(api[_-]?key|token|password|secret|auth)[=:](\S+)",
        r"(?i)(authorization|x-api-key)[=:](\S+)",
        r"(?i)bearer\s+\S+",
    ]

    def __init__(self, log_file: str, fail_on_write: bool = True) -> None:
        """Initialize audit logger.

        Creates log file parent directory if it doesn't exist.

        Args:
            log_file: Path where audit records will be written
            fail_on_write: If True, a failure to persist audit records will
                           raise AuditLogError. If False, failures will be
                           logged and execution will continue (development mode).
        """
        self.log_file = Path(log_file)
        # Ensure parent directory exists where possible
        try:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            # Directory creation might fail in restricted environments; allow
            # construction to succeed so callers can decide how to handle writes.
            pass

        self.fail_on_write = bool(fail_on_write)
        logger.debug(f"Audit logger initialized: {self.log_file} (fail_on_write={self.fail_on_write})")

    def log_operation(
        self,
        user_id: int,
        operation: str,
        tool: str,
        status: OperationStatus,
        risk_level: RiskLevel = RiskLevel.MEDIUM,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log an operation to the audit trail.

        Args:
            user_id: ID of user performing operation
            operation: Name of operation (e.g., "list_files", "execute_command")
            tool: Name of tool used (e.g., "filesystem", "terminal")
            status: Status of operation (success, failure, etc.)
            risk_level: Risk level of this operation
            details: Optional additional details about operation

        Note:
            If audit logging fails and fail_on_write is True, AuditLogError is
            raised. If fail_on_write is False, failures are logged as warnings
            and execution continues.
        """
        if details is None:
            details = {}

        # Sanitize details to remove secrets
        try:
            sanitized_details = self._sanitize_details(details)

            record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "user_id": user_id,
                "operation": operation,
                "tool": tool,
                "status": status.value,
                "risk_level": risk_level.value,
                "details": sanitized_details,
            }

            try:
                self._write_record(record)
            except AuditLogError as e:
                # Fail-closed behavior for security-sensitive contexts
                if self.fail_on_write:
                    logger.critical("Audit logging failed and fail_on_write is enabled; raising AuditLogError", exc_info=True)
                    raise
                else:
                    logger.warning("Audit logging failed but fail_on_write is disabled; continuing", exc_info=True)
            return

        except Exception as e:
            # Catch errors that occur during sanitization or record construction
            if self.fail_on_write:
                # Wrap and raise a generic AuditLogError without exposing details
                logger.critical("Audit logging encountered an unexpected error; raising AuditLogError", exc_info=True)
                raise AuditLogError("Audit logging failed due to an unexpected error") from e
            else:
                logger.warning("Audit logging encountered an unexpected error; continuing", exc_info=True)
                return

    def log_authorization_failure(
        self,
        user_id: int,
        reason: str,
    ) -> None:
        """Log failed authorization attempt.

        Args:
            user_id: ID of user attempting unauthorized action
            reason: Reason for failure
        """
        self.log_operation(
            user_id=user_id,
            operation="authorization_failure",
            tool="system",
            status=OperationStatus.FAILED,
            risk_level=RiskLevel.HIGH,
            details={"reason": reason},
        )

    def log_emergency_stop(
        self,
        reason: str,
    ) -> None:
        """Log emergency stop activation.

        Args:
            reason: Reason emergency stop was triggered
        """
        self.log_operation(
            user_id=0,  # System operation
            operation="emergency_stop_activated",
            tool="system",
            status=OperationStatus.FAILED,
            risk_level=RiskLevel.CRITICAL,
            details={"reason": reason},
        )

    def log_emergency_reset(
        self,
        admin_user_id: int,
    ) -> None:
        """Log emergency stop reset.

        Args:
            admin_user_id: ID of admin resetting emergency stop
        """
        self.log_operation(
            user_id=admin_user_id,
            operation="emergency_stop_reset",
            tool="system",
            status=OperationStatus.SUCCESS,
            risk_level=RiskLevel.CRITICAL,
            details={"admin_id": admin_user_id},
        )

    @staticmethod
    def _sanitize_details(details: Dict[str, Any]) -> Dict[str, Any]:
        """Remove secrets from details dict.

        Recursively searches for secrets and masks them.

        Args:
            details: Dict potentially containing secrets

        Returns:
            Dict with secrets masked
        """
        if not isinstance(details, dict):
            return details

        sanitized = {}

        for key, value in details.items():
            # Check if key looks like a secret
            if AuditLogger._is_secret_key(key):
                sanitized[key] = "***MASKED***"
            # Recursively sanitize nested dicts
            elif isinstance(value, dict):
                sanitized[key] = AuditLogger._sanitize_details(value)
            # Recursively sanitize lists
            elif isinstance(value, list):
                sanitized[key] = [
                    AuditLogger._sanitize_details(item) if isinstance(item, dict) else item
                    for item in value
                ]
            # Check if value looks like a secret
            elif isinstance(value, str) and AuditLogger._is_secret_value(value):
                sanitized[key] = "***MASKED***"
            else:
                sanitized[key] = value

        return sanitized

    @staticmethod
    def _is_secret_key(key: str) -> bool:
        """Check if a key name suggests it contains secrets.

        Args:
            key: Key name to check

        Returns:
            True if key looks like it contains secrets
        """
        secret_keywords = {
            "api_key",
            "apikey",
            "token",
            "password",
            "passwd",
            "secret",
            "auth",
            "authorization",
            "bearer",
            "credential",
        }
        return key.lower() in secret_keywords

    @staticmethod
    def _is_secret_value(value: str) -> bool:
        """Check if a value looks like it contains secrets.

        Args:
            value: Value to check

        Returns:
            True if value looks like it contains secrets
        """
        for pattern in AuditLogger.SECRET_PATTERNS:
            if re.search(pattern, value):
                return True
        return False

    def _write_record(self, record: Dict[str, Any]) -> None:
        """Write an audit record to the log file.

        Args:
            record: Audit record dict

        Raises:
            AuditLogError: If write fails
        """
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as e:
            # Raise a generic AuditLogError without including record contents
            raise AuditLogError("Failed to write audit log") from e

    def read_records(
        self,
        limit: Optional[int] = None,
    ) -> list[Dict[str, Any]]:
        """Read audit records from log file.

        Args:
            limit: Max records to read (None for all)

        Returns:
            List of audit record dicts
        """
        records = []

        if not self.log_file.exists():
            return records

        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                for i, line in enumerate(f):
                    if limit and i >= limit:
                        break
                    try:
                        record = json.loads(line.strip())
                        records.append(record)
                    except json.JSONDecodeError:
                        logger.warning(f"Skipping invalid JSON in audit log: {line}")
        except IOError as e:
            logger.error(f"Failed to read audit log: {e}")

        return records
