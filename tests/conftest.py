"""Shared pytest fixtures and configuration.
"""

import pytest
from pathlib import Path
import tempfile
from typing import Generator

from laptop_control.config import Config
from laptop_control.security import AuthorizationManager, AuditLogger, EmergencyStop


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Provide a temporary directory that cleans up after test."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_authorized_users():
    """Sample set of authorized user IDs."""
    return {123456789, 987654321, 111111111}


@pytest.fixture
def auth_manager(sample_authorized_users) -> AuthorizationManager:
    """Create an AuthorizationManager with sample users."""
    return AuthorizationManager(sample_authorized_users)


@pytest.fixture
def audit_logger(temp_dir) -> AuditLogger:
    """Create an AuditLogger with temporary log file."""
    log_file = temp_dir / "audit.log"
    return AuditLogger(str(log_file))


@pytest.fixture
def emergency_stop(temp_dir) -> EmergencyStop:
    """Create an EmergencyStop with temporary stop file."""
    stop_file = temp_dir / "emergency.stop"
    return EmergencyStop(str(stop_file))
