"""Application configuration management using environment variables.

All sensitive data (API keys, tokens) is loaded from environment variables
and never hard-coded or logged.
"""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Set

from dotenv import load_dotenv

from laptop_control.core.exceptions import ConfigurationError

logger = logging.getLogger(__name__)


@dataclass
class Config:
    """Application configuration loaded from environment variables.

    External integration credentials (Gemini API key and Telegram bot token)
    are required. All required fields must be set in .env or environment.
    Optional fields have sensible defaults.

    Attributes:
        gemini_api_key: Google Gemini API key (required)
        telegram_bot_token: Telegram bot token (required)
        authorized_users: Set of authorized Telegram user IDs (required)
        log_level: Logging level (default: INFO)
        log_file: Path to log file (default: logs/laptop_control.log)
        audit_log_file: Path to audit log file (default: logs/audit.log)
        environment: Environment name (default: development)
        emergency_stop_file: Path to emergency stop file (default: /tmp/laptop-control.stop)
    """

    gemini_api_key: str = ""
    telegram_bot_token: str = ""
    authorized_users: Set[int] = field(default_factory=set)
    log_level: str = "INFO"
    log_file: str = "logs/laptop_control.log"
    audit_log_file: str = "logs/audit.log"
    environment: str = "development"
    emergency_stop_file: str = "/tmp/laptop-control.stop"

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables.

        Loads .env file if present, then reads environment variables.
        Validates required fields and types where appropriate.

        Returns:
            Config: Configured instance ready to use.

        Raises:
            ConfigurationError: If required fields missing or invalid for
                configuration items that must be present (e.g., AUTHORIZED_USERS).
        """
        # Load .env file if it exists
        dotenv_path = Path(".env")
        if dotenv_path.exists():
            load_dotenv(dotenv_path)
        else:
            # Still check environment variables from shell
            load_dotenv(override=False)

        config = cls()

        # Load external integration credentials; these are required
        config.gemini_api_key = os.getenv("GEMINI_API_KEY", "").strip()
        config.telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()

        # Enforce presence of integration credentials
        if not config.gemini_api_key:
            raise ConfigurationError("GEMINI_API_KEY is required")
        if not config.telegram_bot_token:
            raise ConfigurationError("TELEGRAM_BOT_TOKEN is required")

        # Lightweight validation of credential formats
        if config.gemini_api_key:
            if len(config.gemini_api_key) < 20:
                raise ConfigurationError(
                    "GEMINI_API_KEY appears invalid (too short). Check .env file."
                )

        if config.telegram_bot_token:
            # Basic sanity check: tokens are typically non-trivial strings
            if len(config.telegram_bot_token) < 10:
                raise ConfigurationError(
                    "TELEGRAM_BOT_TOKEN appears invalid (too short). Check .env file."
                )

        # Load and parse authorized users (required)
        authorized_users_str = os.getenv("AUTHORIZED_USERS", "").strip()
        if not authorized_users_str:
            raise ConfigurationError(
                "AUTHORIZED_USERS is required (comma-separated user IDs). "
                "Set it in .env or environment."
            )

        config.authorized_users = cls._parse_authorized_users(authorized_users_str)
        if not config.authorized_users:
            raise ConfigurationError(
                "AUTHORIZED_USERS must contain at least one valid user ID. "
                "Format: 123456789,987654321"
            )

        # Load optional fields with defaults
        config.log_level = os.getenv("LOG_LEVEL", "INFO").upper()
        cls._validate_log_level(config.log_level)

        config.log_file = os.getenv("LOG_FILE", "logs/laptop_control.log")
        config.audit_log_file = os.getenv("AUDIT_LOG_FILE", "logs/audit.log")
        config.environment = os.getenv("ENVIRONMENT", "development").lower()
        config.emergency_stop_file = os.getenv(
            "EMERGENCY_STOP_FILE", "/tmp/laptop-control.stop"
        )

        return config

    @staticmethod
    def _parse_authorized_users(users_str: str) -> Set[int]:
        """Parse comma-separated user IDs into a set of integers.

        Args:
            users_str: Comma-separated user IDs (e.g., "123456789,987654321")

        Returns:
            Set of integer user IDs.

        Raises:
            ConfigurationError: If any user ID is not a valid integer.
        """
        authorized_users: Set[int] = set()

        for user_id_str in users_str.split(","):
            user_id_str = user_id_str.strip()
            if not user_id_str:
                continue

            try:
                user_id = int(user_id_str)
                if user_id <= 0:
                    raise ConfigurationError(
                        f"User ID must be positive integer, got: {user_id}"
                    )
                authorized_users.add(user_id)
            except ValueError as e:
                raise ConfigurationError(
                    f"Invalid user ID in AUTHORIZED_USERS: '{user_id_str}' "
                    "is not an integer"
                ) from e

        return authorized_users

    @staticmethod
    def _validate_log_level(level: str) -> None:
        """Validate log level is valid Python logging level.

        Args:
            level: Log level name (DEBUG, INFO, WARNING, ERROR, CRITICAL)

        Raises:
            ConfigurationError: If log level is invalid.
        """
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if level.upper() not in valid_levels:
            raise ConfigurationError(
                f"Invalid LOG_LEVEL: {level}. Must be one of: {', '.join(valid_levels)}"
            )

    def get_log_level_int(self) -> int:
        """Get log level as integer for logging module.

        Returns:
            Integer log level (e.g., logging.INFO)
        """
        return getattr(logging, self.log_level.upper())

    def is_production(self) -> bool:
        """Check if running in production environment.

        Returns:
            True if ENVIRONMENT is 'production', False otherwise.
        """
        return self.environment == "production"

    def __repr__(self) -> str:
        """Return safe string representation without secrets.

        Returns:
            String representation with secrets masked.
        """
        return (
            f"Config(env={self.environment}, log_level={self.log_level}, "
            f"users={len(self.authorized_users)}, "
            f"gemini_key={'***MASKED***'}, "
            f"telegram_token={'***MASKED***'})"
        )
