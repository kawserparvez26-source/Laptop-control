"""Tests for configuration settings."""

import os
import pytest
from pathlib import Path
from laptop_control.config import Config
from laptop_control.core.exceptions import ConfigurationError


class TestConfigValidation:
    """Test Config validation and loading."""

    def test_valid_configuration(self, monkeypatch):
        """Test loading valid configuration."""
        monkeypatch.setenv("GEMINI_API_KEY", "sk_test_1234567890abcdef")
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
        monkeypatch.setenv("AUTHORIZED_USERS", "123456789,987654321")

        config = Config.from_env()
        assert config.gemini_api_key == "sk_test_1234567890abcdef"
        assert config.telegram_bot_token == "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi"
        assert 123456789 in config.authorized_users
        assert 987654321 in config.authorized_users

    def test_missing_gemini_api_key(self, monkeypatch):
        """Test that missing GEMINI_API_KEY raises error."""
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
        monkeypatch.setenv("AUTHORIZED_USERS", "123456789")

        with pytest.raises(ConfigurationError, match="GEMINI_API_KEY is required"):
            Config.from_env()

    def test_invalid_gemini_api_key_too_short(self, monkeypatch):
        """Test that short GEMINI_API_KEY raises error."""
        monkeypatch.setenv("GEMINI_API_KEY", "short_key")
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
        monkeypatch.setenv("AUTHORIZED_USERS", "123456789")

        with pytest.raises(ConfigurationError, match="appears invalid"):
            Config.from_env()

    def test_missing_telegram_bot_token(self, monkeypatch):
        """Test that missing TELEGRAM_BOT_TOKEN raises error."""
        monkeypatch.setenv("GEMINI_API_KEY", "sk_test_1234567890abcdef")
        monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
        monkeypatch.setenv("AUTHORIZED_USERS", "123456789")

        with pytest.raises(ConfigurationError, match="TELEGRAM_BOT_TOKEN is required"):
            Config.from_env()

    def test_missing_authorized_users(self, monkeypatch):
        """Test that missing AUTHORIZED_USERS raises error."""
        monkeypatch.setenv("GEMINI_API_KEY", "sk_test_1234567890abcdef")
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
        monkeypatch.delenv("AUTHORIZED_USERS", raising=False)

        with pytest.raises(ConfigurationError, match="AUTHORIZED_USERS is required"):
            Config.from_env()

    def test_invalid_authorized_users_not_integer(self, monkeypatch):
        """Test that non-integer AUTHORIZED_USERS raises error."""
        monkeypatch.setenv("GEMINI_API_KEY", "sk_test_1234567890abcdef")
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
        monkeypatch.setenv("AUTHORIZED_USERS", "not_an_int,123456789")

        with pytest.raises(ConfigurationError, match="is not an integer"):
            Config.from_env()

    def test_invalid_authorized_users_negative(self, monkeypatch):
        """Test that negative user IDs raise error."""
        monkeypatch.setenv("GEMINI_API_KEY", "sk_test_1234567890abcdef")
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
        monkeypatch.setenv("AUTHORIZED_USERS", "-123")

        with pytest.raises(ConfigurationError, match="must be positive"):
            Config.from_env()

    def test_multiple_authorized_users(self, monkeypatch):
        """Test loading multiple authorized users."""
        monkeypatch.setenv("GEMINI_API_KEY", "sk_test_1234567890abcdef")
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
        monkeypatch.setenv("AUTHORIZED_USERS", "111111111,222222222,333333333,444444444")

        config = Config.from_env()
        assert len(config.authorized_users) == 4
        assert {111111111, 222222222, 333333333, 444444444} == config.authorized_users

    def test_authorized_users_whitespace_handling(self, monkeypatch):
        """Test that whitespace in AUTHORIZED_USERS is handled."""
        monkeypatch.setenv("GEMINI_API_KEY", "sk_test_1234567890abcdef")
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
        monkeypatch.setenv("AUTHORIZED_USERS", "  123456789  ,  987654321  ,  111111111  ")

        config = Config.from_env()
        assert len(config.authorized_users) == 3
        assert {123456789, 987654321, 111111111} == config.authorized_users

    def test_invalid_log_level(self, monkeypatch):
        """Test that invalid LOG_LEVEL raises error."""
        monkeypatch.setenv("GEMINI_API_KEY", "sk_test_1234567890abcdef")
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
        monkeypatch.setenv("AUTHORIZED_USERS", "123456789")
        monkeypatch.setenv("LOG_LEVEL", "INVALID_LEVEL")

        with pytest.raises(ConfigurationError, match="Invalid LOG_LEVEL"):
            Config.from_env()

    def test_valid_log_levels(self, monkeypatch):
        """Test that all valid log levels are accepted."""
        monkeypatch.setenv("GEMINI_API_KEY", "sk_test_1234567890abcdef")
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
        monkeypatch.setenv("AUTHORIZED_USERS", "123456789")

        for level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            monkeypatch.setenv("LOG_LEVEL", level)
            config = Config.from_env()
            assert config.log_level == level

    def test_log_level_case_insensitive(self, monkeypatch):
        """Test that LOG_LEVEL is case-insensitive."""
        monkeypatch.setenv("GEMINI_API_KEY", "sk_test_1234567890abcdef")
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
        monkeypatch.setenv("AUTHORIZED_USERS", "123456789")
        monkeypatch.setenv("LOG_LEVEL", "debug")

        config = Config.from_env()
        assert config.log_level == "DEBUG"

    def test_default_log_level(self, monkeypatch):
        """Test that LOG_LEVEL defaults to INFO."""
        monkeypatch.setenv("GEMINI_API_KEY", "sk_test_1234567890abcdef")
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
        monkeypatch.setenv("AUTHORIZED_USERS", "123456789")
        monkeypatch.delenv("LOG_LEVEL", raising=False)

        config = Config.from_env()
        assert config.log_level == "INFO"

    def test_default_log_file(self, monkeypatch):
        """Test that log_file has default value."""
        monkeypatch.setenv("GEMINI_API_KEY", "sk_test_1234567890abcdef")
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
        monkeypatch.setenv("AUTHORIZED_USERS", "123456789")
        monkeypatch.delenv("LOG_FILE", raising=False)

        config = Config.from_env()
        assert config.log_file == "logs/laptop_control.log"

    def test_default_audit_log_file(self, monkeypatch):
        """Test that audit_log_file has default value."""
        monkeypatch.setenv("GEMINI_API_KEY", "sk_test_1234567890abcdef")
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
        monkeypatch.setenv("AUTHORIZED_USERS", "123456789")
        monkeypatch.delenv("AUDIT_LOG_FILE", raising=False)

        config = Config.from_env()
        assert config.audit_log_file == "logs/audit.log"

    def test_default_environment(self, monkeypatch):
        """Test that environment defaults to 'development'."""
        monkeypatch.setenv("GEMINI_API_KEY", "sk_test_1234567890abcdef")
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
        monkeypatch.setenv("AUTHORIZED_USERS", "123456789")
        monkeypatch.delenv("ENVIRONMENT", raising=False)

        config = Config.from_env()
        assert config.environment == "development"

    def test_environment_lowercase(self, monkeypatch):
        """Test that ENVIRONMENT is converted to lowercase."""
        monkeypatch.setenv("GEMINI_API_KEY", "sk_test_1234567890abcdef")
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
        monkeypatch.setenv("AUTHORIZED_USERS", "123456789")
        monkeypatch.setenv("ENVIRONMENT", "PRODUCTION")

        config = Config.from_env()
        assert config.environment == "production"

    def test_default_emergency_stop_file(self, monkeypatch):
        """Test that emergency_stop_file has default value."""
        monkeypatch.setenv("GEMINI_API_KEY", "sk_test_1234567890abcdef")
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
        monkeypatch.setenv("AUTHORIZED_USERS", "123456789")
        monkeypatch.delenv("EMERGENCY_STOP_FILE", raising=False)

        config = Config.from_env()
        assert config.emergency_stop_file == "/tmp/laptop-control.stop"

    def test_custom_log_file(self, monkeypatch):
        """Test setting custom log file."""
        monkeypatch.setenv("GEMINI_API_KEY", "sk_test_1234567890abcdef")
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
        monkeypatch.setenv("AUTHORIZED_USERS", "123456789")
        monkeypatch.setenv("LOG_FILE", "/custom/path/logs.log")

        config = Config.from_env()
        assert config.log_file == "/custom/path/logs.log"

    def test_is_production_development(self, monkeypatch):
        """Test is_production() returns False for development."""
        monkeypatch.setenv("GEMINI_API_KEY", "sk_test_1234567890abcdef")
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
        monkeypatch.setenv("AUTHORIZED_USERS", "123456789")
        monkeypatch.setenv("ENVIRONMENT", "development")

        config = Config.from_env()
        assert config.is_production() is False

    def test_is_production_production(self, monkeypatch):
        """Test is_production() returns True for production."""
        monkeypatch.setenv("GEMINI_API_KEY", "sk_test_1234567890abcdef")
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
        monkeypatch.setenv("AUTHORIZED_USERS", "123456789")
        monkeypatch.setenv("ENVIRONMENT", "production")

        config = Config.from_env()
        assert config.is_production() is True

    def test_get_log_level_int(self, monkeypatch):
        """Test get_log_level_int returns correct logging level."""
        import logging

        monkeypatch.setenv("GEMINI_API_KEY", "sk_test_1234567890abcdef")
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
        monkeypatch.setenv("AUTHORIZED_USERS", "123456789")
        monkeypatch.setenv("LOG_LEVEL", "DEBUG")

        config = Config.from_env()
        assert config.get_log_level_int() == logging.DEBUG

    def test_repr_masks_secrets(self, monkeypatch):
        """Test that __repr__ masks secrets."""
        monkeypatch.setenv("GEMINI_API_KEY", "sk_test_1234567890abcdef")
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
        monkeypatch.setenv("AUTHORIZED_USERS", "123456789")

        config = Config.from_env()
        repr_str = repr(config)

        assert "***MASKED***" in repr_str
        assert "sk_test_1234567890abcdef" not in repr_str
        assert "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi" not in repr_str

    def test_repr_shows_user_count(self, monkeypatch):
        """Test that __repr__ shows user count."""
        monkeypatch.setenv("GEMINI_API_KEY", "sk_test_1234567890abcdef")
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
        monkeypatch.setenv("AUTHORIZED_USERS", "111,222,333")

        config = Config.from_env()
        repr_str = repr(config)

        assert "users=3" in repr_str
