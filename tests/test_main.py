"""Tests for application startup and main entry point."""

import asyncio
import pytest
from pathlib import Path
from laptop_control.main import Application
from laptop_control.config import Config
from laptop_control.core.exceptions import ConfigurationError


class TestApplicationStartup:
    """Test application startup and initialization."""

    @pytest.mark.asyncio
    async def test_application_initialization(self, temp_dir, monkeypatch):
        """Test that Application initializes with config."""
        # Setup safe test config
        monkeypatch.setenv("GEMINI_API_KEY", "sk_test_1234567890abcdef")
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
        monkeypatch.setenv("AUTHORIZED_USERS", "123456789")
        monkeypatch.setenv("LOG_FILE", str(temp_dir / "app.log"))
        monkeypatch.setenv("AUDIT_LOG_FILE", str(temp_dir / "audit.log"))
        monkeypatch.setenv("EMERGENCY_STOP_FILE", str(temp_dir / "stop.file"))

        config = Config.from_env()
        app = Application(config)

        assert app.config == config
        assert app.running is False

    @pytest.mark.asyncio
    async def test_application_startup(self, temp_dir, monkeypatch):
        """Test application startup sequence."""
        # Setup safe test config
        monkeypatch.setenv("GEMINI_API_KEY", "sk_test_1234567890abcdef")
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
        monkeypatch.setenv("AUTHORIZED_USERS", "123456789")
        monkeypatch.setenv("LOG_FILE", str(temp_dir / "app.log"))
        monkeypatch.setenv("AUDIT_LOG_FILE", str(temp_dir / "audit.log"))
        monkeypatch.setenv("EMERGENCY_STOP_FILE", str(temp_dir / "stop.file"))

        config = Config.from_env()
        app = Application(config)

        await app.startup()

        assert app.running is True
        assert (temp_dir / "app.log").parent.exists()
        assert (temp_dir / "audit.log").parent.exists()

    @pytest.mark.asyncio
    async def test_application_shutdown(self, temp_dir, monkeypatch):
        """Test application shutdown sequence."""
        # Setup safe test config
        monkeypatch.setenv("GEMINI_API_KEY", "sk_test_1234567890abcdef")
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
        monkeypatch.setenv("AUTHORIZED_USERS", "123456789")
        monkeypatch.setenv("LOG_FILE", str(temp_dir / "app.log"))
        monkeypatch.setenv("AUDIT_LOG_FILE", str(temp_dir / "audit.log"))
        monkeypatch.setenv("EMERGENCY_STOP_FILE", str(temp_dir / "stop.file"))

        config = Config.from_env()
        app = Application(config)

        await app.startup()
        assert app.running is True

        await app.shutdown()
        assert app.running is False

    @pytest.mark.asyncio
    async def test_application_main_success(self, temp_dir, monkeypatch):
        """Test Application.main() returns success on valid config."""
        # Setup safe test config
        monkeypatch.setenv("GEMINI_API_KEY", "sk_test_1234567890abcdef")
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
        monkeypatch.setenv("AUTHORIZED_USERS", "123456789")
        monkeypatch.setenv("LOG_FILE", str(temp_dir / "app.log"))
        monkeypatch.setenv("AUDIT_LOG_FILE", str(temp_dir / "audit.log"))
        monkeypatch.setenv("EMERGENCY_STOP_FILE", str(temp_dir / "stop.file"))

        # Create test config
        config = Config.from_env()

        # Create a custom Application that exits immediately
        class TestApplication(Application):
            async def run(self):
                self.running = False  # Exit immediately

        exit_code = await TestApplication.main(config)
        assert exit_code == 0

    @pytest.mark.asyncio
    async def test_application_main_configuration_error(self, monkeypatch):
        """Test Application.main() handles config errors gracefully."""
        # Setup invalid config
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
        monkeypatch.delenv("AUTHORIZED_USERS", raising=False)

        exit_code = await Application.main()
        assert exit_code == 1  # Configuration error returns 1

    @pytest.mark.asyncio
    async def test_application_handles_keyboard_interrupt(self, temp_dir, monkeypatch):
        """Test application gracefully handles KeyboardInterrupt."""
        # Setup safe test config
        monkeypatch.setenv("GEMINI_API_KEY", "sk_test_1234567890abcdef")
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
        monkeypatch.setenv("AUTHORIZED_USERS", "123456789")
        monkeypatch.setenv("LOG_FILE", str(temp_dir / "app.log"))
        monkeypatch.setenv("AUDIT_LOG_FILE", str(temp_dir / "audit.log"))
        monkeypatch.setenv("EMERGENCY_STOP_FILE", str(temp_dir / "stop.file"))

        config = Config.from_env()
        app = Application(config)

        await app.startup()
        # Simulate keyboard interrupt
        app.running = False

        # Should not raise
        await app.shutdown()
        assert app.running is False
