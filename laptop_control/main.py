"""Main application entry point for Laptop Control.

Run with: python -m laptop_control.main

Phase Status:
- Phase 1 (foundation): Complete - Core architecture, security framework, and tool scaffolding
- Phase 2 (security + tools): In review - Keyboard, mouse, and screen tools with backend pending
- Gemini/Telegram integration: Not yet implemented (Phase 3+)

This entry point loads configuration, initializes logging, and validates the environment.
Full message processing and Gemini/Telegram integration will be implemented in Phase 3+.
"""

import asyncio
import logging
import sys
from pathlib import Path
from typing import Optional

from laptop_control.config import Config
from laptop_control.core.exceptions import ConfigurationError, LaptopControlException
from laptop_control.utils import setup_logging


class Application:
    """Main Laptop Control Application.

    Coordinates all system components and manages lifecycle.
    """

    def __init__(self, config: Config) -> None:
        """Initialize the application.

        Args:
            config: Application configuration
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.running = False

    async def startup(self) -> None:
        """Initialize all application components.

        Loads configuration, sets up logging, and validates environment.
        """
        self.logger.info(f"Starting Laptop Control (v0.1.0)")
        self.logger.info(f"Configuration: {self.config}")
        self.logger.info(f"Environment: {self.config.environment}")
        self.logger.info(f"Authorized users: {len(self.config.authorized_users)}")

        # Validate that required files/directories are accessible
        self._validate_environment()

        self.logger.info("Application startup complete")
        self.running = True

    async def shutdown(self) -> None:
        """Gracefully shutdown the application.

        Closes connections, flushes logs, and cleans up resources.
        """
        self.logger.info("Shutting down Laptop Control...")
        self.running = False
        self.logger.info("Shutdown complete")

    def _validate_environment(self) -> None:
        """Validate that the environment is set up correctly.

        Checks:
        - Log directories are writable
        - Emergency stop file location is accessible
        """
        # Check log directory
        log_path = Path(self.config.log_file)
        log_dir = log_path.parent
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            # Try to write a test line
            test_file = log_dir / ".write_test"
            test_file.touch()
            test_file.unlink()
            self.logger.debug(f"Log directory writable: {log_dir}")
        except PermissionError as e:
            raise ConfigurationError(
                f"Cannot write to log directory {log_dir}: {e}"
            ) from e

        # Check audit log directory
        audit_path = Path(self.config.audit_log_file)
        audit_dir = audit_path.parent
        try:
            audit_dir.mkdir(parents=True, exist_ok=True)
            self.logger.debug(f"Audit log directory ready: {audit_dir}")
        except PermissionError as e:
            raise ConfigurationError(
                f"Cannot write to audit log directory {audit_dir}: {e}"
            ) from e

        # Check emergency stop file location
        emergency_path = Path(self.config.emergency_stop_file)
        emergency_dir = emergency_path.parent
        try:
            emergency_dir.mkdir(parents=True, exist_ok=True)
            self.logger.debug(f"Emergency stop file location accessible: {emergency_path}")
        except PermissionError as e:
            self.logger.warning(
                f"Cannot write to emergency stop location {emergency_path}: {e}"
            )
            # Don't fail on this, just warn

    async def run(self) -> None:
        """Main application event loop.

        Phase 1 (foundation) is complete.
        Phase 2 (security + tools) is in review with backend integrations pending.
        Phase 3+ will implement Gemini AI and Telegram integration for message processing.
        """
        self.logger.info("Application event loop started")
        self.logger.info("Phase 1 (foundation): Complete")
        self.logger.info("Phase 2 (security + tools): In review - backend integrations pending")
        self.logger.info("Phase 3+ (Gemini/Telegram integration): Not yet implemented")

        # In current phase, just stay alive
        # Full message processing will be implemented in Phase 3+
        try:
            while self.running:
                await asyncio.sleep(0.1)
        except KeyboardInterrupt:
            self.logger.info("Received interrupt signal")
            self.running = False

    @staticmethod
    async def main(config: Optional[Config] = None) -> int:
        """Main entry point.

        Args:
            config: Application config (loaded from env if not provided)

        Returns:
            Exit code (0 for success, non-zero for error)
        """
        try:
            # Load configuration
            if config is None:
                config = Config.from_env()

            # Setup logging
            logger = setup_logging(
                name="laptop_control",
                level=config.get_log_level_int(),
                log_file=config.log_file,
                console_output=True,
            )

            # Create and run application
            app = Application(config)
            await app.startup()

            try:
                await app.run()
            finally:
                await app.shutdown()

            return 0

        except ConfigurationError as e:
            print(f"Configuration Error: {e}", file=sys.stderr)
            return 1
        except LaptopControlException as e:
            print(f"Application Error: {e}", file=sys.stderr)
            return 2
        except Exception as e:
            print(f"Unexpected Error: {e}", file=sys.stderr)
            return 3


def main() -> int:
    """CLI entry point.

    Returns:
        Exit code
    """
    return asyncio.run(Application.main())


if __name__ == "__main__":
    sys.exit(main())
