"""Main application entry point for Laptop Control.

Run with: python -m laptop_control.main

This is a foundational entry point that loads configuration,
initializes logging, and validates the environment.
Full system integration happens in Phase 1B+.
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

        In Phase 1A, this is a placeholder.
        Phase 1B+ will implement actual message processing.
        """
        self.logger.info("Application event loop started (Phase 1A foundation)")
        self.logger.info(
            "Ready for Phase 1B implementation: Gemini AI + Telegram integration"
        )

        # In foundation phase, just stay alive for a bit
        # Full implementation will process messages here
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
