"""Logging configuration for Laptop Control.

Sets up structured logging with console and file handlers.
Automatically masks sensitive data (API keys, tokens) to prevent
leakage in logs.
"""

import logging
import logging.handlers
import re
from pathlib import Path
from typing import Optional


class SecretMaskingFormatter(logging.Formatter):
    """Custom formatter that masks sensitive data in logs.

    Automatically redacts API keys, tokens, and other secrets to prevent
    them from appearing in log files.
    """

    # Patterns for common secrets that should be masked
    SECRET_PATTERNS = [
        (r"(api[_-]?key)[=:](\S+)", r"\1=***MASKED***"),
        (r"(token)[=:](\S+)", r"\1=***MASKED***"),
        (r"(password)[=:](\S+)", r"\1=***MASKED***"),
        (r"(secret)[=:](\S+)", r"\1=***MASKED***"),
        (r"(Authorization)\s+Bearer\s+\S+", r"\1 Bearer ***MASKED***"),
        (r"(?:https?://)?(?:\w+:)?(\w+@)[\w.]+", r"\1***:***@***"),  # URLs with credentials
    ]

    def format(self, record: logging.LogRecord) -> str:
        """Format log record and mask any sensitive data.

        Args:
            record: Log record to format

        Returns:
            Formatted log message with secrets masked
        """
        message = super().format(record)

        # Apply all masking patterns
        for pattern, replacement in self.SECRET_PATTERNS:
            message = re.sub(pattern, replacement, message, flags=re.IGNORECASE)

        return message


def setup_logging(
    name: str = "laptop_control",
    level: int = logging.INFO,
    log_file: Optional[str] = None,
    console_output: bool = True,
) -> logging.Logger:
    """Configure logging for the application.

    Sets up both console and file handlers with proper formatting.
    File handler uses rotating logs to prevent unbounded file growth.

    Args:
        name: Logger name (usually __name__)
        level: Logging level (logging.DEBUG, logging.INFO, etc.)
        log_file: Path to log file (optional, enables file logging)
        console_output: Whether to output to console

    Returns:
        Configured logger instance

    Example:
        ```python
        logger = setup_logging(
            level=logging.INFO,
            log_file="logs/app.log"
        )
        logger.info("Application started")
        ```
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Prevent duplicate handlers if called multiple times
    if logger.handlers:
        return logger

    # Format with timestamp, level, logger name, and message
    log_format = (
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    formatter = SecretMaskingFormatter(log_format)

    # Console handler (if enabled)
    if console_output:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # File handler (if log file specified)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Use rotating file handler to prevent unbounded growth
        # Max 5 backups, 10MB each
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger
