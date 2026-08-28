"""Emergency stop mechanism for halting all operations.

Provides EmergencyStop for global system shutdown in case
of security incidents or critical failures.
"""

import logging
from pathlib import Path
from typing import Optional

from laptop_control.core.exceptions import EmergencyStopTriggered

logger = logging.getLogger(__name__)


class EmergencyStop:
    """Global emergency stop mechanism.

    When activated, prevents all tool execution and operations.
    Can be triggered manually or by detecting security issues.

    This is a last-resort safety mechanism to completely halt
    the system in case of emergency.

    Attributes:
        stop_file: Path to emergency stop marker file
        _is_active: Internal state flag
    """

    def __init__(self, stop_file: str = "/tmp/laptop-control.stop") -> None:
        """Initialize emergency stop.

        Args:
            stop_file: Path to stop file. If this file exists,
                emergency stop is considered active.
        """
        self.stop_file = Path(stop_file)
        self._is_active = False
        logger.debug(f"Emergency stop initialized: {self.stop_file}")

    def activate(self, reason: str = "") -> None:
        """Activate emergency stop.

        Halts all operations. Log the reason for forensics.

        Args:
            reason: Reason emergency stop was triggered
        """
        self._is_active = True

        # Create stop file as persistent marker
        try:
            self.stop_file.parent.mkdir(parents=True, exist_ok=True)
            self.stop_file.touch()
        except Exception as e:
            logger.error(f"Failed to create emergency stop file: {e}")
            # Continue anyway - internal flag is set

        logger.critical(f"EMERGENCY STOP ACTIVATED: {reason}")

    def reset(self) -> None:
        """Reset emergency stop.

        Re-enables normal operation. Should only be done by
        authorized admin after resolving the emergency.
        """
        self._is_active = False

        # Remove stop file
        try:
            if self.stop_file.exists():
                self.stop_file.unlink()
        except Exception as e:
            logger.error(f"Failed to remove emergency stop file: {e}")
            # Continue anyway - internal flag is cleared

        logger.info("Emergency stop reset by administrator")

    def is_active(self) -> bool:
        """Check if emergency stop is active.

        Checks both internal state and stop file for persistence.

        Returns:
            True if emergency stop is active, False otherwise
        """
        # Check internal flag first (fast path)
        if self._is_active:
            return True

        # Check if stop file exists (external trigger)
        if self.stop_file.exists():
            self._is_active = True
            logger.warning(f"Emergency stop file detected: {self.stop_file}")
            return True

        return False

    def require_not_stopped(self) -> None:
        """Require that emergency stop is not active.

        Raises EmergencyStopTriggered if emergency stop is active.

        Raises:
            EmergencyStopTriggered: If emergency stop is active
        """
        if self.is_active():
            raise EmergencyStopTriggered(
                "All operations are halted due to emergency stop"
            )

    def __repr__(self) -> str:
        """Return string representation.

        Returns:
            Safe string representation of state
        """
        status = "ACTIVE" if self.is_active() else "INACTIVE"
        return f"EmergencyStop(status={status})"
