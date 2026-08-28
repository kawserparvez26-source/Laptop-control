"""User authorization and permission management.

Provides AuthorizationManager for checking if users are authorized
to use the system.
"""

import logging
from typing import Set

from laptop_control.core.exceptions import AuthorizationError

logger = logging.getLogger(__name__)


class AuthorizationManager:
    """Manages user authorization for system access.

    Enforces an allowlist of authorized Telegram user IDs.
    All authorization checks go through this manager.

    Attributes:
        authorized_users: Set of authorized Telegram user IDs
    """

    def __init__(self, authorized_users: Set[int]) -> None:
        """Initialize authorization manager.

        Args:
            authorized_users: Set of authorized Telegram user IDs.
                Empty set will reject all users (safe default).
        """
        if not isinstance(authorized_users, set):
            raise TypeError("authorized_users must be a set of integers")

        # Validate all entries are integers
        for user_id in authorized_users:
            if not isinstance(user_id, int):
                raise TypeError(f"User ID must be integer, got {type(user_id)}")
            if user_id <= 0:
                raise ValueError(f"User ID must be positive, got {user_id}")

        self.authorized_users = authorized_users
        logger.debug(f"Authorization manager initialized with {len(authorized_users)} users")

    def is_authorized(self, user_id: int) -> bool:
        """Check if a user is authorized.

        Args:
            user_id: Telegram user ID to check

        Returns:
            True if user is in authorized list, False otherwise
        """
        if not isinstance(user_id, int):
            logger.warning(f"Authorization check with non-integer user_id: {user_id}")
            return False

        return user_id in self.authorized_users

    def require_authorized(self, user_id: int) -> None:
        """Require that a user is authorized.

        Raises AuthorizationError if user is not authorized.

        Args:
            user_id: Telegram user ID to check

        Raises:
            AuthorizationError: If user is not authorized
        """
        if not self.is_authorized(user_id):
            logger.warning(f"Authorization denied for user_id: {user_id}")
            raise AuthorizationError(f"User {user_id} is not authorized")

    def add_authorized_user(self, user_id: int) -> None:
        """Add a user to the authorized list.

        Args:
            user_id: Telegram user ID to authorize

        Raises:
            TypeError: If user_id is not an integer
            ValueError: If user_id is not positive
        """
        if not isinstance(user_id, int):
            raise TypeError(f"User ID must be integer, got {type(user_id)}")
        if user_id <= 0:
            raise ValueError(f"User ID must be positive, got {user_id}")

        self.authorized_users.add(user_id)
        logger.info(f"User {user_id} added to authorization list")

    def remove_authorized_user(self, user_id: int) -> None:
        """Remove a user from the authorized list.

        Args:
            user_id: Telegram user ID to revoke
        """
        if user_id in self.authorized_users:
            self.authorized_users.discard(user_id)
            logger.info(f"User {user_id} removed from authorization list")

    def get_authorized_users(self) -> Set[int]:
        """Get all authorized users.

        Returns:
            Set of authorized user IDs (copy to prevent external modification)
        """
        return self.authorized_users.copy()

    def count_authorized_users(self) -> int:
        """Get count of authorized users.

        Returns:
            Number of authorized users
        """
        return len(self.authorized_users)
