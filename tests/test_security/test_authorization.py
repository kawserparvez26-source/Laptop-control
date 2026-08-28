"""Tests for authorization manager."""

import pytest
from laptop_control.core.exceptions import AuthorizationError
from laptop_control.security import AuthorizationManager


class TestAuthorizationManager:
    """Test AuthorizationManager functionality."""

    def test_authorized_user_succeeds(self, auth_manager):
        """Test that authorized users pass authorization."""
        # Should not raise
        auth_manager.require_authorized(123456789)

    def test_unauthorized_user_fails(self, auth_manager):
        """Test that unauthorized users fail authorization."""
        with pytest.raises(AuthorizationError):
            auth_manager.require_authorized(999999999)

    def test_empty_allowlist_rejects_all(self):
        """Test that empty allowlist rejects all users."""
        auth_manager = AuthorizationManager(set())
        with pytest.raises(AuthorizationError):
            auth_manager.require_authorized(123456789)

    def test_is_authorized_returns_bool(self, auth_manager):
        """Test that is_authorized returns boolean."""
        assert auth_manager.is_authorized(123456789) is True
        assert auth_manager.is_authorized(999999999) is False

    def test_invalid_user_id_type_fails(self):
        """Test that non-integer user IDs are rejected."""
        auth_manager = AuthorizationManager({123456789})
        assert auth_manager.is_authorized("not_an_int") is False

    def test_add_authorized_user(self, auth_manager):
        """Test adding a user to authorization list."""
        new_user = 555555555
        assert auth_manager.is_authorized(new_user) is False
        auth_manager.add_authorized_user(new_user)
        assert auth_manager.is_authorized(new_user) is True

    def test_remove_authorized_user(self, auth_manager):
        """Test removing a user from authorization list."""
        user = 123456789
        assert auth_manager.is_authorized(user) is True
        auth_manager.remove_authorized_user(user)
        assert auth_manager.is_authorized(user) is False

    def test_get_authorized_users_returns_copy(self, auth_manager):
        """Test that get_authorized_users returns a copy."""
        users = auth_manager.get_authorized_users()
        original_count = len(users)
        users.add(999999999)  # Modify the returned set
        # Original should not be modified
        assert len(auth_manager.get_authorized_users()) == original_count

    def test_count_authorized_users(self, sample_authorized_users):
        """Test counting authorized users."""
        auth_manager = AuthorizationManager(sample_authorized_users)
        assert auth_manager.count_authorized_users() == 3

    def test_authorization_manager_initialization_validates_types(self):
        """Test that initialization validates user ID types."""
        with pytest.raises(TypeError):
            AuthorizationManager("not_a_set")

        with pytest.raises(TypeError):
            AuthorizationManager({123, "not_an_int", 456})

        with pytest.raises(ValueError):
            AuthorizationManager({-1, 123})  # Negative user ID

    def test_add_user_validates_type(self, auth_manager):
        """Test that add_authorized_user validates type."""
        with pytest.raises(TypeError):
            auth_manager.add_authorized_user("not_an_int")

        with pytest.raises(ValueError):
            auth_manager.add_authorized_user(-1)
