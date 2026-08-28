"""Tests for emergency stop mechanism."""

import pytest
from laptop_control.core.exceptions import EmergencyStopTriggered
from laptop_control.security import EmergencyStop


class TestEmergencyStop:
    """Test EmergencyStop functionality."""

    def test_initially_inactive(self, emergency_stop):
        """Test that emergency stop starts inactive."""
        assert emergency_stop.is_active() is False

    def test_activate_works(self, emergency_stop):
        """Test activating emergency stop."""
        assert emergency_stop.is_active() is False
        emergency_stop.activate(reason="Test activation")
        assert emergency_stop.is_active() is True

    def test_reset_works(self, emergency_stop):
        """Test resetting emergency stop."""
        emergency_stop.activate(reason="Test activation")
        assert emergency_stop.is_active() is True
        emergency_stop.reset()
        assert emergency_stop.is_active() is False

    def test_require_not_stopped_when_inactive(self, emergency_stop):
        """Test that require_not_stopped passes when inactive."""
        # Should not raise
        emergency_stop.require_not_stopped()

    def test_require_not_stopped_when_active(self, emergency_stop):
        """Test that require_not_stopped raises when active."""
        emergency_stop.activate(reason="Test")
        with pytest.raises(EmergencyStopTriggered):
            emergency_stop.require_not_stopped()

    def test_stop_file_created_on_activate(self, emergency_stop):
        """Test that stop file is created when emergency stop activated."""
        assert emergency_stop.stop_file.exists() is False
        emergency_stop.activate(reason="Test")
        assert emergency_stop.stop_file.exists() is True

    def test_stop_file_removed_on_reset(self, emergency_stop):
        """Test that stop file is removed when emergency stop reset."""
        emergency_stop.activate(reason="Test")
        assert emergency_stop.stop_file.exists() is True
        emergency_stop.reset()
        assert emergency_stop.stop_file.exists() is False

    def test_stop_file_detected_on_check(self, emergency_stop):
        """Test that stop file is detected on is_active check."""
        # Manually create stop file (external trigger)
        emergency_stop.stop_file.parent.mkdir(parents=True, exist_ok=True)
        emergency_stop.stop_file.touch()

        # Create fresh instance (internal flag not set)
        fresh_instance = EmergencyStop(str(emergency_stop.stop_file))
        assert fresh_instance._is_active is False
        # But detection should work
        assert fresh_instance.is_active() is True

    def test_multiple_activations(self, emergency_stop):
        """Test that multiple activations work correctly."""
        emergency_stop.activate(reason="First activation")
        assert emergency_stop.is_active() is True
        emergency_stop.activate(reason="Second activation")
        assert emergency_stop.is_active() is True

    def test_reset_without_activation(self, emergency_stop):
        """Test that reset works even if never activated."""
        # Should not raise
        emergency_stop.reset()
        assert emergency_stop.is_active() is False

    def test_repr(self, emergency_stop):
        """Test string representation."""
        repr_str = repr(emergency_stop)
        assert "EmergencyStop" in repr_str
        assert "INACTIVE" in repr_str

        emergency_stop.activate(reason="Test")
        repr_str = repr(emergency_stop)
        assert "ACTIVE" in repr_str
