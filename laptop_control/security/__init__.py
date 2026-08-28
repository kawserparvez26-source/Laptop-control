"""Security layer for Laptop Control.

Provides authorization, audit logging, and emergency stop mechanisms.
"""

from laptop_control.security.authorization import AuthorizationManager
from laptop_control.security.audit import AuditLogger
from laptop_control.security.emergency_stop import EmergencyStop

__all__ = [
    "AuthorizationManager",
    "AuditLogger",
    "EmergencyStop",
]
