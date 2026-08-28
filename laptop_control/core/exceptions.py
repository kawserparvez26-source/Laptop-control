"""Custom exceptions for Laptop Control system.

All exceptions inherit from LaptopControlException for easy catching
and provide clear error messages for debugging.
"""


class LaptopControlException(Exception):
    """Base exception for all Laptop Control errors.

    All other exceptions inherit from this, allowing easy catching
    of application-specific errors.
    """

    pass


class ConfigurationError(LaptopControlException):
    """Raised when configuration loading or validation fails.

    Typically indicates missing or invalid environment variables,
    invalid values in .env file, or configuration format issues.
    """

    pass


class AuthorizationError(LaptopControlException):
    """Raised when user is not authorized to perform an operation.

    Indicates that a user attempted an operation they don't have
    permission for (e.g., user not in AUTHORIZED_USERS list).
    """

    pass


class ToolExecutionError(LaptopControlException):
    """Base exception for tool-related errors.

    Raised when a tool fails to execute, validate, or check permissions.
    """

    pass


class ToolNotFoundError(ToolExecutionError):
    """Raised when a requested tool is not registered or available.

    Indicates that Gemini requested a tool that doesn't exist
    in the current tool registry.
    """

    pass


class CommandValidationError(ToolExecutionError):
    """Raised when a command fails validation before execution.

    Indicates that the command syntax is invalid, contains unsafe
    patterns, or doesn't match expected format.
    """

    pass


class ToolRuntimeError(ToolExecutionError):
    """Raised when a tool fails during execution.

    Indicates that a tool started but encountered an error
    (e.g., file not found, command returned non-zero exit code).
    """

    pass


class SecurityError(LaptopControlException):
    """Raised when a security violation is detected.

    Covers various security issues like unauthorized access attempts,
    suspicious activity, or violations of security policies.
    """

    pass


class EmergencyStopTriggered(SecurityError):
    """Raised when emergency stop is active and operation attempted.

    Emergency stop is a global kill switch that prevents all operations
    when triggered (manually or automatically).
    """

    pass


class AuditLogError(LaptopControlException):
    """Raised when audit logging fails.

    Indicates that an operation completed but couldn't be logged
    for audit trail. This is a security-critical error.
    """

    pass
