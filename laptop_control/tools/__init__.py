"""Tool system for Laptop Control.

This package provides the tool abstraction layer, tool registry,
and base tool implementations for the Laptop Control system.

Tools are individual components that perform specific operations
(filesystem, terminal, git, etc.). Each tool:

1. Implements the Tool protocol
2. Validates input before execution
3. Respects authorization boundaries
4. Reports results in a standard format
5. Is auditable for security compliance

The ToolRegistry manages tool registration, discovery, and execution
with full security integration (authorization, emergency stop, auditing).
"""

from laptop_control.tools.base import BaseTool
from laptop_control.tools.registry import ToolRegistry

__all__ = [
    "BaseTool",
    "ToolRegistry",
]
