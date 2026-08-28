"""Protocol definitions for Laptop Control interfaces.

Defines typing protocols (abstract interfaces) that various components
must implement. These are not actual classes but define contracts that
components must satisfy.

See: https://docs.python.org/3/library/typing.html#typing.Protocol
"""

from typing import Any, Dict, Optional, Protocol, runtime_checkable

from laptop_control.core.types import CommandResult, ToolResult


@runtime_checkable
class Tool(Protocol):
    """Protocol for all system tools.

    Any tool implementation must provide these methods to be compatible
    with the Laptop Control system.
    """

    async def execute(
        self,
        command: str,
        user_id: int,
        **kwargs: Any,
    ) -> ToolResult:
        """Execute a command with this tool.

        Args:
            command: Command string to execute
            user_id: ID of user requesting execution
            **kwargs: Additional parameters for this tool

        Returns:
            ToolResult with execution outcome

        Raises:
            AuthorizationError: User not authorized for this operation
            CommandValidationError: Command syntax invalid
            ToolRuntimeError: Tool failed to execute
        """
        ...

    async def validate(self, command: str) -> bool:
        """Validate that a command is syntactically correct.

        This is called before execution to catch errors early.
        Should not have side effects.

        Args:
            command: Command string to validate

        Returns:
            True if command is valid, False otherwise
        """
        ...

    async def can_execute(self, user_id: int) -> bool:
        """Check if user has permission to use this tool.

        Args:
            user_id: ID of user to check

        Returns:
            True if user is authorized, False otherwise
        """
        ...


@runtime_checkable
class AIInterface(Protocol):
    """Protocol for AI backends (Gemini, OpenAI, etc.).

    Laptop Control uses Google Gemini as its primary AI brain,
    but this protocol allows for future extensions.
    """

    async def process_user_input(
        self,
        user_id: int,
        message: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Process user input and generate response.

        Args:
            user_id: ID of user sending message
            message: Natural language message from user
            context: Optional conversation context

        Returns:
            Dict with keys:
            - 'intent': Parsed user intent
            - 'response': Natural language response to user
            - 'tool_calls': List of tool calls to execute
            - 'confidence': Confidence score (0-1)

        Raises:
            Exception: If AI processing fails
        """
        ...

    async def generate_command(
        self,
        intent: str,
        available_tools: list[str],
        constraints: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generate a tool command based on user intent.

        Args:
            intent: User's intent description
            available_tools: List of tool names that can be used
            constraints: Optional constraints on what commands are allowed

        Returns:
            Dict with keys:
            - 'tool': Tool name to use
            - 'command': Command to execute
            - 'parameters': Command parameters
            - 'explanation': Why this command was chosen
        """
        ...


@runtime_checkable
class MessageInterface(Protocol):
    """Protocol for message delivery systems (Telegram, etc.).

    Handles bidirectional communication with remote users.
    """

    async def start(self) -> None:
        """Start listening for incoming messages.

        Should block until stop() is called or fatal error occurs.
        """
        ...

    async def stop(self) -> None:
        """Stop listening for messages and cleanup."""
        ...

    async def send_message(
        self,
        user_id: int,
        message: str,
        **kwargs: Any,
    ) -> bool:
        """Send message to a user.

        Args:
            user_id: Recipient user ID
            message: Message text to send
            **kwargs: Additional options (e.g., parse_mode, disable_notification)

        Returns:
            True if message sent successfully, False otherwise
        """
        ...

    async def receive_message(self) -> Optional[Dict[str, Any]]:
        """Receive next incoming message.

        Blocks until message available or timeout.

        Returns:
            Dict with keys:
            - 'user_id': Sender's user ID
            - 'message': Message text
            - 'timestamp': When message was sent
            Or None if no message available
        """
        ...


@runtime_checkable
class CommandHandler(Protocol):
    """Protocol for command processing and orchestration.

    Coordinates between AI brain, tools, and message interfaces.
    """

    async def handle_user_message(
        self,
        user_id: int,
        message: str,
    ) -> str:
        """Handle incoming user message end-to-end.

        1. Parse intent via AI
        2. Generate command
        3. Execute with tools
        4. Format response
        5. Return to user

        Args:
            user_id: User sending message
            message: User's message

        Returns:
            Response message to send back to user

        Raises:
            AuthorizationError: User not authorized
            Exception: If processing fails
        """
        ...

    async def execute_command(self, command_result: CommandResult) -> None:
        """Execute a command generated by AI.

        Args:
            command_result: Command to execute
        """
        ...
