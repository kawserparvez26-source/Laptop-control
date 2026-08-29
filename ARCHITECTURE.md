"""# Laptop Control - System Architecture

## Overview

This document describes the complete architecture of the Laptop Control system. The system is designed as a modular, extensible platform where Google Gemini serves as the central AI coordinator.

## Core Architecture Principles

1. **Single AI Brain**: Gemini is the only AI engine; all decisions flow through it
2. **Tool Abstraction**: Each system tool (files, terminal, git, etc.) is an independent module with a consistent interface
3. **Security First**: Authorization, audit logging, and secure credential management are fundamental
4. **Type Safety**: Full Python type hints throughout
5. **Loose Coupling**: Modules communicate through well-defined interfaces
6. **Testability**: Each component can be tested independently

## Phase Changelog

### Phase 2 Final Review

**Status**: In Review (backend integrations pending)

**Key Verifications**:
- ✅ ToolResult/OperationStatus/RiskLevel consistency confirmed across `tools/` and `security/`
- ✅ Phase labels updated in keyboard.py, mouse.py, screen.py, main.py
- ✅ Backend dependency warnings preserved throughout (pynput for keyboard/mouse, Pillow for screen)
- ✅ Tool architecture maintains security-first design with proper authorization and audit logging

**Changes in Phase 2**:
- Keyboard tool (Phase 2 - backend pending): Secure key input with allowlist validation
- Mouse tool (Phase 2 - backend pending): Coordinate validation and bounds checking
- Screen tool (Phase 2 - backend pending): In-memory screenshot capture with resource limits
- Main.py lifecycle updated to reflect Phase 1 complete, Phase 2 in review, Phase 3+ for Gemini/Telegram

**Status Updates**:
- Phase 1 (foundation): ✅ Complete
- Phase 2 (security + tools): 🔄 In Review
- Phase 3+ (Gemini/Telegram integration): ⏳ Not yet implemented

---

## System Components

### 1. Configuration Layer (`laptop_control/config/`)

**Responsibility**: Manage all configuration from environment variables with validation.

#### Files:
- `__init__.py` - Package initialization
- `config.py` - Main configuration class with validation

**Key Features**:
- Environment variable loading with defaults
- Type validation
- Secure credential masking in logs
- Support for different environments (dev, test, prod)

**Example Usage**:
```python
from laptop_control.config import Config

config = Config.from_env()
gemini_key = config.gemini_api_key
authorized_users = config.authorized_users
```

**Security**:
- Secrets never logged or printed
- Credentials loaded only from `.env` or environment
- Validation ensures required fields are set

---

### 2. Core Layer (`laptop_control/core/`)

**Responsibility**: Define base classes, protocols, and shared types.

#### Files:
- `__init__.py` - Package initialization
- `protocols.py` - Abstract interfaces (Protocol definitions)
- `types.py` - Shared data models
- `exceptions.py` - Custom exceptions

**Key Protocols**:

#### `Tool` Protocol
```python
class Tool(Protocol):
    """Base protocol for all system tools."""
    
    async def execute(self, command: str, **kwargs) -> ToolResult:
        """Execute a command and return structured result."""
    
    async def validate(self, command: str) -> bool:
        """Validate a command before execution."""
    
    async def can_execute(self, user_id: int) -> bool:
        """Check if user has permission to use this tool."""
```

#### `AIInterface` Protocol
```python
class AIInterface(Protocol):
    """Protocol for AI backends (Gemini, etc.)."""
    
    async def process_user_input(
        self, 
        user_id: int, 
        message: str,
        context: dict
    ) -> AIResponse:
        """Process user input and return structured response."""
    
    async def generate_command(
        self,
        intent: str,
        tools_available: list[str],
        constraints: dict
    ) -> CommandRequest:
        """Generate a command request based on intent."""
```

#### `MessageInterface` Protocol
```python
class MessageInterface(Protocol):
    """Protocol for message delivery (Telegram, etc.)."""
    
    async def send_message(self, user_id: int, message: str) -> bool:
        """Send a message to a user."""
    
    async def receive_message(self) -> UserMessage:
        """Receive the next user message."""
```

**Data Models**:

```python
@dataclass
class ToolResult:
    """Result from tool execution."""
    success: bool
    output: str
    error: Optional[str] = None
    execution_time: float = 0.0
    metadata: dict = field(default_factory=dict)

@dataclass
class AIResponse:
    """Response from AI processing."""
    user_id: int
    message: str
    intent: str
    confidence: float
    requires_approval: bool
    tool_calls: list[str]

@dataclass
class UserMessage:
    """Message from remote user."""
    user_id: int
    message: str
    timestamp: float
    is_authorized: bool
```

---

### 3. Security Layer (`laptop_control/security/`)

**Responsibility**: Authorization, audit logging, and emergency controls.

#### Files:
- `__init__.py` - Package initialization
- `authorization.py` - User authorization and permissions
- `audit.py` - Audit logging system
- `secrets.py` - Secure credential handling

**Key Classes**:

#### `Authorizer`
```python
class Authorizer:
    """Handle user authorization."""
    
    def __init__(self, authorized_users: list[int]):
        self.authorized_users = set(authorized_users)
    
    def is_authorized(self, user_id: int) -> bool:
        """Check if user is authorized."""
    
    def can_perform_operation(
        self, 
        user_id: int, 
        operation: str
    ) -> bool:
        """Check if user can perform specific operation."""
```

#### `AuditLogger`
```python
class AuditLogger:
    """Log all operations for audit trail."""
    
    async def log_operation(
        self,
        user_id: int,
        operation: str,
        tool: str,
        success: bool,
        details: dict
    ) -> None:
        """Log an operation."""
    
    async def log_authorization_failure(
        self,
        user_id: int,
        reason: str
    ) -> None:
        """Log failed authorization attempts."""
```

#### `EmergencyStop`
```python
class EmergencyStop:
    """Emergency stop mechanism."""
    
    def trigger(self, reason: str) -> None:
        """Trigger emergency stop."""
    
    def is_active(self) -> bool:
        """Check if emergency stop is active."""
    
    def reset(self) -> None:
        """Reset emergency stop (admin only)."""
```

**Security Guarantees**:
- All operations logged with timestamp and user ID
- Sensitive data masked in logs
- Authorization checked before every operation
- Emergency stop can halt all operations
- Audit trail preserved for forensics

---

### 4. Tools Layer (`laptop_control/tools/`)

**Responsibility**: Implement each system tool as independent modules.

#### File Structure:
```
tools/
├── __init__.py
├── base.py                    # Base tool class
├── filesystem.py             # File operations
├── terminal.py               # Shell command execution
├── git.py                    # Git/GitHub operations
├── screen.py                 # Screen capture (Phase 2 - backend pending)
├── keyboard.py               # Keyboard control (Phase 2 - backend pending)
├── mouse.py                  # Mouse control (Phase 2 - backend pending)
└── registry.py               # Tool registry and discovery
```

**Base Tool Class**:
```python
class BaseTool:
    """Base class for all tools."""
    
    def __init__(
        self,
        name: str,
        description: str,
        authorizer: Authorizer,
        audit_logger: AuditLogger
    ):
        self.name = name
        self.description = description
        self.authorizer = authorizer
        self.audit_logger = audit_logger
    
    async def execute(
        self,
        command: str,
        user_id: int,
        **kwargs
    ) -> ToolResult:
        """Execute command with authorization check."""
    
    async def validate(self, command: str) -> bool:
        """Validate command syntax."""
    
    async def _authorized_execute(
        self,
        command: str,
        user_id: int
    ) -> ToolResult:
        """Subclasses override this."""
```

**Tool Registry**:
```python
class ToolRegistry:
    """Discover and manage available tools."""
    
    def register(self, tool: BaseTool) -> None:
        """Register a tool."""
    
    def get_tool(self, name: str) -> Optional[BaseTool]:
        """Get tool by name."""
    
    def list_available_tools(self) -> list[str]:
        """List all registered tool names."""
    
    def get_tool_descriptions(self) -> dict[str, str]:
        """Get descriptions for all tools."""
```

**Individual Tools** (Phase 1 foundation complete, Phase 2 in review):
- Each tool implements proper error handling
- Each tool validates inputs before execution
- Each tool logs operations via audit system
- Each tool respects authorization layer
- Phase 2 tools (keyboard, mouse, screen) require external backends (pynput, Pillow) which are not yet project dependencies

---

### 5. Interfaces Layer (`laptop_control/interfaces/`)

**Responsibility**: Implement Gemini AI and Telegram message interfaces.

#### File Structure:
```
interfaces/
├── __init__.py
├── ai/
│   ├── __init__.py
│   ├── gemini.py            # Google Gemini implementation
│   ├── prompts.py           # System prompts and templates
│   └── context.py           # Conversation context management
└── telegram/
    ├── __init__.py
    ├── bot.py               # Telegram bot implementation
    └── handlers.py          # Message handlers
```

**Gemini Interface**:
```python
class GeminiAI:
    """Google Gemini AI brain."""
    
    def __init__(
        self,
        api_key: str,
        tools: ToolRegistry,
        system_prompt: str
    ):
        self.api_key = api_key
        self.tools = tools
        self.system_prompt = system_prompt
        self.context_manager = ContextManager()
    
    async def process_user_input(
        self,
        user_id: int,
        message: str
    ) -> AIResponse:
        """Process user input through Gemini."""
    
    async def generate_command(
        self,
        intent: str,
        available_tools: list[str]
    ) -> CommandRequest:
        """Generate a command based on intent."""
```

**Telegram Interface**:
```python
class TelegramBot:
    """Telegram bot interface."""
    
    def __init__(
        self,
        token: str,
        authorizer: Authorizer,
        ai: GeminiAI
    ):
        self.token = token
        self.authorizer = authorizer
        self.ai = ai
    
    async def start(self) -> None:
        """Start receiving messages."""
    
    async def send_message(
        self,
        user_id: int,
        message: str
    ) -> bool:
        """Send message to user."""
    
    async def handle_user_message(
        self,
        message: UserMessage
    ) -> None:
        """Process incoming user message."""
```

---

### 6. Utils Layer (`laptop_control/utils/`)

**Responsibility**: Logging, timing, formatting, and other utilities.

#### Files:
- `__init__.py` - Package initialization
- `logging_setup.py` - Structured logging configuration
- `decorators.py` - Common decorators (timing, retry, etc.)
- `formatting.py` - Output formatting helpers
- `validators.py` - Input validation functions

**Logging Setup**:
```python
# Configure structured JSON logging
logger = setup_logging(
    level=logging.INFO,
    log_file="logs/laptop_control.log",
    mask_secrets=True  # Automatically mask API keys, tokens
)

logger.info("User executed command", extra={
    "user_id": 123,
    "tool": "filesystem",
    "operation": "list_files"
})
```

**Decorators**:
```python
@retry_on_error(max_attempts=3, backoff=2.0)
@log_execution_time
async def perform_operation():
    """Automatically retry and log timing."""
    pass
```

---

### 7. Main Application (`laptop_control/main.py`)

**Responsibility**: Application entry point that orchestrates all components.

```python
class LaptopControlApplication:
    """Main application orchestrator."""
    
    async def startup(self):
        """Initialize all components."""
        # 1. Load configuration
        # 2. Setup logging
        # 3. Initialize security
        # 4. Register tools
        # 5. Create AI interface
        # 6. Create message interface
        # 7. Start main loop
    
    async def run(self):
        """Main event loop."""
        # Process messages
        # Coordinate between interfaces
        # Handle emergency stops
    
    async def shutdown(self):
        """Graceful shutdown."""
        # Close connections
        # Flush logs
        # Cleanup resources
```

---

## Data Flow

### User Message → Result

```
1. User sends message via Telegram
   ↓
2. TelegramBot.handle_user_message()
   ├─ Verify user authorization (Authorizer)
   └─ Log incoming message (AuditLogger)
   ↓
3. GeminiAI.process_user_input()
   ├─ Add message to conversation context
   ├─ Call Gemini API with available tools
   └─ Parse Gemini response for tool calls
   ↓
4. For each tool call:
   a. Validate tool exists (ToolRegistry)
   b. Validate command (Tool.validate)
   c. Check authorization (Tool.authorized_execute)
   d. Execute tool (Tool.execute)
   e. Log operation (AuditLogger)
   f. Handle results
   ↓
5. GeminiAI.generate_response()
   ├─ Format tool results
   ├─ Call Gemini to generate natural language response
   └─ Prepare Telegram message
   ↓
6. TelegramBot.send_message()
   ├─ Send result to user
   └─ Log message delivery (AuditLogger)
   ↓
7. Operation complete, logged, and audited
```

---

## Error Handling Strategy

### Exception Hierarchy:
```python
LaptopControlException (base)
├── ConfigurationError          # Config loading/validation failed
├── AuthorizationError          # User not authorized
├── ToolExecutionError
│   ├── ToolNotFoundError       # Tool doesn't exist
│   ├── CommandValidationError  # Command syntax invalid
│   ├── ToolRuntimeError        # Tool execution failed
│   └── TimeoutError            # Tool execution timeout
├── AIError
│   ├── GeminiAPIError          # Gemini API call failed
│   └── PromptError             # Invalid prompt/context
├── TelegramError
│   ├── SendMessageError        # Failed to send message
│   └── AuthenticationError     # Bot token invalid
└── SecurityError
    ├── EmergencyStopTriggered  # System in emergency stop
    └── AuditLogError           # Failed to write audit log
```

### Error Handling Principles:
- Never expose internal errors to users
- Always log full error details
- Provide helpful user messages
- Attempt graceful degradation
- Trigger emergency stop on critical failures

---

## Security Model

### Authorization Levels:

1. **User Authorization**
   - Check if user_id in AUTHORIZED_USERS
   - Persistent audit log of all access

2. **Operation Authorization**
   - Different permissions for different tools
   - Dangerous operations may require approval workflow

3. **Approval Workflow** (Future)
   - High-risk operations require admin approval
   - Configurable per operation type
   - Timeout-based denial of unapproved operations

### Audit Trail:
- All operations logged with user ID, timestamp, tool, command, result
- Stored in structured format (JSON logs)
- Queryable for forensics

### Emergency Stop:
- Global kill switch for all operations
- Triggered by security events or admin
- Cannot be bypassed by any tool
- Requires manual reset

---

## Configuration Management

### Environment Variables:
```
# Required
GEMINI_API_KEY=xxx
TELEGRAM_BOT_TOKEN=xxx
AUTHORIZED_USERS=123456789,987654321

# Optional with defaults
LOG_LEVEL=INFO
LOG_FILE=logs/laptop_control.log
ENVIRONMENT=production
AUDIT_LOG_FILE=logs/audit.log
EMERGENCY_STOP_FILE=/tmp/laptop-control.stop
```

### Validation:
- Required fields must be present
- API keys must have minimum length
- User IDs must be positive integers
- Log levels must be valid Python logging levels

---

## Testing Strategy

### Unit Tests:
- Test each component in isolation
- Mock all external dependencies
- Test happy path and error cases
- 100% coverage for critical paths

### Integration Tests:
- Test component interactions
- Use temporary files/databases
- Verify security boundaries

### Security Tests:
- Verify unauthorized users rejected
- Verify secrets not logged
- Verify emergency stop works
- Verify audit trail complete

### Test File Structure:
```
tests/
├── __init__.py
├── conftest.py                # Shared fixtures
├── test_config.py             # Config tests
├── test_security/
│   ├── test_authorization.py
│   └── test_audit.py
├── test_tools/
│   ├── test_base_tool.py
│   ├── test_filesystem.py
│   └── test_registry.py
├── test_interfaces/
│   ├── test_gemini.py
│   └── test_telegram.py
└── test_integration.py        # End-to-end tests
```

---

## Module Dependencies

```
main.py
├─ config.Config
├─ security.Authorizer
├─ security.AuditLogger
├─ security.EmergencyStop
├─ tools.ToolRegistry
├─ interfaces.GeminiAI
├─ interfaces.TelegramBot
└─ utils.setup_logging

GeminiAI
├─ tools.ToolRegistry
├─ interfaces.ai.ContextManager
└─ interfaces.ai.prompts

TelegramBot
├─ security.Authorizer
├─ interfaces.GeminiAI
└─ security.AuditLogger

Tools (all)
├─ security.Authorizer
├─ security.AuditLogger
└─ core.types
```

No circular dependencies. All dependencies flow downward.

---

## Future Extensibility

### Adding New Tools:
1. Create `tools/newtool.py`
2. Inherit from `BaseTool`
3. Implement `_authorized_execute()` and `validate()`
4. Register in `tools.registry`
5. Update Gemini system prompt
6. Add tests in `tests/test_tools/`

### Adding New Message Interface:
1. Create `interfaces/slack/bot.py`
2. Implement `MessageInterface` protocol
3. Register in main.py
4. Add configuration for new interface

### Adding New AI Backend:
1. Create `interfaces/ai/openai.py`
2. Implement `AIInterface` protocol
3. Update main.py to support switching
4. Add tests

---

## Performance Considerations

### Concurrency:
- All I/O operations are async
- Tool execution can be parallelized
- Message handling uses asyncio queues

### Resource Limits:
- Timeout on tool execution (configurable)
- Maximum message size limits
- Rate limiting on Gemini API calls

### Caching:
- Tool descriptions cached in registry
- Conversation context cached per user
- API responses can be cached (future)

---

## Deployment Targets

### Current Phase (Foundation):
- Linux development environment
- Python 3.9+
- Local testing only

### Phase 2:
- Kali Linux target support
- Systemd service integration
- Log rotation

### Phase 3:
- Docker container support
- Multiple deployment targets
- Cloud integration

---

## See Also

- **[ROADMAP.md](ROADMAP.md)** - Development phases
- **[README.md](README.md)** - Project overview
- **tests/** - Reference implementations and examples
"""
