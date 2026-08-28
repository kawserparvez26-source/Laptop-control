# Laptop Control

A secure AI-powered remote computer control system built with Python and Google Gemini AI.

## Overview

Laptop Control is a production-grade system that enables remote computer management through natural language commands via Telegram. The system uses Google Gemini as its primary AI brain to understand commands and coordinate with various system tools.

### Architecture

```
Telegram User
    ↓
Laptop Control Agent
    ↓
Gemini (Main AI Brain)
    ↓
Controlled Tools
    ├── File System
    ├── Terminal
    ├── Git/GitHub
    ├── Screen Capture
    ├── Keyboard
    └── Mouse
    ↓
Kali Linux Laptop (Target Environment)
    ↓
Result
    ↓
Telegram
```

## Key Features

- **AI-Powered**: Google Gemini as the central intelligence engine
- **Secure**: Authorization layer, encrypted credentials, audit logging
- **Modular**: Independent, testable components
- **Extensible**: Easy to add new tools and capabilities
- **Production-Ready**: Type hints, error handling, structured logging

## Project Status

**PHASE 1 (Current)**: Foundation and Core Architecture
- Core project structure
- Configuration management
- Logging system
- Module interfaces
- Base classes and protocols
- Foundation tests

## Requirements

- Python 3.9+
- Google Gemini API key
- Telegram Bot token
- Linux system with standard tools (bash, git, etc.)

## Getting Started

### Installation

```bash
git clone https://github.com/kawserparvez26-source/Laptop-control.git
cd Laptop-control
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e .
```

### Configuration

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

2. Add your credentials:
   ```
   GEMINI_API_KEY=your_key_here
   TELEGRAM_BOT_TOKEN=your_token_here
   AUTHORIZED_USERS=123456789,987654321
   ```

3. Ensure `.env` is never committed (added to `.gitignore`)

### Running the System

```bash
python -m laptop_control.main
```

### Running Tests

```bash
pytest tests/ -v
```

## Documentation

- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Detailed module documentation and design patterns
- **[ROADMAP.md](ROADMAP.md)** - Development phases and feature implementation schedule
- **[docs/](docs/)** - Comprehensive technical documentation

## Security

This system is designed with security-first principles:

- All credentials stored in environment variables
- Sensitive data never logged
- Telegram user authorization via allowlist
- Future support for operation approval workflows
- Emergency stop mechanism
- Audit logging of all operations

⚠️ **WARNING**: This system provides powerful remote control capabilities. Only deploy with trusted users and proper authorization controls.

## Directory Structure

```
laptop_control/
├── main.py                 # Application entry point
├── config/                 # Configuration management
├── core/                   # Core classes and protocols
├── tools/                  # Tool implementations
├── interfaces/             # AI, Telegram interfaces
├── security/               # Authorization and audit
└── utils/                  # Utilities and helpers
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for comprehensive module documentation.

## License

MIT License - See LICENSE file

## Contributing

See [ROADMAP.md](ROADMAP.md) for development priorities.

## Support

For issues, questions, or contributions, please use the GitHub issue tracker.
