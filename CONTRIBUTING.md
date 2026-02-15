# Contributing

## Development Setup

```bash
# Clone repository
git clone https://github.com/wowemulation-dev/cascette-py.git
cd cascette-py

# Install development dependencies
uv sync --all-extras
```

## Before Submitting

Run these checks:

```bash
# Tests (must maintain 80% coverage)
uv run pytest

# Linting
uv run ruff check cascette_tools tests

# Type checking
uv run pyright cascette_tools

# Markdown linting
npx markdownlint-cli2 "**/*.md"

# Auto-format code
uv run black cascette_tools tests
uv run ruff check --fix cascette_tools tests
```

## Commit Messages

Use conventional commits format:

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Test changes
- `refactor:` Code refactoring
- `chore:` Maintenance tasks

Example: `feat: add BLTE compression support for mode F`

## Pull Request Process

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes
4. Ensure all checks pass
5. Submit pull request with clear description

## Code Style

- Type hints required for all functions
- Docstrings for public functions
- Follow existing code patterns
