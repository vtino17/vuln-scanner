# Contributing

## Development Setup

```bash
git clone https://github.com/vtino17/vuln-scanner.git
cd vuln-scanner
pip install -e .
pip install pytest
```

## Running Tests

```bash
pytest tests/ --verbose
```

## Code Style

- Follow PEP 8
- Use type hints for all function signatures
- Write tests for new functionality
- Keep functions focused and small (under 50 lines preferred)

## Pull Request Process

1. Create a feature branch
2. Add tests for new functionality
3. Ensure all tests pass
4. Update CHANGELOG.md
5. Submit PR with clear description
