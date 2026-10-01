# Contributing to SONiC Smart Patch

Thank you for your interest in contributing to SONiC Smart Patch! This document provides guidelines for contributions.

## Code of Conduct

This project adheres to the [SONiC Community Code of Conduct](https://github.com/sonic-net/SONiC/blob/master/CODE_OF_CONDUCT.md).

## Getting Started

### Development Setup

```bash
# Clone the repository
git clone https://github.com/sonic-net/sonic-buildimage.git
cd sonic-buildimage/src/sonic-smart-patch

# Install development dependencies
pip install -r requirements.txt
pip install pytest pytest-cov pylint flake8 black

# Run tests
pytest tests/ -v --cov=smart_patch
```

### Code Style

We follow PEP 8 with Black formatting:

```bash
# Format code
black smart_patch/ tests/

# Check style
flake8 smart_patch/ tests/
pylint smart_patch/ tests/
```

## Making Changes

### 1. Create Feature Branch

```bash
git checkout -b smart_patch/feature-name
git branch -u origin/smart_patch/feature-name
```

### 2. Code Guidelines

- **Python 3.9+** only
- **Type hints** for all functions
- **Docstrings** for modules, classes, and public methods
- **Error handling** at system boundaries only
- **Logging** for all operations
- **No external secrets** in code

### 3. Testing Requirements

All contributions must include tests:

```python
# tests/unit/test_new_feature.py
import pytest
from smart_patch.new_module import NewFeature

class TestNewFeature:
    def test_basic_functionality(self):
        feature = NewFeature()
        assert feature.works()

    def test_error_handling(self):
        with pytest.raises(ValueError):
            feature.invalid_input()
```

### 4. Documentation

Update relevant docs:
- Code docstrings
- `README.md` for user-facing changes
- `IMPLEMENTATION_GUIDE.md` for architecture changes
- CLI help text for new commands

## Pull Request Process

1. **Create PR** with descriptive title and description
2. **Link issues**: Reference related issues (fixes #123)
3. **Test locally**: Run full test suite before submitting
4. **Code review**: Address reviewer feedback
5. **Approval**: Requires 2 approvals from maintainers
6. **Merge**: Squash and merge to main branch

### PR Title Format

```
[module] Brief description of change

Examples:
- [scanner] Add SBOM validation
- [remediation] Fix kernel package timeout
- [cli] Add VEX record commands
- [docs] Update integration guide
```

### PR Description Template

```markdown
## Description
Brief summary of what this PR does.

## Motivation
Why is this change needed? What problem does it solve?

## Changes
- Change 1
- Change 2
- Change 3

## Testing
How was this tested?
- [ ] Unit tests added
- [ ] Integration tests passed
- [ ] Manual testing on SONiC device

## Checklist
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] No breaking changes
- [ ] Tests added/updated
```

## Reporting Issues

Use GitHub Issues with template:

```markdown
## Description
Clear description of the issue.

## Steps to Reproduce
1. Step 1
2. Step 2
3. Step 3

## Expected Behavior
What should happen.

## Actual Behavior
What actually happens.

## Environment
- SONiC version:
- Smart Patch version:
- Python version:
- OS:

## Logs
Relevant logs (JSON format preferred):
```

## Module Structure

When adding new modules:

```
smart_patch/
├── new_module.py          # Implementation
├── __init__.py            # Exports
└── tests/
    └── test_new_module.py # Tests
```

### Module Template

```python
"""Brief module description.

Longer description of what this module does and how it integrates
with the rest of SONiC Smart Patch.
"""

from typing import Optional, Dict, Any
from smart_patch.exceptions import SmartPatchException
from smart_patch.logging import setup_logging

logger = setup_logging(__name__)


class NewModule:
    """Class description."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize module.

        Args:
            config: Optional configuration dict

        Raises:
            ConfigError: If config is invalid
        """
        self.config = config or {}

    def do_something(self) -> bool:
        """Perform some action.

        Returns:
            True if successful

        Raises:
            SmartPatchException: If operation fails
        """
        try:
            logger.info("Doing something...")
            # Implementation here
            return True
        except Exception as e:
            logger.error(f"Failed: {e}")
            raise SmartPatchException(f"Operation failed: {e}")
```

## Testing Guidelines

### Unit Tests

- Test single functions in isolation
- Mock external dependencies
- Cover happy path and error cases
- Use fixtures from `tests/conftest.py`

### Integration Tests

- Test Smart Patch components together
- Require SONiC switch or simulator
- Marked with `@pytest.mark.integration`
- Test realistic workflows

### Test Naming

```python
# ✓ Good
def test_scan_detects_known_cves():
def test_remediation_fails_without_network():
def test_rollback_restores_previous_version():

# ✗ Bad
def test_scan():
def test_error():
def test_fix():
```

## Performance Considerations

Smart Patch must maintain strict performance targets:

| Operation | Target | How to Test |
|-----------|--------|------------|
| Scan | <2 min | `pytest tests/perf/test_scan_performance.py` |
| Remediation | <5 min | Device test |
| Health checks | <1 min | Unit test with mocks |

## Security

### Security Fixes

For security vulnerabilities, please report privately:
- Email: security@sonic.org
- Do NOT open public GitHub issues

### Code Security

- Never log sensitive data (tokens, passwords)
- Validate all external inputs
- Use SONiC Config DB for secrets
- Encrypt sensitive files at rest

## Documentation Improvements

Good documentation is just as important as code:

- README updates for user-facing changes
- Docstring updates for API changes
- Guide updates for workflow changes
- Examples for complex features

## Questions?

- **Technical**: Create GitHub Discussion
- **Process**: Email smart_patchs@sonic.org
- **Community**: SONiC Slack #smart_patch

## Recognition

Contributors are recognized in:
- `CONTRIBUTORS.md` file
- Release notes for major contributions
- SONiC community announcements

Thank you for making SONiC Smart Patch better!
