# Challenge Validators

This directory contains modular challenge validator implementations for ACME challenge types. Each validator is implemented as a separate class following the Strategy pattern.

## Structure

```
challenge_validators/
├── __init__.py                 # Package initialization and exports
├── base.py                     # Base classes and common structures
├── registry.py                 # Validator registry implementation
├── http_validator.py           # HTTP-01 challenge validator
├── dns_validator.py            # DNS-01 challenge validator
├── tls_alpn_validator.py       # TLS-ALPN-01 challenge validator
├── email_reply_validator.py    # Email-reply-00 challenge validator
├── tkauth_validator.py         # TKAuth-01 challenge validator
└── README.md                   # This file
```

## Usage

### Basic Usage

```python
import logging
from challenge_validators import ChallengeValidatorRegistry
from challenge_validators.http_validator import HttpChallengeValidator

# Create registry and register validators
logger = logging.getLogger('acme')
registry = ChallengeValidatorRegistry(logger)
registry.register_validator(HttpChallengeValidator(logger))

# Use registry to validate challenges
from challenge_validators import ChallengeContext
context = ChallengeContext(
    challenge_name="example_challenge",
    token="token123",
    jwk_thumbprint="thumbprint456",
    authorization_type="dns",
    authorization_value="example.com"
)

result = registry.validate_challenge("http-01", context)
print(f"Success: {result.success}, Invalid: {result.invalid}")
```

### Using the Registry Factory

```python
from challenge_registry_setup import create_challenge_validator_registry

# Create a pre-configured registry with all standard validators
registry = create_challenge_validator_registry(logger)
print(f"Supported types: {registry.get_supported_types()}")
```

## Adding New Challenge Types

To add a new challenge type:

1. Create a new validator file (e.g., `my_validator.py`)
2. Inherit from `ChallengeValidator`
3. Implement the required methods
4. Register it with the registry

Example:

```python
# my_validator.py
from .base import ChallengeValidator, ChallengeContext, ValidationResult

class MyCustomValidator(ChallengeValidator):
    def get_challenge_type(self) -> str:
        return "my-custom-01"

    def perform_validation(self, context: ChallengeContext) -> ValidationResult:
        # Implement your validation logic
        return ValidationResult(success=True, invalid=False)

# Register it
from challenge_validators import ChallengeValidatorRegistry
registry = ChallengeValidatorRegistry(logger)
registry.register_validator(MyCustomValidator(logger))
```

## Architecture

The modular design provides:

- **Separation of Concerns**: Each validator handles only one challenge type
- **Easy Extension**: Add new challenge types without modifying existing code
- **Testability**: Each validator can be tested in isolation
- **Clear Interfaces**: Standardized validation interface across all types
- **Error Handling**: Structured error reporting with context

## Validators

### HttpChallengeValidator
Handles HTTP-01 challenges by making HTTP requests to verify challenge tokens.

### DnsChallengeValidator
Handles DNS-01 challenges by querying DNS TXT records.

### TlsAlpnChallengeValidator
Handles TLS-ALPN-01 challenges by validating TLS certificate extensions.

### EmailReplyChallengeValidator
Handles email-reply-00 challenges by processing email responses.

### TkauthChallengeValidator
Handles tkauth-01 challenges for telephone number authorization.

## Error Handling

All validators return `ValidationResult` objects with:
- `success`: Boolean indicating if validation passed
- `invalid`: Boolean indicating if validation definitively failed
- `error_message`: Optional error description
- `details`: Optional dictionary with additional context

## Dependencies

Validators import helper functions as needed to avoid circular dependencies and handle missing optional dependencies gracefully.