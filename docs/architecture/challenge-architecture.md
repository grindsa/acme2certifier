# Challenge Architecture Documentation

## Overview

This document describes the implemented challenge architecture and provides guidance for extending the system with new challenge types.

## Architecture Summary

The refactored challenge system implements a clean, modular architecture using established design patterns:

### Design Patterns Implemented

- **Strategy Pattern**: Separate validation algorithms for each challenge type
- **Registry Pattern**: Dynamic discovery and management of validators
- **Repository Pattern**: Clean separation of data access logic
- **State Pattern**: Challenge lifecycle management
- **Factory Pattern**: Challenge creation and configuration
- **Context Manager Pattern**: Resource management and initialization

### Component Structure

```text
┌─────────────────────────────────────────────────────────────┐
│                    Challenge Class                          │
│              (ACME Protocol Handler)                        │
└──────────────────────┬──────────────────────────────────────┘
                       │
    ┌──────────────────┼──────────────────┐
    │                  │                  │
    ▼                  ▼                  ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────────┐
│ChallengeRepo│ │StateManager │ │ValidatorRegistry│
│             │ │             │ │                 │
└─────────────┘ └─────────────┘ └─────────────────┘
    │                  │                  │
    │                  │                  ▼
    │                  │        ┌─────────────────┐
    │                  │        │   Validators    │
    │                  │        │  ┌─────────────┐│
    │                  │        │  │HttpValidator││
    ▼                  ▼        │  │DnsValidator ││
┌─────────────┐ ┌─────────────┐ │  │TlsValidator ││
│  Database   │ │Challenge    │ │  │EmailValid...││
│  Operations │ │Lifecycle    │ │  │TkauthValid..││
└─────────────┘ └─────────────┘ │  └─────────────┘│
                                └─────────────────┘
```

## Core Components

### 1. Challenge Validators (`/acme_srv/challenge_validators/`)

The validator system provides modular, type-specific validation logic:

```text
challenge_validators/
├── __init__.py                 # Package initialization and exports
├── base.py                     # Base classes and common structures
├── registry.py                 # Validator registry implementation
├── http_validator.py           # HTTP-01 challenge validator
├── dns_validator.py            # DNS-01 challenge validator
├── tls_alpn_validator.py       # TLS-ALPN-01 challenge validator
├── email_reply_validator.py    # Email-reply-00 challenge validator
├── tkauth_validator.py         # TKAuth-01 challenge validator
├── source_address_validator.py # Source address validation
└── README.md                   # Documentation
```

#### Base Classes

- **`ChallengeValidator`**: Abstract base class defining the validation interface
- **`ChallengeContext`**: Data structure containing challenge validation parameters
- **`ValidationResult`**: Structured result object with success status and details

#### Implemented Validators

1. **`HttpChallengeValidator`**: HTTP-01 challenge validation
1. **`DnsChallengeValidator`**: DNS-01 challenge validation
1. **`TlsAlpnChallengeValidator`**: TLS-ALPN-01 challenge validation
1. **`EmailReplyChallengeValidator`**: Email-reply-00 challenge validation
1. **`TkauthChallengeValidator`**: TKAuth-01 challenge validation
1. **`SourceAddressValidator`**: Source address validation support

### 2. Business Logic Layer (`/acme_srv/challenge_business_logic.py`)

Handles challenge lifecycle management and business rules:

- **`ChallengeRepository`**: Database operations and data access
- **`ChallengeStateManager`**: Challenge state transitions and lifecycle
- **`ChallengeFactory`**: Challenge creation and configuration
- **`ChallengeService`**: High-level business operations
- **`ChallengeInfo`**: Challenge data structures

### 3. Error Handling (`/acme_srv/challenge_error_handling.py`)

Comprehensive error management system:

- **`ErrorHandler`**: Centralized error processing and logging
- **`ChallengeError`**: Base exception class with error categorization
- **Custom Exception Hierarchy**: Specific error types for different failure modes

### 4. Registry Setup (`/acme_srv/challenge_registry_setup.py`)

Factory functions for creating and configuring the validator registry:

- **`create_challenge_validator_registry()`**: Main registry creation function
- Configuration-driven validator registration
- Support for optional challenge types (email, tkauth)

### 5. Main Challenge Class (`/acme_srv/challenge.py`)

The Challenge class serves as the main entry point:

- **Public API Methods**:

  - `process_challenge_request()`: Handle ACME challenge requests
  - `retrieve_challenge_set()`: Get or create challenge sets
  - `challengeset_get()`: Legacy API compatibility
  - `parse()`: Legacy API compatibility

- **Context Manager Support**: Automatic resource initialization and cleanup

## Design principles

### 1. Modular components with clear, single responsibilities

- Validators handle only validation logic
- Repository handles only data access
- State manager handles only lifecycle transitions
- Factory handles only challenge creation

### 2. Method Naming Clarity

- `perform_validation()` - Each validator's main validation method
- `get_challenge_details()` - Retrieve challenge information
- `create_challenge_set()` - Create new challenges
- `process_challenge_request()` - Handle ACME challenge requests
- `retrieve_challenge_set()` - Get existing or create new challenges

### 3. Extensibility

Adding new challenge types is straightforward through the registry pattern:

```python
# Example: Adding a new challenge type
class NewChallengeValidator(ChallengeValidator):
    def get_challenge_type(self) -> str:
        return "new-challenge-01"

    def perform_validation(self, context: ChallengeContext) -> ValidationResult:
        # Implement validation logic
        pass


# Register with the system
registry.register_validator(NewChallengeValidator(logger))
```

### 4. Error Handling

Structured error handling with:

- Custom exception hierarchy
- Detailed error context and suggestions
- ACME-compliant error responses
- Comprehensive logging with stack traces

### 5. Testing

Comprehensive test coverage across multiple levels:

- **Unit Tests**: `test_challenge.py`
- **Component Tests**: `test_challenge_validators.py` - Individual validator testing
- **Business Logic Tests**: `test_challenge_business_logic.py` - Repository and service layer
- **Error Handling Tests**: `test_challenge_error_handling.py` - Exception scenarios
- **E2E Tests**: `test_challenge_e2e.py` - End-to-end integration testing

## Creating New Challenge Types

This section provides step-by-step guidance for implementing new challenge types in the modular architecture.

### Step 1: Create the Validator Class

Create a new file in `/acme_srv/challenge_validators/` following the naming convention:

```python
# /acme_srv/challenge_validators/mychallengie_validator.py
"""
MyChallenge-01 Challenge Validator.

Implements validation logic for mychallengie-01 challenges.
"""
from .base import ChallengeValidator, ChallengeContext, ValidationResult


class MyChallengeValidator(ChallengeValidator):
    """Validator for mychallengie-01 challenges."""

    def get_challenge_type(self) -> str:
        """Return the challenge type identifier."""
        return "mychallengie-01"

    def perform_validation(self, context: ChallengeContext) -> ValidationResult:
        """Perform mychallengie-01 challenge validation."""
        self.logger.debug("MyChallengeValidator.perform_validation()")

        try:
            # Import required helpers
            from acme_srv.helper import some_helper_function
        except ImportError as e:
            return ValidationResult(
                success=False,
                invalid=True,
                error_message=f"Required dependencies not available: {e}",
                details={"import_error": str(e)},
            )

        # Implement your validation logic here
        try:
            # Example validation steps:
            # 1. Extract needed information from context
            challenge_name = context.challenge_name
            token = context.token
            jwk_thumbprint = context.jwk_thumbprint
            auth_value = context.authorization_value

            # 2. Perform the specific validation for your challenge type
            validation_successful = self._perform_my_validation(
                token, jwk_thumbprint, auth_value
            )

            # 3. Return appropriate result
            if validation_successful:
                return ValidationResult(
                    success=True,
                    invalid=False,
                    details={
                        "validation_type": "mychallengie-01",
                        "authorization_value": auth_value,
                        "validated_at": context.timestamp or time.time(),
                    },
                )
            else:
                return ValidationResult(
                    success=False,
                    invalid=True,
                    error_message="MyChallenge validation failed",
                    details={
                        "validation_type": "mychallengie-01",
                        "authorization_value": auth_value,
                        "reason": "Specific failure reason here",
                    },
                )

        except Exception as e:
            self.logger.error(
                "MyChallengeValidator.perform_validation() error: %s", str(e)
            )
            return ValidationResult(
                success=False,
                invalid=True,
                error_message=f"Validation error: {str(e)}",
                details={"exception": str(e)},
            )

    def _perform_my_validation(
        self, token: str, jwk_thumbprint: str, auth_value: str
    ) -> bool:
        """Implement your specific validation logic."""
        # Add your challenge-specific validation code here
        # This is where you implement the actual challenge verification
        # according to your challenge type's specification

        # Example implementation (replace with actual logic):
        expected_response = f"{token}.{jwk_thumbprint}"
        # ... perform validation steps ...
        return True  # or False based on validation result
```

### Step 2: Register the Validator

Update `/acme_srv/challenge_validators/__init__.py` to include your new validator:

```python
# Add import
from .mychallengie_validator import MyChallengeValidator

# Add to __all__ list
__all__ = [
    # ... existing exports ...
    "MyChallengeValidator",
]
```

### Step 3: Configure Registration

Update `/acme_srv/challenge_registry_setup.py` to register your validator:

```python
def create_challenge_validator_registry(
    logger: logging.Logger, config: Optional[Dict[str, Any]] = None
) -> ChallengeValidatorRegistry:
    """Create a fully configured challenge validator registry with all standard validators"""

    registry = ChallengeValidatorRegistry(logger)

    # Register standard ACME challenge validators
    registry.register_validator(HttpChallengeValidator(logger))
    registry.register_validator(DnsChallengeValidator(logger))
    registry.register_validator(TlsAlpnChallengeValidator(logger))

    # Add your new validator (conditionally if needed)
    if config and getattr(config, "mychallengie_support", False):
        registry.register_validator(MyChallengeValidator(logger))

    return registry
```

### Step 4: Update Challenge Factory

If your challenge type requires special creation logic, update `/acme_srv/challenge_business_logic.py`:

```python
class ChallengeFactory:
    def create_challenge_set(
        self, authorization_name: str, token: str, id_type: str, value: str, **kwargs
    ) -> List[Dict[str, Any]]:
        """Create appropriate challenge set based on configuration."""
        challenges = []

        # ... existing challenge creation logic ...

        # Add your challenge type
        if self.config.mychallengie_support:
            my_challenge = self.create_mychallengie_challenge(
                authorization_name, token, value
            )
            if my_challenge:
                challenges.append(my_challenge)

        return challenges

    def create_mychallengie_challenge(
        self, authorization_name: str, token: str, value: str
    ) -> Optional[Dict[str, Any]]:
        """Create mychallengie-01 challenge."""
        return self._create_single_challenge(
            challenge_type="mychallengie-01",
            authorization_name=authorization_name,
            token=token,
            # Add any challenge-specific parameters
        )
```

### Step 5: Add Configuration Support

Update configuration handling to support your new challenge type. In the configuration system:

```python
# Example configuration option
mychallengie_support = False  # Enable/disable your challenge type
```

### Step 6: Create Tests

Create comprehensive tests for your validator in `/test/`:

```python
# /test/test_mychallengie_validator.py
#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Unit tests for MyChallengeValidator"""

import unittest
from unittest.mock import Mock, patch
from acme_srv.challenge_validators.mychallengie_validator import MyChallengeValidator
from acme_srv.challenge_validators import ChallengeContext, ValidationResult


class TestMyChallengeValidator(unittest.TestCase):
    """Test cases for MyChallengeValidator"""

    def setUp(self):
        """Setup for tests"""
        self.logger = Mock()
        self.validator = MyChallengeValidator(self.logger)

    def test_001_get_challenge_type(self):
        """Test get_challenge_type returns correct type"""
        result = self.validator.get_challenge_type()
        self.assertEqual(result, "mychallengie-01")

    def test_002_perform_validation_success(self):
        """Test successful validation"""
        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )

        with patch.object(self.validator, "_perform_my_validation", return_value=True):
            result = self.validator.perform_validation(context)

        self.assertTrue(result.success)
        self.assertFalse(result.invalid)
        self.assertIsNone(result.error_message)

    def test_003_perform_validation_failure(self):
        """Test validation failure"""
        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )

        with patch.object(self.validator, "_perform_my_validation", return_value=False):
            result = self.validator.perform_validation(context)

        self.assertFalse(result.success)
        self.assertTrue(result.invalid)
        self.assertEqual(result.error_message, "MyChallenge validation failed")

    # Add more tests for edge cases, error conditions, etc.


if __name__ == "__main__":
    unittest.main()
```

### Step 7: Documentation

Update documentation:

1. Add your validator to the README in `/acme_srv/challenge_validators/README.md`
1. Document configuration options
1. Add usage examples

### Step 8: Integration Testing

Test your new challenge type with the complete system:

```python
# Example integration test
def test_new_challenge_integration(self):
    """Test integration of new challenge type"""
    from acme_srv.challenge_registry_setup import create_challenge_validator_registry

    # Configure with your challenge enabled
    config = Mock()
    config.mychallengie_support = True

    registry = create_challenge_validator_registry(self.logger, config)

    # Verify your validator is registered
    validator = registry.get_validator("mychallengie-01")
    self.assertIsNotNone(validator)
    self.assertIsInstance(validator, MyChallengeValidator)
```

## Best Practices for New Challenge Types

### 1. Follow the Interface Contract

- Implement all required methods from `ChallengeValidator`
- Return properly structured `ValidationResult` objects
- Handle all error conditions gracefully

### 2. Error Handling

```python
# Always handle import errors
try:
    from acme_srv.helper import required_function
except ImportError as e:
    return ValidationResult(
        success=False,
        invalid=True,
        error_message=f"Required dependencies not available: {e}",
        details={"import_error": str(e)},
    )

# Catch and handle validation exceptions
try:
    # validation logic
    pass
except Exception as e:
    self.logger.error("Validation error: %s", str(e))
    return ValidationResult(
        success=False,
        invalid=True,
        error_message=f"Validation error: {str(e)}",
        details={"exception": str(e)},
    )
```

### 3. Logging

```python
# Use structured logging with appropriate levels
self.logger.debug("Starting validation for %s", context.challenge_name)
self.logger.info("Validation completed successfully")
self.logger.error("Validation failed: %s", error_message)
```

### 4. Configuration

- Make challenge types optional through configuration
- Provide reasonable defaults
- Document configuration options

### 5. Comprehensive Testing

- Test success and failure paths
- Test error conditions and edge cases
- Include integration tests
- Mock external dependencies appropriately

### 6. Performance

- Avoid blocking operations where possible
- Implement timeouts for network operations
- Consider caching for expensive operations

## Migration Considerations

### Backward Compatibility

The refactored architecture maintains backward compatibility:

- Legacy API methods (`parse()`, `challengeset_get()`) are preserved
- Existing integrations continue to work without modification
- Gradual migration path available

### Configuration Migration

- Existing configuration options continue to work
- New configuration options are additive
- Default behavior remains unchanged
