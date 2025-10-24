"""
Challenge Validators Package.

This package provides a modular system for ACME challenge validation using
the Strategy pattern. Each challenge type has its own validator class with
clear separation of concerns.

Usage:
    from challenge_validators import ChallengeValidatorRegistry
    from challenge_validators.http_validator import HttpChallengeValidator

    registry = ChallengeValidatorRegistry(logger)
    registry.register_validator(HttpChallengeValidator(logger))
"""

# Import base classes and common structures
from .base import (
    ChallengeValidator,
    ChallengeContext,
    ValidationResult,
    ChallengeValidationError,
    ValidationTimeoutError,
    InvalidChallengeTypeError
)

# Import registry
from .registry import ChallengeValidatorRegistry

# Import all validator implementations
from .http_validator import HttpChallengeValidator
from .dns_validator import DnsChallengeValidator
from .tls_alpn_validator import TlsAlpnChallengeValidator
from .email_reply_validator import EmailReplyChallengeValidator
from .tkauth_validator import TkauthChallengeValidator

__all__ = [
    # Base classes
    'ChallengeValidator',
    'ChallengeContext',
    'ValidationResult',
    'ChallengeValidationError',
    'ValidationTimeoutError',
    'InvalidChallengeTypeError',

    # Registry
    'ChallengeValidatorRegistry',

    # Validators
    'HttpChallengeValidator',
    'DnsChallengeValidator',
    'TlsAlpnChallengeValidator',
    'EmailReplyChallengeValidator',
    'TkauthChallengeValidator'
]