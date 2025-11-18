"""
Base classes and common structures for challenge validators.

This module contains the abstract base classes, data structures, and exceptions
used across all challenge validator implementations.
"""
from abc import ABC, abstractmethod
from typing import Dict, Tuple, Any, List, Optional
from dataclasses import dataclass
import logging


@dataclass
class ValidationResult:
    """Structured result from challenge validation."""

    success: bool
    invalid: bool
    error_message: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


@dataclass
class ChallengeContext:
    """Context information for challenge validation."""

    challenge_name: str
    token: str
    jwk_thumbprint: str
    authorization_type: str  # 'dns' or 'ip'
    authorization_value: str
    keyauthorization: Optional[str] = None
    dns_servers: Optional[List[str]] = None
    proxy_servers: Optional[Dict[str, str]] = None
    timeout: int = 10
    source_address: Optional[str] = None  # For source address validation
    options: Optional[Dict[str, Any]] = None  # Additional options


class ChallengeValidationError(Exception):
    """Base exception for challenge validation errors."""

    pass  # pragma: no cover


class ValidationTimeoutError(ChallengeValidationError):
    """Raised when validation times out."""

    pass  # pragma: no cover


class InvalidChallengeTypeError(ChallengeValidationError):
    """Raised when an unsupported challenge type is encountered."""

    pass  # pragma: no cover


class ChallengeValidator(ABC):
    """Abstract base class for all challenge validators."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    @abstractmethod
    def get_challenge_type(self) -> str:
        """Return the challenge type this validator handles (e.g., 'http-01')."""
        pass  # pragma: no cover

    @abstractmethod
    def perform_validation(self, context: ChallengeContext) -> ValidationResult:
        """
        Perform the actual validation logic for this challenge type.

        Args:
            context: Challenge context containing all necessary information

        Returns:
            ValidationResult: Structured result with success/failure status
        """
        pass  # pragma: no cover

    def validate_challenge(self, context: ChallengeContext) -> ValidationResult:
        """
        Main entry point for validation with error handling and logging.

        Args:
            context: Challenge context containing all necessary information

        Returns:
            ValidationResult: Structured result with success/failure status
        """
        self.logger.debug(
            "Starting %s validation for challenge: %s",
            self.get_challenge_type(),
            context.challenge_name,
        )

        try:
            result = self.perform_validation(context)
            self.logger.debug(
                "%s validation completed for %s: success=%s, invalid=%s, error=%s",
                self.get_challenge_type(),
                context.challenge_name,
                result.success,
                result.invalid,
                result.error_message if result.error_message else "None",
            )
            return result
        except Exception as e:
            self.logger.error(
                "%s validation failed for %s: %s",
                self.get_challenge_type(),
                context.challenge_name,
                str(e),
            )
            return ValidationResult(
                success=False,
                invalid=True,
                error_message=str(e),
                details={"exception_type": type(e).__name__},
            )
