"""
Challenge Validator Registry.

Provides a registry system for managing and accessing challenge validators.
"""
from typing import Dict, List, Optional
import logging
from .base import ChallengeValidator, ChallengeContext, ValidationResult, InvalidChallengeTypeError


class ChallengeValidatorRegistry:
    """Registry for managing challenge validators."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self._validators: Dict[str, ChallengeValidator] = {}

    def register_validator(self, validator: ChallengeValidator) -> None:
        """Register a challenge validator."""
        challenge_type = validator.get_challenge_type()
        self._validators[challenge_type] = validator
        self.logger.debug("ChallengeValidatorRegistry.register_validator(): Registered validator for challenge type: %s", challenge_type)

    #def get_validator(self, challenge_type: str) -> Optional[ChallengeValidator]:
    #    """Get a validator for the specified challenge type."""
    #    return self._validators.get(challenge_type)

    def get_supported_types(self) -> List[str]:
        """Get list of supported challenge types."""
        return list(self._validators.keys())

    #def is_supported(self, challenge_type: str) -> bool:
    #    """Check if a challenge type is supported."""
    #    return challenge_type in self._validators

    #def validate_challenge(self, challenge_type: str, context: ChallengeContext) -> ValidationResult:
    #    """Validate a challenge using the appropriate validator."""
    #    validator = self.get_validator(challenge_type)
    #    if not validator:
    #        raise InvalidChallengeTypeError(f"Unsupported challenge type: {challenge_type}")
    #
    #    return validator.validate_challenge(context)