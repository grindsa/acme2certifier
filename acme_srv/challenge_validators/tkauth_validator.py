"""
TKAuth Challenge Validator.

Implements validation logic for tkauth-01 challenges.
"""
from .base import ChallengeValidator, ChallengeContext, ValidationResult


class TkauthChallengeValidator(ChallengeValidator):
    """Validator for tkauth-01 challenges."""

    def get_challenge_type(self) -> str:
        return "tkauth-01"

    def perform_validation(self, context: ChallengeContext) -> ValidationResult:
        """Perform tkauth-01 challenge validation."""
        # For now, this always returns success as in the original implementation
        # This would be expanded with actual validation logic when requirements are defined

        self.logger.debug(
            "TKAuth validation for challenge %s with authorization value %s",
            context.challenge_name,
            context.authorization_value
        )

        return ValidationResult(
            success=True,
            invalid=False,
            details={
                "validation_type": "tkauth-01",
                "authorization_value": context.authorization_value
            }
        )