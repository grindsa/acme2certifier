"""
TKAuth Challenge Validator.

Implements validation logic for tkauth-01 challenges.
"""

from acme2certifier.acme_srv.helpers.security_gate import (
    SECURITY_DISABLE_ACK_ENV,
    security_disable_acknowledged,
)
from .base import ChallengeValidator, ChallengeContext, ValidationResult

NOT_IMPLEMENTED_MSG = (
    "tkauth-01 validation is not implemented: the authority token is not verified"
)


class TkauthChallengeValidator(ChallengeValidator):
    """Validator for tkauth-01 challenges."""

    def get_challenge_type(self) -> str:
        return "tkauth-01"

    def perform_validation(self, context: ChallengeContext) -> ValidationResult:
        """Perform tkauth-01 challenge validation."""

        details = {
            "validation_type": "tkauth-01",
            "authorization_value": context.authorization_value,
        }

        # There is no ATC verification (RFC 9447) anywhere in the tree, so accepting
        # the challenge would authorize any SPC the client cares to claim.
        if not security_disable_acknowledged():
            self.logger.error(
                "%s; rejecting challenge %s for %s. Set %s=1 to accept any authority "
                "token for testing purposes only.",
                NOT_IMPLEMENTED_MSG,
                context.challenge_name,
                context.authorization_value,
                SECURITY_DISABLE_ACK_ENV,
            )
            return ValidationResult(
                success=False,
                invalid=True,
                error_message=NOT_IMPLEMENTED_MSG,
                details=details,
            )

        self.logger.critical(
            "**** SECURITY DISABLE ACKNOWLEDGED via %s: accepting unverified tkauth-01 "
            "authority token for challenge %s (%s) ****",
            SECURITY_DISABLE_ACK_ENV,
            context.challenge_name,
            context.authorization_value,
        )
        return ValidationResult(
            success=True,
            invalid=False,
            details=details,
        )
