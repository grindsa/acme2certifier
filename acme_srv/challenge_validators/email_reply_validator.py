"""
Email Reply Challenge Validator.

Implements validation logic for email-reply-00 challenges.
"""
from typing import Dict, Tuple
import re
from .base import ChallengeValidator, ChallengeContext, ValidationResult
from acme_srv.helper import b64_url_encode, convert_byte_to_string, sha256_hash


class EmailReplyChallengeValidator(ChallengeValidator):
    """Validator for email-reply-00 challenges."""

    def get_challenge_type(self) -> str:
        """Return the challenge type this validator handles."""
        return "email-reply-00"

    def perform_validation(self, context: ChallengeContext) -> ValidationResult:
        """Perform email-reply-00 challenge validation."""
        self.logger.debug("EmailReplyChallengeValidator.perform_validation()")
        try:
            from acme_srv.email_handler import EmailHandler
        except ImportError as e:
            return ValidationResult(
                success=False,
                invalid=True,
                error_message=f"Email handler not available: {e}",
                details={"import_error": str(e)},
            )

        calculated_keyauth, rfc_token1 = self._generate_email_keyauth(
            context.challenge_name,
            context.token,
            context.jwk_thumbprint,
            context.keyauthorization,
        )

        with EmailHandler(debug=False, logger=self.logger) as email_handler:
            email_receive = email_handler.receive(
                callback=lambda email_data: self._filter_email(email_data, rfc_token1)
            )

            if not email_receive or "body" not in email_receive:
                return ValidationResult(
                    success=False,
                    invalid=False,
                    error_message="No email received or email body missing",
                )

            email_keyauth = self._extract_email_keyauth(email_receive["body"])

            if (
                email_keyauth
                and calculated_keyauth
                and email_keyauth == calculated_keyauth
            ):
                return ValidationResult(
                    success=True,
                    invalid=False,
                    details={"calculated_keyauth": calculated_keyauth},
                )
            else:
                return ValidationResult(
                    success=False,
                    invalid=True,
                    error_message="Email keyauthorization mismatch",
                    details={"expected": calculated_keyauth, "received": email_keyauth},
                )
        self.logger.debug("EmailReplyChallengeValidator.perform_validation() complete")

    def _generate_email_keyauth(
        self, challenge_name: str, rfc_token2: str, jwk_thumbprint: str, rfc_token1: str
    ) -> Tuple[str, str]:
        """Generate email keyauthorization - placeholder for actual implementation."""
        self.logger.debug(
            "EmailReplyChallengeValidator._generate_email_keyauth() for %s",
            challenge_name,
        )

        calculated_keyauth = convert_byte_to_string(
            b64_url_encode(
                self.logger,
                sha256_hash(self.logger, f"{rfc_token1}{rfc_token2}.{jwk_thumbprint}"),
            )
        )
        return calculated_keyauth, rfc_token1

    def _filter_email(self, email_data, rfc_token1):

        filter_string = f"ACME: {rfc_token1}"
        self.logger.debug(
            "Challenge._validate_email_reply_challenge(): filter string: %s",
            filter_string,
        )

        if filter_string in email_data.get("subject", ""):
            self.logger.debug(
                "Challenge._validate_email_reply_challenge(): email subject matches filter: %s",
                email_data["subject"],
            )
            return email_data
        else:
            self.logger.debug(
                "Challenge._validate_email_reply_challenge(): email subject does not match filter: %s",
                email_data.get("subject", ""),
            )
            return None

    def _extract_email_keyauth(self, email_body: str) -> str:
        """Extract keyauthorization from email body - placeholder for actual implementation."""
        self.logger.debug("EmailReplyChallengeValidator._extract_email_keyauth()")
        email_keyauthorization = None
        if email_body:
            # extract keyauthorization from email body
            match = re.search(
                r"-+BEGIN ACME RESPONSE-+\s*([\w=+/ -]+)\s*-+END ACME RESPONSE-+",
                email_body,
                re.DOTALL,
            )
            if match:
                email_keyauthorization = match.group(1).strip()

        self.logger.debug(
            "Challenge._emailchallenge_keyauth_extract() ended with: %s",
            bool(email_keyauthorization),
        )
        return email_keyauthorization
