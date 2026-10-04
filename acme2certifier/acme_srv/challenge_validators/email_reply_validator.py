"""
Email Reply Challenge Validator.

Implements validation logic for email-reply-00 challenges.
"""

import re
from typing import Any, Dict, Optional, Tuple

from .base import ChallengeValidator, ChallengeContext, ValidationResult
from acme2certifier.acme_srv.helper import (
    b64_url_encode,
    convert_byte_to_string,
    normalize_email_address,
    sha256_hash,
)

_MSG_ID_PATTERN = re.compile(r"<[^>]+>")


class EmailReplyChallengeValidator(ChallengeValidator):
    """Validator for email-reply-00 challenges."""

    def get_challenge_type(self) -> str:
        """Return the challenge type this validator handles."""
        return "email-reply-00"

    def perform_validation(self, context: ChallengeContext) -> ValidationResult:
        """Perform email-reply-00 challenge validation."""
        self.logger.debug("EmailReplyChallengeValidator.perform_validation()")
        try:
            from acme2certifier.acme_srv.email_handler import EmailHandler
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
                callback=lambda email_data: self._filter_email(
                    email_data, rfc_token1, context.authorization_value
                )
            )

            if not email_receive or "body" not in email_receive:
                self.logger.warning(
                    "Challenge validation failed: no email received or email body missing challenge=%s",
                    context.challenge_name,
                )
                return ValidationResult(
                    success=False,
                    invalid=False,
                    error_message="No email received or email body missing",
                )

            header_result = self._validate_response_headers(email_receive, context)
            if header_result is not None:
                return header_result

            email_keyauth = self._extract_email_keyauth(email_receive["body"])

            if (
                email_keyauth
                and calculated_keyauth
                and email_keyauth == calculated_keyauth
            ):
                self.logger.debug(
                    "EmailReplyChallengeValidator.perform_validation() complete"
                )
                return ValidationResult(
                    success=True,
                    invalid=False,
                    details={"calculated_keyauth": calculated_keyauth},
                )

            self.logger.error(
                "Email keyauthorization does not match calculated keyauthorization"
            )
            return ValidationResult(
                success=False,
                invalid=True,
                error_message="Email keyauthorization mismatch",
                details={"expected": calculated_keyauth, "received": email_keyauth},
            )

    def _generate_email_keyauth(
        self, challenge_name: str, rfc_token2: str, jwk_thumbprint: str, rfc_token1: str
    ) -> Tuple[str, str]:
        """Generate email keyauthorization digest from token parts."""
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

    def _sender_matches_identifier(self, from_header: str, identifier: str) -> bool:
        """Return True when parsed From matches the email identifier under validation."""
        sender = normalize_email_address(self.logger, from_header)
        expected = normalize_email_address(self.logger, identifier)
        if not sender or not expected:
            return False
        return sender == expected

    def _validate_response_headers(
        self, email_data: Dict[str, Any], context: ChallengeContext
    ) -> Optional[ValidationResult]:
        """Validate RFC 8823 response headers; None if checks pass."""
        if not self._sender_matches_identifier(
            email_data.get("from", ""), context.authorization_value
        ):
            self.logger.error(
                "Email reply From does not match identifier challenge=%s expected=%s received=%s",
                context.challenge_name,
                context.authorization_value,
                email_data.get("from", ""),
            )
            return ValidationResult(
                success=False,
                invalid=True,
                error_message="Reply From does not match email identifier",
                details={
                    "expected": context.authorization_value,
                    "received": email_data.get("from", ""),
                },
            )

        if email_data.get("has_list_headers"):
            self.logger.error(
                "Email reply contains List-* headers challenge=%s",
                context.challenge_name,
            )
            return ValidationResult(
                success=False,
                invalid=True,
                error_message="List-* headers not allowed in response",
            )

        stored_message_id = None
        if context.options:
            stored_message_id = context.options.get("challenge_message_id")

        thread_result = self._thread_matches_challenge(email_data, stored_message_id)
        if thread_result is False:
            self.logger.warning(
                "Email reply threading headers do not match challenge Message-ID challenge=%s",
                context.challenge_name,
            )
            return ValidationResult(
                success=False,
                invalid=True,
                error_message="In-Reply-To/References do not match challenge Message-ID",
                details={"expected_message_id": stored_message_id},
            )

        return None

    def _thread_matches_challenge(
        self, email_data: Dict[str, Any], expected_message_id: Optional[str]
    ) -> Optional[bool]:
        """Advisory threading check: None skip, True match, False mismatch."""
        in_reply_to = (email_data.get("in_reply_to") or "").strip()
        references = (email_data.get("references") or "").strip()
        if not in_reply_to and not references:
            self.logger.debug(
                "Email reply has no threading headers; skipping Message-ID check"
            )
            return None

        if not expected_message_id:
            self.logger.debug(
                "No stored challenge Message-ID; skipping threading check"
            )
            return None

        reply_ids = self._extract_message_ids(in_reply_to, references)
        expected = expected_message_id.strip()
        if expected in reply_ids:
            return True
        return False

    @staticmethod
    def _extract_message_ids(in_reply_to: str, references: str) -> set:
        """Collect Message-IDs from In-Reply-To and References header values."""
        ids: set = set()
        for header_value in (in_reply_to, references):
            if header_value:
                ids.update(_MSG_ID_PATTERN.findall(header_value))
        return ids

    def _filter_email(
        self, email_data: Dict[str, Any], rfc_token1: str, authorization_value: str
    ):
        filter_string = f"ACME: {rfc_token1}"
        self.logger.debug(
            "Challenge._validate_email_reply_challenge(): filter string: %s",
            filter_string,
        )

        if filter_string not in email_data.get("subject", ""):
            self.logger.debug(
                "Challenge._validate_email_reply_challenge(): email subject does not match filter: %s",
                email_data.get("subject", ""),
            )
            return None

        if not self._sender_matches_identifier(
            email_data.get("from", ""), authorization_value
        ):
            self.logger.debug(
                "Challenge._validate_email_reply_challenge(): email From does not match identifier: %s",
                email_data.get("from", ""),
            )
            return None

        self.logger.debug(
            "Challenge._validate_email_reply_challenge(): email subject matches filter: %s",
            email_data["subject"],
        )
        return email_data

    def _extract_email_keyauth(self, email_body: Optional[str]) -> Optional[str]:
        """Extract keyauthorization from email body between PEM-style delimiters."""
        self.logger.debug("EmailReplyChallengeValidator._extract_email_keyauth()")
        begin = "-----BEGIN ACME RESPONSE-----"
        end = "-----END ACME RESPONSE-----"
        email_keyauthorization = None
        if email_body:
            start = email_body.find(begin)
            if start >= 0:
                start += len(begin)
                stop = email_body.find(end, start)
                if stop >= 0:
                    email_keyauthorization = email_body[start:stop].strip() or None

        self.logger.debug(
            "Challenge._emailchallenge_keyauth_extract() ended with: %s",
            bool(email_keyauthorization),
        )
        return email_keyauthorization
