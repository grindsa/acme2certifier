"""
DNS-01 Challenge Validator.

Implements validation logic for DNS-01 challenges according to RFC 8555.
"""
from .base import ChallengeValidator, ChallengeContext, ValidationResult


class DnsChallengeValidator(ChallengeValidator):
    """Validator for DNS-01 challenges."""

    def get_challenge_type(self) -> str:
        return "dns-01"

    def perform_validation(self, context: ChallengeContext) -> ValidationResult:
        """Perform DNS-01 challenge validation."""
        try:
            from acme_srv.helper import b64_url_encode, sha256_hash, txt_get
        except ImportError as e:
            return ValidationResult(
                success=False,
                invalid=True,
                error_message=f"Required dependencies not available: {e}",
                details={"import_error": str(e)}
            )

        # Handle wildcard domain
        fqdn = self._handle_wildcard_domain(context.authorization_value)

        # Construct the DNS record name
        dns_record_name = f"_acme-challenge.{fqdn}"

        # Compute expected hash
        expected_hash = b64_url_encode(
            self.logger,
            sha256_hash(self.logger, f"{context.token}.{context.jwk_thumbprint}")
        )

        # Query DNS
        txt_records = txt_get(self.logger, dns_record_name, context.dns_servers)

        success = expected_hash in txt_records
        return ValidationResult(
            success=success,
            invalid=not success,
            error_message=None if success else "DNS record not found or incorrect",
            details={
                "dns_record": dns_record_name,
                "expected_hash": expected_hash,
                "found_records": txt_records
            }
        )

    def _handle_wildcard_domain(self, fqdn: str) -> str:
        """Handle wildcard domain by removing the '*.' prefix."""
        if fqdn.startswith("*."):
            return fqdn[2:]
        return fqdn