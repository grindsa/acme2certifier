"""
HTTP-01 Challenge Validator.

Implements validation logic for HTTP-01 challenges according to RFC 8555.
"""
from typing import Optional
from .base import ChallengeValidator, ChallengeContext, ValidationResult


class HttpChallengeValidator(ChallengeValidator):
    """Validator for HTTP-01 challenges."""

    def get_challenge_type(self) -> str:
        return "http-01"

    def perform_validation(self, context: ChallengeContext) -> ValidationResult:
        """Perform HTTP-01 challenge validation."""
        # Import here to avoid circular imports and missing dependencies
        try:
            from acme_srv.helper import fqdn_resolve, ip_validate, proxy_check, url_get
        except ImportError as e:
            return ValidationResult(
                success=False,
                invalid=True,
                error_message=f"Required dependencies not available: {e}",
                details={"import_error": str(e)}
            )

        # Determine if we're dealing with DNS or IP
        if context.authorization_type == "dns":
            _, invalid = fqdn_resolve(
                self.logger, context.authorization_value, context.dns_servers
            )
            if invalid:
                return ValidationResult(
                    success=False,
                    invalid=True,
                    error_message="DNS resolution failed",
                    details={"fqdn": context.authorization_value}
                )
        elif context.authorization_type == "ip":
            _, invalid = ip_validate(self.logger, context.authorization_value)
            if invalid:
                return ValidationResult(
                    success=False,
                    invalid=True,
                    error_message="Invalid IP address",
                    details={"ip": context.authorization_value}
                )
        else:
            return ValidationResult(
                success=False,
                invalid=True,
                error_message="Unsupported authorization type",
                details={"type": context.authorization_type}
            )

        # Check for proxy configuration
        proxy_server = None
        if context.proxy_servers:
            proxy_server = proxy_check(
                self.logger, context.authorization_value, context.proxy_servers
            )

        # Perform HTTP request
        url = f"http://{context.authorization_value}/.well-known/acme-challenge/{context.token}"
        req = url_get(
            self.logger,
            url,
            dns_server_list=context.dns_servers,
            proxy_server=proxy_server,
            verify=False,
            timeout=context.timeout,
        )

        if not req:
            return ValidationResult(
                success=False,
                invalid=False,
                error_message="HTTP request failed",
                details={"url": url}
            )

        response_got = req.splitlines()[0]
        response_expected = f"{context.token}.{context.jwk_thumbprint}"

        success = response_got == response_expected
        return ValidationResult(
            success=success,
            invalid=not success,
            error_message=None if success else "Response mismatch",
            details={
                "expected": response_expected,
                "received": response_got,
                "url": url
            }
        )