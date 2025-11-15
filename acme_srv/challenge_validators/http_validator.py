"""
HTTP-01 Challenge Validator.

Implements validation logic for HTTP-01 challenges according to RFC 8555.
"""
from typing import Optional
import json
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
                details={"import_error": str(e)},
            )

        # Determine if we're dealing with DNS or IP
        if context.authorization_type == "dns":
            _, invalid, error_msg = fqdn_resolve(
                self.logger, context.authorization_value, context.dns_servers
            )
            if invalid:
                return ValidationResult(
                    success=False,
                    invalid=True,
                    error_message=json.dumps(
                        {
                            "status": 400,
                            "type": "urn:ietf:params:acme:error:dns",
                            "detail": f"DNS resolution failed: {error_msg}"
                            if error_msg
                            else "DNS resolution failed",
                        }
                    ),
                    details={"fqdn": context.authorization_value},
                )
        elif context.authorization_type == "ip":
            _, invalid = ip_validate(self.logger, context.authorization_value)
            if invalid:
                return ValidationResult(
                    success=False,
                    invalid=True,
                    error_message=json.dumps(
                        {
                            "status": 400,
                            "type": "urn:ietf:params:acme:error:malformed",
                            "detail": f"Invalid IP address: {context.authorization_value}",
                        }
                    ),
                    details={"ip": context.authorization_value},
                )
        else:
            return ValidationResult(
                success=False,
                invalid=True,
                error_message=json.dumps(
                    {
                        "status": 400,
                        "type": "urn:ietf:params:acme:error:unsupported",
                        "detail": f"Unsupported authorization type: {context.authorization_type}",
                    }
                ),
                details={"type": context.authorization_type},
            )

        # Check for proxy configuration
        proxy_server = None
        if context.proxy_servers:
            proxy_server = proxy_check(
                self.logger, context.authorization_value, context.proxy_servers
            )

        # Perform HTTP request
        url = f"http://{context.authorization_value}/.well-known/acme-challenge/{context.token}"
        req, status_code, error_msg = url_get(
            self.logger,
            url,
            dns_server_list=context.dns_servers,
            proxy_server=proxy_server,
            verify=False,
            timeout=context.timeout,
        )
        if not req or status_code != 200:
            return ValidationResult(
                success=False,
                invalid=False,
                error_message=json.dumps(
                    {
                        "status": 403,
                        "type": "urn:ietf:params:acme:error:connection",
                        "detail": f"HTTP request failed: {status_code} {error_msg}",
                    }
                ),
                details={"url": url},
            )

        response_got = req.splitlines()[0]
        response_expected = f"{context.token}.{context.jwk_thumbprint}"

        success = response_got == response_expected
        return ValidationResult(
            success=success,
            invalid=not success,
            error_message=None if success else json.dumps({"status": 403, "type": "urn:ietf:params:acme:error:incorrectResponse", "detail": "Keyauthorization mismatch"}),
            details={
                "expected": response_expected,
                "received": response_got,
                "url": url,
            },
        )
