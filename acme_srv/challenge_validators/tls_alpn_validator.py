"""
TLS-ALPN-01 Challenge Validator.

Implements validation logic for TLS-ALPN-01 challenges according to RFC 8737.
"""
from .base import ChallengeValidator, ChallengeContext, ValidationResult


class TlsAlpnChallengeValidator(ChallengeValidator):
    """Validator for TLS-ALPN-01 challenges."""

    def get_challenge_type(self) -> str:
        return "tls-alpn-01"

    def perform_validation(self, context: ChallengeContext) -> ValidationResult:
        """Perform TLS-ALPN-01 challenge validation."""
        try:
            from acme_srv.helper import (
                fqdn_resolve, ip_validate, proxy_check, servercert_get,
                sha256_hash_hex, b64_encode
            )
        except ImportError as e:
            return ValidationResult(
                success=False,
                invalid=True,
                error_message=f"Required dependencies not available: {e}",
                details={"import_error": str(e)}
            )

        # Determine SNI value
        if context.authorization_type == "dns":
            _, invalid = fqdn_resolve(
                self.logger, context.authorization_value, context.dns_servers
            )
            if invalid:
                return ValidationResult(
                    success=False,
                    invalid=True,
                    error_message="DNS resolution failed for TLS-ALPN validation"
                )
            sni = context.authorization_value
        elif context.authorization_type == "ip":
            sni, invalid = ip_validate(self.logger, context.authorization_value)
            if invalid:
                return ValidationResult(
                    success=False,
                    invalid=True,
                    error_message="Invalid IP address for TLS-ALPN validation"
                )
        else:
            return ValidationResult(
                success=False,
                invalid=True,
                error_message="Unsupported authorization type for TLS-ALPN"
            )

        # Compute expected extension value
        sha256_digest = sha256_hash_hex(
            self.logger, f"{context.token}.{context.jwk_thumbprint}"
        )
        extension_value = b64_encode(
            self.logger, bytearray.fromhex(f"0420{sha256_digest}")
        )

        # Check for proxy configuration
        proxy_server = None
        if context.proxy_servers:
            proxy_server = proxy_check(
                self.logger, context.authorization_value, context.proxy_servers
            )

        # Get server certificate
        cert = servercert_get(
            self.logger, context.authorization_value, 443, proxy_server, sni
        )

        if not cert:
            return ValidationResult(
                success=False,
                invalid=False,
                error_message="Unable to retrieve server certificate"
            )

        # Validate certificate extensions
        success = self._validate_certificate_extensions(
            cert, extension_value, context.authorization_value
        )

        return ValidationResult(
            success=success,
            invalid=not success,
            error_message=None if success else "Certificate extension validation failed",
            details={
                "expected_extension": extension_value,
                "sni": sni
            }
        )

    def _validate_certificate_extensions(self, cert: str, extension_value: str, fqdn: str) -> bool:
        """Validate certificate extensions for TLS-ALPN challenge."""
        try:
            from acme_srv.helper import cert_san_get, fqdn_in_san_check, cert_extensions_get
        except ImportError:
            self.logger.error("Required helper functions not available for certificate validation")
            return False

        san_list = cert_san_get(self.logger, cert, recode=False)
        fqdn_in_san = fqdn_in_san_check(self.logger, san_list, fqdn)

        if not fqdn_in_san:
            self.logger.debug("FQDN check against SAN failed")
            return False

        extension_list = cert_extensions_get(self.logger, cert, recode=False)
        if extension_value in extension_list:
            self.logger.debug("TLS-ALPN validation successful")
            return True
        else:
            self.logger.debug("TLS-ALPN validation not successful")
            return False