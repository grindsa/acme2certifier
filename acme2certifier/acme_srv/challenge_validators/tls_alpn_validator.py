"""
TLS-ALPN-01 Challenge Validator.

Implements validation logic for TLS-ALPN-01 challenges according to RFC 8737.
"""

import json
from typing import List, Optional, Tuple, Union

from .base import ChallengeValidator, ChallengeContext, ValidationResult

TLS_ALPN_VALIDATION_FAILED_LOG = (
    "tls-alpn-01 validation failed: challenge=%s host=%s reason=%s"
)
ACME_TLS_ALPN_PROTOCOL = "acme-tls/1"


class TlsAlpnChallengeValidator(ChallengeValidator):
    """Validator for TLS-ALPN-01 challenges."""

    def get_challenge_type(self) -> str:
        return "tls-alpn-01"

    def perform_validation(self, context: ChallengeContext) -> ValidationResult:
        """Perform TLS-ALPN-01 challenge validation."""
        self.logger.debug("TlsAlpnChallengeValidator.perform_validation()")
        try:
            from acme2certifier.acme_srv.helper import (
                fqdn_resolve,
                ip_validate,
                proxy_check,
                servercert_get,
                sha256_hash_hex,
            )
        except ImportError as e:
            return ValidationResult(
                success=False,
                invalid=True,
                error_message=f"Required dependencies not available: {e}",
                details={"import_error": str(e)},
            )

        sni, connect_host, early_failure = self._resolve_target(context, fqdn_resolve, ip_validate)
        if early_failure is not None:
            return early_failure

        # Compute expected SHA-256 digest of key authorization (RFC 8737)
        sha256_digest = sha256_hash_hex(
            self.logger, f"{context.token}.{context.jwk_thumbprint}"
        )

        # Check for proxy configuration
        proxy_server = None
        if context.proxy_servers:
            proxy_server = proxy_check(
                self.logger, context.authorization_value, context.proxy_servers
            )

        # Get server certificate (connect to pinned IP when DNS-resolved)
        cert, selected_alpn = servercert_get(
            self.logger,
            context.authorization_value,
            443,
            proxy_server,
            sni,
            connect_host=connect_host,
        )

        if not cert:
            detail = f"Unable to retrieve server certificate for {context.authorization_value}"
            self.logger.warning(
                TLS_ALPN_VALIDATION_FAILED_LOG,
                context.challenge_name,
                context.authorization_value,
                detail,
            )
            return ValidationResult(
                success=False,
                invalid=False,
                error_message=json.dumps(
                    {
                        "status": 400,
                        "type": "urn:ietf:params:acme:error:incorrectResponse",
                        "detail": detail,
                    }
                ),
            )

        if selected_alpn != ACME_TLS_ALPN_PROTOCOL:
            detail = (
                f"Negotiated ALPN {selected_alpn!r} does not match "
                f"{ACME_TLS_ALPN_PROTOCOL!r}"
            )
            self.logger.warning(
                TLS_ALPN_VALIDATION_FAILED_LOG,
                context.challenge_name,
                context.authorization_value,
                detail,
            )
            return ValidationResult(
                success=False,
                invalid=True,
                error_message=json.dumps(
                    {
                        "status": 403,
                        "type": "urn:ietf:params:acme:error:incorrectResponse",
                        "detail": detail,
                    }
                ),
                details={"selected_alpn": selected_alpn, "sni": sni},
            )

        # Validate certificate SAN + critical id-pe-acmeIdentifier
        success = self._validate_certificate_extensions(
            cert, sha256_digest, context.authorization_value
        )

        if not success:
            self.logger.warning(
                "tls-alpn-01 validation failed: challenge=%s host=%s reason=%s "
                "expected_digest=%s sni=%s alpn=%s",
                context.challenge_name,
                context.authorization_value,
                "Certificate extension validation failed",
                sha256_digest,
                sni,
                selected_alpn,
            )
        self.logger.debug(
            "TlsAlpnChallengeValidator.perform_validation() ended with: %s", success
        )
        return ValidationResult(
            success=success,
            invalid=not success,
            error_message=(
                None
                if success
                else json.dumps(
                    {
                        "status": 403,
                        "type": "urn:ietf:params:acme:error:incorrectResponse",
                        "detail": "Certificate extension validation failed",
                    }
                )
            ),
            details={
                "expected_digest": sha256_digest,
                "sni": sni,
                "selected_alpn": selected_alpn,
                "connect_host": connect_host,
            },
        )

    def _resolve_target(
        self,
        context: ChallengeContext,
        fqdn_resolve,
        ip_validate,
    ) -> Tuple[Optional[str], Optional[str], Optional[ValidationResult]]:
        """Return (sni, connect_host, early_failure)."""
        if context.authorization_type == "dns":
            resolved, invalid, error_msg = fqdn_resolve(
                self.logger, context.authorization_value, context.dns_servers
            )
            if invalid:
                detail = (
                    f"DNS resolution failed: {error_msg}"
                    if error_msg
                    else "DNS resolution failed"
                )
                self.logger.warning(
                    TLS_ALPN_VALIDATION_FAILED_LOG,
                    context.challenge_name,
                    context.authorization_value,
                    detail,
                )
                return (
                    None,
                    None,
                    ValidationResult(
                        success=False,
                        invalid=True,
                        error_message=json.dumps(
                            {
                                "status": 400,
                                "type": "urn:ietf:params:acme:error:dns",
                                "detail": detail,
                            }
                        ),
                    ),
                )
            connect_host = self._first_resolved_ip(resolved)
            return context.authorization_value, connect_host, None

        if context.authorization_type == "ip":
            sni, invalid = ip_validate(self.logger, context.authorization_value)
            if invalid:
                detail = f"Invalid IP address: {context.authorization_value}"
                self.logger.warning(
                    TLS_ALPN_VALIDATION_FAILED_LOG,
                    context.challenge_name,
                    context.authorization_value,
                    detail,
                )
                return (
                    None,
                    None,
                    ValidationResult(
                        success=False,
                        invalid=True,
                        error_message=json.dumps(
                            {
                                "status": 400,
                                "type": "urn:ietf:params:acme:error:malformed",
                                "detail": detail,
                            }
                        ),
                        details={"ip": context.authorization_value},
                    ),
                )
            # IP identifier: connect directly to the address
            return sni, context.authorization_value, None

        detail = f"Unsupported authorization type: {context.authorization_type}"
        self.logger.warning(
            TLS_ALPN_VALIDATION_FAILED_LOG,
            context.challenge_name,
            context.authorization_value,
            detail,
        )
        return (
            None,
            None,
            ValidationResult(
                success=False,
                invalid=True,
                error_message=json.dumps(
                    {
                        "status": 400,
                        "type": "urn:ietf:params:acme:error:unsupported",
                        "detail": detail,
                    }
                ),
                details={"type": context.authorization_type},
            ),
        )

    @staticmethod
    def _first_resolved_ip(
        resolved: Union[str, List[str], None],
    ) -> Optional[str]:
        """Pick the first resolved address for connection pinning."""
        if isinstance(resolved, list):
            return resolved[0] if resolved else None
        if isinstance(resolved, str) and resolved:
            return resolved
        return None

    def _validate_certificate_extensions(
        self, cert: str, sha256_digest_hex: str, fqdn: str
    ) -> bool:
        """Validate SAN and critical id-pe-acmeIdentifier for TLS-ALPN."""
        self.logger.debug(
            "TlsAlpnChallengeValidator._validate_certificate_extensions()"
        )
        try:
            from acme2certifier.acme_srv.helper import (
                cert_san_get,
                fqdn_in_san_check,
                cert_acme_tls_alpn_extension_ok,
            )
        except ImportError:
            self.logger.error(
                "Required helper functions not available for certificate validation"
            )
            return False

        san_list = cert_san_get(self.logger, cert, recode=False)
        fqdn_in_san = fqdn_in_san_check(self.logger, san_list, fqdn)

        if not fqdn_in_san:
            self.logger.warning(
                "tls-alpn-01 certificate SAN check failed: fqdn=%s san_list=%s",
                fqdn,
                san_list,
            )
            return False

        if not cert_acme_tls_alpn_extension_ok(
            self.logger, cert, sha256_digest_hex, recode=False
        ):
            return False

        self.logger.debug(
            "TlsAlpnChallengeValidator._validate_certificate_extensions(): "
            "TLS-ALPN validation successful"
        )
        return True
