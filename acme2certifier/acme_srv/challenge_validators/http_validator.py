"""
HTTP-01 Challenge Validator.

Implements validation logic for HTTP-01 challenges according to RFC 8555.
"""

import json
from typing import List, Optional, Tuple
from .base import ChallengeValidator, ChallengeContext, ValidationResult


class HttpChallengeValidator(ChallengeValidator):
    """Validator for HTTP-01 challenges."""

    def get_challenge_type(self) -> str:
        return "http-01"

    def perform_validation(self, context: ChallengeContext) -> ValidationResult:
        """Perform HTTP-01 challenge validation."""
        # Import here to avoid circular imports and missing dependencies
        try:
            from acme2certifier.acme_srv.helper import (
                fqdn_resolve,
                ip_validate,
                proxy_check,
                url_get,
                normalize_resolved_ips,
                filter_http01_target_ips,
                url_get_dns_pinned,
            )
        except ImportError as e:
            return ValidationResult(
                success=False,
                invalid=True,
                error_message=f"Required dependencies not available: {e}",
                details={"import_error": str(e)},
            )

        block_private = bool(
            (context.options or {}).get("http01_block_private_ips", False)
        )
        challenge_path = f"/.well-known/acme-challenge/{context.token}"
        logical_url = (
            f"http://{context.authorization_value}{challenge_path}"
        )

        target_ips, resolve_error = self._resolve_http01_targets(
            context,
            fqdn_resolve,
            ip_validate,
            normalize_resolved_ips,
        )
        if resolve_error is not None:
            return resolve_error

        allowed_ips, filter_error = filter_http01_target_ips(
            self.logger, target_ips, block_private=block_private
        )
        if filter_error or not allowed_ips:
            return ValidationResult(
                success=False,
                invalid=True,
                error_message=json.dumps(
                    {
                        "status": 400,
                        "type": "urn:ietf:params:acme:error:rejectedIdentifier",
                        "detail": filter_error
                        or "No allowed address for HTTP-01 validation",
                    }
                ),
                details={
                    "identifier": context.authorization_value,
                    "resolved_ips": target_ips,
                    "http01_block_private_ips": block_private,
                },
            )

        proxy_server = None
        if context.proxy_servers:
            proxy_server = proxy_check(
                self.logger, context.authorization_value, context.proxy_servers
            )

        if proxy_server:
            # Proxy must resolve the hostname; IP policy still applied above.
            # DNS pinning cannot bind the TCP peer when traffic goes via proxy.
            self.logger.debug(
                "HttpChallengeValidator: proxy in use; skipping DNS-pinned connect"
            )
            req, status_code, error_msg = url_get(
                self.logger,
                logical_url,
                dns_server_list=context.dns_servers,
                proxy_server=proxy_server,
                verify=False,
                timeout=context.timeout,
            )
        else:
            req, status_code, error_msg = url_get_dns_pinned(
                self.logger,
                host=context.authorization_value,
                path=challenge_path,
                pinned_ips=allowed_ips,
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
                details={
                    "url": logical_url,
                    "pinned_ips": allowed_ips,
                },
            )

        response_got = req.splitlines()[0]
        response_expected = f"{context.token}.{context.jwk_thumbprint}"

        success = response_got == response_expected
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
                        "detail": "Keyauthorization mismatch",
                    }
                )
            ),
            details={
                "expected": response_expected,
                "received": response_got,
                "url": logical_url,
                "pinned_ips": allowed_ips,
            },
        )

    def _resolve_http01_targets(
        self,
        context: ChallengeContext,
        fqdn_resolve,
        ip_validate,
        normalize_resolved_ips,
    ) -> Tuple[List[str], Optional[ValidationResult]]:
        """Resolve authorization identifier to candidate IP addresses."""
        if context.authorization_type == "dns":
            resolved, invalid, error_msg = fqdn_resolve(
                self.logger,
                context.authorization_value,
                context.dns_servers,
                catch_all=True,
            )
            if invalid:
                return [], ValidationResult(
                    success=False,
                    invalid=True,
                    error_message=json.dumps(
                        {
                            "status": 400,
                            "type": "urn:ietf:params:acme:error:dns",
                            "detail": (
                                f"DNS resolution failed: {error_msg}"
                                if error_msg
                                else "DNS resolution failed"
                            ),
                        }
                    ),
                    details={"fqdn": context.authorization_value},
                )
            return normalize_resolved_ips(resolved), None

        if context.authorization_type == "ip":
            _, invalid = ip_validate(self.logger, context.authorization_value)
            if invalid:
                return [], ValidationResult(
                    success=False,
                    invalid=True,
                    error_message=json.dumps(
                        {
                            "status": 400,
                            "type": "urn:ietf:params:acme:error:malformed",
                            "detail": (
                                f"Invalid IP address: {context.authorization_value}"
                            ),
                        }
                    ),
                    details={"ip": context.authorization_value},
                )
            return [context.authorization_value], None

        return [], ValidationResult(
            success=False,
            invalid=True,
            error_message=json.dumps(
                {
                    "status": 400,
                    "type": "urn:ietf:params:acme:error:unsupported",
                    "detail": (
                        f"Unsupported authorization type: {context.authorization_type}"
                    ),
                }
            ),
            details={"type": context.authorization_type},
        )
