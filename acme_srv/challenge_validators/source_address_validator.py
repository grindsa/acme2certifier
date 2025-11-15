"""
Source Address Validator.

Implements source address validation for challenges, including forward and reverse
address checking capabilities.
"""
from typing import Optional, Tuple, Dict, Any, List

from acme_srv.helpers.network import ptr_resolve
from .base import ChallengeValidator, ChallengeContext, ValidationResult


class SourceAddressValidator(ChallengeValidator):
    """Validator for source address checks across all challenge types."""

    def __init__(
        self, logger, forward_check: bool = False, reverse_check: bool = False
    ):
        super().__init__(logger)
        self.forward_check = forward_check
        self.reverse_check = reverse_check

    def get_challenge_type(self) -> str:
        return "source-address"

    def perform_validation(self, context: ChallengeContext) -> ValidationResult:
        """Perform source address validation."""
        self.logger.debug("SourceAddressValidator.perform_validation() called")
        # Import here to avoid circular imports
        try:
            from acme_srv.helper import fqdn_resolve, ip_validate, ptr_resolve
        except ImportError as e:
            return ValidationResult(
                success=False,
                invalid=True,
                error_message=f"Required dependencies not available: {e}",
                details={"import_error": str(e)},
            )

        self.logger.debug(
            "SourceAddressValidator.perform_validation(): source address validation for %s (forward: %s, reverse: %s)",
            context.authorization_value,
            self.forward_check,
            self.reverse_check,
        )

        # Update forward and reverse check settings from context options if available
        if context.options:
            self.forward_check = context.options.get(
                "forward_address_check", self.forward_check
            )
            self.reverse_check = context.options.get(
                "reverse_address_check", self.reverse_check
            )

        # Get source address from context
        source_address = getattr(context, "source_address", None)
        if not source_address:
            return ValidationResult(
                success=True,
                invalid=False,
                details={"message": "No source address provided, skipping validation"},
            )

        validation_details = {
            "source_address": source_address,
            "authorization_value": context.authorization_value,
            "forward_check": self.forward_check,
            "reverse_check": self.reverse_check,
        }

        # Perform forward address check
        if self.forward_check:
            self.logger.debug(
                "SourceAddressValidator.perform_validation(): Performing forward address check"
            )
            forward_result = self._perform_forward_check(
                context.authorization_value, source_address, context.dns_servers
            )
            validation_details.update(forward_result)

            if not forward_result.get("forward_check_passed", False):
                self.logger.debug(
                    "SourceAddressValidator.perform_validation(): Forward address check failed"
                )
                return ValidationResult(
                    success=False,
                    invalid=True,
                    error_message="Forward address check failed",
                    details=validation_details,
                )

        # Perform reverse address check
        if self.reverse_check:
            self.logger.debug(
                "SourceAddressValidator.perform_validation(): Performing reverse address check"
            )
            reverse_result = self._perform_reverse_check(
                context.authorization_value, source_address, context.dns_servers
            )
            validation_details.update(reverse_result)

            if not reverse_result.get("reverse_check_passed", False):
                self.logger.debug(
                    "SourceAddressValidator.perform_validation(): Reverse address check failed"
                )
                return ValidationResult(
                    success=False,
                    invalid=True,
                    error_message="Reverse address check failed",
                    details=validation_details,
                )

        return ValidationResult(success=True, invalid=False, details=validation_details)

    def _perform_forward_check(
        self, domain: str, source_address: str, dns_servers: List[str]
    ) -> Dict[str, Any]:
        """Perform forward DNS lookup to verify source address."""
        self.logger.debug(
            "SourceAddressValidator._perform_forward_check(): Performing forward address check: %s -> %s",
            domain,
            source_address,
        )

        try:
            from acme_srv.helper import fqdn_resolve

            # Resolve the domain to IP addresses
            resolved_ips, _invalid, _error = fqdn_resolve(
                logger=self.logger, host=domain, dnssrv=dns_servers, catch_all=True
            )

            # Check if source address matches any resolved IP
            forward_check_passed = source_address in resolved_ips
            self.logger.debug(
                "SourceAddressValidator._perform_forward_check(): Forward check %s for %s",
                "passed" if forward_check_passed else "failed",
                domain,
            )
            return {
                "forward_check_passed": forward_check_passed,
                "resolved_ips": resolved_ips,
                "domain": domain,
            }

        except Exception as e:
            self.logger.error("Forward address check failed: %s", str(e))
            return {"forward_check_passed": False, "error": str(e), "domain": domain}

    def _perform_reverse_check(
        self, domain: str, source_address: str, dns_servers: List[str]
    ) -> Dict[str, Any]:
        """Perform reverse DNS lookup to verify domain ownership."""
        self.logger.debug(
            "SourceAddressValidator._perform_reverse_check(): Performing reverse address check: %s -> %s",
            source_address,
            domain,
        )
        try:
            from acme_srv.helper import ptr_resolve

            # Perform reverse lookup on source address
            reverse_domains = ptr_resolve(
                self.logger, source_address, dnssrv=dns_servers
            )

            # Check if any reverse domain matches or is a subdomain of the requested domain
            reverse_check_passed = any(
                self._domain_matches(domain, reverse_domain)
                for reverse_domain in reverse_domains
            )
            self.logger.debug(
                "SourceAddressValidator._perform_reverse_check(): Reverse check %s for %s",
                "passed" if reverse_check_passed else "failed",
                domain,
            )
            return {
                "reverse_check_passed": reverse_check_passed,
                "reverse_domains": reverse_domains,
                "source_address": source_address,
            }

        except Exception as e:
            self.logger.error("Reverse address check failed: %s", str(e))
            return {
                "reverse_check_passed": False,
                "error": str(e),
                "source_address": source_address,
            }

    def _domain_matches(self, requested_domain: str, resolved_domain: str) -> bool:
        """Check if domains match (exact or subdomain)."""
        if requested_domain:
            requested_domain = requested_domain.lower().rstrip(".")
        if resolved_domain:
            resolved_domain = resolved_domain.lower().rstrip(".")

        # Exact match
        if requested_domain == resolved_domain:
            return True

        # Subdomain match (resolved domain ends with requested domain)
        return resolved_domain.endswith("." + requested_domain)
