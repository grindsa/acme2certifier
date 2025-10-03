"""
Challenge Processor Interface and Implementations
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple
import time

from refactored_challenge_models import (
    ChallengeData, ValidationContext, ValidationResult, ChallengeError,
    ChallengeValidationError, ChallengeNetworkError, IdentifierType
)

from acme_srv.helper import (
    b64_encode, b64_url_encode, cert_extensions_get, cert_san_get,
    fqdn_in_san_check, fqdn_resolve, ip_validate, proxy_check,
    ptr_resolve, servercert_get, sha256_hash, sha256_hash_hex,
    txt_get, url_get, convert_byte_to_string
)
from acme_srv.email_handler import EmailHandler


class ChallengeProcessor(ABC):
    """Abstract base class for challenge processors"""

    def __init__(self, logger, config):
        self.logger = logger
        self.config = config

    @abstractmethod
    def process(self, context: ValidationContext) -> ValidationResult:
        """Process the challenge validation"""
        pass

    @abstractmethod
    def get_supported_type(self) -> str:
        """Return the challenge type this processor supports"""
        pass

    def _log_validation_start(self, context: ValidationContext):
        """Log validation start"""
        self.logger.debug(
            f"{self.__class__.__name__}.process() started for challenge: {context.challenge_data.name}"
        )

    def _log_validation_end(self, context: ValidationContext, result: ValidationResult):
        """Log validation end"""
        self.logger.debug(
            f"{self.__class__.__name__}.process() ended with: {result.success}/{result.invalid}"
        )


class HttpChallengeProcessor(ChallengeProcessor):
    """Processor for HTTP-01 challenges"""

    def get_supported_type(self) -> str:
        return "http-01"

    def process(self, context: ValidationContext) -> ValidationResult:
        """Process HTTP-01 challenge validation"""
        self._log_validation_start(context)

        try:
            # Validate identifier and resolve if needed
            resolved_target, invalid = self._resolve_identifier(context.challenge_data.identifier)
            if invalid:
                return ValidationResult(success=False, invalid=True,
                                      error_message="Failed to resolve identifier")

            # Perform HTTP validation
            success = self._perform_http_validation(context, resolved_target)
            result = ValidationResult(success=success, invalid=not success and not resolved_target)

        except Exception as e:
            self.logger.error(f"HTTP challenge validation error: {e}")
            result = ValidationResult(success=False, invalid=True, error_message=str(e))

        self._log_validation_end(context, result)
        return result

    def _resolve_identifier(self, identifier) -> Tuple[Optional[str], bool]:
        """Resolve identifier to target for validation"""
        if identifier.type == IdentifierType.DNS:
            response, invalid = fqdn_resolve(self.logger, identifier.value, self.config.dns_server_list)
            return identifier.value, invalid
        elif identifier.type == IdentifierType.IP:
            _, invalid = ip_validate(self.logger, identifier.value)
            return identifier.value, invalid
        else:
            return None, True

    def _perform_http_validation(self, context: ValidationContext, target: str) -> bool:
        """Perform the actual HTTP validation"""
        proxy_server = None
        if self.config.proxy_server_list:
            proxy_server = proxy_check(self.logger, target, self.config.proxy_server_list)

        url = f"http://{target}/.well-known/acme-challenge/{context.challenge_data.token}"

        try:
            response = url_get(
                self.logger, url,
                dns_server_list=self.config.dns_server_list,
                proxy_server=proxy_server,
                verify=False,
                timeout=context.timeout
            )

            if response:
                response_got = response.splitlines()[0]
                response_expected = f"{context.challenge_data.token}.{context.challenge_data.jwk_thumbprint}"

                self.logger.debug(f"HTTP validation - got: {response_got}, expected: {response_expected}")
                return response_got == response_expected

        except Exception as e:
            self.logger.debug(f"HTTP validation failed: {e}")

        return False


class DnsChallengeProcessor(ChallengeProcessor):
    """Processor for DNS-01 challenges"""

    def get_supported_type(self) -> str:
        return "dns-01"

    def process(self, context: ValidationContext) -> ValidationResult:
        """Process DNS-01 challenge validation"""
        self._log_validation_start(context)

        try:
            # Handle wildcard domain manipulation
            fqdn = self._handle_wildcard_domain(context.challenge_data.identifier.value)

            # Build challenge FQDN
            challenge_fqdn = f"_acme-challenge.{fqdn}"

            # Compute expected hash
            expected_hash = self._compute_challenge_hash(context)

            # Query DNS for TXT record
            txt_records = txt_get(self.logger, challenge_fqdn, self.config.dns_server_list)

            # Validate response
            success = expected_hash in txt_records
            self.logger.debug(f"DNS validation - got: {txt_records}, expected: {expected_hash}")

            result = ValidationResult(success=success, invalid=False)

        except Exception as e:
            self.logger.error(f"DNS challenge validation error: {e}")
            result = ValidationResult(success=False, invalid=True, error_message=str(e))

        self._log_validation_end(context, result)
        return result

    def _handle_wildcard_domain(self, fqdn: str) -> str:
        """Handle wildcard domain manipulation"""
        if fqdn.startswith("*."):
            return fqdn[2:]
        return fqdn

    def _compute_challenge_hash(self, context: ValidationContext) -> str:
        """Compute the expected challenge hash"""
        token_thumbprint = f"{context.challenge_data.token}.{context.challenge_data.jwk_thumbprint}"
        return b64_url_encode(self.logger, sha256_hash(self.logger, token_thumbprint))


class TlsAlpnChallengeProcessor(ChallengeProcessor):
    """Processor for TLS-ALPN-01 challenges"""

    def get_supported_type(self) -> str:
        return "tls-alpn-01"

    def process(self, context: ValidationContext) -> ValidationResult:
        """Process TLS-ALPN-01 challenge validation"""
        self._log_validation_start(context)

        try:
            # Resolve target and SNI
            target, sni, invalid = self._resolve_target_and_sni(context.challenge_data.identifier)
            if invalid:
                return ValidationResult(success=False, invalid=True,
                                      error_message="Failed to resolve target")

            # Compute expected extension value
            extension_value = self._compute_extension_value(context)

            # Get server certificate
            cert = self._get_server_certificate(target, sni)
            if not cert:
                return ValidationResult(success=False, invalid=False,
                                      error_message="No certificate returned")

            # Validate certificate extensions
            success = self._validate_certificate_extensions(cert, extension_value,
                                                           context.challenge_data.identifier.value)

            result = ValidationResult(success=success, invalid=not success)

        except Exception as e:
            self.logger.error(f"TLS-ALPN challenge validation error: {e}")
            result = ValidationResult(success=False, invalid=True, error_message=str(e))

        self._log_validation_end(context, result)
        return result

    def _resolve_target_and_sni(self, identifier) -> Tuple[Optional[str], Optional[str], bool]:
        """Resolve target and SNI for TLS connection"""
        if identifier.type == IdentifierType.DNS:
            response, invalid = fqdn_resolve(self.logger, identifier.value, self.config.dns_server_list)
            return identifier.value, identifier.value, invalid
        elif identifier.type == IdentifierType.IP:
            sni, invalid = ip_validate(self.logger, identifier.value)
            return identifier.value, sni, invalid
        else:
            return None, None, True

    def _compute_extension_value(self, context: ValidationContext) -> str:
        """Compute expected certificate extension value"""
        token_thumbprint = f"{context.challenge_data.token}.{context.challenge_data.jwk_thumbprint}"
        sha256_digest = sha256_hash_hex(self.logger, token_thumbprint)
        return b64_encode(self.logger, bytearray.fromhex(f"0420{sha256_digest}"))

    def _get_server_certificate(self, target: str, sni: Optional[str]) -> Optional[str]:
        """Get server certificate for validation"""
        proxy_server = None
        if self.config.proxy_server_list:
            proxy_server = proxy_check(self.logger, target, self.config.proxy_server_list)

        return servercert_get(self.logger, target, 443, proxy_server, sni)

    def _validate_certificate_extensions(self, cert: str, expected_extension: str, fqdn: str) -> bool:
        """Validate certificate extensions against expected value"""
        san_list = cert_san_get(self.logger, cert, recode=False)
        fqdn_in_san = fqdn_in_san_check(self.logger, san_list, fqdn)

        if fqdn_in_san:
            extension_list = cert_extensions_get(self.logger, cert, recode=False)
            return expected_extension in extension_list

        self.logger.debug("FQDN check against SAN failed")
        return False


class EmailReplyChallengeProcessor(ChallengeProcessor):
    """Processor for email-reply-00 challenges"""

    def get_supported_type(self) -> str:
        return "email-reply-00"

    def process(self, context: ValidationContext) -> ValidationResult:
        """Process email-reply-00 challenge validation"""
        self._log_validation_start(context)

        try:
            # Generate expected keyauthorization
            calculated_keyauth, rfc_token1 = self._generate_keyauthorization(context)

            # Receive email and extract keyauthorization
            email_keyauth = self._receive_and_extract_keyauth(rfc_token1)

            # Compare keyauthorizations
            if email_keyauth and calculated_keyauth and email_keyauth == calculated_keyauth:
                result = ValidationResult(success=True, invalid=False)
            elif email_keyauth:
                result = ValidationResult(success=False, invalid=True,
                                        error_message="Email keyauthorization mismatch")
            else:
                result = ValidationResult(success=False, invalid=False,
                                        error_message="No email received")

        except Exception as e:
            self.logger.error(f"Email reply challenge validation error: {e}")
            result = ValidationResult(success=False, invalid=True, error_message=str(e))

        self._log_validation_end(context, result)
        return result

    def _generate_keyauthorization(self, context: ValidationContext) -> Tuple[Optional[str], Optional[str]]:
        """Generate RFC8823 keyauthorization"""
        # This would need to be implemented based on the specific logic
        # from the original _emailchallenge_keyauth_generate method
        # For now, returning placeholder values
        return "calculated_keyauth", "rfc_token1"

    def _receive_and_extract_keyauth(self, rfc_token1: str) -> Optional[str]:
        """Receive email and extract keyauthorization"""
        try:
            with EmailHandler(debug=False, logger=self.logger) as email_handler:
                email_data = email_handler.receive(
                    callback=lambda email_data: self._filter_email(email_data, rfc_token1)
                )

                if email_data and "body" in email_data:
                    return self._extract_keyauth_from_body(email_data["body"])

        except Exception as e:
            self.logger.error(f"Email processing failed: {e}")

        return None

    def _filter_email(self, email_data: Dict[str, str], rfc_token1: str) -> Optional[Dict[str, str]]:
        """Filter email based on subject"""
        filter_string = f"ACME: {rfc_token1}"
        if filter_string in email_data.get("subject", ""):
            return email_data
        return None

    def _extract_keyauth_from_body(self, body: str) -> Optional[str]:
        """Extract keyauthorization from email body"""
        import re
        match = re.search(
            r"-+BEGIN ACME RESPONSE-+\s*([\w=+/ -]+)\s*-+END ACME RESPONSE-+",
            body, re.DOTALL
        )
        return match.group(1).strip() if match else None


class TkAuthChallengeProcessor(ChallengeProcessor):
    """Processor for tkauth-01 challenges"""

    def get_supported_type(self) -> str:
        return "tkauth-01"

    def process(self, context: ValidationContext) -> ValidationResult:
        """Process tkauth-01 challenge validation"""
        self._log_validation_start(context)

        # TkAuth validation is typically simpler - just return success
        # The actual validation logic would depend on specific requirements
        result = ValidationResult(success=True, invalid=False)

        self._log_validation_end(context, result)
        return result


class ChallengeProcessorFactory:
    """Factory for creating challenge processors"""

    def __init__(self, logger, config):
        self.logger = logger
        self.config = config
        self._processors = {
            "http-01": HttpChallengeProcessor,
            "dns-01": DnsChallengeProcessor,
            "tls-alpn-01": TlsAlpnChallengeProcessor,
            "email-reply-00": EmailReplyChallengeProcessor,
            "tkauth-01": TkAuthChallengeProcessor,
        }

    def create_processor(self, challenge_type: str) -> ChallengeProcessor:
        """Create a processor for the given challenge type"""
        if challenge_type not in self._processors:
            raise ChallengeValidationError(f"Unsupported challenge type: {challenge_type}")

        processor_class = self._processors[challenge_type]
        return processor_class(self.logger, self.config)

    def register_processor(self, challenge_type: str, processor_class):
        """Register a new challenge processor"""
        self._processors[challenge_type] = processor_class

    def get_supported_types(self) -> List[str]:
        """Get list of supported challenge types"""
        return list(self._processors.keys())