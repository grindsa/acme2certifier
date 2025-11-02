"""
Enhanced error handling system for challenge processing.

This module provides a comprehensive error handling framework with custom exceptions,
error categorization, and standardized error responses for challenge operations.
"""
from typing import Dict, Optional, Any, List
from dataclasses import dataclass
from enum import Enum
import traceback
import logging


class ErrorCategory(Enum):
    """Categories of errors that can occur during challenge processing."""

    VALIDATION_ERROR = "validation_error"
    NETWORK_ERROR = "network_error"
    DATABASE_ERROR = "database_error"
    CONFIGURATION_ERROR = "configuration_error"
    AUTHENTICATION_ERROR = "authentication_error"
    MALFORMED_REQUEST = "malformed_request"
    TIMEOUT_ERROR = "timeout_error"
    UNKNOWN_ERROR = "unknown_error"


class ErrorSeverity(Enum):
    """Severity levels for errors."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ErrorDetail:
    """Detailed error information."""

    category: ErrorCategory
    severity: ErrorSeverity
    message: str
    details: Optional[Dict[str, Any]] = None
    suggestion: Optional[str] = None
    error_code: Optional[str] = None


class ChallengeError(Exception):
    """Base exception for all challenge-related errors."""

    def __init__(
        self,
        message: str,
        category: ErrorCategory = ErrorCategory.UNKNOWN_ERROR,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        details: Optional[Dict[str, Any]] = None,
        suggestion: Optional[str] = None,
        error_code: Optional[str] = None,
    ):
        super().__init__(message)
        self.error_detail = ErrorDetail(
            category=category,
            severity=severity,
            message=message,
            details=details or {},
            suggestion=suggestion,
            error_code=error_code,
        )


class ValidationError(ChallengeError):
    """Raised when challenge validation fails."""

    def __init__(self, message: str, **kwargs):
        super().__init__(message, category=ErrorCategory.VALIDATION_ERROR, **kwargs)


class NetworkError(ChallengeError):
    """Raised when network operations fail."""

    def __init__(self, message: str, **kwargs):
        super().__init__(message, category=ErrorCategory.NETWORK_ERROR, **kwargs)


class DatabaseError(ChallengeError):
    """Raised when database operations fail."""

    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.DATABASE_ERROR,
            severity=ErrorSeverity.HIGH,
            **kwargs,
        )


class ConfigurationError(ChallengeError):
    """Raised when configuration is invalid."""

    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.CONFIGURATION_ERROR,
            severity=ErrorSeverity.HIGH,
            **kwargs,
        )


class AuthenticationError(ChallengeError):
    """Raised when authentication fails."""

    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.AUTHENTICATION_ERROR,
            severity=ErrorSeverity.HIGH,
            **kwargs,
        )


class MalformedRequestError(ChallengeError):
    """Raised when request is malformed."""

    def __init__(self, message: str, **kwargs):
        super().__init__(message, category=ErrorCategory.MALFORMED_REQUEST, **kwargs)


class TimeoutError(ChallengeError):
    """Raised when operations timeout."""

    def __init__(self, message: str, **kwargs):
        super().__init__(message, category=ErrorCategory.TIMEOUT_ERROR, **kwargs)


class UnsupportedChallengeTypeError(ValidationError):
    """Raised when an unsupported challenge type is encountered."""

    def __init__(self, challenge_type: str, supported_types: List[str]):
        message = f"Unsupported challenge type: {challenge_type}"
        super().__init__(
            message,
            details={
                "challenge_type": challenge_type,
                "supported_types": supported_types,
            },
            suggestion=f"Use one of the supported types: {', '.join(supported_types)}",
            error_code="UNSUPPORTED_CHALLENGE_TYPE",
        )


class DNSResolutionError(NetworkError):
    """Raised when DNS resolution fails."""

    def __init__(self, domain: str, dns_servers: Optional[List[str]] = None):
        message = f"DNS resolution failed for domain: {domain}"
        super().__init__(
            message,
            details={"domain": domain, "dns_servers": dns_servers},
            suggestion="Check domain validity and DNS server configuration",
            error_code="DNS_RESOLUTION_FAILED",
        )


class HTTPChallengeError(ValidationError):
    """Raised when HTTP challenge validation fails."""

    def __init__(self, url: str, expected: str, received: str):
        message = f"HTTP challenge validation failed for {url}"
        super().__init__(
            message,
            details={
                "url": url,
                "expected_response": expected,
                "received_response": received,
            },
            suggestion="Ensure the challenge file is accessible and contains the correct token",
            error_code="HTTP_CHALLENGE_FAILED",
        )


class DNSChallengeError(ValidationError):
    """Raised when DNS challenge validation fails."""

    def __init__(self, dns_record: str, expected_hash: str, found_records: List[str]):
        message = f"DNS challenge validation failed for {dns_record}"
        super().__init__(
            message,
            details={
                "dns_record": dns_record,
                "expected_hash": expected_hash,
                "found_records": found_records,
            },
            suggestion="Ensure the DNS TXT record is properly configured",
            error_code="DNS_CHALLENGE_FAILED",
        )


class TLSALPNChallengeError(ValidationError):
    """Raised when TLS-ALPN challenge validation fails."""

    def __init__(self, domain: str, expected_extension: str):
        message = f"TLS-ALPN challenge validation failed for {domain}"
        super().__init__(
            message,
            details={"domain": domain, "expected_extension": expected_extension},
            suggestion="Ensure the TLS certificate contains the required extension",
            error_code="TLS_ALPN_CHALLENGE_FAILED",
        )


class ErrorHandler:
    """Centralized error handling and logging."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.error_counts: Dict[ErrorCategory, int] = {}

    def handle_error(
        self, error: Exception, context: Optional[Dict[str, Any]] = None
    ) -> ErrorDetail:
        """Handle and log an error, returning structured error information."""
        self.logger.debug("ErrorHandler.handle_error(): %s", str(error))
        if isinstance(error, ChallengeError):
            error_detail = error.error_detail
        else:
            # Convert generic exceptions to ChallengeError
            error_detail = ErrorDetail(
                category=ErrorCategory.UNKNOWN_ERROR,
                severity=ErrorSeverity.MEDIUM,
                message=str(error),
                details={"exception_type": type(error).__name__},
            )

        # Add context information
        if context:
            error_detail.details.update(context)

        # Log the error
        self._log_error(error_detail, error)

        # Update error counts
        # self._update_error_counts(error_detail.category)

        return error_detail

    def _log_error(self, error_detail: ErrorDetail, original_error: Exception):
        """Log error with appropriate level based on severity."""
        self.logger.debug("ErrorHandler._log_error(): %s", str(original_error))
        log_message = f"[{error_detail.category.value}] {error_detail.message}"

        if error_detail.details:
            log_message += f" | Details: {error_detail.details}"

        if error_detail.severity == ErrorSeverity.CRITICAL:
            self.logger.critical(log_message, exc_info=True)
        elif error_detail.severity == ErrorSeverity.HIGH:
            self.logger.error(log_message)
        elif error_detail.severity == ErrorSeverity.MEDIUM:
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)

        # Log stack trace for debugging in debug mode
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(
                "Stack trace for error: %s",
                "".join(
                    traceback.format_exception(
                        type(original_error),
                        original_error,
                        original_error.__traceback__,
                    )
                ),
            )

    # def _update_error_counts(self, category: ErrorCategory):
    #    """Update error counts for monitoring."""
    #    self.error_counts[category] = self.error_counts.get(category, 0) + 1

    # def get_error_statistics(self) -> Dict[str, int]:
    #    """Get error statistics for monitoring."""
    #    return {category.value: count for category, count in self.error_counts.items()}

    def create_acme_error_response(
        self, error_detail: ErrorDetail, status_code: int = 400
    ) -> Dict[str, Any]:
        """Create an ACME-compliant error response."""

        # Map internal categories to ACME error types
        acme_error_type_map = {
            ErrorCategory.VALIDATION_ERROR: "incorrectResponse",
            ErrorCategory.NETWORK_ERROR: "connection",
            ErrorCategory.MALFORMED_REQUEST: "malformed",
            ErrorCategory.AUTHENTICATION_ERROR: "unauthorized",
            ErrorCategory.TIMEOUT_ERROR: "connection",
            ErrorCategory.CONFIGURATION_ERROR: "serverInternal",
            ErrorCategory.DATABASE_ERROR: "serverInternal",
            ErrorCategory.UNKNOWN_ERROR: "serverInternal",
        }

        acme_type = acme_error_type_map.get(error_detail.category, "serverInternal")

        response = {
            "code": status_code,
            "type": f"urn:ietf:params:acme:error:{acme_type}",
            "detail": error_detail.message,
        }

        # Add additional context if available
        if error_detail.suggestion:
            response["detail"] += f" Suggestion: {error_detail.suggestion}"

        return response


class ErrorRecovery:
    """Provides error recovery strategies."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def should_retry(self, error_detail: ErrorDetail, attempt_count: int) -> bool:
        """Determine if an operation should be retried based on error type."""

        # Don't retry beyond maximum attempts
        if attempt_count >= 3:
            return False

        # Retry network errors and timeouts
        if error_detail.category in [
            ErrorCategory.NETWORK_ERROR,
            ErrorCategory.TIMEOUT_ERROR,
        ]:
            return True

        # Don't retry validation errors, malformed requests, or authentication errors
        if error_detail.category in [
            ErrorCategory.VALIDATION_ERROR,
            ErrorCategory.MALFORMED_REQUEST,
            ErrorCategory.AUTHENTICATION_ERROR,
        ]:
            return False

        # Retry database errors (might be temporary)
        if error_detail.category == ErrorCategory.DATABASE_ERROR:
            return True

        return False

    def get_retry_delay(self, attempt_count: int) -> float:
        """Get delay before retry with exponential backoff."""
        return min(2**attempt_count, 30)  # Max 30 seconds
