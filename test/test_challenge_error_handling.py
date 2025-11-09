#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Comprehensive unit tests for challenge_error_handling.py"""
# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212
import unittest
import sys
import logging
from unittest.mock import Mock, MagicMock, patch, call
from typing import Dict, Optional, Any, List

sys.path.insert(0, ".")
sys.path.insert(1, "..")

# Import the module under test
from acme_srv.challenge_error_handling import (
    ErrorCategory,
    ErrorSeverity,
    ErrorDetail,
    ChallengeError,
    ValidationError,
    NetworkError,
    DatabaseError,
    ConfigurationError,
    AuthenticationError,
    MalformedRequestError,
    TimeoutError,
    UnsupportedChallengeTypeError,
    DNSResolutionError,
    HTTPChallengeError,
    DNSChallengeError,
    TLSALPNChallengeError,
    ErrorHandler,
    ErrorRecovery,
)


class TestErrorCategory(unittest.TestCase):
    """Test cases for ErrorCategory enum"""

    def test_001_error_category_values(self):
        """Test ErrorCategory enum has correct values"""
        self.assertEqual(ErrorCategory.VALIDATION_ERROR.value, "validation_error")
        self.assertEqual(ErrorCategory.NETWORK_ERROR.value, "network_error")
        self.assertEqual(ErrorCategory.DATABASE_ERROR.value, "database_error")
        self.assertEqual(ErrorCategory.CONFIGURATION_ERROR.value, "configuration_error")
        self.assertEqual(
            ErrorCategory.AUTHENTICATION_ERROR.value, "authentication_error"
        )
        self.assertEqual(ErrorCategory.MALFORMED_REQUEST.value, "malformed_request")
        self.assertEqual(ErrorCategory.TIMEOUT_ERROR.value, "timeout_error")
        self.assertEqual(ErrorCategory.UNKNOWN_ERROR.value, "unknown_error")

    def test_002_error_category_completeness(self):
        """Test that all expected error categories exist"""
        expected_categories = {
            "validation_error",
            "network_error",
            "database_error",
            "configuration_error",
            "authentication_error",
            "malformed_request",
            "timeout_error",
            "unknown_error",
        }
        actual_categories = {category.value for category in ErrorCategory}
        self.assertEqual(expected_categories, actual_categories)

    def test_003_error_category_enum_behavior(self):
        """Test ErrorCategory enum behavior"""
        # Test enum can be compared
        self.assertEqual(ErrorCategory.VALIDATION_ERROR, ErrorCategory.VALIDATION_ERROR)
        self.assertNotEqual(ErrorCategory.VALIDATION_ERROR, ErrorCategory.NETWORK_ERROR)

        # Test enum can be used in sets and dicts
        category_set = {ErrorCategory.VALIDATION_ERROR, ErrorCategory.NETWORK_ERROR}
        self.assertEqual(len(category_set), 2)

        category_dict = {ErrorCategory.VALIDATION_ERROR: "test"}
        self.assertEqual(category_dict[ErrorCategory.VALIDATION_ERROR], "test")


class TestErrorSeverity(unittest.TestCase):
    """Test cases for ErrorSeverity enum"""

    def test_001_error_severity_values(self):
        """Test ErrorSeverity enum has correct values"""
        self.assertEqual(ErrorSeverity.LOW.value, "low")
        self.assertEqual(ErrorSeverity.MEDIUM.value, "medium")
        self.assertEqual(ErrorSeverity.HIGH.value, "high")
        self.assertEqual(ErrorSeverity.CRITICAL.value, "critical")

    def test_002_error_severity_completeness(self):
        """Test that all expected severity levels exist"""
        expected_severities = {"low", "medium", "high", "critical"}
        actual_severities = {severity.value for severity in ErrorSeverity}
        self.assertEqual(expected_severities, actual_severities)

    def test_003_error_severity_enum_behavior(self):
        """Test ErrorSeverity enum behavior"""
        # Test enum can be compared
        self.assertEqual(ErrorSeverity.HIGH, ErrorSeverity.HIGH)
        self.assertNotEqual(ErrorSeverity.HIGH, ErrorSeverity.LOW)


class TestErrorDetail(unittest.TestCase):
    """Test cases for ErrorDetail dataclass"""

    def test_001_error_detail_creation_minimal(self):
        """Test ErrorDetail creation with minimal parameters"""
        detail = ErrorDetail(
            category=ErrorCategory.VALIDATION_ERROR,
            severity=ErrorSeverity.MEDIUM,
            message="Test error message",
        )

        self.assertEqual(detail.category, ErrorCategory.VALIDATION_ERROR)
        self.assertEqual(detail.severity, ErrorSeverity.MEDIUM)
        self.assertEqual(detail.message, "Test error message")
        self.assertIsNone(detail.details)
        self.assertIsNone(detail.suggestion)
        self.assertIsNone(detail.error_code)

    def test_002_error_detail_creation_full(self):
        """Test ErrorDetail creation with all parameters"""
        test_details = {"key": "value", "count": 42}
        detail = ErrorDetail(
            category=ErrorCategory.NETWORK_ERROR,
            severity=ErrorSeverity.HIGH,
            message="Network timeout",
            details=test_details,
            suggestion="Check network connectivity",
            error_code="NET_001",
        )

        self.assertEqual(detail.category, ErrorCategory.NETWORK_ERROR)
        self.assertEqual(detail.severity, ErrorSeverity.HIGH)
        self.assertEqual(detail.message, "Network timeout")
        self.assertEqual(detail.details, test_details)
        self.assertEqual(detail.suggestion, "Check network connectivity")
        self.assertEqual(detail.error_code, "NET_001")

    def test_003_error_detail_dataclass_behavior(self):
        """Test ErrorDetail dataclass behavior"""
        detail1 = ErrorDetail(
            category=ErrorCategory.VALIDATION_ERROR,
            severity=ErrorSeverity.MEDIUM,
            message="Test",
        )
        detail2 = ErrorDetail(
            category=ErrorCategory.VALIDATION_ERROR,
            severity=ErrorSeverity.MEDIUM,
            message="Test",
        )
        detail3 = ErrorDetail(
            category=ErrorCategory.NETWORK_ERROR,
            severity=ErrorSeverity.MEDIUM,
            message="Test",
        )

        # Test equality
        self.assertEqual(detail1, detail2)
        self.assertNotEqual(detail1, detail3)

        # Test string representation
        self.assertIn("ErrorDetail", str(detail1))
        self.assertIn("validation_error", str(detail1))


class TestChallengeError(unittest.TestCase):
    """Test cases for ChallengeError base exception"""

    def test_001_challenge_error_minimal_creation(self):
        """Test ChallengeError creation with minimal parameters"""
        error = ChallengeError("Test error message")

        self.assertEqual(str(error), "Test error message")
        self.assertIsInstance(error.error_detail, ErrorDetail)
        self.assertEqual(error.error_detail.message, "Test error message")
        self.assertEqual(error.error_detail.category, ErrorCategory.UNKNOWN_ERROR)
        self.assertEqual(error.error_detail.severity, ErrorSeverity.MEDIUM)
        self.assertEqual(error.error_detail.details, {})
        self.assertIsNone(error.error_detail.suggestion)
        self.assertIsNone(error.error_detail.error_code)

    def test_002_challenge_error_full_creation(self):
        """Test ChallengeError creation with all parameters"""
        test_details = {"test": "data"}
        error = ChallengeError(
            message="Detailed error",
            category=ErrorCategory.VALIDATION_ERROR,
            severity=ErrorSeverity.HIGH,
            details=test_details,
            suggestion="Fix the validation",
            error_code="VAL_001",
        )

        self.assertEqual(str(error), "Detailed error")
        self.assertEqual(error.error_detail.message, "Detailed error")
        self.assertEqual(error.error_detail.category, ErrorCategory.VALIDATION_ERROR)
        self.assertEqual(error.error_detail.severity, ErrorSeverity.HIGH)
        self.assertEqual(error.error_detail.details, test_details)
        self.assertEqual(error.error_detail.suggestion, "Fix the validation")
        self.assertEqual(error.error_detail.error_code, "VAL_001")

    def test_003_challenge_error_inheritance(self):
        """Test ChallengeError inheritance from Exception"""
        error = ChallengeError("Test")
        self.assertIsInstance(error, Exception)

        # Test it can be raised and caught
        with self.assertRaises(ChallengeError) as context:
            raise error
        self.assertEqual(str(context.exception), "Test")

    def test_004_challenge_error_none_details(self):
        """Test ChallengeError handles None details correctly"""
        error = ChallengeError("Test", details=None)
        self.assertEqual(error.error_detail.details, {})


class TestValidationError(unittest.TestCase):
    """Test cases for ValidationError exception"""

    def test_001_validation_error_creation(self):
        """Test ValidationError creation and inheritance"""
        error = ValidationError("Validation failed")

        self.assertIsInstance(error, ChallengeError)
        self.assertEqual(str(error), "Validation failed")
        self.assertEqual(error.error_detail.category, ErrorCategory.VALIDATION_ERROR)
        self.assertEqual(error.error_detail.severity, ErrorSeverity.MEDIUM)

    def test_002_validation_error_with_kwargs(self):
        """Test ValidationError with additional parameters"""
        error = ValidationError(
            "Validation failed",
            severity=ErrorSeverity.HIGH,
            details={"field": "test"},
            suggestion="Check field format",
        )

        self.assertEqual(error.error_detail.category, ErrorCategory.VALIDATION_ERROR)
        self.assertEqual(error.error_detail.severity, ErrorSeverity.HIGH)
        self.assertEqual(error.error_detail.details, {"field": "test"})
        self.assertEqual(error.error_detail.suggestion, "Check field format")


class TestNetworkError(unittest.TestCase):
    """Test cases for NetworkError exception"""

    def test_001_network_error_creation(self):
        """Test NetworkError creation and inheritance"""
        error = NetworkError("Connection failed")

        self.assertIsInstance(error, ChallengeError)
        self.assertEqual(str(error), "Connection failed")
        self.assertEqual(error.error_detail.category, ErrorCategory.NETWORK_ERROR)
        self.assertEqual(error.error_detail.severity, ErrorSeverity.MEDIUM)

    def test_002_network_error_with_kwargs(self):
        """Test NetworkError with additional parameters"""
        error = NetworkError(
            "Connection timeout", severity=ErrorSeverity.HIGH, details={"timeout": 30}
        )

        self.assertEqual(error.error_detail.category, ErrorCategory.NETWORK_ERROR)
        self.assertEqual(error.error_detail.severity, ErrorSeverity.HIGH)
        self.assertEqual(error.error_detail.details, {"timeout": 30})


class TestDatabaseError(unittest.TestCase):
    """Test cases for DatabaseError exception"""

    def test_001_database_error_creation(self):
        """Test DatabaseError creation and default HIGH severity"""
        error = DatabaseError("Database connection lost")

        self.assertIsInstance(error, ChallengeError)
        self.assertEqual(str(error), "Database connection lost")
        self.assertEqual(error.error_detail.category, ErrorCategory.DATABASE_ERROR)
        self.assertEqual(error.error_detail.severity, ErrorSeverity.HIGH)

    def test_002_database_error_with_kwargs(self):
        """Test DatabaseError with additional parameters"""
        error = DatabaseError(
            "Query failed",
            details={"query": "SELECT * FROM users"},
            suggestion="Check database schema",
        )

        self.assertEqual(error.error_detail.category, ErrorCategory.DATABASE_ERROR)
        self.assertEqual(error.error_detail.severity, ErrorSeverity.HIGH)
        self.assertEqual(error.error_detail.details, {"query": "SELECT * FROM users"})


class TestConfigurationError(unittest.TestCase):
    """Test cases for ConfigurationError exception"""

    def test_001_configuration_error_creation(self):
        """Test ConfigurationError creation and default HIGH severity"""
        error = ConfigurationError("Invalid configuration")

        self.assertIsInstance(error, ChallengeError)
        self.assertEqual(str(error), "Invalid configuration")
        self.assertEqual(error.error_detail.category, ErrorCategory.CONFIGURATION_ERROR)
        self.assertEqual(error.error_detail.severity, ErrorSeverity.HIGH)

    def test_002_configuration_error_with_kwargs(self):
        """Test ConfigurationError with additional parameters"""
        error = ConfigurationError(
            "Missing required setting",
            details={"setting": "api_key"},
            error_code="CONF_001",
        )

        self.assertEqual(error.error_detail.category, ErrorCategory.CONFIGURATION_ERROR)
        self.assertEqual(error.error_detail.severity, ErrorSeverity.HIGH)
        self.assertEqual(error.error_detail.details, {"setting": "api_key"})
        self.assertEqual(error.error_detail.error_code, "CONF_001")


class TestAuthenticationError(unittest.TestCase):
    """Test cases for AuthenticationError exception"""

    def test_001_authentication_error_creation(self):
        """Test AuthenticationError creation and default HIGH severity"""
        error = AuthenticationError("Invalid credentials")

        self.assertIsInstance(error, ChallengeError)
        self.assertEqual(str(error), "Invalid credentials")
        self.assertEqual(
            error.error_detail.category, ErrorCategory.AUTHENTICATION_ERROR
        )
        self.assertEqual(error.error_detail.severity, ErrorSeverity.HIGH)

    def test_002_authentication_error_with_kwargs(self):
        """Test AuthenticationError with additional parameters"""
        error = AuthenticationError(
            "Token expired",
            details={"token_type": "JWT"},
            suggestion="Refresh the authentication token",
        )

        self.assertEqual(
            error.error_detail.category, ErrorCategory.AUTHENTICATION_ERROR
        )
        self.assertEqual(error.error_detail.severity, ErrorSeverity.HIGH)
        self.assertEqual(error.error_detail.details, {"token_type": "JWT"})


class TestMalformedRequestError(unittest.TestCase):
    """Test cases for MalformedRequestError exception"""

    def test_001_malformed_request_error_creation(self):
        """Test MalformedRequestError creation"""
        error = MalformedRequestError("Invalid JSON format")

        self.assertIsInstance(error, ChallengeError)
        self.assertEqual(str(error), "Invalid JSON format")
        self.assertEqual(error.error_detail.category, ErrorCategory.MALFORMED_REQUEST)
        self.assertEqual(error.error_detail.severity, ErrorSeverity.MEDIUM)

    def test_002_malformed_request_error_with_kwargs(self):
        """Test MalformedRequestError with additional parameters"""
        error = MalformedRequestError(
            "Missing required field",
            details={"field": "challenge_type"},
            error_code="MALFORMED_001",
        )

        self.assertEqual(error.error_detail.category, ErrorCategory.MALFORMED_REQUEST)
        self.assertEqual(error.error_detail.details, {"field": "challenge_type"})
        self.assertEqual(error.error_detail.error_code, "MALFORMED_001")


class TestTimeoutError(unittest.TestCase):
    """Test cases for TimeoutError exception"""

    def test_001_timeout_error_creation(self):
        """Test TimeoutError creation"""
        error = TimeoutError("Operation timed out")

        self.assertIsInstance(error, ChallengeError)
        self.assertEqual(str(error), "Operation timed out")
        self.assertEqual(error.error_detail.category, ErrorCategory.TIMEOUT_ERROR)
        self.assertEqual(error.error_detail.severity, ErrorSeverity.MEDIUM)

    def test_002_timeout_error_with_kwargs(self):
        """Test TimeoutError with additional parameters"""
        error = TimeoutError(
            "HTTP request timeout",
            details={"timeout": 30, "url": "https://example.com"},
            suggestion="Increase timeout or check network connection",
        )

        self.assertEqual(error.error_detail.category, ErrorCategory.TIMEOUT_ERROR)
        self.assertEqual(
            error.error_detail.details, {"timeout": 30, "url": "https://example.com"}
        )


class TestUnsupportedChallengeTypeError(unittest.TestCase):
    """Test cases for UnsupportedChallengeTypeError exception"""

    def test_001_unsupported_challenge_type_error_creation(self):
        """Test UnsupportedChallengeTypeError creation"""
        supported_types = ["http-01", "dns-01", "tls-alpn-01"]
        error = UnsupportedChallengeTypeError("custom-challenge", supported_types)

        self.assertIsInstance(error, ValidationError)
        self.assertIsInstance(error, ChallengeError)
        self.assertEqual(str(error), "Unsupported challenge type: custom-challenge")
        self.assertEqual(error.error_detail.category, ErrorCategory.VALIDATION_ERROR)
        self.assertEqual(error.error_detail.error_code, "UNSUPPORTED_CHALLENGE_TYPE")

        expected_details = {
            "challenge_type": "custom-challenge",
            "supported_types": supported_types,
        }
        self.assertEqual(error.error_detail.details, expected_details)
        self.assertEqual(
            error.error_detail.suggestion,
            "Use one of the supported types: http-01, dns-01, tls-alpn-01",
        )

    def test_002_unsupported_challenge_type_error_empty_supported_types(self):
        """Test UnsupportedChallengeTypeError with empty supported types"""
        error = UnsupportedChallengeTypeError("unknown", [])

        self.assertEqual(str(error), "Unsupported challenge type: unknown")
        self.assertEqual(error.error_detail.details["supported_types"], [])
        self.assertEqual(
            error.error_detail.suggestion, "Use one of the supported types: "
        )


class TestDNSResolutionError(unittest.TestCase):
    """Test cases for DNSResolutionError exception"""

    def test_001_dns_resolution_error_basic(self):
        """Test DNSResolutionError creation without DNS servers"""
        error = DNSResolutionError("example.com")

        self.assertIsInstance(error, NetworkError)
        self.assertIsInstance(error, ChallengeError)
        self.assertEqual(str(error), "DNS resolution failed for domain: example.com")
        self.assertEqual(error.error_detail.category, ErrorCategory.NETWORK_ERROR)
        self.assertEqual(error.error_detail.error_code, "DNS_RESOLUTION_FAILED")

        expected_details = {"domain": "example.com", "dns_servers": None}
        self.assertEqual(error.error_detail.details, expected_details)
        self.assertEqual(
            error.error_detail.suggestion,
            "Check domain validity and DNS server configuration",
        )

    def test_002_dns_resolution_error_with_dns_servers(self):
        """Test DNSResolutionError creation with DNS servers"""
        dns_servers = ["8.8.8.8", "1.1.1.1"]
        error = DNSResolutionError("test.example.com", dns_servers)

        self.assertEqual(
            str(error), "DNS resolution failed for domain: test.example.com"
        )
        expected_details = {"domain": "test.example.com", "dns_servers": dns_servers}
        self.assertEqual(error.error_detail.details, expected_details)


class TestHTTPChallengeError(unittest.TestCase):
    """Test cases for HTTPChallengeError exception"""

    def test_001_http_challenge_error_creation(self):
        """Test HTTPChallengeError creation"""
        url = "http://example.com/.well-known/acme-challenge/token"
        expected = "expected_token_response"
        received = "unexpected_response"

        error = HTTPChallengeError(url, expected, received)

        self.assertIsInstance(error, ValidationError)
        self.assertIsInstance(error, ChallengeError)
        self.assertEqual(str(error), f"HTTP challenge validation failed for {url}")
        self.assertEqual(error.error_detail.category, ErrorCategory.VALIDATION_ERROR)
        self.assertEqual(error.error_detail.error_code, "HTTP_CHALLENGE_FAILED")

        expected_details = {
            "url": url,
            "expected_response": expected,
            "received_response": received,
        }
        self.assertEqual(error.error_detail.details, expected_details)
        self.assertEqual(
            error.error_detail.suggestion,
            "Ensure the challenge file is accessible and contains the correct token",
        )

    def test_002_http_challenge_error_empty_responses(self):
        """Test HTTPChallengeError with empty responses"""
        error = HTTPChallengeError("http://test.com/acme", "", "")

        self.assertEqual(error.error_detail.details["expected_response"], "")
        self.assertEqual(error.error_detail.details["received_response"], "")


class TestDNSChallengeError(unittest.TestCase):
    """Test cases for DNSChallengeError exception"""

    def test_001_dns_challenge_error_creation(self):
        """Test DNSChallengeError creation"""
        dns_record = "_acme-challenge.example.com"
        expected_hash = "expected_hash_value"
        found_records = ["wrong_hash1", "wrong_hash2"]

        error = DNSChallengeError(dns_record, expected_hash, found_records)

        self.assertIsInstance(error, ValidationError)
        self.assertIsInstance(error, ChallengeError)
        self.assertEqual(
            str(error), f"DNS challenge validation failed for {dns_record}"
        )
        self.assertEqual(error.error_detail.category, ErrorCategory.VALIDATION_ERROR)
        self.assertEqual(error.error_detail.error_code, "DNS_CHALLENGE_FAILED")

        expected_details = {
            "dns_record": dns_record,
            "expected_hash": expected_hash,
            "found_records": found_records,
        }
        self.assertEqual(error.error_detail.details, expected_details)
        self.assertEqual(
            error.error_detail.suggestion,
            "Ensure the DNS TXT record is properly configured",
        )

    def test_002_dns_challenge_error_empty_found_records(self):
        """Test DNSChallengeError with empty found records"""
        error = DNSChallengeError("_acme-challenge.test.com", "hash123", [])

        self.assertEqual(error.error_detail.details["found_records"], [])


class TestTLSALPNChallengeError(unittest.TestCase):
    """Test cases for TLSALPNChallengeError exception"""

    def test_001_tls_alpn_challenge_error_creation(self):
        """Test TLSALPNChallengeError creation"""
        domain = "example.com"
        expected_extension = "acme-tls/1"

        error = TLSALPNChallengeError(domain, expected_extension)

        self.assertIsInstance(error, ValidationError)
        self.assertIsInstance(error, ChallengeError)
        self.assertEqual(
            str(error), f"TLS-ALPN challenge validation failed for {domain}"
        )
        self.assertEqual(error.error_detail.category, ErrorCategory.VALIDATION_ERROR)
        self.assertEqual(error.error_detail.error_code, "TLS_ALPN_CHALLENGE_FAILED")

        expected_details = {"domain": domain, "expected_extension": expected_extension}
        self.assertEqual(error.error_detail.details, expected_details)
        self.assertEqual(
            error.error_detail.suggestion,
            "Ensure the TLS certificate contains the required extension",
        )


class TestErrorHandler(unittest.TestCase):
    """Test cases for ErrorHandler class"""

    def setUp(self):
        """Setup for ErrorHandler tests"""
        self.logger = Mock(spec=logging.Logger)
        self.logger.isEnabledFor.return_value = False
        self.error_handler = ErrorHandler(self.logger)

    def test_001_error_handler_initialization(self):
        """Test ErrorHandler initialization"""
        self.assertEqual(self.error_handler.logger, self.logger)
        self.assertEqual(self.error_handler.error_counts, {})

    def test_002_handle_challenge_error(self):
        """Test handling ChallengeError instances"""
        error = ValidationError("Test validation error")
        context = {"test_context": "value"}

        result = self.error_handler.handle_error(error, context)

        self.assertIsInstance(result, ErrorDetail)
        self.assertEqual(result.message, "Test validation error")
        self.assertEqual(result.category, ErrorCategory.VALIDATION_ERROR)
        self.assertIn("test_context", result.details)
        self.assertEqual(result.details["test_context"], "value")

    def test_003_handle_generic_exception(self):
        """Test handling generic Exception instances"""
        error = ValueError("Generic error message")
        context = {"operation": "test_operation"}

        result = self.error_handler.handle_error(error, context)

        self.assertIsInstance(result, ErrorDetail)
        self.assertEqual(result.message, "Generic error message")
        self.assertEqual(result.category, ErrorCategory.UNKNOWN_ERROR)
        self.assertEqual(result.severity, ErrorSeverity.MEDIUM)
        self.assertEqual(result.details["exception_type"], "ValueError")
        self.assertEqual(result.details["operation"], "test_operation")

    def test_004_handle_error_without_context(self):
        """Test handling error without context"""
        error = NetworkError("Network failure")

        result = self.error_handler.handle_error(error)

        self.assertIsInstance(result, ErrorDetail)
        self.assertEqual(result.message, "Network failure")
        self.assertEqual(result.category, ErrorCategory.NETWORK_ERROR)

    def test_005_log_error_critical_severity(self):
        """Test logging error with CRITICAL severity"""
        error_detail = ErrorDetail(
            category=ErrorCategory.DATABASE_ERROR,
            severity=ErrorSeverity.CRITICAL,
            message="Critical database error",
            details={"connection": "lost"},
        )
        original_error = Exception("Test error")

        self.error_handler._log_error(error_detail, original_error)

        self.logger.critical.assert_called_once()
        log_message = self.logger.critical.call_args[0][0]
        self.assertIn("[database_error]", log_message)
        self.assertIn("Critical database error", log_message)
        self.assertIn("Details:", log_message)

    def test_006_log_error_high_severity(self):
        """Test logging error with HIGH severity"""
        error_detail = ErrorDetail(
            category=ErrorCategory.CONFIGURATION_ERROR,
            severity=ErrorSeverity.HIGH,
            message="High severity error",
        )
        original_error = Exception("Test error")

        self.error_handler._log_error(error_detail, original_error)

        self.logger.error.assert_called_once()
        log_message = self.logger.error.call_args[0][0]
        self.assertIn("[configuration_error]", log_message)
        self.assertIn("High severity error", log_message)

    def test_007_log_error_medium_severity(self):
        """Test logging error with MEDIUM severity"""
        error_detail = ErrorDetail(
            category=ErrorCategory.VALIDATION_ERROR,
            severity=ErrorSeverity.MEDIUM,
            message="Medium severity error",
        )
        original_error = Exception("Test error")

        self.error_handler._log_error(error_detail, original_error)

        self.logger.warning.assert_called_once()
        log_message = self.logger.warning.call_args[0][0]
        self.assertIn("[validation_error]", log_message)
        self.assertIn("Medium severity error", log_message)

    def test_008_log_error_low_severity(self):
        """Test logging error with LOW severity"""
        error_detail = ErrorDetail(
            category=ErrorCategory.UNKNOWN_ERROR,
            severity=ErrorSeverity.LOW,
            message="Low severity error",
        )
        original_error = Exception("Test error")

        self.error_handler._log_error(error_detail, original_error)

        self.logger.info.assert_called_once()
        log_message = self.logger.info.call_args[0][0]
        self.assertIn("[unknown_error]", log_message)
        self.assertIn("Low severity error", log_message)

    def test_009_log_error_debug_mode(self):
        """Test logging error in debug mode with stack trace"""
        self.logger.isEnabledFor.return_value = True

        error_detail = ErrorDetail(
            category=ErrorCategory.NETWORK_ERROR,
            severity=ErrorSeverity.MEDIUM,
            message="Debug mode error",
        )
        original_error = Exception("Debug error")

        with patch("traceback.format_exception") as mock_format:
            mock_format.return_value = ["Traceback line 1\n", "Traceback line 2\n"]

            self.error_handler._log_error(error_detail, original_error)

            self.logger.warning.assert_called_once()
            self.logger.debug.assert_called_with(
                "Stack trace for error: %s", "Traceback line 1\nTraceback line 2\n"
            )

    def test_010_log_error_without_details(self):
        """Test logging error without details"""
        error_detail = ErrorDetail(
            category=ErrorCategory.TIMEOUT_ERROR,
            severity=ErrorSeverity.MEDIUM,
            message="Simple timeout error",
        )
        original_error = Exception("Test error")

        self.error_handler._log_error(error_detail, original_error)

        self.logger.warning.assert_called_once()
        log_message = self.logger.warning.call_args[0][0]
        self.assertIn("[timeout_error]", log_message)
        self.assertIn("Simple timeout error", log_message)
        self.assertNotIn("Details:", log_message)

    def test_011_create_acme_error_response_validation_error(self):
        """Test creating ACME error response for validation error"""
        error_detail = ErrorDetail(
            category=ErrorCategory.VALIDATION_ERROR,
            severity=ErrorSeverity.MEDIUM,
            message="Invalid challenge response",
            suggestion="Check token format",
        )

        response = self.error_handler.create_acme_error_response(error_detail, 400)

        expected_response = {
            "code": 400,
            "type": "urn:ietf:params:acme:error:incorrectResponse",
            "detail": "Invalid challenge response Suggestion: Check token format",
        }
        self.assertEqual(response, expected_response)

    def test_012_create_acme_error_response_network_error(self):
        """Test creating ACME error response for network error"""
        error_detail = ErrorDetail(
            category=ErrorCategory.NETWORK_ERROR,
            severity=ErrorSeverity.HIGH,
            message="Connection failed",
        )

        response = self.error_handler.create_acme_error_response(error_detail, 502)

        expected_response = {
            "code": 502,
            "type": "urn:ietf:params:acme:error:connection",
            "detail": "Connection failed",
        }
        self.assertEqual(response, expected_response)

    def test_013_create_acme_error_response_malformed_request(self):
        """Test creating ACME error response for malformed request"""
        error_detail = ErrorDetail(
            category=ErrorCategory.MALFORMED_REQUEST,
            severity=ErrorSeverity.MEDIUM,
            message="Invalid JSON format",
        )

        response = self.error_handler.create_acme_error_response(error_detail)

        expected_response = {
            "code": 400,
            "type": "urn:ietf:params:acme:error:malformed",
            "detail": "Invalid JSON format",
        }
        self.assertEqual(response, expected_response)

    def test_014_create_acme_error_response_authentication_error(self):
        """Test creating ACME error response for authentication error"""
        error_detail = ErrorDetail(
            category=ErrorCategory.AUTHENTICATION_ERROR,
            severity=ErrorSeverity.HIGH,
            message="Invalid credentials",
        )

        response = self.error_handler.create_acme_error_response(error_detail, 401)

        expected_response = {
            "code": 401,
            "type": "urn:ietf:params:acme:error:unauthorized",
            "detail": "Invalid credentials",
        }
        self.assertEqual(response, expected_response)

    def test_015_create_acme_error_response_timeout_error(self):
        """Test creating ACME error response for timeout error"""
        error_detail = ErrorDetail(
            category=ErrorCategory.TIMEOUT_ERROR,
            severity=ErrorSeverity.MEDIUM,
            message="Request timeout",
        )

        response = self.error_handler.create_acme_error_response(error_detail, 408)

        expected_response = {
            "code": 408,
            "type": "urn:ietf:params:acme:error:connection",
            "detail": "Request timeout",
        }
        self.assertEqual(response, expected_response)

    def test_016_create_acme_error_response_server_errors(self):
        """Test creating ACME error response for server-side errors"""
        for category in [
            ErrorCategory.CONFIGURATION_ERROR,
            ErrorCategory.DATABASE_ERROR,
            ErrorCategory.UNKNOWN_ERROR,
        ]:
            with self.subTest(category=category):
                error_detail = ErrorDetail(
                    category=category,
                    severity=ErrorSeverity.HIGH,
                    message="Server error",
                )

                response = self.error_handler.create_acme_error_response(
                    error_detail, 500
                )

                expected_response = {
                    "code": 500,
                    "type": "urn:ietf:params:acme:error:serverInternal",
                    "detail": "Server error",
                }
                self.assertEqual(response, expected_response)

    def test_017_create_acme_error_response_without_suggestion(self):
        """Test creating ACME error response without suggestion"""
        error_detail = ErrorDetail(
            category=ErrorCategory.VALIDATION_ERROR,
            severity=ErrorSeverity.MEDIUM,
            message="Simple validation error",
        )

        response = self.error_handler.create_acme_error_response(error_detail)

        expected_response = {
            "code": 400,
            "type": "urn:ietf:params:acme:error:incorrectResponse",
            "detail": "Simple validation error",
        }
        self.assertEqual(response, expected_response)


class TestErrorRecovery(unittest.TestCase):
    """Test cases for ErrorRecovery class"""

    def setUp(self):
        """Setup for ErrorRecovery tests"""
        self.logger = Mock(spec=logging.Logger)
        self.error_recovery = ErrorRecovery(self.logger)

    def test_001_error_recovery_initialization(self):
        """Test ErrorRecovery initialization"""
        self.assertEqual(self.error_recovery.logger, self.logger)

    def test_002_should_retry_network_errors(self):
        """Test retry logic for network errors"""
        error_detail = ErrorDetail(
            category=ErrorCategory.NETWORK_ERROR,
            severity=ErrorSeverity.MEDIUM,
            message="Network failure",
        )

        # Should retry for attempts 1 and 2
        self.assertTrue(self.error_recovery.should_retry(error_detail, 1))
        self.assertTrue(self.error_recovery.should_retry(error_detail, 2))
        # Should not retry after 3 attempts
        self.assertFalse(self.error_recovery.should_retry(error_detail, 3))

    def test_003_should_retry_timeout_errors(self):
        """Test retry logic for timeout errors"""
        error_detail = ErrorDetail(
            category=ErrorCategory.TIMEOUT_ERROR,
            severity=ErrorSeverity.MEDIUM,
            message="Timeout",
        )

        # Should retry for attempts 1 and 2
        self.assertTrue(self.error_recovery.should_retry(error_detail, 1))
        self.assertTrue(self.error_recovery.should_retry(error_detail, 2))
        # Should not retry after 3 attempts
        self.assertFalse(self.error_recovery.should_retry(error_detail, 3))

    def test_004_should_retry_database_errors(self):
        """Test retry logic for database errors"""
        error_detail = ErrorDetail(
            category=ErrorCategory.DATABASE_ERROR,
            severity=ErrorSeverity.HIGH,
            message="Database error",
        )

        # Should retry for attempts 1 and 2
        self.assertTrue(self.error_recovery.should_retry(error_detail, 1))
        self.assertTrue(self.error_recovery.should_retry(error_detail, 2))
        # Should not retry after 3 attempts
        self.assertFalse(self.error_recovery.should_retry(error_detail, 3))

    def test_005_should_not_retry_validation_errors(self):
        """Test no retry for validation errors"""
        error_detail = ErrorDetail(
            category=ErrorCategory.VALIDATION_ERROR,
            severity=ErrorSeverity.MEDIUM,
            message="Validation failed",
        )

        # Should never retry validation errors
        self.assertFalse(self.error_recovery.should_retry(error_detail, 1))
        self.assertFalse(self.error_recovery.should_retry(error_detail, 2))

    def test_006_should_not_retry_malformed_requests(self):
        """Test no retry for malformed request errors"""
        error_detail = ErrorDetail(
            category=ErrorCategory.MALFORMED_REQUEST,
            severity=ErrorSeverity.MEDIUM,
            message="Malformed request",
        )

        # Should never retry malformed requests
        self.assertFalse(self.error_recovery.should_retry(error_detail, 1))

    def test_007_should_not_retry_authentication_errors(self):
        """Test no retry for authentication errors"""
        error_detail = ErrorDetail(
            category=ErrorCategory.AUTHENTICATION_ERROR,
            severity=ErrorSeverity.HIGH,
            message="Authentication failed",
        )

        # Should never retry authentication errors
        self.assertFalse(self.error_recovery.should_retry(error_detail, 1))

    def test_008_should_not_retry_unknown_errors(self):
        """Test default no retry for unknown errors"""
        error_detail = ErrorDetail(
            category=ErrorCategory.UNKNOWN_ERROR,
            severity=ErrorSeverity.MEDIUM,
            message="Unknown error",
        )

        # Should not retry unknown errors by default
        self.assertFalse(self.error_recovery.should_retry(error_detail, 1))

    def test_009_should_not_retry_configuration_errors(self):
        """Test no retry for configuration errors"""
        error_detail = ErrorDetail(
            category=ErrorCategory.CONFIGURATION_ERROR,
            severity=ErrorSeverity.HIGH,
            message="Configuration error",
        )

        # Should not retry configuration errors
        self.assertFalse(self.error_recovery.should_retry(error_detail, 1))

    def test_010_get_retry_delay_exponential_backoff(self):
        """Test exponential backoff delay calculation"""
        # Test exponential backoff: 2^attempt_count
        self.assertEqual(self.error_recovery.get_retry_delay(1), 2)  # 2^1
        self.assertEqual(self.error_recovery.get_retry_delay(2), 4)  # 2^2
        self.assertEqual(self.error_recovery.get_retry_delay(3), 8)  # 2^3
        self.assertEqual(self.error_recovery.get_retry_delay(4), 16)  # 2^4

    def test_011_get_retry_delay_max_cap(self):
        """Test retry delay maximum cap"""
        # Test maximum cap of 30 seconds
        self.assertEqual(
            self.error_recovery.get_retry_delay(10), 30
        )  # 2^10 = 1024, capped at 30
        self.assertEqual(
            self.error_recovery.get_retry_delay(20), 30
        )  # Should still be capped

    def test_012_get_retry_delay_zero_attempts(self):
        """Test retry delay with zero attempts"""
        self.assertEqual(self.error_recovery.get_retry_delay(0), 1)  # 2^0 = 1


if __name__ == "__main__":
    unittest.main()
