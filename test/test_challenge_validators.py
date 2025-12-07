#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Comprehensive unit tests for challenge_validators package"""
# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212
import unittest
import sys
import logging
from unittest.mock import Mock, patch

sys.path.insert(0, ".")
sys.path.insert(1, "..")

# Import the modules under test
from acme_srv.challenge_validators.base import (
    ValidationResult,
    ChallengeContext,
    ChallengeValidator,
    ChallengeValidationError,
    ValidationTimeoutError,
    InvalidChallengeTypeError,
)
from acme_srv.challenge_validators.registry import ChallengeValidatorRegistry
from acme_srv.challenge_validators.http_validator import HttpChallengeValidator
from acme_srv.challenge_validators.dns_validator import DnsChallengeValidator
from acme_srv.challenge_validators.tls_alpn_validator import TlsAlpnChallengeValidator
from acme_srv.challenge_validators.email_reply_validator import (
    EmailReplyChallengeValidator,
)
from acme_srv.challenge_validators.tkauth_validator import TkauthChallengeValidator
from acme_srv.challenge_validators.source_address_validator import (
    SourceAddressValidator,
)


class TestValidationResult(unittest.TestCase):
    """Test cases for ValidationResult dataclass"""

    def test_001_validation_result_creation_minimal(self):
        """Test ValidationResult creation with minimal parameters"""
        result = ValidationResult(success=True, invalid=False)

        self.assertTrue(result.success)
        self.assertFalse(result.invalid)
        self.assertIsNone(result.error_message)
        self.assertIsNone(result.details)

    def test_002_validation_result_creation_full(self):
        """Test ValidationResult creation with all parameters"""
        details = {"key": "value", "count": 42}
        result = ValidationResult(
            success=False, invalid=True, error_message="Test error", details=details
        )

        self.assertFalse(result.success)
        self.assertTrue(result.invalid)
        self.assertEqual(result.error_message, "Test error")
        self.assertEqual(result.details, details)

    def test_003_validation_result_dataclass_behavior(self):
        """Test ValidationResult dataclass behavior"""
        result1 = ValidationResult(success=True, invalid=False)
        result2 = ValidationResult(success=True, invalid=False)
        result3 = ValidationResult(success=False, invalid=True)

        # Test equality
        self.assertEqual(result1, result2)
        self.assertNotEqual(result1, result3)

        # Test string representation
        self.assertIn("ValidationResult", str(result1))


class TestChallengeContext(unittest.TestCase):
    """Test cases for ChallengeContext dataclass"""

    def test_001_challenge_context_creation_minimal(self):
        """Test ChallengeContext creation with required parameters"""
        context = ChallengeContext(
            challenge_name="test_challenge",
            token="test_token",
            jwk_thumbprint="test_thumbprint",
            authorization_type="dns",
            authorization_value="example.com",
        )

        self.assertEqual(context.challenge_name, "test_challenge")
        self.assertEqual(context.token, "test_token")
        self.assertEqual(context.jwk_thumbprint, "test_thumbprint")
        self.assertEqual(context.authorization_type, "dns")
        self.assertEqual(context.authorization_value, "example.com")
        # Test default values
        self.assertIsNone(context.keyauthorization)
        self.assertIsNone(context.dns_servers)
        self.assertIsNone(context.proxy_servers)
        self.assertEqual(context.timeout, 10)
        self.assertIsNone(context.source_address)

    def test_002_challenge_context_creation_full(self):
        """Test ChallengeContext creation with all parameters"""
        dns_servers = ["8.8.8.8", "1.1.1.1"]
        proxy_servers = {"http": "http://proxy.example.com:8080"}

        context = ChallengeContext(
            challenge_name="full_challenge",
            token="full_token",
            jwk_thumbprint="full_thumbprint",
            authorization_type="ip",
            authorization_value="192.168.1.1",
            keyauthorization="test_keyauth",
            dns_servers=dns_servers,
            proxy_servers=proxy_servers,
            timeout=30,
            source_address="192.168.1.100",
        )

        self.assertEqual(context.challenge_name, "full_challenge")
        self.assertEqual(context.token, "full_token")
        self.assertEqual(context.jwk_thumbprint, "full_thumbprint")
        self.assertEqual(context.authorization_type, "ip")
        self.assertEqual(context.authorization_value, "192.168.1.1")
        self.assertEqual(context.keyauthorization, "test_keyauth")
        self.assertEqual(context.dns_servers, dns_servers)
        self.assertEqual(context.proxy_servers, proxy_servers)
        self.assertEqual(context.timeout, 30)
        self.assertEqual(context.source_address, "192.168.1.100")

    def test_003_challenge_context_dataclass_behavior(self):
        """Test ChallengeContext dataclass behavior"""
        context1 = ChallengeContext(
            challenge_name="test",
            token="token",
            jwk_thumbprint="thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )
        context2 = ChallengeContext(
            challenge_name="test",
            token="token",
            jwk_thumbprint="thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )
        context3 = ChallengeContext(
            challenge_name="different",
            token="token",
            jwk_thumbprint="thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )

        # Test equality
        self.assertEqual(context1, context2)
        self.assertNotEqual(context1, context3)

        # Test string representation
        self.assertIn("ChallengeContext", str(context1))


class TestChallengeValidationExceptions(unittest.TestCase):
    """Test cases for challenge validation exceptions"""

    def test_001_challenge_validation_error(self):
        """Test ChallengeValidationError exception"""
        error = ChallengeValidationError("Test validation error")

        self.assertIsInstance(error, Exception)
        self.assertEqual(str(error), "Test validation error")

        # Test it can be raised and caught
        with self.assertRaises(ChallengeValidationError) as context:
            raise error
        self.assertEqual(str(context.exception), "Test validation error")

    def test_002_validation_timeout_error(self):
        """Test ValidationTimeoutError exception"""
        error = ValidationTimeoutError("Timeout occurred")

        self.assertIsInstance(error, ChallengeValidationError)
        self.assertIsInstance(error, Exception)
        self.assertEqual(str(error), "Timeout occurred")

    def test_003_invalid_challenge_type_error(self):
        """Test InvalidChallengeTypeError exception"""
        error = InvalidChallengeTypeError("Unsupported challenge type")

        self.assertIsInstance(error, ChallengeValidationError)
        self.assertIsInstance(error, Exception)
        self.assertEqual(str(error), "Unsupported challenge type")


class TestChallengeValidator(unittest.TestCase):
    """Test cases for ChallengeValidator abstract base class"""

    def setUp(self):
        """Setup for ChallengeValidator tests"""
        self.logger = Mock(spec=logging.Logger)

    def test_001_challenge_validator_abstract(self):
        """Test ChallengeValidator is abstract and cannot be instantiated"""
        with self.assertRaises(TypeError):
            ChallengeValidator(self.logger)

    def test_002_challenge_validator_validate_challenge_success(self):
        """Test validate_challenge method with successful validation"""
        # Create a concrete implementation for testing
        class TestValidator(ChallengeValidator):
            def get_challenge_type(self):
                return "test-01"

            def perform_validation(self, context):
                return ValidationResult(success=True, invalid=False)

        validator = TestValidator(self.logger)
        context = ChallengeContext(
            challenge_name="test",
            token="token",
            jwk_thumbprint="thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )

        result = validator.validate_challenge(context)

        self.assertIsInstance(result, ValidationResult)
        self.assertTrue(result.success)
        self.assertFalse(result.invalid)

        # Verify logging calls
        self.logger.debug.assert_called()

    def test_003_challenge_validator_validate_challenge_exception(self):
        """Test validate_challenge method with exception handling"""
        # Create a concrete implementation that raises an exception
        class FailingValidator(ChallengeValidator):
            def get_challenge_type(self):
                return "failing-01"

            def perform_validation(self, context):
                raise ValueError("Test validation error")

        validator = FailingValidator(self.logger)
        context = ChallengeContext(
            challenge_name="test",
            token="token",
            jwk_thumbprint="thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )

        result = validator.validate_challenge(context)

        self.assertIsInstance(result, ValidationResult)
        self.assertFalse(result.success)
        self.assertTrue(result.invalid)
        self.assertEqual(result.error_message, "Test validation error")
        self.assertEqual(result.details["exception_type"], "ValueError")

        # Verify error logging
        self.logger.error.assert_called()


class TestChallengeValidatorRegistry(unittest.TestCase):
    """Test cases for ChallengeValidatorRegistry"""

    def setUp(self):
        """Setup for registry tests"""
        self.logger = Mock(spec=logging.Logger)
        self.registry = ChallengeValidatorRegistry(self.logger)

    def test_001_registry_initialization(self):
        """Test registry initialization"""
        self.assertEqual(self.registry.logger, self.logger)
        self.assertEqual(self.registry._validators, {})

    def test_002_register_validator(self):
        """Test registering a validator"""
        # Create a mock validator
        mock_validator = Mock(spec=ChallengeValidator)
        mock_validator.get_challenge_type.return_value = "test-01"

        self.registry.register_validator(mock_validator)

        # Check validator was registered
        self.assertIn("test-01", self.registry._validators)
        self.assertEqual(self.registry._validators["test-01"], mock_validator)

        # Verify logging
        self.logger.debug.assert_called()

    def test_003_get_validator_existing(self):
        """Test getting an existing validator"""
        # Create and register a mock validator
        mock_validator = Mock(spec=ChallengeValidator)
        mock_validator.get_challenge_type.return_value = "test-01"
        self.registry.register_validator(mock_validator)

        # Get the validator
        result = self.registry.get_validator("test-01")

        self.assertEqual(result, mock_validator)
        self.logger.debug.assert_called()

    def test_004_get_validator_non_existing(self):
        """Test getting a non-existing validator"""
        result = self.registry.get_validator("non-existent")

        self.assertIsNone(result)
        self.logger.debug.assert_called()

    def test_005_get_supported_types_empty(self):
        """Test getting supported types from empty registry"""
        result = self.registry.get_supported_types()

        self.assertEqual(result, [])
        self.logger.debug.assert_called()

    def test_006_get_supported_types_with_validators(self):
        """Test getting supported types with registered validators"""
        # Register multiple validators
        for challenge_type in ["http-01", "dns-01", "tls-alpn-01"]:
            mock_validator = Mock(spec=ChallengeValidator)
            mock_validator.get_challenge_type.return_value = challenge_type
            self.registry.register_validator(mock_validator)

        result = self.registry.get_supported_types()

        self.assertEqual(set(result), {"http-01", "dns-01", "tls-alpn-01"})
        self.logger.debug.assert_called()

    def test_007_is_supported_true(self):
        """Test is_supported with supported challenge type"""
        # Register a validator
        mock_validator = Mock(spec=ChallengeValidator)
        mock_validator.get_challenge_type.return_value = "test-01"
        self.registry.register_validator(mock_validator)

        result = self.registry.is_supported("test-01")

        self.assertTrue(result)
        self.logger.debug.assert_called()

    def test_008_is_supported_false(self):
        """Test is_supported with unsupported challenge type"""
        result = self.registry.is_supported("non-existent")

        self.assertFalse(result)
        self.logger.debug.assert_called()

    def test_009_validate_challenge_success(self):
        """Test validate_challenge with supported challenge type"""
        # Create a mock validator with validation result
        mock_validator = Mock(spec=ChallengeValidator)
        mock_validator.get_challenge_type.return_value = "test-01"
        validation_result = ValidationResult(success=True, invalid=False)
        mock_validator.validate_challenge.return_value = validation_result

        self.registry.register_validator(mock_validator)

        context = ChallengeContext(
            challenge_name="test",
            token="token",
            jwk_thumbprint="thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )

        result = self.registry.validate_challenge("test-01", context)

        self.assertEqual(result, validation_result)
        mock_validator.validate_challenge.assert_called_once_with(context)
        self.logger.debug.assert_called()

    def test_010_validate_challenge_unsupported_type(self):
        """Test validate_challenge with unsupported challenge type"""
        context = ChallengeContext(
            challenge_name="test",
            token="token",
            jwk_thumbprint="thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )

        with self.assertRaises(InvalidChallengeTypeError) as cm:
            self.registry.validate_challenge("unsupported", context)

        self.assertIn("Unsupported challenge type: unsupported", str(cm.exception))
        self.logger.debug.assert_called()

    def test_011_register_multiple_validators_same_type(self):
        """Test registering multiple validators for the same type overwrites"""
        # Create two validators for the same type
        validator1 = Mock(spec=ChallengeValidator)
        validator1.get_challenge_type.return_value = "test-01"
        validator2 = Mock(spec=ChallengeValidator)
        validator2.get_challenge_type.return_value = "test-01"

        # Register both
        self.registry.register_validator(validator1)
        self.registry.register_validator(validator2)

        # The second should overwrite the first
        result = self.registry.get_validator("test-01")
        self.assertEqual(result, validator2)
        self.assertNotEqual(result, validator1)


class TestHttpChallengeValidator(unittest.TestCase):
    """Test cases for HttpChallengeValidator"""

    def setUp(self):
        """Setup for HTTP validator tests"""
        self.logger = Mock(spec=logging.Logger)
        self.validator = HttpChallengeValidator(self.logger)

    def test_001_get_challenge_type(self):
        """Test get_challenge_type returns correct type"""
        result = self.validator.get_challenge_type()
        self.assertEqual(result, "http-01")

    def test_002_perform_validation_import_error(self):
        """Test perform_validation with import error"""
        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )

        # Mock the import to raise ImportError
        with patch(
            "builtins.__import__", side_effect=ImportError("Module not found")
        ) as mock_import:

            def selective_import_error(name, *args, **kwargs):
                if name == "acme_srv.helper" or (
                    len(args) > 0 and "acme_srv.helper" in str(args)
                ):
                    raise ImportError("Module not found")
                return mock_import.return_value

            mock_import.side_effect = selective_import_error

            result = self.validator.perform_validation(context)

            self.assertFalse(result.success)
            self.assertTrue(result.invalid)
            self.assertIn("Required dependencies not available", result.error_message)
            self.assertIn("import_error", result.details)
            self.assertIn("import_error", result.details)

    @patch("acme_srv.helper.fqdn_resolve")
    @patch("acme_srv.helper.url_get")
    @patch("acme_srv.helper.proxy_check")
    def test_003_perform_validation_dns_success(
        self, mock_proxy_check, mock_url_get, mock_fqdn_resolve
    ):
        """Test successful DNS-based HTTP validation"""
        # Setup mocks
        mock_fqdn_resolve.return_value = (["192.168.1.1"], False, None)
        mock_proxy_check.return_value = None
        expected_response = "test_token.test_thumb"
        mock_url_get.return_value = (expected_response, 200, None)

        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="dns",
            authorization_value="example.com",
            timeout=10,
        )

        result = self.validator.perform_validation(context)

        self.assertTrue(result.success)
        self.assertFalse(result.invalid)
        self.assertIsNone(result.error_message)
        self.assertEqual(result.details["expected"], expected_response)
        self.assertEqual(result.details["received"], expected_response)

        # Verify function calls
        mock_fqdn_resolve.assert_called_once_with(self.logger, "example.com", None)
        mock_url_get.assert_called_once_with(
            self.logger,
            "http://example.com/.well-known/acme-challenge/test_token",
            dns_server_list=None,
            proxy_server=None,
            verify=False,
            timeout=10,
        )

    @patch("acme_srv.helper.fqdn_resolve")
    def test_004_perform_validation_dns_resolution_failed(self, mock_fqdn_resolve):
        """Test HTTP validation with DNS resolution failure"""
        mock_fqdn_resolve.return_value = ([], True, "NXDOMAIN: test.com does not exist")

        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="dns",
            authorization_value="invalid.example.com",
        )

        result = self.validator.perform_validation(context)

        self.assertFalse(result.success)
        self.assertTrue(result.invalid)
        self.assertEqual(
            result.error_message,
            '{"status": 400, "type": "urn:ietf:params:acme:error:dns", "detail": "DNS resolution failed: NXDOMAIN: test.com does not exist"}',
        )
        self.assertEqual(result.details["fqdn"], "invalid.example.com")

    @patch("acme_srv.helper.ip_validate")
    @patch("acme_srv.helper.url_get")
    @patch("acme_srv.helper.proxy_check")
    def test_005_perform_validation_ip_success(
        self, mock_proxy_check, mock_url_get, mock_ip_validate
    ):
        """Test successful IP-based HTTP validation"""
        # Setup mocks
        mock_ip_validate.return_value = ("192.168.1.1", False)
        mock_proxy_check.return_value = None
        expected_response = "test_token.test_thumb"
        mock_url_get.return_value = (expected_response, 200, None)

        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="ip",
            authorization_value="192.168.1.1",
        )

        result = self.validator.perform_validation(context)

        self.assertTrue(result.success)
        self.assertFalse(result.invalid)

        # Verify function calls
        mock_ip_validate.assert_called_once_with(self.logger, "192.168.1.1")

    @patch("acme_srv.helper.ip_validate")
    def test_006_perform_validation_invalid_ip(self, mock_ip_validate):
        """Test HTTP validation with invalid IP address"""
        mock_ip_validate.return_value = ("", True)

        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="ip",
            authorization_value="invalid.ip",
        )

        result = self.validator.perform_validation(context)

        self.assertFalse(result.success)
        self.assertTrue(result.invalid)
        self.assertEqual(
            result.error_message,
            '{"status": 400, "type": "urn:ietf:params:acme:error:malformed", "detail": "Invalid IP address: invalid.ip"}',
        )
        self.assertEqual(result.details["ip"], "invalid.ip")

    def test_007_perform_validation_unsupported_authorization_type(self):
        """Test HTTP validation with unsupported authorization type"""
        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="unsupported",
            authorization_value="test.example.com",
        )

        result = self.validator.perform_validation(context)

        self.assertFalse(result.success)
        self.assertTrue(result.invalid)
        self.assertEqual(
            result.error_message,
            '{"status": 400, "type": "urn:ietf:params:acme:error:unsupported", "detail": "Unsupported authorization type: unsupported"}',
        )
        self.assertEqual(result.details["type"], "unsupported")

    @patch("acme_srv.helper.fqdn_resolve")
    @patch("acme_srv.helper.url_get")
    @patch("acme_srv.helper.proxy_check")
    def test_008_perform_validation_http_request_failed(
        self, mock_proxy_check, mock_url_get, mock_fqdn_resolve
    ):
        """Test HTTP validation with failed HTTP request"""
        mock_fqdn_resolve.return_value = (["192.168.1.1"], False, None)
        mock_proxy_check.return_value = None
        mock_url_get.return_value = (
            None,
            500,
            "Connection failed",
        )  # Simulate request failure

        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )

        result = self.validator.perform_validation(context)

        self.assertFalse(result.success)
        self.assertFalse(result.invalid)
        self.assertEqual(
            result.error_message,
            '{"status": 403, "type": "urn:ietf:params:acme:error:connection", "detail": "HTTP request failed: 500 Connection failed"}',
        )
        self.assertIn("url", result.details)
        self.assertEqual(
            result.details["url"],
            "http://example.com/.well-known/acme-challenge/test_token",
        )

    @patch("acme_srv.helper.fqdn_resolve")
    @patch("acme_srv.helper.url_get")
    @patch("acme_srv.helper.proxy_check")
    def test_009_perform_validation_response_mismatch(
        self, mock_proxy_check, mock_url_get, mock_fqdn_resolve
    ):
        """Test HTTP validation with response mismatch"""
        mock_fqdn_resolve.return_value = (["192.168.1.1"], False, None)
        mock_proxy_check.return_value = None
        mock_url_get.return_value = ("wrong_response\nmore_content", 200, None)

        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )

        result = self.validator.perform_validation(context)

        self.assertFalse(result.success)
        self.assertTrue(result.invalid)
        self.assertEqual(
            result.error_message,
            '{"status": 403, "type": "urn:ietf:params:acme:error:incorrectResponse", "detail": "Keyauthorization mismatch"}',
        )
        self.assertEqual(result.details["expected"], "test_token.test_thumb")
        self.assertEqual(result.details["received"], "wrong_response")

    @patch("acme_srv.helper.fqdn_resolve")
    @patch("acme_srv.helper.url_get")
    @patch("acme_srv.helper.proxy_check")
    def test_010_perform_validation_with_proxy(
        self, mock_proxy_check, mock_url_get, mock_fqdn_resolve
    ):
        """Test HTTP validation with proxy server"""
        mock_fqdn_resolve.return_value = (["192.168.1.1"], False, None)
        mock_proxy_check.return_value = "http://proxy.example.com:8080"
        expected_response = "test_token.test_thumb"
        mock_url_get.return_value = (expected_response, 200, None)

        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="dns",
            authorization_value="example.com",
            proxy_servers={"http": "http://proxy.example.com:8080"},
        )

        result = self.validator.perform_validation(context)

        self.assertTrue(result.success)

        # Verify proxy_check was called
        mock_proxy_check.assert_called_once_with(
            self.logger, "example.com", {"http": "http://proxy.example.com:8080"}
        )

        # Verify url_get was called with proxy
        mock_url_get.assert_called_once_with(
            self.logger,
            "http://example.com/.well-known/acme-challenge/test_token",
            dns_server_list=None,
            proxy_server="http://proxy.example.com:8080",
            verify=False,
            timeout=10,
        )


class TestDnsChallengeValidator(unittest.TestCase):
    """Test cases for DnsChallengeValidator"""

    def setUp(self):
        """Setup for DNS validator tests"""
        self.logger = Mock(spec=logging.Logger)
        self.validator = DnsChallengeValidator(self.logger)

    def test_001_get_challenge_type(self):
        """Test get_challenge_type returns correct type"""
        result = self.validator.get_challenge_type()
        self.assertEqual(result, "dns-01")

    def test_002_perform_validation_import_error(self):
        """Test perform_validation with import error"""
        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )

        # Mock the import to raise ImportError
        with patch(
            "builtins.__import__", side_effect=ImportError("Module not found")
        ) as mock_import:

            def selective_import_error(name, *args, **kwargs):
                if name == "acme_srv.helper" or (
                    len(args) > 0 and "acme_srv.helper" in str(args)
                ):
                    raise ImportError("Module not found")
                return mock_import.return_value

            mock_import.side_effect = selective_import_error

            result = self.validator.perform_validation(context)

            self.assertFalse(result.success)
            self.assertTrue(result.invalid)
            self.assertIn("Required dependencies not available", result.error_message)
            self.assertIn("import_error", result.details)

    @patch("acme_srv.helper.txt_get")
    @patch("acme_srv.helper.b64_url_encode")
    @patch("acme_srv.helper.sha256_hash")
    def test_003_perform_validation_basic_functionality(
        self, mock_sha256, mock_b64_encode, mock_txt_get
    ):
        """Test perform_validation basic functionality"""
        # Mock all external calls to avoid actual DNS lookups
        mock_sha256.return_value = b"mocked_hash"
        mock_b64_encode.return_value = "mocked_encoded_hash"
        mock_txt_get.return_value = []  # Empty DNS response

        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )

        # This should not crash and return a ValidationResult
        result = self.validator.perform_validation(context)
        self.assertIsInstance(result, ValidationResult)

    @patch("acme_srv.helper.b64_url_encode")
    @patch("acme_srv.helper.sha256_hash")
    @patch("acme_srv.helper.txt_get")
    def test_004_perform_validation_success(
        self, mock_txt_get, mock_sha256_hash, mock_b64_url_encode
    ):
        """Test successful DNS validation"""
        # Setup mocks
        mock_sha256_hash.return_value = b"mocked_hash"
        mock_b64_url_encode.return_value = "expected_hash"
        mock_txt_get.return_value = ["expected_hash", "other_record"]

        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )

        result = self.validator.perform_validation(context)

        self.assertTrue(result.success)
        self.assertFalse(result.invalid)
        self.assertIsNone(result.error_message)
        self.assertEqual(result.details["dns_record"], "_acme-challenge.example.com")
        self.assertEqual(result.details["expected_hash"], "expected_hash")
        self.assertEqual(
            result.details["found_records"], ["expected_hash", "other_record"]
        )

        # Verify function calls
        mock_sha256_hash.assert_called_once_with(self.logger, "test_token.test_thumb")
        mock_b64_url_encode.assert_called_once_with(self.logger, b"mocked_hash")
        mock_txt_get.assert_called_once_with(
            self.logger, "_acme-challenge.example.com", None
        )

    @patch("acme_srv.helper.b64_url_encode")
    @patch("acme_srv.helper.sha256_hash")
    @patch("acme_srv.helper.txt_get")
    def test_005_perform_validation_hash_not_found(
        self, mock_txt_get, mock_sha256_hash, mock_b64_url_encode
    ):
        """Test DNS validation when expected hash is not found"""
        # Setup mocks
        mock_sha256_hash.return_value = b"mocked_hash"
        mock_b64_url_encode.return_value = "expected_hash"
        mock_txt_get.return_value = ["wrong_hash", "other_record"]

        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )

        result = self.validator.perform_validation(context)

        self.assertFalse(result.success)
        self.assertTrue(result.invalid)
        self.assertEqual(
            result.error_message,
            '{"status": 403, "type": "urn:ietf:params:acme:error:incorrectResponse", "detail": "DNS record not found or incorrect"}',
        )
        self.assertEqual(result.details["expected_hash"], "expected_hash")
        self.assertEqual(
            result.details["found_records"], ["wrong_hash", "other_record"]
        )

    @patch("acme_srv.helper.b64_url_encode")
    @patch("acme_srv.helper.sha256_hash")
    @patch("acme_srv.helper.txt_get")
    def test_006_perform_validation_wildcard_domain(
        self, mock_txt_get, mock_sha256_hash, mock_b64_url_encode
    ):
        """Test DNS validation with wildcard domain"""
        # Setup mocks
        mock_sha256_hash.return_value = b"mocked_hash"
        mock_b64_url_encode.return_value = "expected_hash"
        mock_txt_get.return_value = ["expected_hash"]

        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="dns",
            authorization_value="*.example.com",
        )

        result = self.validator.perform_validation(context)

        self.assertTrue(result.success)
        self.assertFalse(result.invalid)

        # Verify that wildcard was handled correctly
        mock_txt_get.assert_called_once_with(
            self.logger, "_acme-challenge.example.com", None
        )

    @patch("acme_srv.helper.b64_url_encode")
    @patch("acme_srv.helper.sha256_hash")
    @patch("acme_srv.helper.txt_get")
    def test_007_perform_validation_with_dns_servers(
        self, mock_txt_get, mock_sha256_hash, mock_b64_url_encode
    ):
        """Test DNS validation with custom DNS servers"""
        # Setup mocks
        mock_sha256_hash.return_value = b"mocked_hash"
        mock_b64_url_encode.return_value = "expected_hash"
        mock_txt_get.return_value = ["expected_hash"]

        dns_servers = ["8.8.8.8", "1.1.1.1"]
        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="dns",
            authorization_value="example.com",
            dns_servers=dns_servers,
        )

        result = self.validator.perform_validation(context)

        self.assertTrue(result.success)

        # Verify DNS servers were passed to txt_get
        mock_txt_get.assert_called_once_with(
            self.logger, "_acme-challenge.example.com", dns_servers
        )

    def test_008_handle_wildcard_domain_with_wildcard(self):
        """Test _handle_wildcard_domain with wildcard domain"""
        result = self.validator._handle_wildcard_domain("*.example.com")
        self.assertEqual(result, "example.com")

    def test_009_handle_wildcard_domain_without_wildcard(self):
        """Test _handle_wildcard_domain with regular domain"""
        result = self.validator._handle_wildcard_domain("example.com")
        self.assertEqual(result, "example.com")

    def test_010_handle_wildcard_domain_subdomain_wildcard(self):
        """Test _handle_wildcard_domain with subdomain wildcard"""
        result = self.validator._handle_wildcard_domain("*.sub.example.com")
        self.assertEqual(result, "sub.example.com")

    @patch("acme_srv.helper.b64_url_encode")
    @patch("acme_srv.helper.sha256_hash")
    @patch("acme_srv.helper.txt_get")
    def test_011_perform_validation_empty_dns_records(
        self, mock_txt_get, mock_sha256_hash, mock_b64_url_encode
    ):
        """Test DNS validation with empty DNS records"""
        # Setup mocks
        mock_sha256_hash.return_value = b"mocked_hash"
        mock_b64_url_encode.return_value = "expected_hash"
        mock_txt_get.return_value = []

        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )

        result = self.validator.perform_validation(context)

        self.assertFalse(result.success)
        self.assertTrue(result.invalid)
        self.assertEqual(result.details["found_records"], [])


class TestTlsAlpnChallengeValidator(unittest.TestCase):
    """Test cases for TlsAlpnChallengeValidator"""

    def setUp(self):
        """Setup for TLS-ALPN validator tests"""
        self.logger = Mock(spec=logging.Logger)
        self.validator = TlsAlpnChallengeValidator(self.logger)

    def test_001_get_challenge_type(self):
        """Test get_challenge_type returns correct type"""
        result = self.validator.get_challenge_type()
        self.assertEqual(result, "tls-alpn-01")

    def test_002_perform_validation_import_error(self):
        """Test perform_validation with import error"""
        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )

        # Mock the import to raise ImportError
        with patch(
            "builtins.__import__", side_effect=ImportError("Module not found")
        ) as mock_import:

            def selective_import_error(name, *args, **kwargs):
                if name == "acme_srv.helper" or (
                    len(args) > 0 and "acme_srv.helper" in str(args)
                ):
                    raise ImportError("Module not found")
                return mock_import.return_value

            mock_import.side_effect = selective_import_error

            result = self.validator.perform_validation(context)

            self.assertFalse(result.success)
            self.assertTrue(result.invalid)
            self.assertIn("Required dependencies not available", result.error_message)
            self.assertIn("import_error", result.details)

    @patch("acme_srv.helper.fqdn_resolve")
    @patch("acme_srv.helper.sha256_hash_hex")
    @patch("acme_srv.helper.b64_encode")
    @patch("acme_srv.helper.servercert_get")
    @patch("acme_srv.helper.proxy_check")
    def test_003_perform_validation_basic_functionality(
        self,
        mock_proxy_check,
        mock_servercert_get,
        mock_b64_encode,
        mock_sha256_hash_hex,
        mock_fqdn_resolve,
    ):
        """Test perform_validation basic functionality"""
        # Mock all external calls to avoid actual network operations
        mock_fqdn_resolve.return_value = (
            [],
            True,
            "DNS resolution error",
        )  # DNS resolution failed
        mock_sha256_hash_hex.return_value = (
            "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
        )
        mock_b64_encode.return_value = "mocked_extension"
        mock_servercert_get.return_value = None
        mock_proxy_check.return_value = None

        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )

        # This should not crash and return a ValidationResult
        result = self.validator.perform_validation(context)
        self.assertIsInstance(result, ValidationResult)

    @patch("acme_srv.helper.fqdn_resolve")
    @patch("acme_srv.helper.sha256_hash_hex")
    @patch("acme_srv.helper.b64_encode")
    @patch("acme_srv.helper.servercert_get")
    @patch("acme_srv.helper.proxy_check")
    def test_003_perform_validation_dns_success(
        self,
        mock_proxy_check,
        mock_servercert_get,
        mock_b64_encode,
        mock_sha256_hash_hex,
        mock_fqdn_resolve,
    ):
        """Test successful TLS-ALPN validation with DNS"""
        # Setup mocks
        mock_fqdn_resolve.return_value = (["192.168.1.1"], False, None)
        mock_sha256_hash_hex.return_value = (
            "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
        )
        mock_b64_encode.return_value = "expected_extension"
        mock_servercert_get.return_value = "mock_certificate"
        mock_proxy_check.return_value = None

        # Mock the certificate validation method
        with patch.object(
            self.validator, "_validate_certificate_extensions", return_value=True
        ):
            context = ChallengeContext(
                challenge_name="test",
                token="test_token",
                jwk_thumbprint="test_thumb",
                authorization_type="dns",
                authorization_value="example.com",
            )

            result = self.validator.perform_validation(context)

            self.assertTrue(result.success)
            self.assertFalse(result.invalid)
            self.assertIsNone(result.error_message)

            # Verify function calls
            mock_fqdn_resolve.assert_called_once_with(self.logger, "example.com", None)
            mock_sha256_hash_hex.assert_called_once_with(
                self.logger, "test_token.test_thumb"
            )
            mock_servercert_get.assert_called_once_with(
                self.logger, "example.com", 443, None, "example.com"
            )

    @patch("acme_srv.helper.fqdn_resolve")
    def test_004_perform_validation_dns_resolution_failed(self, mock_fqdn_resolve):
        """Test TLS-ALPN validation with DNS resolution failure"""
        mock_fqdn_resolve.return_value = ([], True, "DNS resolution error")

        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="dns",
            authorization_value="invalid.example.com",
        )

        result = self.validator.perform_validation(context)

        self.assertFalse(result.success)
        self.assertTrue(result.invalid)
        self.assertEqual(
            result.error_message,
            '{"status": 400, "type": "urn:ietf:params:acme:error:dns", "detail": "DNS resolution failed: DNS resolution error"}',
        )

    @patch("acme_srv.helper.ip_validate")
    @patch("acme_srv.helper.sha256_hash_hex")
    @patch("acme_srv.helper.b64_encode")
    @patch("acme_srv.helper.servercert_get")
    @patch("acme_srv.helper.proxy_check")
    def test_005_perform_validation_ip_success(
        self,
        mock_proxy_check,
        mock_servercert_get,
        mock_b64_encode,
        mock_sha256_hash_hex,
        mock_ip_validate,
    ):
        """Test successful TLS-ALPN validation with IP"""
        # Setup mocks
        mock_ip_validate.return_value = ("192.168.1.1", False)
        mock_sha256_hash_hex.return_value = (
            "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
        )
        mock_b64_encode.return_value = "expected_extension"
        mock_servercert_get.return_value = "mock_certificate"
        mock_proxy_check.return_value = None

        # Mock the certificate validation method
        with patch.object(
            self.validator, "_validate_certificate_extensions", return_value=True
        ):
            context = ChallengeContext(
                challenge_name="test",
                token="test_token",
                jwk_thumbprint="test_thumb",
                authorization_type="ip",
                authorization_value="192.168.1.1",
            )

            result = self.validator.perform_validation(context)

            self.assertTrue(result.success)
            self.assertFalse(result.invalid)

            # Verify IP validation was called
            mock_ip_validate.assert_called_once_with(self.logger, "192.168.1.1")

    @patch("acme_srv.helper.ip_validate")
    def test_006_perform_validation_invalid_ip(self, mock_ip_validate):
        """Test TLS-ALPN validation with invalid IP"""
        mock_ip_validate.return_value = ("", True)

        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="ip",
            authorization_value="invalid.ip",
        )

        result = self.validator.perform_validation(context)

        self.assertFalse(result.success)
        self.assertTrue(result.invalid)
        self.assertEqual(
            result.error_message,
            '{"status": 400, "type": "urn:ietf:params:acme:error:malformed", "detail": "Invalid IP address: invalid.ip"}',
        )

    def test_007_perform_validation_unsupported_authorization_type(self):
        """Test TLS-ALPN validation with unsupported authorization type"""
        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="unsupported",
            authorization_value="test.example.com",
        )

        result = self.validator.perform_validation(context)

        self.assertFalse(result.success)
        self.assertTrue(result.invalid)
        self.assertEqual(
            result.error_message,
            '{"status": 400, "type": "urn:ietf:params:acme:error:unsupported", "detail": "Unsupported authorization type: unsupported"}',
        )

    @patch("acme_srv.helper.fqdn_resolve")
    @patch("acme_srv.helper.sha256_hash_hex")
    @patch("acme_srv.helper.b64_encode")
    @patch("acme_srv.helper.servercert_get")
    @patch("acme_srv.helper.proxy_check")
    def test_008_perform_validation_cert_retrieval_failed(
        self,
        mock_proxy_check,
        mock_servercert_get,
        mock_b64_encode,
        mock_sha256_hash_hex,
        mock_fqdn_resolve,
    ):
        """Test TLS-ALPN validation with certificate retrieval failure"""
        # Setup mocks
        mock_fqdn_resolve.return_value = (["192.168.1.1"], False, None)
        mock_sha256_hash_hex.return_value = (
            "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
        )
        mock_b64_encode.return_value = "expected_extension"
        mock_servercert_get.return_value = None  # Simulate failure
        mock_proxy_check.return_value = None

        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )

        result = self.validator.perform_validation(context)

        self.assertFalse(result.success)
        self.assertFalse(result.invalid)
        self.assertEqual(
            result.error_message,
            '{"status": 400, "type": "urn:ietf:params:acme:error:incorrectResponse", "detail": "Unable to retrieve server certificate for example.com"}',
        )

    @patch("acme_srv.helper.fqdn_resolve")
    @patch("acme_srv.helper.sha256_hash_hex")
    @patch("acme_srv.helper.b64_encode")
    @patch("acme_srv.helper.servercert_get")
    @patch("acme_srv.helper.proxy_check")
    def test_009_perform_validation_cert_validation_failed(
        self,
        mock_proxy_check,
        mock_servercert_get,
        mock_b64_encode,
        mock_sha256_hash_hex,
        mock_fqdn_resolve,
    ):
        """Test TLS-ALPN validation with certificate validation failure"""
        # Setup mocks
        mock_fqdn_resolve.return_value = (["192.168.1.1"], False, None)
        mock_sha256_hash_hex.return_value = (
            "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
        )
        mock_b64_encode.return_value = "expected_extension"
        mock_servercert_get.return_value = "mock_certificate"
        mock_proxy_check.return_value = None

        # Mock the certificate validation method to return False
        with patch.object(
            self.validator, "_validate_certificate_extensions", return_value=False
        ):
            context = ChallengeContext(
                challenge_name="test",
                token="test_token",
                jwk_thumbprint="test_thumb",
                authorization_type="dns",
                authorization_value="example.com",
            )

            result = self.validator.perform_validation(context)

            self.assertFalse(result.success)
            self.assertTrue(result.invalid)
            self.assertEqual(
                result.error_message,
                '{"status": 403, "type": "urn:ietf:params:acme:error:incorrectResponse", "detail": "Certificate extension validation failed"}',
            )

    @patch("acme_srv.helper.cert_san_get")
    @patch("acme_srv.helper.fqdn_in_san_check")
    @patch("acme_srv.helper.cert_extensions_get")
    def test_010_validate_certificate_extensions_success(
        self, mock_cert_extensions_get, mock_fqdn_in_san_check, mock_cert_san_get
    ):
        """Test _validate_certificate_extensions with successful validation"""
        # Setup mocks
        mock_cert_san_get.return_value = ["example.com", "www.example.com"]
        mock_fqdn_in_san_check.return_value = True
        mock_cert_extensions_get.return_value = [
            "expected_extension",
            "other_extension",
        ]

        result = self.validator._validate_certificate_extensions(
            cert="mock_cert", extension_value="expected_extension", fqdn="example.com"
        )

        self.assertTrue(result)

        # Verify function calls
        mock_cert_san_get.assert_called_once_with(
            self.logger, "mock_cert", recode=False
        )
        mock_fqdn_in_san_check.assert_called_once_with(
            self.logger, ["example.com", "www.example.com"], "example.com"
        )
        mock_cert_extensions_get.assert_called_once_with(
            self.logger, "mock_cert", recode=False
        )

    @patch("acme_srv.helper.cert_san_get")
    @patch("acme_srv.helper.fqdn_in_san_check")
    def test_011_validate_certificate_extensions_fqdn_not_in_san(
        self, mock_fqdn_in_san_check, mock_cert_san_get
    ):
        """Test _validate_certificate_extensions with FQDN not in SAN"""
        # Setup mocks
        mock_cert_san_get.return_value = ["other.example.com"]
        mock_fqdn_in_san_check.return_value = False

        result = self.validator._validate_certificate_extensions(
            cert="mock_cert", extension_value="expected_extension", fqdn="example.com"
        )

        self.assertFalse(result)

    @patch("acme_srv.helper.cert_san_get")
    @patch("acme_srv.helper.fqdn_in_san_check")
    @patch("acme_srv.helper.cert_extensions_get")
    def test_012_validate_certificate_extensions_extension_not_found(
        self, mock_cert_extensions_get, mock_fqdn_in_san_check, mock_cert_san_get
    ):
        """Test _validate_certificate_extensions with extension not found"""
        # Setup mocks
        mock_cert_san_get.return_value = ["example.com"]
        mock_fqdn_in_san_check.return_value = True
        mock_cert_extensions_get.return_value = ["other_extension", "wrong_extension"]

        result = self.validator._validate_certificate_extensions(
            cert="mock_cert", extension_value="expected_extension", fqdn="example.com"
        )

        self.assertFalse(result)

    @patch("acme_srv.helper.cert_san_get")
    @patch("acme_srv.helper.fqdn_in_san_check")
    @patch("acme_srv.helper.cert_extensions_get")
    def test_013_validate_certificate_extensions_basic_functionality(
        self, mock_cert_extensions_get, mock_fqdn_in_san_check, mock_cert_san_get
    ):
        """Test _validate_certificate_extensions basic functionality"""
        # Setup mocks to avoid actual certificate parsing
        mock_cert_san_get.return_value = ["example.com"]
        mock_fqdn_in_san_check.return_value = True
        mock_cert_extensions_get.return_value = ["expected_extension"]

        result = self.validator._validate_certificate_extensions(
            cert="mock_cert", extension_value="expected_extension", fqdn="example.com"
        )

        # Should return True when everything matches
        self.assertTrue(result)

    def test_014_validate_certificate_extensions_import_error(self):
        """Test _validate_certificate_extensions with import error"""
        # Mock the import to raise ImportError for the helper functions
        with patch(
            "builtins.__import__", side_effect=ImportError("Module not found")
        ) as mock_import:

            def selective_import_error(name, *args, **kwargs):
                if name == "acme_srv.helper" or (
                    len(args) > 0 and "acme_srv.helper" in str(args)
                ):
                    raise ImportError("Module not found")
                return mock_import.return_value

            mock_import.side_effect = selective_import_error

            result = self.validator._validate_certificate_extensions(
                cert="mock_cert",
                extension_value="expected_extension",
                fqdn="example.com",
            )

            # Should return False when import fails
            self.assertFalse(result)

    @patch("acme_srv.helper.fqdn_resolve")
    @patch("acme_srv.helper.sha256_hash_hex")
    @patch("acme_srv.helper.b64_encode")
    @patch("acme_srv.helper.servercert_get")
    @patch("acme_srv.helper.proxy_check")
    def test_015_perform_validation_with_proxy_servers(
        self,
        mock_proxy_check,
        mock_servercert_get,
        mock_b64_encode,
        mock_sha256_hash_hex,
        mock_fqdn_resolve,
    ):
        """Test TLS-ALPN validation with proxy servers configured"""
        # Setup mocks
        mock_fqdn_resolve.return_value = (["192.168.1.1"], False, None)
        mock_sha256_hash_hex.return_value = (
            "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
        )
        mock_b64_encode.return_value = "expected_extension"
        mock_servercert_get.return_value = "mock_certificate"
        mock_proxy_check.return_value = (
            "proxy.example.com:8080"  # Return a proxy server
        )

        # Mock the certificate validation method
        with patch.object(
            self.validator, "_validate_certificate_extensions", return_value=True
        ):
            context = ChallengeContext(
                challenge_name="test",
                token="test_token",
                jwk_thumbprint="test_thumb",
                authorization_type="dns",
                authorization_value="example.com",
            )
            # Set proxy_servers to trigger the proxy_check code path (line 73)
            context.proxy_servers = [
                "proxy1.example.com:8080",
                "proxy2.example.com:8080",
            ]

            result = self.validator.perform_validation(context)

            self.assertTrue(result.success)
            self.assertFalse(result.invalid)
            self.assertIsNone(result.error_message)

            # Verify that proxy_check was called with the correct parameters
            mock_proxy_check.assert_called_once_with(
                self.logger,
                "example.com",
                ["proxy1.example.com:8080", "proxy2.example.com:8080"],
            )
            # Verify that servercert_get was called with the proxy server
            mock_servercert_get.assert_called_once_with(
                self.logger, "example.com", 443, "proxy.example.com:8080", "example.com"
            )


class TestEmailReplyChallengeValidator(unittest.TestCase):
    """Test cases for EmailReplyChallengeValidator"""

    def setUp(self):
        """Setup for Email Reply validator tests"""
        self.logger = Mock(spec=logging.Logger)
        self.validator = EmailReplyChallengeValidator(self.logger)

    def test_001_get_challenge_type(self):
        """Test get_challenge_type returns correct type"""
        result = self.validator.get_challenge_type()
        self.assertEqual(result, "email-reply-00")

    def test_002_perform_validation_import_error(self):
        """Test perform_validation with import error"""
        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )

        # Mock the import to raise ImportError
        with patch(
            "builtins.__import__", side_effect=ImportError("Module not found")
        ) as mock_import:

            def selective_import_error(name, *args, **kwargs):
                if name == "acme_srv.email_handler" or (
                    len(args) > 0 and "acme_srv.email_handler" in str(args)
                ):
                    raise ImportError("Module not found")
                return mock_import.return_value

            mock_import.side_effect = selective_import_error

            result = self.validator.perform_validation(context)

            self.assertFalse(result.success)
            self.assertTrue(result.invalid)
            self.assertIn("Email handler not available", result.error_message)
            self.assertIn("import_error", result.details)

    @patch("acme_srv.email_handler.EmailHandler")
    def test_003_perform_validation_basic_functionality(self, mock_email_handler):
        """Test perform_validation basic functionality"""
        # Setup a basic mock that doesn't crash
        mock_handler_instance = Mock()
        mock_handler_instance.receive.return_value = None
        mock_email_handler.return_value.__enter__.return_value = mock_handler_instance

        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="email",
            authorization_value="test@example.com",
        )

        # This should not crash and return a ValidationResult
        result = self.validator.perform_validation(context)
        self.assertIsInstance(result, ValidationResult)

    @patch("acme_srv.email_handler.EmailHandler")
    @patch.object(EmailReplyChallengeValidator, "_generate_email_keyauth")
    @patch.object(EmailReplyChallengeValidator, "_extract_email_keyauth")
    def test_004_perform_validation_success(
        self, mock_extract, mock_generate, mock_email_handler
    ):
        """Test successful email reply validation"""
        # Setup mocks
        mock_generate.return_value = ("expected_keyauth", "rfc_token1")
        mock_extract.return_value = "expected_keyauth"

        mock_handler_instance = Mock()
        mock_handler_instance.receive.return_value = {"body": "email_body_content"}
        mock_email_handler.return_value.__enter__.return_value = mock_handler_instance

        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="email",
            authorization_value="test@example.com",
            keyauthorization="test_keyauth",
        )

        result = self.validator.perform_validation(context)

        self.assertTrue(result.success)
        self.assertFalse(result.invalid)
        self.assertIsNone(result.error_message)
        self.assertEqual(result.details["calculated_keyauth"], "expected_keyauth")

    @patch("acme_srv.email_handler.EmailHandler")
    @patch.object(EmailReplyChallengeValidator, "_generate_email_keyauth")
    def test_005_perform_validation_no_email_received(
        self, mock_generate, mock_email_handler
    ):
        """Test validation with no email received"""
        # Setup mocks
        mock_generate.return_value = ("expected_keyauth", "rfc_token1")

        mock_handler_instance = Mock()
        mock_handler_instance.receive.return_value = None
        mock_email_handler.return_value.__enter__.return_value = mock_handler_instance

        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="email",
            authorization_value="test@example.com",
        )

        result = self.validator.perform_validation(context)

        self.assertFalse(result.success)
        self.assertFalse(result.invalid)
        self.assertEqual(
            result.error_message, "No email received or email body missing"
        )

    @patch("acme_srv.email_handler.EmailHandler")
    @patch.object(EmailReplyChallengeValidator, "_generate_email_keyauth")
    def test_006_perform_validation_email_missing_body(
        self, mock_generate, mock_email_handler
    ):
        """Test validation with email missing body"""
        # Setup mocks
        mock_generate.return_value = ("expected_keyauth", "rfc_token1")

        mock_handler_instance = Mock()
        mock_handler_instance.receive.return_value = {"subject": "ACME challenge"}
        mock_email_handler.return_value.__enter__.return_value = mock_handler_instance

        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="email",
            authorization_value="test@example.com",
        )

        result = self.validator.perform_validation(context)

        self.assertFalse(result.success)
        self.assertFalse(result.invalid)
        self.assertEqual(
            result.error_message, "No email received or email body missing"
        )

    @patch("acme_srv.email_handler.EmailHandler")
    @patch.object(EmailReplyChallengeValidator, "_generate_email_keyauth")
    @patch.object(EmailReplyChallengeValidator, "_extract_email_keyauth")
    def test_007_perform_validation_keyauth_mismatch(
        self, mock_extract, mock_generate, mock_email_handler
    ):
        """Test validation with keyauth mismatch"""
        # Setup mocks
        mock_generate.return_value = ("expected_keyauth", "rfc_token1")
        mock_extract.return_value = "wrong_keyauth"

        mock_handler_instance = Mock()
        mock_handler_instance.receive.return_value = {"body": "email_body_content"}
        mock_email_handler.return_value.__enter__.return_value = mock_handler_instance

        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="email",
            authorization_value="test@example.com",
        )

        result = self.validator.perform_validation(context)

        self.assertFalse(result.success)
        self.assertTrue(result.invalid)
        self.assertEqual(result.error_message, "Email keyauthorization mismatch")
        self.assertEqual(result.details["expected"], "expected_keyauth")
        self.assertEqual(result.details["received"], "wrong_keyauth")

    @patch("acme_srv.challenge_validators.email_reply_validator.convert_byte_to_string")
    @patch("acme_srv.challenge_validators.email_reply_validator.b64_url_encode")
    @patch("acme_srv.challenge_validators.email_reply_validator.sha256_hash")
    def test_007_generate_email_keyauth(
        self, mock_sha256, mock_b64_encode, mock_convert
    ):
        """Test _generate_email_keyauth method"""
        mock_sha256.return_value = b"hash_result"
        mock_b64_encode.return_value = b"encoded_result"
        mock_convert.return_value = "string_result"

        result, rfc_token = self.validator._generate_email_keyauth(
            challenge_name="test_challenge",
            rfc_token2="token2",
            jwk_thumbprint="thumb",
            rfc_token1="token1",
        )

        self.assertEqual(result, "string_result")
        self.assertEqual(rfc_token, "token1")

        # Verify function calls
        mock_sha256.assert_called_once_with(self.logger, "token1token2.thumb")
        mock_b64_encode.assert_called_once_with(self.logger, b"hash_result")
        mock_convert.assert_called_once_with(b"encoded_result")

    def test_008_filter_email_matching_subject(self):
        """Test _filter_email with matching subject"""
        email_data = {"subject": "ACME: token123", "body": "test email body"}
        rfc_token1 = "token123"

        result = self.validator._filter_email(email_data, rfc_token1)

        self.assertEqual(result, email_data)

    def test_009_filter_email_non_matching_subject(self):
        """Test _filter_email with non-matching subject"""
        email_data = {"subject": "Different subject", "body": "test email body"}
        rfc_token1 = "token123"

        result = self.validator._filter_email(email_data, rfc_token1)

        self.assertIsNone(result)

    def test_010_filter_email_missing_subject(self):
        """Test _filter_email with missing subject"""
        email_data = {"body": "test email body"}
        rfc_token1 = "token123"

        result = self.validator._filter_email(email_data, rfc_token1)

        self.assertIsNone(result)

    def test_011_extract_email_keyauth_valid_format(self):
        """Test _extract_email_keyauth with valid format"""
        email_body = """
        Some email content
        -----BEGIN ACME RESPONSE-----
        test_keyauth_value
        -----END ACME RESPONSE-----
        More content
        """

        result = self.validator._extract_email_keyauth(email_body)

        self.assertEqual(result, "test_keyauth_value")

    def test_012_extract_email_keyauth_multiline_response(self):
        """Test _extract_email_keyauth with multiline response - current limitation"""
        email_body = """
        Some email content
        -----BEGIN ACME RESPONSE-----
        test_keyauth_value
        with multiple lines
        -----END ACME RESPONSE-----
        More content
        """

        result = self.validator._extract_email_keyauth(email_body)

        # Current implementation limitation: regex pattern [\w=+/ -]+ doesn't match newlines
        # so multiline ACME responses return None instead of the expected content
        self.assertIsNone(result)

    def test_013_extract_email_keyauth_no_match(self):
        """Test _extract_email_keyauth with no match"""
        email_body = "Some email content without ACME response"

        result = self.validator._extract_email_keyauth(email_body)

        self.assertIsNone(result)

    def test_014_extract_email_keyauth_empty_body(self):
        """Test _extract_email_keyauth with empty body"""
        result = self.validator._extract_email_keyauth("")

        self.assertIsNone(result)

    def test_015_extract_email_keyauth_none_body(self):
        """Test _extract_email_keyauth with None body"""
        result = self.validator._extract_email_keyauth(None)

        self.assertIsNone(result)


class TestTkauthChallengeValidator(unittest.TestCase):
    """Test cases for TkauthChallengeValidator"""

    def setUp(self):
        """Setup for TKAuth validator tests"""
        self.logger = Mock(spec=logging.Logger)
        self.validator = TkauthChallengeValidator(self.logger)

    def test_001_get_challenge_type(self):
        """Test get_challenge_type returns correct type"""
        result = self.validator.get_challenge_type()
        self.assertEqual(result, "tkauth-01")

    def test_002_perform_validation_success(self):
        """Test perform_validation success (placeholder implementation)"""
        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )

        result = self.validator.perform_validation(context)

        # Based on the actual placeholder implementation
        self.assertTrue(result.success)
        self.assertFalse(result.invalid)
        self.assertIsNone(result.error_message)
        self.assertEqual(result.details["validation_type"], "tkauth-01")
        self.assertEqual(result.details["authorization_value"], "example.com")


class TestSourceAddressValidator(unittest.TestCase):
    """Test cases for SourceAddressValidator"""

    def setUp(self):
        """Setup for Source Address validator tests"""
        self.logger = Mock(spec=logging.Logger)
        self.validator = SourceAddressValidator(
            self.logger, forward_check=True, reverse_check=True
        )

    def test_001_get_challenge_type(self):
        """Test get_challenge_type returns correct type"""
        result = self.validator.get_challenge_type()
        self.assertEqual(result, "source-address")

    def test_002_perform_validation_import_error(self):
        """Test perform_validation with import error"""
        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )
        context.source_address = "192.168.1.1"

        # Mock the import to raise ImportError
        with patch(
            "builtins.__import__", side_effect=ImportError("Module not found")
        ) as mock_import:

            def selective_import_error(name, *args, **kwargs):
                if name == "acme_srv.helper" or (
                    len(args) > 0 and "acme_srv.helper" in str(args)
                ):
                    raise ImportError("Module not found")
                return mock_import.return_value

            mock_import.side_effect = selective_import_error

            result = self.validator.perform_validation(context)

            self.assertFalse(result.success)
            self.assertTrue(result.invalid)
            self.assertIn("Required dependencies not available", result.error_message)
            self.assertIn("import_error", result.details)

    @patch("acme_srv.helper.ptr_resolve")
    @patch("acme_srv.helper.fqdn_resolve")
    def test_003_perform_validation_basic_functionality(
        self, mock_fqdn_resolve, mock_ptr_resolve
    ):
        """Test perform_validation basic functionality"""
        # Mock DNS resolution to prevent network calls
        mock_fqdn_resolve.return_value = (["192.168.1.1"], False, None)
        mock_ptr_resolve.return_value = []

        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )
        context.source_address = "192.168.1.1"

        # This should not crash and return a ValidationResult
        result = self.validator.perform_validation(context)
        self.assertIsInstance(result, ValidationResult)

    def test_004_perform_validation_no_source_address(self):
        """Test perform_validation with no source address"""
        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )
        # No source_address set

        result = self.validator.perform_validation(context)

        self.assertTrue(result.success)
        self.assertFalse(result.invalid)
        self.assertEqual(
            result.details["message"], "No source address provided, skipping validation"
        )

    @patch.object(SourceAddressValidator, "_perform_forward_check")
    @patch.object(SourceAddressValidator, "_perform_reverse_check")
    def test_005_perform_validation_both_checks_success(
        self, mock_reverse, mock_forward
    ):
        """Test successful validation with both checks enabled"""
        # Setup mocks
        mock_forward.return_value = {
            "forward_check_passed": True,
            "resolved_ips": ["192.168.1.1"],
        }
        mock_reverse.return_value = {
            "reverse_check_passed": True,
            "reverse_domains": ["example.com"],
        }

        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )
        context.source_address = "192.168.1.1"
        context.dns_servers = []

        result = self.validator.perform_validation(context)

        self.assertTrue(result.success)
        self.assertFalse(result.invalid)

        # Verify method calls
        mock_forward.assert_called_once_with("example.com", "192.168.1.1", [])
        mock_reverse.assert_called_once_with("example.com", "192.168.1.1", [])

    @patch.object(SourceAddressValidator, "_perform_forward_check")
    def test_006_perform_validation_forward_check_failed(self, mock_forward):
        """Test validation with forward check failure"""
        mock_forward.return_value = {
            "forward_check_passed": False,
            "resolved_ips": ["192.168.1.100"],
        }

        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )
        context.source_address = "192.168.1.1"
        context.dns_servers = []

        result = self.validator.perform_validation(context)

        self.assertFalse(result.success)
        self.assertTrue(result.invalid)
        self.assertEqual(
            result.error_message,
            '{"status": 400, "type": "urn:ietf:params:acme:error:unauthorized", "detail": "Forward check failed: Forward address check failed"}',
        )

    @patch.object(SourceAddressValidator, "_perform_forward_check")
    @patch.object(SourceAddressValidator, "_perform_reverse_check")
    def test_007_perform_validation_reverse_check_failed(
        self, mock_reverse, mock_forward
    ):
        """Test validation with reverse check failure"""
        mock_forward.return_value = {
            "forward_check_passed": True,
            "resolved_ips": ["192.168.1.1"],
        }
        mock_reverse.return_value = {
            "reverse_check_passed": False,
            "reverse_domains": ["other.com"],
        }

        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )
        context.source_address = "192.168.1.1"
        context.dns_servers = []

        result = self.validator.perform_validation(context)

        self.assertFalse(result.success)
        self.assertTrue(result.invalid)
        self.assertEqual(
            result.error_message,
            '{"status": 400, "type": "urn:ietf:params:acme:error:unauthorized", "detail": "Reverse check failed: Reverse address check failed"}',
        )

    def test_008_perform_validation_forward_only(self):
        """Test validation with only forward check enabled"""
        validator = SourceAddressValidator(
            self.logger, forward_check=True, reverse_check=False
        )

        with patch.object(validator, "_perform_forward_check") as mock_forward:
            mock_forward.return_value = {
                "forward_check_passed": True,
                "resolved_ips": ["192.168.1.1"],
            }

            context = ChallengeContext(
                challenge_name="test",
                token="test_token",
                jwk_thumbprint="test_thumb",
                authorization_type="dns",
                authorization_value="example.com",
            )
            context.source_address = "192.168.1.1"
            context.dns_servers = []

            result = validator.perform_validation(context)

            self.assertTrue(result.success)
            self.assertFalse(result.invalid)
            mock_forward.assert_called_once()

    @patch("acme_srv.helper.fqdn_resolve")
    def test_009_perform_forward_check_success(self, mock_fqdn_resolve):
        """Test _perform_forward_check success"""
        mock_fqdn_resolve.return_value = (["192.168.1.1", "192.168.1.2"], False, None)

        result = self.validator._perform_forward_check("example.com", "192.168.1.1", [])

        self.assertTrue(result["forward_check_passed"])
        self.assertEqual(result["resolved_ips"], ["192.168.1.1", "192.168.1.2"])
        self.assertEqual(result["domain"], "example.com")

    @patch("acme_srv.helper.fqdn_resolve")
    def test_010_perform_forward_check_failure(self, mock_fqdn_resolve):
        """Test _perform_forward_check failure"""
        mock_fqdn_resolve.return_value = (
            ["192.168.1.100"],
            False,
            None,
        )  # Different IP

        result = self.validator._perform_forward_check("example.com", "192.168.1.1", [])

        self.assertFalse(result["forward_check_passed"])
        self.assertEqual(result["resolved_ips"], ["192.168.1.100"])

    @patch("acme_srv.helper.fqdn_resolve")
    def test_011_perform_forward_check_exception(self, mock_fqdn_resolve):
        """Test _perform_forward_check with exception"""
        mock_fqdn_resolve.side_effect = Exception("DNS error")

        result = self.validator._perform_forward_check("example.com", "192.168.1.1", [])

        self.assertFalse(result["forward_check_passed"])
        self.assertEqual(result["error"], "DNS error")

    @patch("acme_srv.helper.ptr_resolve")
    def test_012_perform_reverse_check_success(self, mock_ptr_resolve):
        """Test _perform_reverse_check success"""
        mock_ptr_resolve.return_value = ["example.com", "www.example.com"]

        with patch.object(self.validator, "_domain_matches", return_value=True):
            result = self.validator._perform_reverse_check(
                "example.com", "192.168.1.1", []
            )

            self.assertTrue(result["reverse_check_passed"])
            self.assertEqual(
                result["reverse_domains"], ["example.com", "www.example.com"]
            )

    @patch("acme_srv.helper.ptr_resolve")
    def test_013_perform_reverse_check_failure(self, mock_ptr_resolve):
        """Test _perform_reverse_check failure"""
        mock_ptr_resolve.return_value = ["other.com"]

        with patch.object(self.validator, "_domain_matches", return_value=False):
            result = self.validator._perform_reverse_check(
                "example.com", "192.168.1.1", []
            )

            self.assertFalse(result["reverse_check_passed"])

    @patch("acme_srv.helper.ptr_resolve")
    def test_014_perform_reverse_check_exception(self, mock_ptr_resolve):
        """Test _perform_reverse_check with exception"""
        mock_ptr_resolve.side_effect = Exception("PTR error")

        result = self.validator._perform_reverse_check("example.com", "192.168.1.1", [])

        self.assertFalse(result["reverse_check_passed"])
        self.assertEqual(result["error"], "PTR error")

    def test_015_domain_matches_exact(self):
        """Test _domain_matches with exact match"""
        result = self.validator._domain_matches("example.com", "example.com")
        self.assertTrue(result)

    def test_016_domain_matches_subdomain(self):
        """Test _domain_matches with subdomain"""
        result = self.validator._domain_matches("example.com", "www.example.com")
        self.assertTrue(result)

    def test_017_domain_matches_no_match(self):
        """Test _domain_matches with no match"""
        result = self.validator._domain_matches("example.com", "other.com")
        self.assertFalse(result)

    def test_018_domain_matches_case_insensitive(self):
        """Test _domain_matches is case insensitive"""
        result = self.validator._domain_matches("Example.Com", "EXAMPLE.COM")
        self.assertTrue(result)

    def test_019_domain_matches_trailing_dots(self):
        """Test _domain_matches handles trailing dots"""
        result = self.validator._domain_matches("example.com.", "example.com")
        self.assertTrue(result)

    def test_020_perform_validation_context_options_override(self):
        """Test perform_validation with context options overriding check settings"""
        context = ChallengeContext(
            challenge_name="test",
            token="test_token",
            jwk_thumbprint="test_thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )
        context.source_address = "192.168.1.1"
        context.dns_servers = []
        # Set options to override the validator's default settings
        context.options = {
            "forward_address_check": False,
            "reverse_address_check": False,
        }

        # Mock the forward and reverse check methods to track if they're called
        with patch.object(
            self.validator, "_perform_forward_check"
        ) as mock_forward, patch.object(
            self.validator, "_perform_reverse_check"
        ) as mock_reverse:

            result = self.validator.perform_validation(context)

            # Since both checks are disabled via options, neither should be called
            mock_forward.assert_not_called()
            mock_reverse.assert_not_called()

            # Should return success since no validation is performed
            self.assertTrue(result.success)
            self.assertFalse(result.invalid)

    @patch("acme_srv.helper.fqdn_resolve")
    def test_021_perform_forward_check_dns_error_logging(self, mock_fqdn_resolve):
        """Test _perform_forward_check with DNS resolution error and logging"""
        # Setup mock to return an error message
        mock_fqdn_resolve.return_value = ([], False, "DNS resolution timeout")

        result = self.validator._perform_forward_check("example.com", "192.168.1.1", [])

        self.assertFalse(result["forward_check_passed"])
        self.assertEqual(result["error"], "DNS resolution timeout")
        self.assertEqual(result["domain"], "example.com")

        # Verify that the error was logged
        self.logger.error.assert_called_once_with(
            "Forward address check DNS resolution failed: %s", "DNS resolution timeout"
        )

    def test_022_domain_matches_empty_resolved_domain(self):
        """Test _domain_matches with empty resolved_domain returns False"""
        # Test with None resolved_domain
        result = self.validator._domain_matches("example.com", None)
        self.assertFalse(result)

        # Test with empty string resolved_domain
        result = self.validator._domain_matches("example.com", "")
        self.assertFalse(result)

        # Test with whitespace-only resolved_domain
        result = self.validator._domain_matches("example.com", "   ")
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
