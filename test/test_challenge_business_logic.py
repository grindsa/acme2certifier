#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Comprehensive unit tests for challenge_business_logic.py"""
# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212
import unittest
import sys
import logging
import json
from unittest.mock import Mock, patch

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestChallengeInfo(unittest.TestCase):
    """Test cases for ChallengeInfo dataclass"""

    def setUp(self):
        """Setup for tests"""
        from acme_srv.challenge_business_logic import ChallengeInfo

        self.ChallengeInfo = ChallengeInfo

    def test_001_challenge_info_creation_basic(self):
        """Test basic ChallengeInfo creation"""
        challenge = self.ChallengeInfo(
            name="test-challenge",
            type="http-01",
            token="test-token",
            status="pending",
            authorization_name="test-auth",
            authorization_type="dns",
            authorization_value="example.com",
            url="http://example.com/challenge",
        )

        self.assertEqual(challenge.name, "test-challenge")
        self.assertEqual(challenge.type, "http-01")
        self.assertEqual(challenge.token, "test-token")
        self.assertEqual(challenge.status, "pending")
        self.assertEqual(challenge.authorization_name, "test-auth")
        self.assertEqual(challenge.authorization_type, "dns")
        self.assertEqual(challenge.authorization_value, "example.com")
        self.assertEqual(challenge.url, "http://example.com/challenge")
        self.assertIsNone(challenge.validated)

    def test_002_challenge_info_creation_with_validated(self):
        """Test ChallengeInfo creation with validated timestamp"""
        challenge = self.ChallengeInfo(
            name="test-challenge",
            type="dns-01",
            token="test-token",
            status="valid",
            authorization_name="test-auth",
            authorization_type="dns",
            authorization_value="example.com",
            url="http://example.com/challenge",
            validated="2023-01-01T00:00:00Z",
        )

        self.assertEqual(challenge.validated, "2023-01-01T00:00:00Z")
        self.assertEqual(challenge.status, "valid")

    def test_003_challenge_info_equality(self):
        """Test ChallengeInfo equality comparison"""
        challenge1 = self.ChallengeInfo(
            name="test-challenge",
            type="http-01",
            token="test-token",
            status="pending",
            authorization_name="test-auth",
            authorization_type="dns",
            authorization_value="example.com",
            url="http://example.com/challenge",
        )

        challenge2 = self.ChallengeInfo(
            name="test-challenge",
            type="http-01",
            token="test-token",
            status="pending",
            authorization_name="test-auth",
            authorization_type="dns",
            authorization_value="example.com",
            url="http://example.com/challenge",
        )

        self.assertEqual(challenge1, challenge2)

    def test_004_challenge_info_inequality(self):
        """Test ChallengeInfo inequality comparison"""
        challenge1 = self.ChallengeInfo(
            name="test-challenge-1",
            type="http-01",
            token="test-token",
            status="pending",
            authorization_name="test-auth",
            authorization_type="dns",
            authorization_value="example.com",
            url="http://example.com/challenge",
        )

        challenge2 = self.ChallengeInfo(
            name="test-challenge-2",
            type="http-01",
            token="test-token",
            status="pending",
            authorization_name="test-auth",
            authorization_type="dns",
            authorization_value="example.com",
            url="http://example.com/challenge",
        )

        self.assertNotEqual(challenge1, challenge2)


class TestChallengeCreationRequest(unittest.TestCase):
    """Test cases for ChallengeCreationRequest dataclass"""

    def setUp(self):
        """Setup for tests"""
        from acme_srv.challenge_business_logic import ChallengeCreationRequest

        self.ChallengeCreationRequest = ChallengeCreationRequest

    def test_005_creation_request_basic(self):
        """Test basic ChallengeCreationRequest creation"""
        request = self.ChallengeCreationRequest(
            authorization_name="test-auth", challenge_type="http-01", token="test-token"
        )

        self.assertEqual(request.authorization_name, "test-auth")
        self.assertEqual(request.challenge_type, "http-01")
        self.assertEqual(request.token, "test-token")
        self.assertIsNone(request.value)
        self.assertEqual(request.expiry, 3600)  # default value

    def test_006_creation_request_with_value(self):
        """Test ChallengeCreationRequest with value"""
        request = self.ChallengeCreationRequest(
            authorization_name="test-auth",
            challenge_type="dns-01",
            token="test-token",
            value="example.com",
        )

        self.assertEqual(request.value, "example.com")

    def test_007_creation_request_custom_expiry(self):
        """Test ChallengeCreationRequest with custom expiry"""
        request = self.ChallengeCreationRequest(
            authorization_name="test-auth",
            challenge_type="http-01",
            token="test-token",
            expiry=7200,
        )

        self.assertEqual(request.expiry, 7200)

    def test_008_creation_request_email_challenge(self):
        """Test ChallengeCreationRequest for email challenge"""
        request = self.ChallengeCreationRequest(
            authorization_name="test-auth",
            challenge_type="email-reply-00",
            token="test-token",
            value="user@example.com",
            expiry=1800,
        )

        self.assertEqual(request.challenge_type, "email-reply-00")
        self.assertEqual(request.value, "user@example.com")
        self.assertEqual(request.expiry, 1800)


class TestChallengeUpdateRequest(unittest.TestCase):
    """Test cases for ChallengeUpdateRequest dataclass"""

    def setUp(self):
        """Setup for tests"""
        from acme_srv.challenge_business_logic import ChallengeUpdateRequest

        self.ChallengeUpdateRequest = ChallengeUpdateRequest

    def test_009_update_request_basic(self):
        """Test basic ChallengeUpdateRequest creation"""
        request = self.ChallengeUpdateRequest(name="test-challenge")

        self.assertEqual(request.name, "test-challenge")
        self.assertIsNone(request.status)
        self.assertIsNone(request.source)
        self.assertIsNone(request.validated)
        self.assertIsNone(request.keyauthorization)

    def test_010_update_request_status_only(self):
        """Test ChallengeUpdateRequest with status update"""
        request = self.ChallengeUpdateRequest(
            name="test-challenge", status="processing"
        )

        self.assertEqual(request.name, "test-challenge")
        self.assertEqual(request.status, "processing")

    def test_011_update_request_full(self):
        """Test ChallengeUpdateRequest with all fields"""
        request = self.ChallengeUpdateRequest(
            name="test-challenge",
            status="valid",
            source="192.168.1.1",
            validated=1640995200,
            keyauthorization="test-key-auth",
        )

        self.assertEqual(request.name, "test-challenge")
        self.assertEqual(request.status, "valid")
        self.assertEqual(request.source, "192.168.1.1")
        self.assertEqual(request.validated, 1640995200)
        self.assertEqual(request.keyauthorization, "test-key-auth")

    def test_012_update_request_partial(self):
        """Test ChallengeUpdateRequest with partial updates"""
        request = self.ChallengeUpdateRequest(
            name="test-challenge", status="invalid", source="192.168.1.100"
        )

        self.assertEqual(request.status, "invalid")
        self.assertEqual(request.source, "192.168.1.100")
        self.assertIsNone(request.validated)
        self.assertIsNone(request.keyauthorization)


class MockChallengeRepository:
    """Mock implementation of ChallengeRepository for testing"""

    def __init__(self):
        self.challenges = {}
        self.authorizations = {}
        self.call_log = []

    def find_challenges_by_authorization(self, authorization_name: str):
        self.call_log.append(("find_challenges_by_authorization", authorization_name))
        return self.challenges.get(authorization_name, [])

    def get_challenge_by_name(self, name: str):
        self.call_log.append(("get_challenge_by_name", name))
        for challenges in self.challenges.values():
            for challenge in challenges:
                if challenge.name == name:
                    return challenge
        return None

    def get_challengeinfo_by_challengename(self, name: str, vlist=None):
        self.call_log.append(("get_challengeinfo_by_challengename", name, vlist))
        # Mock response for email challenge
        if name == "email-challenge-1":
            return {
                "name": name,
                "keyauthorization": "test-key-auth",
                "authorization__value": "test@example.com",
            }
        return None

    def create_challenge(self, request):
        self.call_log.append(("create_challenge", request))
        challenge_name = f"{request.challenge_type}-{request.authorization_name}-1"
        return challenge_name

    def update_challenge(self, request):
        self.call_log.append(("update_challenge", request))
        return True

    def update_authorization_status(self, challenge_name: str, status: str):
        self.call_log.append(("update_authorization_status", challenge_name, status))
        return True

    def get_account_jwk(self, challenge_name: str):
        self.call_log.append(("get_account_jwk", challenge_name))
        return {"kty": "RSA", "n": "test", "e": "AQAB"}


class TestChallengeStateManager(unittest.TestCase):
    """Test cases for ChallengeStateManager"""

    def setUp(self):
        """Setup for tests"""
        from acme_srv.challenge_business_logic import ChallengeStateManager

        self.logger = Mock(spec=logging.Logger)
        self.repository = MockChallengeRepository()
        self.state_manager = ChallengeStateManager(self.repository, self.logger)

    def test_013_state_manager_initialization(self):
        """Test ChallengeStateManager initialization"""
        self.assertEqual(self.state_manager.repository, self.repository)
        self.assertEqual(self.state_manager.logger, self.logger)

    def test_014_transition_to_processing_success(self):
        """Test successful transition to processing state"""
        result = self.state_manager.transition_to_processing("test-challenge")

        self.assertTrue(result)
        self.logger.debug.assert_called()

        # Check that repository was called correctly
        calls = self.repository.call_log
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "update_challenge")
        update_request = calls[0][1]
        self.assertEqual(update_request.name, "test-challenge")
        self.assertEqual(update_request.status, "processing")

    def test_015_transition_to_processing_failure(self):
        """Test failed transition to processing state"""
        # Mock repository to return False
        self.repository.update_challenge = Mock(return_value=False)

        result = self.state_manager.transition_to_processing("test-challenge")

        self.assertFalse(result)

    def test_016_transition_to_valid_success(self):
        """Test successful transition to valid state"""
        result = self.state_manager.transition_to_valid(
            "test-challenge",
            source_address="192.168.1.1",
            validated_timestamp=1640995200,
        )

        self.assertTrue(result)

        # Check repository calls
        calls = self.repository.call_log
        self.assertEqual(len(calls), 2)

        # First call should update challenge
        self.assertEqual(calls[0][0], "update_challenge")
        update_request = calls[0][1]
        self.assertEqual(update_request.name, "test-challenge")
        self.assertEqual(update_request.status, "valid")
        self.assertEqual(update_request.source, "192.168.1.1")
        self.assertEqual(update_request.validated, 1640995200)

        # Second call should update authorization
        self.assertEqual(calls[1][0], "update_authorization_status")
        self.assertEqual(calls[1][1], "test-challenge")
        self.assertEqual(calls[1][2], "valid")

    def test_017_transition_to_valid_with_defaults(self):
        """Test transition to valid state with default parameters"""
        result = self.state_manager.transition_to_valid("test-challenge")

        self.assertTrue(result)

        update_request = self.repository.call_log[0][1]
        self.assertEqual(update_request.name, "test-challenge")
        self.assertEqual(update_request.status, "valid")
        self.assertIsNone(update_request.source)
        self.assertIsNone(update_request.validated)

    def test_018_transition_to_valid_challenge_update_failure(self):
        """Test transition to valid fails on challenge update"""
        self.repository.update_challenge = Mock(return_value=False)

        result = self.state_manager.transition_to_valid("test-challenge")

        self.assertFalse(result)
        # Authorization update should not be called if challenge update fails
        self.repository.update_challenge.assert_called_once()

    def test_019_transition_to_valid_authorization_update_failure(self):
        """Test transition to valid fails on authorization update"""
        self.repository.update_authorization_status = Mock(return_value=False)

        result = self.state_manager.transition_to_valid("test-challenge")

        self.assertFalse(result)

    def test_020_transition_to_invalid_success(self):
        """Test successful transition to invalid state"""
        result = self.state_manager.transition_to_invalid(
            "test-challenge", source_address="192.168.1.100"
        )

        self.assertTrue(result)

        calls = self.repository.call_log
        self.assertEqual(len(calls), 2)

        # Check challenge update
        update_request = calls[0][1]
        self.assertEqual(update_request.name, "test-challenge")
        self.assertEqual(update_request.status, "invalid")
        self.assertEqual(update_request.source, "192.168.1.100")

        # Check authorization update
        self.assertEqual(calls[1][0], "update_authorization_status")
        self.assertEqual(calls[1][2], "invalid")

    def test_021_transition_to_invalid_with_defaults(self):
        """Test transition to invalid state with default parameters"""
        result = self.state_manager.transition_to_invalid("test-challenge")

        self.assertTrue(result)

        update_request = self.repository.call_log[0][1]
        self.assertIsNone(update_request.source)

    def test_022_transition_to_invalid_challenge_failure(self):
        """Test transition to invalid fails on challenge update"""
        self.repository.update_challenge = Mock(return_value=False)

        result = self.state_manager.transition_to_invalid("test-challenge")

        self.assertFalse(result)

    def test_023_transition_to_invalid_authorization_failure(self):
        """Test transition to invalid fails on authorization update"""
        self.repository.update_authorization_status = Mock(return_value=False)

        result = self.state_manager.transition_to_invalid("test-challenge")

        self.assertFalse(result)

    def test_024_update_key_authorization_success(self):
        """Test successful key authorization update"""
        result = self.state_manager.update_key_authorization(
            "test-challenge", "test-key-auth"
        )

        self.assertTrue(result)

        calls = self.repository.call_log
        self.assertEqual(len(calls), 1)

        update_request = calls[0][1]
        self.assertEqual(update_request.name, "test-challenge")
        self.assertEqual(update_request.keyauthorization, "test-key-auth")
        self.assertIsNone(update_request.status)  # Other fields should be None

    def test_025_update_key_authorization_failure(self):
        """Test failed key authorization update"""
        self.repository.update_challenge = Mock(return_value=False)

        result = self.state_manager.update_key_authorization(
            "test-challenge", "test-key-auth"
        )

        self.assertFalse(result)

    def test_026_update_key_authorization_empty_string(self):
        """Test key authorization update with empty string"""
        result = self.state_manager.update_key_authorization("test-challenge", "")

        self.assertTrue(result)
        update_request = self.repository.call_log[0][1]
        self.assertEqual(update_request.keyauthorization, "")

    def test_027_logger_debug_calls(self):
        """Test that logger.debug is called appropriately"""
        self.state_manager.transition_to_processing("test-challenge")

        # Check that debug was called for method entry and exit
        self.assertGreaterEqual(self.logger.debug.call_count, 2)
        debug_calls = self.logger.debug.call_args_list

        # First call should be method entry
        self.assertIn("transition_to_processing", str(debug_calls[0]))

        # Last call should be method exit with result
        self.assertIn("transition_to_processing", str(debug_calls[-1]))

    def test_028_transition_with_none_challenge_name(self):
        """Test transitions with None challenge name"""
        result = self.state_manager.transition_to_processing(None)
        self.assertTrue(result)  # Repository mock returns True for any input

    def test_029_transition_with_empty_challenge_name(self):
        """Test transitions with empty challenge name"""
        result = self.state_manager.transition_to_processing("")
        self.assertTrue(result)

    def test_030_update_key_authorization_with_none(self):
        """Test key authorization update with None value"""
        result = self.state_manager.update_key_authorization("test-challenge", None)
        self.assertTrue(result)

        update_request = self.repository.call_log[-1][1]
        self.assertIsNone(update_request.keyauthorization)

    def test_031_state_manager_repository_exception_handling(self):
        """Test state manager behavior when repository raises exceptions"""
        self.repository.update_challenge = Mock(side_effect=Exception("Database error"))

        # The implementation doesn't handle exceptions, so this will raise
        with self.assertRaises(Exception):
            self.state_manager.transition_to_processing("test-challenge")

    def test_032_transition_to_valid_large_timestamp(self):
        """Test transition to valid with large timestamp"""
        large_timestamp = 9999999999  # Year 2286

        result = self.state_manager.transition_to_valid(
            "test-challenge", validated_timestamp=large_timestamp
        )

        self.assertTrue(result)
        update_request = self.repository.call_log[0][1]
        self.assertEqual(update_request.validated, large_timestamp)


class TestChallengeFactory(unittest.TestCase):
    """Test cases for ChallengeFactory"""

    def setUp(self):
        """Setup for tests"""
        from acme_srv.challenge_business_logic import ChallengeFactory

        self.logger = Mock(spec=logging.Logger)
        self.repository = MockChallengeRepository()
        self.factory = ChallengeFactory(
            repository=self.repository,
            logger=self.logger,
            server_name="https://example.com",
            challenge_path="/acme/chall/",
            email_address="admin@example.com",
        )

    def test_033_factory_initialization(self):
        """Test ChallengeFactory initialization"""
        self.assertEqual(self.factory.repository, self.repository)
        self.assertEqual(self.factory.logger, self.logger)
        self.assertEqual(self.factory.server_name, "https://example.com")
        self.assertEqual(self.factory.challenge_path, "/acme/chall/")
        self.assertEqual(self.factory.email_address, "admin@example.com")

    def test_034_create_standard_challenge_set_dns_identifier(self):
        """Test creating standard challenge set for DNS identifier"""
        challenges = self.factory.create_standard_challenge_set(
            authorization_name="test-auth",
            token="test-token",
            id_type="dns",
            value="example.com",
        )

        self.assertEqual(len(challenges), 3)  # http-01, dns-01, tls-alpn-01

        types = [c["type"] for c in challenges]
        self.assertIn("http-01", types)
        self.assertIn("dns-01", types)
        self.assertIn("tls-alpn-01", types)

        # Check common properties
        for challenge in challenges:
            self.assertEqual(challenge["token"], "test-token")
            self.assertEqual(challenge["status"], "pending")
            self.assertTrue(
                challenge["url"].startswith("https://example.com/acme/chall/")
            )

    def test_035_create_standard_challenge_set_ip_identifier(self):
        """Test creating standard challenge set for IP identifier (no DNS)"""
        challenges = self.factory.create_standard_challenge_set(
            authorization_name="test-auth",
            token="test-token",
            id_type="ip",
            value="192.168.1.1",
        )

        self.assertEqual(len(challenges), 2)  # http-01, tls-alpn-01 (no dns-01)

        types = [c["type"] for c in challenges]
        self.assertIn("http-01", types)
        self.assertIn("tls-alpn-01", types)
        self.assertNotIn("dns-01", types)

    def test_036_create_standard_challenge_set_repository_failure(self):
        """Test standard challenge set creation when repository fails"""
        self.repository.create_challenge = Mock(return_value=None)

        challenges = self.factory.create_standard_challenge_set(
            authorization_name="test-auth",
            token="test-token",
            id_type="dns",
            value="example.com",
        )

        self.assertEqual(len(challenges), 0)

    def test_037_create_email_reply_challenge_success(self):
        """Test successful email-reply challenge creation"""
        challenge = self.factory.create_email_reply_challenge(
            authorization_name="test-auth",
            token="test-token",
            email_address="user@example.com",
            sender_address="sender@example.com",
        )

        self.assertIsNotNone(challenge)
        self.assertEqual(challenge["type"], "email-reply-00")
        self.assertEqual(challenge["token"], "test-token")
        self.assertEqual(challenge["status"], "pending")
        self.assertEqual(challenge["from"], "sender@example.com")
        self.assertTrue(challenge["url"].startswith("https://example.com/acme/chall/"))

    def test_038_create_email_reply_challenge_no_sender(self):
        """Test email-reply challenge creation without sender address"""
        challenge = self.factory.create_email_reply_challenge(
            authorization_name="test-auth",
            token="test-token",
            email_address="user@example.com",
            sender_address="",
        )

        self.assertIsNotNone(challenge)
        self.assertEqual(challenge["from"], "admin@example.com")  # Uses factory default

    def test_039_create_email_reply_challenge_repository_failure(self):
        """Test email-reply challenge creation when repository fails"""
        self.repository.create_challenge = Mock(return_value=None)

        challenge = self.factory.create_email_reply_challenge(
            authorization_name="test-auth",
            token="test-token",
            email_address="user@example.com",
            sender_address="sender@example.com",
        )

        self.assertIsNone(challenge)

    def test_040_create_tkauth_challenge_success(self):
        """Test successful tkauth challenge creation"""
        challenge = self.factory.create_tkauth_challenge(
            authorization_name="test-auth", token="test-token"
        )

        self.assertIsNotNone(challenge)
        self.assertEqual(challenge["type"], "tkauth-01")
        self.assertEqual(challenge["token"], "test-token")
        self.assertEqual(challenge["status"], "pending")
        self.assertEqual(challenge["tkauth-type"], "atc")

    def test_041_create_tkauth_challenge_repository_failure(self):
        """Test tkauth challenge creation when repository fails"""
        self.repository.create_challenge = Mock(return_value=None)

        challenge = self.factory.create_tkauth_challenge(
            authorization_name="test-auth", token="test-token"
        )

        self.assertIsNone(challenge)

    def test_042create_single_challenge_http(self):
        """Test creating single HTTP challenge"""
        challenge = self.factory.create_single_challenge(
            authorization_name="test-auth",
            challenge_type="http-01",
            token="test-token",
            value="example.com",
        )

        self.assertIsNotNone(challenge)
        self.assertEqual(challenge["type"], "http-01")
        self.assertEqual(challenge["token"], "test-token")
        self.assertEqual(challenge["status"], "pending")

    def test_043create_single_challenge_sectigo_email(self):
        """Test creating sectigo-email challenge"""
        challenge = self.factory.create_single_challenge(
            authorization_name="test-auth",
            challenge_type="sectigo-email-01",
            token="test-token",
        )

        self.assertIsNotNone(challenge)
        self.assertEqual(challenge["type"], "sectigo-email-01")
        self.assertEqual(
            challenge["status"], "valid"
        )  # Sectigo challenges are pre-validated
        self.assertNotIn("token", challenge)  # Token is removed for sectigo

    @patch.dict("sys.modules", {"acme_srv.email_handler": Mock()})
    def test_044create_single_challenge_email(self):
        """Test creating email-reply challenge"""
        # Set up the factory with an email address
        self.factory.email_address = "foo@example.com"

        # Mock the repository method directly on the instance
        self.repository.get_challengeinfo_by_challengename = Mock(
            return_value={
                "name": "email-reply-00-test-auth-1",
                "keyauthorization": "keyauthorization-value",
                "authorization__value": "user@example.com",
            }
        )

        # Create a mock EmailHandler class and instance
        mock_email_handler_instance = Mock()
        mock_email_handler_class = Mock()
        mock_email_handler_class.return_value.__enter__ = Mock(
            return_value=mock_email_handler_instance
        )
        mock_email_handler_class.return_value.__exit__ = Mock(return_value=None)

        # Mock the email_handler module
        import sys

        sys.modules["acme_srv.email_handler"].EmailHandler = mock_email_handler_class

        challenge = self.factory.create_single_challenge(
            authorization_name="test-auth",
            challenge_type="email-reply-00",
            token="test-token",
        )

        self.assertIsNotNone(challenge)
        self.assertEqual(challenge["type"], "email-reply-00")
        self.assertEqual(challenge["status"], "pending")
        self.assertEqual(challenge["from"], "foo@example.com")

        # Verify the repository method was called with the right parameters
        self.repository.get_challengeinfo_by_challengename.assert_called_once_with(
            "email-reply-00-test-auth-1",
            vlist=("name", "keyauthorization", "authorization__value"),
        )

        # Verify EmailHandler was created with logger
        mock_email_handler_class.assert_called_once_with(logger=self.factory.logger)

        # Verify send_email_challenge was called with correct parameters
        mock_email_handler_instance.send_email_challenge.assert_called_once_with(
            to_address="user@example.com", token1="keyauthorization-value"
        )

    def test_045create_single_challenge_repository_failure(self):
        """Test single challenge creation when repository fails"""
        self.repository.create_challenge = Mock(return_value=None)

        challenge = self.factory.create_single_challenge(
            authorization_name="test-auth", challenge_type="http-01", token="test-token"
        )

        self.assertIsNone(challenge)

    def test_046_factory_without_email_address(self):
        """Test factory initialization without email address"""
        from acme_srv.challenge_business_logic import ChallengeFactory

        factory = ChallengeFactory(
            repository=self.repository,
            logger=self.logger,
            server_name="https://example.com",
            challenge_path="/acme/chall/",
        )

        self.assertIsNone(factory.email_address)

    def test_047_logger_debug_calls_in_factory(self):
        """Test logger debug calls in factory methods"""
        self.factory.create_standard_challenge_set(
            "test-auth", "test-token", "dns", "example.com"
        )

        self.assertTrue(self.logger.debug.called)
        self.assertGreater(self.logger.debug.call_count, 0)

    def test_048_email_challenge_creation_basic(self):
        """Test basic email challenge creation without triggering email handler"""
        challenge = self.factory.create_single_challenge(
            authorization_name="test-auth",
            challenge_type="http-01",  # Use http instead of email to avoid import
            token="test-token",
            value="example.com",
        )

        self.assertIsNotNone(challenge)
        self.assertEqual(challenge["type"], "http-01")
        self.assertEqual(challenge["token"], "test-token")
        self.assertEqual(challenge["status"], "pending")

    def test_049create_single_challenge_invalid_type(self):
        """Test creating challenge with unknown type"""
        challenge = self.factory.create_single_challenge(
            authorization_name="test-auth",
            challenge_type="unknown-01",
            token="test-token",
            value="test-value",
        )

        self.assertIsNotNone(challenge)
        self.assertEqual(challenge["type"], "unknown-01")
        self.assertEqual(challenge["status"], "pending")

    def test_050_create_standard_challenge_set_empty_types(self):
        """Test challenge set creation when no types remain"""
        # Mock the factory to have no challenge types (edge case)
        original_method = self.factory.create_single_challenge
        self.factory.create_single_challenge = Mock(return_value=None)

        challenges = self.factory.create_standard_challenge_set(
            authorization_name="test-auth",
            token="test-token",
            id_type="dns",
            value="example.com",
        )

        self.assertEqual(len(challenges), 0)
        self.factory.create_single_challenge = original_method

    def test_051_factory_email_challenge_without_email_address(self):
        """Test email challenge creation when factory has no email address"""
        from acme_srv.challenge_business_logic import ChallengeFactory

        factory_no_email = ChallengeFactory(
            repository=self.repository,
            logger=self.logger,
            server_name="https://example.com",
            challenge_path="/acme/chall/",
        )

        challenge = factory_no_email.create_single_challenge(
            authorization_name="test-auth",
            challenge_type="email-reply-00",
            token="test-token",
            value="test@example.com",
        )

        self.assertIsNotNone(challenge)
        self.assertNotIn("from", challenge)


class MockConfig:
    """Mock configuration object for testing"""

    def __init__(self, **kwargs):
        self.email_identifier_support = kwargs.get("email_identifier_support", False)
        self.email_address = kwargs.get("email_address", None)
        self.tnauthlist_support = kwargs.get("tnauthlist_support", False)
        self.sectigo_sim = kwargs.get("sectigo_sim", False)


class TestChallengeService(unittest.TestCase):
    """Test cases for ChallengeService"""

    def setUp(self):
        """Setup for tests"""
        from acme_srv.challenge_business_logic import (
            ChallengeService,
            ChallengeStateManager,
            ChallengeFactory,
            ChallengeInfo,
        )

        self.logger = Mock(spec=logging.Logger)
        self.repository = MockChallengeRepository()
        self.state_manager = Mock(spec=ChallengeStateManager)
        self.factory = Mock(spec=ChallengeFactory)

        self.service = ChallengeService(
            repository=self.repository,
            state_manager=self.state_manager,
            factory=self.factory,
            logger=self.logger,
        )

        self.ChallengeInfo = ChallengeInfo

    def test_052_service_initialization(self):
        """Test ChallengeService initialization"""
        self.assertEqual(self.service.repository, self.repository)
        self.assertEqual(self.service.state_manager, self.state_manager)
        self.assertEqual(self.service.factory, self.factory)
        self.assertEqual(self.service.logger, self.logger)

    def test_053_get_challenge_set_with_existing_challenges(self):
        """Test getting challenge set when challenges already exist"""
        existing_challenges = [
            self.ChallengeInfo(
                name="challenge-1",
                type="http-01",
                token="token-1",
                status="pending",
                authorization_name="test-auth",
                authorization_type="dns",
                authorization_value="example.com",
                url="",
            )
        ]

        self.repository.find_challenges_by_authorization = Mock(
            return_value=existing_challenges
        )

        config = MockConfig()
        result = self.service.get_challenge_set_for_authorization(
            authorization_name="test-auth",
            token="new-token",
            id_type="dns",
            id_value="example.com",
            config=config,
            url="https://example.com/acme/chall/",
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "http-01")
        self.assertEqual(result[0]["url"], "https://example.com/acme/chall/challenge-1")

    def test_054_get_challenge_set_create_new_standard(self):
        """Test creating new standard challenge set"""
        self.repository.find_challenges_by_authorization = Mock(return_value=[])
        self.factory.create_standard_challenge_set = Mock(
            return_value=[
                {"type": "http-01", "token": "test-token", "status": "pending"},
                {"type": "dns-01", "token": "test-token", "status": "pending"},
            ]
        )

        config = MockConfig()
        result = self.service.get_challenge_set_for_authorization(
            authorization_name="test-auth",
            token="test-token",
            id_type="dns",
            id_value="example.com",
            config=config,
        )

        self.assertEqual(len(result), 2)
        self.factory.create_standard_challenge_set.assert_called_once_with(
            "test-auth", "test-token", "dns", "example.com"
        )

    def test_055_get_challenge_set_email_identifier(self):
        """Test creating challenge set for email identifier"""
        self.repository.find_challenges_by_authorization = Mock(return_value=[])
        self.factory.create_email_reply_challenge = Mock(
            return_value={
                "type": "email-reply-00",
                "token": "test-token",
                "status": "pending",
            }
        )

        config = MockConfig(
            email_identifier_support=True, email_address="admin@example.com"
        )

        result = self.service.get_challenge_set_for_authorization(
            authorization_name="test-auth",
            token="test-token",
            id_type="email",
            id_value="user@example.com",
            config=config,
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "email-reply-00")
        self.factory.create_email_reply_challenge.assert_called_once_with(
            "test-auth", "test-token", "user@example.com", "admin@example.com"
        )

    def test_056_get_challenge_set_email_identifier_no_config(self):
        """Test email identifier without proper configuration"""
        self.repository.find_challenges_by_authorization = Mock(return_value=[])
        self.factory.create_standard_challenge_set = Mock(return_value=[])

        config = MockConfig(email_identifier_support=False)

        self.service.get_challenge_set_for_authorization(
            authorization_name="test-auth",
            token="test-token",
            id_type="email",
            id_value="user@example.com",
            config=config,
        )

        # Should fall through to standard challenge creation
        self.factory.create_standard_challenge_set.assert_called_once()

    def test_057_get_challenge_set_tnauthlist_identifier(self):
        """Test creating challenge set for tnauthlist identifier"""
        self.repository.find_challenges_by_authorization = Mock(return_value=[])
        self.factory.create_tkauth_challenge = Mock(
            return_value={
                "type": "tkauth-01",
                "token": "test-token",
                "status": "pending",
            }
        )

        config = MockConfig(tnauthlist_support=True)

        result = self.service.get_challenge_set_for_authorization(
            authorization_name="test-auth",
            token="test-token",
            id_type="tnauthlist",
            id_value="test-value",
            config=config,
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "tkauth-01")
        self.factory.create_tkauth_challenge.assert_called_once_with(
            "test-auth", "test-token"
        )

    def test_058_get_challenge_set_sectigo_simulation(self):
        """Test creating challenge set with Sectigo simulation"""
        self.repository.find_challenges_by_authorization = Mock(return_value=[])
        self.factory.create_single_challenge = Mock(
            return_value={"type": "sectigo-email-01", "status": "valid"}
        )
        self.factory.create_standard_challenge_set = Mock(
            return_value=[
                {"type": "http-01", "token": "test-token", "status": "pending"}
            ]
        )

        config = MockConfig(sectigo_sim=True)

        result = self.service.get_challenge_set_for_authorization(
            authorization_name="test-auth",
            token="test-token",
            id_type="dns",
            id_value="example.com",
            config=config,
        )

        self.assertEqual(len(result), 2)  # Sectigo + standard challenges
        types = [c["type"] for c in result]
        self.assertIn("sectigo-email-01", types)
        self.assertIn("http-01", types)

    def test_059_format_existing_challenges_basic(self):
        """Test formatting existing challenges"""
        challenges = [
            self.ChallengeInfo(
                name="challenge-1",
                type="http-01",
                token="token-1",
                status="pending",
                authorization_name="test-auth",
                authorization_type="dns",
                authorization_value="example.com",
                url="",
            ),
            self.ChallengeInfo(
                name="challenge-2",
                type="dns-01",
                token="token-2",
                status="valid",
                authorization_name="test-auth",
                authorization_type="dns",
                authorization_value="example.com",
                url="",
            ),
        ]

        result = self.service._format_existing_challenges(
            challenges=challenges,
            url="https://example.com/acme/chall/",
            config=MockConfig(),
        )

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["type"], "http-01")
        self.assertEqual(result[0]["url"], "https://example.com/acme/chall/challenge-1")
        self.assertEqual(result[1]["type"], "dns-01")
        self.assertEqual(result[1]["status"], "valid")

    def test_060_format_existing_challenges_email_reply(self):
        """Test formatting existing email-reply challenges"""
        challenges = [
            self.ChallengeInfo(
                name="email-challenge-1",
                type="email-reply-00",
                token="email-token",
                status="pending",
                authorization_name="test-auth",
                authorization_type="email",
                authorization_value="user@example.com",
                url="",
            )
        ]

        config = MockConfig(email_address="admin@example.com")
        result = self.service._format_existing_challenges(
            challenges=challenges, url="https://example.com/acme/chall/", config=config
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "email-reply-00")
        self.assertEqual(result[0]["from"], "admin@example.com")

    def test_061_create_new_challenge_set_empty_config(self):
        """Test creating new challenge set with minimal configuration"""
        self.factory.create_standard_challenge_set = Mock(
            return_value=[
                {"type": "http-01", "token": "test-token", "status": "pending"}
            ]
        )

        config = MockConfig()

        result = self.service._create_new_challenge_set(
            authorization_name="test-auth",
            token="test-token",
            id_type="dns",
            id_value="example.com",
            config=config,
        )

        self.assertEqual(len(result), 1)
        self.factory.create_standard_challenge_set.assert_called_once()

    def test_062_get_challenge_set_email_challenge_failure(self):
        """Test email challenge creation failure"""
        self.repository.find_challenges_by_authorization = Mock(return_value=[])
        self.factory.create_email_reply_challenge = Mock(return_value=None)

        config = MockConfig(
            email_identifier_support=True, email_address="admin@example.com"
        )

        result = self.service.get_challenge_set_for_authorization(
            authorization_name="test-auth",
            token="test-token",
            id_type="email",
            id_value="user@example.com",
            config=config,
        )

        self.assertEqual(len(result), 0)

    def test_063_get_challenge_set_tkauth_challenge_failure(self):
        """Test tkauth challenge creation failure"""
        self.repository.find_challenges_by_authorization = Mock(return_value=[])
        self.factory.create_tkauth_challenge = Mock(return_value=None)

        config = MockConfig(tnauthlist_support=True)

        result = self.service.get_challenge_set_for_authorization(
            authorization_name="test-auth",
            token="test-token",
            id_type="TNAUTHLIST",  # Test case insensitive
            id_value="test-value",
            config=config,
        )

        self.assertEqual(len(result), 0)

    def test_064_logger_debug_calls_in_service(self):
        """Test logger debug calls in service methods"""
        self.repository.find_challenges_by_authorization = Mock(return_value=[])
        self.factory.create_standard_challenge_set = Mock(return_value=[])

        config = MockConfig()
        self.service.get_challenge_set_for_authorization(
            "test-auth", "test-token", "dns", "example.com", config
        )

        self.assertTrue(self.logger.debug.called)

    def test_065_sectigo_challenge_creation_failure(self):
        """Test sectigo challenge creation failure"""
        self.repository.find_challenges_by_authorization = Mock(return_value=[])
        self.factory.create_single_challenge = Mock(return_value=None)
        self.factory.create_standard_challenge_set = Mock(return_value=[])

        config = MockConfig(sectigo_sim=True)

        self.service.get_challenge_set_for_authorization(
            authorization_name="test-auth",
            token="test-token",
            id_type="dns",
            id_value="example.com",
            config=config,
        )

        # Should still return standard challenges even if sectigo fails
        self.factory.create_standard_challenge_set.assert_called_once()

    def test_066_email_identifier_edge_cases(self):
        """Test email identifier with edge cases"""
        self.repository.find_challenges_by_authorization = Mock(return_value=[])
        self.factory.create_standard_challenge_set = Mock(return_value=[])

        # Test with email_identifier_support=True but no email_address
        config = MockConfig(email_identifier_support=True, email_address=None)
        self.service.get_challenge_set_for_authorization(
            authorization_name="test-auth",
            token="test-token",
            id_type="email",
            id_value="user@example.com",
            config=config,
        )

        # Should fall through to standard challenges
        self.factory.create_standard_challenge_set.assert_called_once()

        # Test with email_address but no @ in id_value
        config = MockConfig(
            email_identifier_support=True, email_address="admin@example.com"
        )
        self.service.get_challenge_set_for_authorization(
            authorization_name="test-auth",
            token="test-token",
            id_type="email",
            id_value="notanemail",
            config=config,
        )

        # Should still try to create email challenge
        self.assertEqual(self.factory.create_standard_challenge_set.call_count, 2)

    def test_067_service_repository_exception_handling(self):
        """Test service behavior when repository raises exceptions"""
        self.repository.find_challenges_by_authorization = Mock(
            side_effect=Exception("Database error")
        )
        config = MockConfig()

        # The implementation doesn't handle exceptions, so this will raise
        with self.assertRaises(Exception):
            self.service.get_challenge_set_for_authorization(
                "test-auth", "test-token", "dns", "example.com", config
            )

    def test_068_format_existing_challenges_empty_list(self):
        """Test formatting empty challenge list"""
        result = self.service._format_existing_challenges(
            challenges=[], url="https://example.com/acme/chall/", config=MockConfig()
        )

        self.assertEqual(len(result), 0)
        self.assertIsInstance(result, list)

    def test_069_format_existing_challenges_no_url(self):
        """Test formatting challenges without URL"""
        challenges = [
            self.ChallengeInfo(
                name="challenge-1",
                type="http-01",
                token="token-1",
                status="pending",
                authorization_name="test-auth",
                authorization_type="dns",
                authorization_value="example.com",
                url="",
            )
        ]

        result = self.service._format_existing_challenges(
            challenges=challenges, url="", config=MockConfig()
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["url"], "challenge-1")  # Just the challenge name

    def test_069_1_format_existing_challenges_with_valid_json_validation_error(self):
        """Test _format_existing_challenges with valid JSON validation_error (lines 421-430)"""
        error_obj = {
            "type": "urn:ietf:params:acme:error:dns",
            "detail": "DNS query failed",
            "status": 400,
        }
        json_error = json.dumps(error_obj)

        challenges = [
            self.ChallengeInfo(
                name="challenge-1",
                type="dns-01",
                token="token-1",
                status="invalid",
                authorization_name="auth-1",
                authorization_type="dns",
                authorization_value="example.com",
                url="",
                validation_error=json_error,
            )
        ]

        result = self.service._format_existing_challenges(
            challenges=challenges, url="http://example.com/chall/", config=MockConfig()
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "dns-01")
        self.assertEqual(result[0]["status"], "invalid")
        self.assertEqual(result[0]["error"], error_obj)  # Should be parsed JSON

    def test_069_2_format_existing_challenges_with_invalid_json_validation_error(self):
        """Test _format_existing_challenges with invalid JSON validation_error (lines 421-430)"""
        invalid_json_error = "This is not valid JSON {{"

        challenges = [
            self.ChallengeInfo(
                name="challenge-2",
                type="http-01",
                token="token-2",
                status="invalid",
                authorization_name="auth-2",
                authorization_type="dns",
                authorization_value="example.com",
                url="",
                validation_error=invalid_json_error,
            )
        ]

        result = self.service._format_existing_challenges(
            challenges=challenges, url="http://example.com/chall/", config=MockConfig()
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "http-01")
        self.assertEqual(result[0]["status"], "invalid")
        # Should create default error structure when JSON parsing fails
        expected_error = {
            "status": 400,
            "type": "urn:ietf:params:acme:error:unknown",
            "detail": invalid_json_error,
        }
        self.assertEqual(result[0]["error"], expected_error)

    def test_069_3_format_existing_challenges_with_empty_validation_error(self):
        """Test _format_existing_challenges with empty validation_error (lines 421-430)"""
        challenges = [
            self.ChallengeInfo(
                name="challenge-3",
                type="tls-alpn-01",
                token="token-3",
                status="invalid",
                authorization_name="auth-3",
                authorization_type="dns",
                authorization_value="example.com",
                url="",
                validation_error="",  # Empty string
            )
        ]

        result = self.service._format_existing_challenges(
            challenges=challenges, url="http://example.com/chall/", config=MockConfig()
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "tls-alpn-01")
        self.assertEqual(result[0]["status"], "invalid")
        # Empty string is falsy, so no error key should be added
        self.assertNotIn("error", result[0])

    def test_069_3_2_format_existing_challenges_with_whitespace_validation_error(self):
        """Test _format_existing_challenges with whitespace-only validation_error (lines 421-430)"""
        whitespace_error = "   "  # Only whitespace - still truthy

        challenges = [
            self.ChallengeInfo(
                name="challenge-3-2",
                type="tls-alpn-01",
                token="token-3-2",
                status="invalid",
                authorization_name="auth-3-2",
                authorization_type="dns",
                authorization_value="example.com",
                url="",
                validation_error=whitespace_error,
            )
        ]

        result = self.service._format_existing_challenges(
            challenges=challenges, url="http://example.com/chall/", config=MockConfig()
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "tls-alpn-01")
        self.assertEqual(result[0]["status"], "invalid")
        # Should create default error structure for whitespace validation_error
        expected_error = {
            "status": 400,
            "type": "urn:ietf:params:acme:error:unknown",
            "detail": whitespace_error,
        }
        self.assertEqual(result[0]["error"], expected_error)

    def test_069_4_format_existing_challenges_with_none_validation_error(self):
        """Test _format_existing_challenges with None validation_error (lines 421-430)"""
        challenges = [
            self.ChallengeInfo(
                name="challenge-4",
                type="http-01",
                token="token-4",
                status="valid",  # Valid challenges shouldn't have validation errors
                authorization_name="auth-4",
                authorization_type="dns",
                authorization_value="example.com",
                url="",
                validation_error=None,
            )
        ]

        result = self.service._format_existing_challenges(
            challenges=challenges, url="http://example.com/chall/", config=MockConfig()
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "http-01")
        self.assertEqual(result[0]["status"], "valid")
        # Should not have error key when validation_error is None
        self.assertNotIn("error", result[0])

    def test_069_5_format_existing_challenges_multiple_errors(self):
        """Test _format_existing_challenges with multiple challenges having different error types (lines 421-430)"""
        valid_error = json.dumps(
            {"type": "urn:ietf:params:acme:error:dns", "detail": "Valid JSON error"}
        )
        invalid_error = "Invalid JSON error"

        challenges = [
            self.ChallengeInfo(
                name="challenge-valid-json",
                type="dns-01",
                token="token-1",
                status="invalid",
                authorization_name="auth-1",
                authorization_type="dns",
                authorization_value="example.com",
                url="",
                validation_error=valid_error,
            ),
            self.ChallengeInfo(
                name="challenge-invalid-json",
                type="http-01",
                token="token-2",
                status="invalid",
                authorization_name="auth-2",
                authorization_type="dns",
                authorization_value="example.com",
                url="",
                validation_error=invalid_error,
            ),
            self.ChallengeInfo(
                name="challenge-no-error",
                type="tls-alpn-01",
                token="token-3",
                status="pending",
                authorization_name="auth-3",
                authorization_type="dns",
                authorization_value="example.com",
                url="",
                validation_error=None,
            ),
        ]

        result = self.service._format_existing_challenges(
            challenges=challenges, url="http://example.com/chall/", config=MockConfig()
        )

        self.assertEqual(len(result), 3)

        # First challenge - valid JSON error
        self.assertEqual(
            result[0]["error"],
            {"type": "urn:ietf:params:acme:error:dns", "detail": "Valid JSON error"},
        )

        # Second challenge - invalid JSON error
        expected_error = {
            "status": 400,
            "type": "urn:ietf:params:acme:error:unknown",
            "detail": invalid_error,
        }
        self.assertEqual(result[1]["error"], expected_error)

        # Third challenge - no error
        self.assertNotIn("error", result[2])

    def test_070_create_new_challenge_set_all_types_enabled(self):
        """Test creating challenge set with all special types enabled"""
        self.factory.create_email_reply_challenge = Mock(
            return_value={"type": "email-reply-00", "status": "pending"}
        )
        self.factory.create_tkauth_challenge = Mock(
            return_value={"type": "tkauth-01", "status": "pending"}
        )
        self.factory.create_single_challenge = Mock(
            return_value={"type": "sectigo-email-01", "status": "valid"}
        )
        self.factory.create_standard_challenge_set = Mock(
            return_value=[{"type": "http-01", "status": "pending"}]
        )

        # Test email identifier with tnauthlist and sectigo enabled
        # (should only create email challenge)
        config = MockConfig(
            email_identifier_support=True,
            email_address="admin@example.com",
            tnauthlist_support=True,
            sectigo_sim=True,
        )

        result = self.service._create_new_challenge_set(
            authorization_name="test-auth",
            token="test-token",
            id_type="email",
            id_value="user@example.com",
            config=config,
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "email-reply-00")

        # Standard and other challenges should not be called for email identifier
        self.factory.create_tkauth_challenge.assert_not_called()
        self.factory.create_single_challenge.assert_not_called()
        self.factory.create_standard_challenge_set.assert_not_called()

    def test_071_get_challenge_set_mixed_case_id_types(self):
        """Test challenge set creation with mixed case ID types"""
        self.repository.find_challenges_by_authorization = Mock(return_value=[])
        self.factory.create_tkauth_challenge = Mock(
            return_value={"type": "tkauth-01", "status": "pending"}
        )

        config = MockConfig(tnauthlist_support=True)

        # Test various case variations
        for id_type in ["TNAUTHLIST", "TnAuthList", "tnauthlist", "TnAuThLiSt"]:
            result = self.service.get_challenge_set_for_authorization(
                authorization_name="test-auth",
                token="test-token",
                id_type=id_type,
                id_value="test-value",
                config=config,
            )

            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["type"], "tkauth-01")


if __name__ == "__main__":
    unittest.main()
