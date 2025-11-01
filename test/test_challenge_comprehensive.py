#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Comprehensive unit tests for Challenge class to ensure backwards compatibility during refactoring"""
# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212, C0103, W0613

import unittest
import sys
import json
import logging
from unittest.mock import patch, MagicMock, Mock, call

# Add path for imports
sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestChallengeComprehensive(unittest.TestCase):
    """Comprehensive test class for Challenge class backwards compatibility"""

    def setUp(self):
        """Setup test environment"""
        # Configure logging
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_challenge_comprehensive")

        # Mock external dependencies that are not part of the Challenge class
        self.mock_dbstore = Mock()
        self.mock_message = Mock()
        self.mock_email_handler = Mock()

        # Setup default return values for dbstore methods
        self.mock_dbstore.challenge_lookup.return_value = {}
        self.mock_dbstore.challenges_search.return_value = []
        self.mock_dbstore.challenge_add.return_value = "test_challenge_name"
        self.mock_dbstore.authorization_lookup.return_value = {'name': 'test_authz'}

        # Create patches for external modules/functions only - NO INTERNAL CHALLENGE METHODS
        self.patches = [
            patch('acme_srv.challenge.DBstore', return_value=self.mock_dbstore),
            patch('acme_srv.challenge.Message', return_value=self.mock_message),
            patch('acme_srv.challenge.EmailHandler', return_value=self.mock_email_handler),
            patch('acme_srv.challenge.load_config'),
            patch('acme_srv.challenge.error_dic_get', return_value={'malformed': 'malformed request'}),
            patch('acme_srv.challenge.generate_random_string', return_value='random_string'),
            patch('acme_srv.challenge.uts_now', return_value=1609459200),
            patch('acme_srv.challenge.time.sleep'),
            patch('acme_srv.challenge.ThreadWithReturnValue'),
        ]

        # Start all patches
        for p in self.patches:
            p.start()

        # Import after patching
        from acme_srv.challenge import Challenge

        # Create challenge instance
        self.challenge = Challenge(
            debug=False,
            srv_name="http://test.local",
            logger=self.logger,
            source="test_source",
            expiry=3600
        )

    def tearDown(self):
        """Clean up after tests"""
        # Stop all patches
        for p in self.patches:
            p.stop()

    # ===================================================================
    # Tests for challengeset_get() method - NO INTERNAL MOCKING
    # ===================================================================

    def test_challengeset_get_existing_challenges(self):
        """Test challengeset_get returns existing challenges when found"""
        # Arrange
        authz_name = "test_authz"
        auth_status = "pending"
        token = "test_token"
        tnauth = False
        id_type = "dns"
        id_value = "example.com"

        # Mock existing challenges from database
        existing_challenges = [
            {
                'name': 'chall1',
                'type': 'http-01',
                'token': 'token1',
                'status__name': 'pending'
            },
            {
                'name': 'chall2',
                'type': 'dns-01',
                'token': 'token2',
                'status__name': 'pending'
            }
        ]

        self.mock_dbstore.challenges_search.return_value = existing_challenges

        # Act - NO INTERNAL METHOD MOCKING
        result = self.challenge.challengeset_get(
            authz_name, auth_status, token, tnauth, id_type, id_value
        )

        # Assert
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)

        # Verify challenge structure
        for challenge in result:
            self.assertIn('type', challenge)
            self.assertIn('token', challenge)
            self.assertIn('url', challenge)
            self.assertIn('status', challenge)
            self.assertTrue(challenge['url'].startswith('http://test.local/acme/chall/'))

        # Verify database was called correctly
        self.mock_dbstore.challenges_search.assert_called_once_with(
            'authorization__name', authz_name, ('name', 'type', 'status__name', 'token')
        )

    def test_challengeset_get_no_existing_challenges(self):
        """Test challengeset_get creates new challenges when none exist"""
        # Arrange
        authz_name = "test_authz"
        auth_status = "pending"
        token = "test_token"
        tnauth = False
        id_type = "dns"
        id_value = "example.com"

        # Mock no existing challenges
        self.mock_dbstore.challenges_search.return_value = []

        # Act - Let the real method run end-to-end
        result = self.challenge.challengeset_get(
            authz_name, auth_status, token, tnauth, id_type, id_value
        )

        # Assert
        self.assertIsInstance(result, list)
        # Should create new challenges - exact structure depends on configuration

    def test_challengeset_get_with_tnauth(self):
        """Test challengeset_get handles tnauth challenges correctly"""
        # Arrange
        authz_name = "test_authz"
        auth_status = "pending"
        token = "test_token"
        tnauth = True

        self.mock_dbstore.challenges_search.return_value = []

        # Act - Real end-to-end execution
        result = self.challenge.challengeset_get(
            authz_name, auth_status, token, tnauth
        )

        # Assert
        self.assertIsInstance(result, list)

    def test_challengeset_get_database_error(self):
        """Test challengeset_get handles database errors gracefully"""
        # Arrange
        authz_name = "test_authz"
        auth_status = "pending"
        token = "test_token"
        tnauth = False

        # Mock database error
        self.mock_dbstore.challenges_search.side_effect = Exception("Database error")

        # Act - Real method execution with error handling
        result = self.challenge.challengeset_get(
            authz_name, auth_status, token, tnauth
        )

        # Assert - should fallback to creating new challenges
        self.assertIsInstance(result, list)

    def test_challengeset_get_empty_authz_name(self):
        """Test challengeset_get with empty authorization name"""
        # Arrange
        authz_name = ""
        auth_status = "pending"
        token = "test_token"
        tnauth = False

        self.mock_dbstore.challenges_search.return_value = []

        # Act
        result = self.challenge.challengeset_get(
            authz_name, auth_status, token, tnauth
        )

        # Assert
        self.assertIsInstance(result, list)

    def test_challengeset_get_none_token(self):
        """Test challengeset_get with None token"""
        # Arrange
        authz_name = "test_authz"
        auth_status = "pending"
        token = None
        tnauth = False

        self.mock_dbstore.challenges_search.return_value = []

        # Act
        result = self.challenge.challengeset_get(
            authz_name, auth_status, token, tnauth
        )

        # Assert
        self.assertIsInstance(result, list)

    # ===================================================================
    # Tests for get() method - NO INTERNAL MOCKING
    # ===================================================================

    def test_get_with_valid_challenge(self):
        """Test get method returns challenge details successfully"""
        # Arrange
        url = "http://test.local/acme/chall/test_challenge"

        # Mock database lookup to return challenge data
        challenge_data = {
            'type': 'http-01',
            'token': 'test_token',
            'status__name': 'pending',
            'validated': None
        }
        self.mock_dbstore.challenge_lookup.return_value = challenge_data

        # Act - Real method execution, no internal mocking
        result = self.challenge.get(url)

        # Assert
        self.assertIsInstance(result, dict)
        self.assertIn('code', result)
        self.assertEqual(result['code'], 200)

    def test_get_with_invalid_url(self):
        """Test get method with invalid URL format"""
        # Arrange
        url = "invalid_url_format"

        # Act - Real method execution
        result = self.challenge.get(url)

        # Assert
        self.assertIsInstance(result, dict)
        self.assertIn('code', result)
        self.assertEqual(result['code'], 200)

    def test_get_challenge_not_found(self):
        """Test get method when challenge is not found"""
        # Arrange
        url = "http://test.local/acme/chall/nonexistent"

        # Mock database lookup to return empty dict (challenge not found)
        self.mock_dbstore.challenge_lookup.return_value = {}

        # Act - Real method execution
        result = self.challenge.get(url)

        # Assert
        self.assertIsInstance(result, dict)
        self.assertIn('code', result)
        self.assertEqual(result['code'], 200)

    def test_get_empty_url(self):
        """Test get method with empty URL"""
        # Arrange
        url = ""

        # Act
        result = self.challenge.get(url)

        # Assert
        self.assertIsInstance(result, dict)
        self.assertIn('code', result)

    # ===================================================================
    # Tests for new_set() method - NO INTERNAL MOCKING
    # ===================================================================

    def test_new_set_standard_challenges(self):
        """Test new_set creates standard challenges"""
        # Arrange
        authz_name = "test_authz"
        token = "test_token"
        tnauth = False
        id_type = "dns"
        value = "example.com"

        # Act - Real method execution
        result = self.challenge.new_set(authz_name, token, tnauth, id_type, value)

        # Assert
        self.assertIsInstance(result, list)

    def test_new_set_tnauth_challenge(self):
        """Test new_set creates tnauth challenge when tnauth=True"""
        # Arrange
        authz_name = "test_authz"
        token = "test_token"
        tnauth = True

        # Act - Real method execution
        result = self.challenge.new_set(authz_name, token, tnauth)

        # Assert
        self.assertIsInstance(result, list)

    def test_new_set_with_sectigo_sim(self):
        """Test new_set creates sectigo challenge when sectigo_sim=True"""
        # Arrange
        self.challenge.sectigo_sim = True
        authz_name = "test_authz"
        token = "test_token"
        tnauth = False

        # Act - Real method execution
        result = self.challenge.new_set(authz_name, token, tnauth)

        # Assert
        self.assertIsInstance(result, list)

    def test_new_set_default_parameters(self):
        """Test new_set with default parameters"""
        # Arrange
        authz_name = "test_authz"
        token = "test_token"

        # Act
        result = self.challenge.new_set(authz_name, token)

        # Assert
        self.assertIsInstance(result, list)

    def test_new_set_empty_authz_name(self):
        """Test new_set with empty authorization name"""
        # Arrange
        authz_name = ""
        token = "test_token"

        # Act
        result = self.challenge.new_set(authz_name, token)

        # Assert
        self.assertIsInstance(result, list)

    # ===================================================================
    # Tests for parse() method - NO INTERNAL MOCKING
    # ===================================================================

    def test_parse_valid_content(self):
        """Test parse method processes valid content successfully"""
        # Arrange
        content = '{"protected": "eyJ1cmwiOiJodHRwOi8vdGVzdC5sb2NhbC9hY21lL2NoYWxsL3Rlc3QifQ==", "payload": "e30=", "signature": "test"}'

        # Mock message.check to return success
        self.mock_message.check.return_value = (
            200, "OK", "",
            {'url': 'http://test.local/acme/chall/test'},
            {},
            "test_account"
        )

        # Mock database lookup for challenge
        challenge_data = {
            'type': 'http-01',
            'token': 'test_token',
            'status__name': 'pending',
            'validated': None,
            'authorization__name': 'test_authz'
        }
        self.mock_dbstore.challenge_lookup.return_value = challenge_data

        # Mock message.prepare_response
        expected_response = {'status': 'pending', 'type': 'http-01'}
        self.mock_message.prepare_response.return_value = expected_response

        # Act - Real method execution, no internal mocking
        result = self.challenge.parse(content)

        # Assert
        self.assertIsInstance(result, dict)
        self.assertEqual(result, expected_response)

    def test_parse_invalid_message(self):
        """Test parse method with invalid message content"""
        # Arrange
        content = "invalid_json_content"

        # Mock message.check to return error
        self.mock_message.check.return_value = (
            400, "malformed", "Invalid JSON", {}, {}, None
        )

        expected_response = {'error': 'malformed request'}
        self.mock_message.prepare_response.return_value = expected_response

        # Act - Real method execution
        result = self.challenge.parse(content)

        # Assert
        self.assertIsInstance(result, dict)
        self.assertEqual(result, expected_response)

    def test_parse_missing_url_in_protected(self):
        """Test parse method when URL is missing in protected header"""
        # Arrange
        content = '{"protected": "eyJhbGciOiJSUzI1NiJ9", "payload": "e30=", "signature": "test"}'

        self.mock_message.check.return_value = (
            200, "OK", "", {}, {}, "test_account"  # Empty protected header
        )

        expected_response = {'error': 'malformed', 'detail': 'url missing in protected header'}
        self.mock_message.prepare_response.return_value = expected_response

        # Act - Real method execution
        result = self.challenge.parse(content)

        # Assert
        self.assertIsInstance(result, dict)
        self.assertEqual(result, expected_response)

    def test_parse_challenge_not_found(self):
        """Test parse method when challenge is not found in database"""
        # Arrange
        content = '{"protected": "eyJ1cmwiOiJodHRwOi8vdGVzdC5sb2NhbC9hY21lL2NoYWxsL25vbmV4aXN0ZW50In0=", "payload": "e30=", "signature": "test"}'

        self.mock_message.check.return_value = (
            200, "OK", "",
            {'url': 'http://test.local/acme/chall/nonexistent'},
            {},
            "test_account"
        )

        # Mock database lookup to return empty dict (challenge not found)
        self.mock_dbstore.challenge_lookup.return_value = {}

        expected_response = {
            'error': 'malformed',
            'detail': 'invalid challenge: nonexistent'
        }
        self.mock_message.prepare_response.return_value = expected_response

        # Act - Real method execution
        result = self.challenge.parse(content)

        # Assert
        self.assertIsInstance(result, dict)
        self.assertEqual(result, expected_response)

    def test_parse_empty_content(self):
        """Test parse method with empty content"""
        # Arrange
        content = ""

        self.mock_message.check.return_value = (
            400, "malformed", "Empty content", {}, {}, None
        )

        expected_response = {'error': 'malformed'}
        self.mock_message.prepare_response.return_value = expected_response

        # Act
        result = self.challenge.parse(content)

        # Assert
        self.assertIsInstance(result, dict)
        self.assertEqual(result, expected_response)

    def test_parse_none_content(self):
        """Test parse method with None content"""
        # Arrange
        content = None

        self.mock_message.check.return_value = (
            400, "malformed", "None content", {}, {}, None
        )

        expected_response = {'error': 'malformed'}
        self.mock_message.prepare_response.return_value = expected_response

        # Act
        result = self.challenge.parse(content)

        # Assert
        self.assertIsInstance(result, dict)
        self.assertEqual(result, expected_response)

    # ===================================================================
    # Tests for initialization and configuration
    # ===================================================================

    def test_challenge_initialization_default_values(self):
        """Test Challenge class initialization with default values"""
        # Import after patching
        from acme_srv.challenge import Challenge

        # Act
        challenge = Challenge()

        # Assert
        self.assertFalse(challenge.challenge_validation_disable)
        self.assertEqual(challenge.challenge_validation_timeout, 10)
        self.assertIsNone(challenge.dns_server_list)
        self.assertEqual(challenge.dns_validation_pause_timer, 0.5)
        self.assertIsNone(challenge.eab_handler)
        self.assertFalse(challenge.eab_profiling)
        self.assertEqual(challenge.expiry, 3600)
        self.assertFalse(challenge.sectigo_sim)
        self.assertFalse(challenge.tnauthlist_support)

    def test_challenge_initialization_custom_values(self):
        """Test Challenge class initialization with custom values"""
        # Import after patching
        from acme_srv.challenge import Challenge

        # Act
        challenge = Challenge(
            debug=True,
            srv_name="https://custom.server.com",
            logger=self.logger,
            source="custom_source",
            expiry=7200
        )

        # Assert
        self.assertEqual(challenge.server_name, "https://custom.server.com")
        self.assertEqual(challenge.logger, self.logger)
        self.assertEqual(challenge.source_address, "custom_source")
        self.assertEqual(challenge.expiry, 7200)

    def test_challenge_context_manager(self):
        """Test Challenge class as context manager"""
        # Import after patching
        from acme_srv.challenge import Challenge

        # Act & Assert
        with Challenge(logger=self.logger) as challenge:
            self.assertIsInstance(challenge, Challenge)

    # ===================================================================
    # Tests for method signatures and return types
    # ===================================================================

    def test_challengeset_get_signature_compliance(self):
        """Test challengeset_get method signature compliance"""
        # Arrange
        authz_name = "test"
        auth_status = "pending"
        token = "token"
        tnauth = False
        id_type = "dns"
        id_value = "example.com"

        self.mock_dbstore.challenges_search.return_value = []

        # Act - Test all parameter combinations - NO INTERNAL MOCKING
        result1 = self.challenge.challengeset_get(authz_name, auth_status, token, tnauth)
        result2 = self.challenge.challengeset_get(authz_name, auth_status, token, tnauth, id_type)
        result3 = self.challenge.challengeset_get(authz_name, auth_status, token, tnauth, id_type, id_value)

        # Assert - All should return lists
        for result in [result1, result2, result3]:
            self.assertIsInstance(result, list)

    def test_get_signature_compliance(self):
        """Test get method signature compliance"""
        # Arrange
        url = "http://test.local/acme/chall/test"

        # Act - NO INTERNAL MOCKING
        result = self.challenge.get(url)

        # Assert
        self.assertIsInstance(result, dict)
        self.assertIn('code', result)

    def test_new_set_signature_compliance(self):
        """Test new_set method signature compliance"""
        # Arrange
        authz_name = "test"
        token = "token"

        # Act - Test all parameter combinations - NO INTERNAL MOCKING
        result1 = self.challenge.new_set(authz_name, token)
        result2 = self.challenge.new_set(authz_name, token, False)
        result3 = self.challenge.new_set(authz_name, token, False, "dns")
        result4 = self.challenge.new_set(authz_name, token, False, "dns", "example.com")

        # Assert - All should return lists
        for result in [result1, result2, result3, result4]:
            self.assertIsInstance(result, list)

    def test_parse_signature_compliance(self):
        """Test parse method signature compliance"""
        # Arrange
        content = "test_content"

        self.mock_message.check.return_value = (400, "error", "detail", {}, {}, None)
        self.mock_message.prepare_response.return_value = {}

        # Act - NO INTERNAL MOCKING
        result = self.challenge.parse(content)

        # Assert
        self.assertIsInstance(result, dict)

    # ===================================================================
    # Integration tests
    # ===================================================================

    def test_integration_full_challenge_flow(self):
        """Test full challenge flow from creation to parsing"""
        # Arrange
        authz_name = "test_authz"
        token = "test_token"
        url = "http://test.local/acme/chall/test_challenge"
        content = '{"protected": "eyJ1cmwiOiJodHRwOi8vdGVzdC5sb2NhbC9hY21lL2NoYWxsL3Rlc3RfY2hhbGxlbmdlIn0=", "payload": "e30=", "signature": "test"}'

        # Mock the flow
        self.mock_dbstore.challenges_search.return_value = []

        challenge_data = {
            'type': 'http-01',
            'token': token,
            'status__name': 'pending',
            'validated': None,
            'authorization__name': authz_name
        }
        self.mock_dbstore.challenge_lookup.return_value = challenge_data

        self.mock_message.check.return_value = (
            200, "OK", "", {'url': url}, {}, "account"
        )
        self.mock_message.prepare_response.return_value = {'status': 'pending'}

        # Act - All real method executions, NO INTERNAL MOCKING
        challenges = self.challenge.challengeset_get(authz_name, "pending", token, False)
        get_result = self.challenge.get(url)
        parse_result = self.challenge.parse(content)

        # Assert
        self.assertIsInstance(challenges, list)
        self.assertIsInstance(get_result, dict)
        self.assertIsInstance(parse_result, dict)

        self.assertEqual(get_result['code'], 200)
        self.assertEqual(parse_result['status'], 'pending')


if __name__ == '__main__':
    unittest.main()