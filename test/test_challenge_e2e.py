#!/usr/bin/python
# -*- coding: utf-8 -*-
"""End-to-End tests for Challenge class public methods"""
# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212

import unittest
import sys
import os
import tempfile
import sqlite3
import json
import base64
from unittest.mock import patch, MagicMock

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestChallengeE2E(unittest.TestCase):
    """End-to-End test class for Challenge public methods"""

    def setUp(self):
        """Setup test environment with real database"""
        import logging
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_challenge_e2e")

        # Create temporary database for testing
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_db.close()

        # Set up database with required tables
        self._setup_test_database()

        # Mock the database path
        self.db_patcher = patch('acme_srv.challenge.DBstore')
        self.mock_dbstore_class = self.db_patcher.start()

        # Create real DBstore instance with our test database
        from acme_srv.db_handler import DBstore
        self.real_dbstore = DBstore(debug=False, logger=self.logger)
        self.real_dbstore.db_file = self.temp_db.name

        self.mock_dbstore_class.return_value = self.real_dbstore

        # Import Challenge class after mocking DBstore
        from acme_srv.challenge import Challenge
        self.challenge = Challenge(debug=False, srv_name="http://test.local", logger=self.logger)

        # Initialize challenge components by entering context manager
        self.challenge.__enter__()

    def tearDown(self):
        """Clean up test environment"""
        # Exit context manager
        try:
            self.challenge.__exit__(None, None, None)
        except:
            pass
        self.db_patcher.stop()
        try:
            os.unlink(self.temp_db.name)
        except:
            pass

    def _setup_test_database(self):
        """Set up test database with required schema and test data"""
        conn = sqlite3.connect(self.temp_db.name)
        cursor = conn.cursor()

        # Create necessary tables (simplified schema for testing)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS account (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE,
                jwk TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS status (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS authorization (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE,
                type TEXT,
                value TEXT,
                status_id INTEGER,
                account_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (status_id) REFERENCES status(id),
                FOREIGN KEY (account_id) REFERENCES account(id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS challenge (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE,
                type TEXT,
                status_id INTEGER,
                authorization_id INTEGER,
                token TEXT,
                keyauthorization TEXT,
                source TEXT,
                validated TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (status_id) REFERENCES status(id),
                FOREIGN KEY (authorization_id) REFERENCES authorization(id)
            )
        ''')

        # Insert test data
        # Insert statuses
        cursor.execute("INSERT OR IGNORE INTO status (id, name) VALUES (1, 'pending')")
        cursor.execute("INSERT OR IGNORE INTO status (id, name) VALUES (2, 'valid')")
        cursor.execute("INSERT OR IGNORE INTO status (id, name) VALUES (3, 'invalid')")
        cursor.execute("INSERT OR IGNORE INTO status (id, name) VALUES (4, 'processing')")

        # Insert test account
        test_jwk = json.dumps({
            "kty": "RSA",
            "n": "test-modulus",
            "e": "AQAB"
        })
        cursor.execute("INSERT OR IGNORE INTO account (id, name, jwk) VALUES (1, 'test_account', ?)", (test_jwk,))

        # Insert test authorization
        cursor.execute("""
            INSERT OR IGNORE INTO authorization (id, name, type, value, status_id, account_id)
            VALUES (1, 'test_authz', 'dns', 'example.com', 1, 1)
        """)

        # Insert test challenge
        cursor.execute("""
            INSERT OR IGNORE INTO challenge (id, name, type, status_id, authorization_id, token, keyauthorization)
            VALUES (1, 'test_challenge', 'dns-01', 1, 1, 'test_token', 'test_keyauth')
        """)

        conn.commit()
        conn.close()

    def _create_valid_acme_request(self, challenge_name="test_challenge", include_url=True):
        """Helper to create valid ACME request payload"""
        protected_data = {
            "alg": "RS256",
            "nonce": "test_nonce",
            "jwk": {"kty": "RSA", "n": "test-n", "e": "AQAB"}
        }

        if include_url:
            protected_data["url"] = f"http://test.local/acme/chall/{challenge_name}"

        return json.dumps({
            "protected": base64.b64encode(json.dumps(protected_data).encode()).decode(),
            "payload": base64.b64encode(json.dumps({}).encode()).decode(),
            "signature": "test_signature"
        })

    # === Successful Cases ===

    def test_0001_parse_legacy_api_compatibility(self):
        """Test parse() method (legacy API) handles requests"""
        test_content = self._create_valid_acme_request()

        with patch.object(self.challenge.message, 'check') as mock_check:
            mock_check.return_value = (
                400, "malformed", "test error", {}, {}, None
            )

            result = self.challenge.parse(test_content)

            # Should return proper response structure
            self.assertIsInstance(result, dict)
            self.assertIn("data", result)
            self.assertEqual(result["data"]["status"], 400)

    def test_0002_challengeset_get_legacy_api_compatibility(self):
        """Test challengeset_get() method (legacy API) returns challenge sets"""
        result = self.challenge.challengeset_get(
            authz_name="test_authz",
            auth_status="pending",
            token="test_token",
            tnauth=False
        )

        # Should return list (legacy compatibility)
        self.assertIsInstance(result, list)

    def test_0003_retrieve_challenge_set_success(self):
        """Test retrieve_challenge_set() returns challenge data"""
        result = self.challenge.retrieve_challenge_set(
            authz_name="test_authz",
            auth_status="pending",
            token="test_token",
            tnauth=False,
            id_type="dns",
            id_value="example.com"
        )

        # Should return list of challenges
        self.assertIsInstance(result, list)

    def test_0004_context_manager_functionality(self):
        """Test Challenge can be used as context manager"""
        # Create new instance to test context manager
        from acme_srv.challenge import Challenge
        challenge = Challenge(debug=False, srv_name="http://test.local", logger=self.logger)

        # Test context manager
        with challenge as challenge_instance:
            self.assertEqual(challenge_instance, challenge)
            # Configuration should be loaded
            self.assertIsNotNone(challenge_instance.config)

    # === Error Condition Tests ===

    def test_0005_process_challenge_request_invalid_json(self):
        """Test process_challenge_request with invalid JSON"""
        result = self.challenge.process_challenge_request("invalid_json")

        # Should return error response
        self.assertIsInstance(result, dict)
        self.assertIn("data", result)
        self.assertIn("status", result["data"])
        # Should be a server error (500) due to JSON parsing failure
        self.assertGreaterEqual(result["data"]["status"], 400)

    def test_0006_process_challenge_request_missing_url(self):
        """Test process_challenge_request with missing URL in protected header"""
        test_content = self._create_valid_acme_request(include_url=False)

        with patch.object(self.challenge.message, 'check') as mock_check:
            mock_check.return_value = (
                200, None, None, {}, {}, "test_account"  # No URL in protected
            )

            result = self.challenge.process_challenge_request(test_content)

            # Should return error for missing URL
            self.assertIn("data", result)
            self.assertEqual(result["data"]["status"], 400)
            self.assertIn("url missing", result["data"]["detail"])

    def test_0007_process_challenge_request_nonexistent_challenge(self):
        """Test process_challenge_request with nonexistent challenge"""
        test_content = self._create_valid_acme_request("nonexistent_challenge")

        with patch.object(self.challenge.message, 'check') as mock_check:
            mock_check.return_value = (
                200, None, None,
                {"url": "http://test.local/acme/chall/nonexistent_challenge"},
                {}, "test_account"
            )

            result = self.challenge.process_challenge_request(test_content)

            # Should return error for nonexistent challenge
            self.assertIn("data", result)
            self.assertEqual(result["data"]["status"], 400)
            self.assertIn("could not get challenge", result["data"]["detail"])

    def test_0008_process_challenge_request_message_check_failure(self):
        """Test process_challenge_request when message.check fails"""
        test_content = self._create_valid_acme_request()

        with patch.object(self.challenge.message, 'check') as mock_check:
            mock_check.return_value = (
                400, "malformed", "signature verification failed", {}, {}, None
            )

            result = self.challenge.process_challenge_request(test_content)

            # Should return the error from message.check
            self.assertIn("data", result)
            self.assertEqual(result["data"]["status"], 400)
            self.assertEqual(result["data"]["type"], "malformed")
            self.assertEqual(result["data"]["detail"], "signature verification failed")

    def test_0009_process_challenge_request_empty_challenge_name(self):
        """Test process_challenge_request when challenge name extraction fails"""
        test_content = self._create_valid_acme_request()

        with patch.object(self.challenge.message, 'check') as mock_check:
            mock_check.return_value = (
                200, None, None,
                {"url": "http://test.local/acme/chall/"},  # Empty challenge name
                {}, "test_account"
            )

            result = self.challenge.process_challenge_request(test_content)

            # Should return error for empty challenge name
            self.assertIn("data", result)
            self.assertEqual(result["data"]["status"], 400)
            self.assertIn("could not get challenge", result["data"]["detail"])

    def test_0010_retrieve_challenge_set_error_handling(self):
        """Test retrieve_challenge_set error handling"""
        # Mock the service to raise an exception
        with patch.object(self.challenge, 'service', spec=[]) as mock_service:
            # Create a mock service that doesn't have the required method
            mock_service.get_challenge_set_for_authorization = MagicMock(
                side_effect=Exception("Database connection failed")
            )

            result = self.challenge.retrieve_challenge_set(
                authz_name="test_authz",
                auth_status="pending",
                token="test_token",
                tnauth=False
            )

            # Should return empty list on error and log the error
            self.assertEqual(result, [])

    def test_0011_challenge_initialization_error_conditions(self):
        """Test Challenge initialization with various error conditions"""
        from acme_srv.challenge import Challenge

        # Test with invalid server name - just verify the attribute is set
        challenge = Challenge(debug=False, srv_name=None, logger=self.logger)
        self.assertIsNone(challenge.server_name)

        # Test that Challenge raises error when logger is None during Message creation
        with self.assertRaises(AttributeError):
            Challenge(debug=False, srv_name="http://test.local", logger=None)

    def test_0012_challenge_components_not_initialized(self):
        """Test error when challenge components are not initialized"""
        from acme_srv.challenge import Challenge
        challenge = Challenge(debug=False, srv_name="http://test.local", logger=self.logger)

        # Don't initialize components (don't call __enter__)

        # Should raise RuntimeError when trying to use uninitialized challenge
        with self.assertRaises(RuntimeError) as cm:
            challenge.process_challenge_request('{"test": "data"}')

        self.assertIn("not initialized", str(cm.exception))

    def test_0013_database_error_conditions(self):
        """Test database error handling"""
        # Create a challenge with a corrupted/missing database
        invalid_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        invalid_db.close()
        os.unlink(invalid_db.name)  # Delete the file to simulate missing DB

        # Create DBstore with invalid path
        from acme_srv.db_handler import DBstore
        invalid_dbstore = DBstore(debug=False, logger=self.logger)
        invalid_dbstore.db_file = invalid_db.name

        with patch('acme_srv.challenge.DBstore', return_value=invalid_dbstore):
            from acme_srv.challenge import Challenge
            challenge = Challenge(debug=False, srv_name="http://test.local", logger=self.logger)

            # Initialize the challenge
            challenge.__enter__()

            # Test should handle database errors gracefully
            test_content = self._create_valid_acme_request("nonexistent")

            with patch.object(challenge.message, 'check') as mock_check:
                mock_check.return_value = (
                    200, None, None,
                    {"url": "http://test.local/acme/chall/nonexistent"},
                    {}, "test_account"
                )

                result = challenge.process_challenge_request(test_content)

                # Should handle database error and return appropriate response
                self.assertIsInstance(result, dict)
                self.assertIn("data", result)

    def test_0014_challenge_malformed_protected_header(self):
        """Test challenge request with malformed protected header"""
        test_content = json.dumps({
            "protected": "invalid_base64!!!",
            "payload": base64.b64encode(json.dumps({}).encode()).decode(),
            "signature": "test_signature"
        })

        result = self.challenge.process_challenge_request(test_content)

        # Should return error response
        self.assertIsInstance(result, dict)
        self.assertIn("data", result)
        self.assertIn("status", result["data"])
        self.assertGreaterEqual(result["data"]["status"], 400)

    def test_0015_challenge_empty_content(self):
        """Test challenge processing with empty content"""
        result = self.challenge.process_challenge_request("")

        # Should handle empty content gracefully
        self.assertIsInstance(result, dict)
        self.assertIn("data", result)
        self.assertIn("status", result["data"])
        self.assertGreaterEqual(result["data"]["status"], 400)

    def test_0016_challenge_none_content(self):
        """Test challenge processing with None content"""
        result = self.challenge.process_challenge_request(None)

        # Should handle None content gracefully
        self.assertIsInstance(result, dict)
        self.assertIn("data", result)
        self.assertIn("status", result["data"])
        self.assertGreaterEqual(result["data"]["status"], 400)

    def test_0017_retrieve_challenge_set_with_invalid_parameters(self):
        """Test retrieve_challenge_set with invalid parameters"""
        # Test with None authz_name
        result = self.challenge.retrieve_challenge_set(
            authz_name=None,
            auth_status="pending",
            token="test_token",
            tnauth=False
        )

        # Should handle gracefully and return empty list or error
        self.assertIsInstance(result, list)

        # Test with empty string authz_name
        result = self.challenge.retrieve_challenge_set(
            authz_name="",
            auth_status="pending",
            token="test_token",
            tnauth=False
        )

        self.assertIsInstance(result, list)

    def test_0018_challenge_url_parsing_edge_cases(self):
        """Test challenge URL parsing edge cases"""
        test_cases = [
            # Malformed URLs that should be handled gracefully
            "http://test.local/acme/chall",  # Missing challenge name
            "http://test.local/wrong/path/challenge",  # Wrong path
            "invalid-url",  # Invalid URL format
            "",  # Empty URL
        ]

        for test_url in test_cases:
            test_content = self._create_valid_acme_request()

            with patch.object(self.challenge.message, 'check') as mock_check:
                mock_check.return_value = (
                    200, None, None,
                    {"url": test_url},
                    {}, "test_account"
                )

                result = self.challenge.process_challenge_request(test_content)

                # Should handle malformed URLs gracefully
                self.assertIsInstance(result, dict)
                self.assertIn("data", result)
                # Should return an error for malformed URLs
                self.assertEqual(result["data"]["status"], 400)

    def test_0019_challenge_with_valid_challenge_exists(self):
        """Test process_challenge_request with valid challenge that exists"""
        test_content = self._create_valid_acme_request("test_challenge")

        with patch.object(self.challenge.message, 'check') as mock_check:
            mock_check.return_value = (
                200, None, None,
                {"url": "http://test.local/acme/chall/test_challenge"},
                {}, "test_account"
            )

            result = self.challenge.process_challenge_request(test_content)

            # Should return a response (either success or error depending on challenge state)
            self.assertIsInstance(result, dict)
            self.assertIn("data", result)

    def test_0020_challengeset_get_with_tnauth_enabled(self):
        """Test challengeset_get with TNAuthList support enabled"""
        # Enable tnauthlist support
        self.challenge.config.tnauthlist_support = True

        result = self.challenge.challengeset_get(
            authz_name="test_authz",
            auth_status="pending",
            token="test_token",
            tnauth=True,
            id_type="sip",
            id_value="sip:user@example.com"
        )

        # Should return list with TNAuth challenges
        self.assertIsInstance(result, list)


if __name__ == "__main__":
    unittest.main()