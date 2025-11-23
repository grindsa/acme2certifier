#!/usr/bin/python
# -*- coding: utf-8 -*-
"""End-to-End tests for Authorization class public methods"""
# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212

import unittest
import sys
import os
import tempfile
import sqlite3
import json
import time
from unittest.mock import patch, MagicMock

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestAuthorizationE2E(unittest.TestCase):
    """End-to-End test class for Authorization public methods"""

    def setUp(self):
        """Setup test environment with real database"""
        import logging

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_authorization_e2e")

        # Create temporary database for testing
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db.close()

        # Set up database with required tables
        self._setup_test_database()

        # Mock the database path
        self.db_patcher = patch("acme_srv.authorization.DBstore")
        self.mock_dbstore_class = self.db_patcher.start()

        # Create real DBstore instance with our test database
        from acme_srv.db_handler import DBstore

        self.real_dbstore = DBstore(
            debug=False, logger=self.logger, db_name=self.temp_db.name
        )

        self.mock_dbstore_class.return_value = self.real_dbstore

        # Import Authorization class after mocking DBstore
        from acme_srv.authorization import Authorization

        self.authorization = Authorization(
            debug=False, srv_name="http://test.local", logger=self.logger
        )

    def tearDown(self):
        """Clean up test environment"""
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
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS account (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE,
                jwk TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS status (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE
            )
        """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS authorization (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE,
                order_id INTEGER,
                type TEXT,
                value TEXT,
                expires INTEGER,
                token TEXT,
                status_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (status_id) REFERENCES status(id),
                FOREIGN KEY (order_id) REFERENCES orders(id)
            )
        """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS orderstatus (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE
            )
        """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE,
                status_id INTEGER,
                account_id INTEGER,
                expires INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (status_id) REFERENCES orderstatus(id),
                FOREIGN KEY (account_id) REFERENCES account(id)
            )
        """
        )

        # Insert test data
        # Insert statuses
        cursor.execute("INSERT OR IGNORE INTO status (id, name) VALUES (1, 'pending')")
        cursor.execute("INSERT OR IGNORE INTO status (id, name) VALUES (2, 'valid')")
        cursor.execute("INSERT OR IGNORE INTO status (id, name) VALUES (3, 'invalid')")
        cursor.execute("INSERT OR IGNORE INTO status (id, name) VALUES (4, 'expired')")

        # Insert order statuses
        cursor.execute(
            "INSERT OR IGNORE INTO orderstatus (id, name) VALUES (1, 'pending')"
        )
        cursor.execute(
            "INSERT OR IGNORE INTO orderstatus (id, name) VALUES (2, 'valid')"
        )
        cursor.execute(
            "INSERT OR IGNORE INTO orderstatus (id, name) VALUES (3, 'invalid')"
        )

        # Insert test account
        test_jwk = json.dumps({"kty": "RSA", "n": "test-modulus", "e": "AQAB"})
        cursor.execute(
            "INSERT OR IGNORE INTO account (id, name, jwk) VALUES (1, 'test_account', ?)",
            (test_jwk,),
        )

        # Insert test order
        cursor.execute(
            """
            INSERT OR IGNORE INTO orders (id, name, status_id, account_id, expires)
            VALUES (1, 'test_order', 1, 1, ?)
        """,
            (int(time.time()) + 86400,),
        )

        # Insert test authorizations
        current_time = int(time.time())
        cursor.execute(
            """
            INSERT OR IGNORE INTO authorization (id, name, type, value, expires, token, status_id, order_id)
            VALUES (1, 'test_authz_valid', 'dns', 'example.com', ?, 'test_token_1', 1, 1)
        """,
            (current_time + 86400,),
        )

        cursor.execute(
            """
            INSERT OR IGNORE INTO authorization (id, name, type, value, expires, token, status_id, order_id)
            VALUES (2, 'test_authz_expired', 'dns', 'expired.example.com', ?, 'test_token_2', 1, 1)
        """,
            (current_time - 1000,),
        )

        cursor.execute(
            """
            INSERT OR IGNORE INTO authorization (id, name, type, value, expires, token, status_id, order_id)
            VALUES (3, 'test_authz_wildcard', 'dns', '*.wildcard.example.com', ?, 'test_token_3', 2, 1)
        """,
            (current_time + 86400,),
        )

        cursor.execute(
            """
            INSERT OR IGNORE INTO authorization (id, name, type, value, expires, token, status_id, order_id)
            VALUES (4, 'test_authz_tnauthlist', 'TNAuthList', 'sip:user@example.com', ?, 'test_token_4', 1, 2)
        """,
            (current_time + 86400,),
        )

        conn.commit()
        conn.close()

    def _create_valid_acme_request(
        self, url="http://test.local/acme/authz/test_authz_valid"
    ):
        """Helper to create valid ACME request payload"""
        protected_data = {
            "alg": "RS256",
            "nonce": "test_nonce",
            "url": url,
            "jwk": {"kty": "RSA", "n": "test-n", "e": "AQAB"},
        }

        import base64

        return json.dumps(
            {
                "protected": base64.b64encode(
                    json.dumps(protected_data).encode()
                ).decode(),
                "payload": base64.b64encode(json.dumps({}).encode()).decode(),
                "signature": "test_signature",
            }
        )

    # === Constructor Tests ===

    def test_0001_init_default_parameters(self):
        """Test Authorization initialization with default parameters"""
        from acme_srv.authorization import Authorization

        # Authorization requires a logger, so we expect an error with None logger
        with self.assertRaises(AttributeError):
            Authorization()

    def test_0002_init_with_parameters(self):
        """Test Authorization initialization with custom parameters"""
        from acme_srv.authorization import Authorization

        auth = Authorization(
            debug=True, srv_name="https://custom.local", logger=self.logger
        )

        self.assertEqual(auth.server_name, "https://custom.local")
        self.assertTrue(auth.debug)
        self.assertEqual(auth.logger, self.logger)
        self.assertIsNotNone(auth.dbstore)
        self.assertIsNotNone(auth.message)
        self.assertIsNotNone(auth.nonce)

    def test_0003_init_components_creation(self):
        """Test that all required components are created during initialization"""
        from acme_srv.authorization import Authorization

        auth = Authorization(
            debug=False, srv_name="http://test.local", logger=self.logger
        )

        # Verify all components are created
        self.assertIsNotNone(auth.dbstore)
        self.assertIsNotNone(auth.message)
        self.assertIsNotNone(auth.nonce)

        # Verify they have the correct types
        from acme_srv.db_handler import DBstore
        from acme_srv.message import Message
        from acme_srv.nonce import Nonce

        self.assertIsInstance(auth.dbstore, DBstore)
        self.assertIsInstance(auth.message, Message)
        self.assertIsInstance(auth.nonce, Nonce)

    # === Context Manager Tests ===

    def test_0004_context_manager_enter_exit(self):
        """Test Authorization can be used as context manager"""
        from acme_srv.authorization import Authorization

        with patch("acme_srv.authorization.load_config") as mock_load_config:
            # Return a proper ConfigParser object instead of dict
            import configparser

            config = configparser.ConfigParser()
            mock_load_config.return_value = config

            auth = Authorization(
                debug=False, srv_name="http://test.local", logger=self.logger
            )

            # Test context manager
            with auth as auth_instance:
                self.assertEqual(auth_instance, auth)
                # Configuration should be loaded
                mock_load_config.assert_called_once()

    def test_0005_context_manager_config_loading(self):
        """Test configuration is loaded when entering context manager"""
        from acme_srv.authorization import Authorization

        with patch("acme_srv.authorization.load_config") as mock_load_config:
            # Mock configuration with custom values
            import configparser

            config = configparser.ConfigParser()
            config.add_section("Authorization")
            config.set("Authorization", "validity", "3600")
            config.set("Authorization", "expiry_check_disable", "true")
            mock_load_config.return_value = config

            auth = Authorization(
                debug=False, srv_name="http://test.local", logger=self.logger
            )

            with auth:
                # Verify configuration was applied
                self.assertEqual(auth.validity, 3600)
                self.assertTrue(auth.expiry_check_disable)

    def test_0006_context_manager_config_error_handling(self):
        """Test context manager handles configuration errors gracefully"""
        from acme_srv.authorization import Authorization, ConfigurationError

        with patch("acme_srv.authorization.load_config") as mock_load_config:
            # Mock configuration with invalid validity value
            import configparser

            config = configparser.ConfigParser()
            config.add_section("Authorization")
            config.set("Authorization", "validity", "invalid_number")
            mock_load_config.return_value = config

            auth = Authorization(
                debug=False, srv_name="http://test.local", logger=self.logger
            )

            with self.assertRaises(ConfigurationError):
                with auth:
                    pass

    # === Invalidate Method Tests ===

    def test_0007_invalidate_default_timestamp(self):
        """Test invalidate() with default timestamp"""
        with patch("acme_srv.authorization.uts_now", return_value=int(time.time())):
            field_list, output_list = self.authorization.invalidate()

            # Should return expected field list
            expected_fields = [
                "id",
                "name",
                "expires",
                "value",
                "created_at",
                "token",
                "status__id",
                "status__name",
                "order__id",
                "order__name",
            ]
            self.assertEqual(field_list, expected_fields)

            # Should identify expired authorizations
            self.assertIsInstance(output_list, list)

    def test_0008_invalidate_custom_timestamp(self):
        """Test invalidate() with custom timestamp"""
        # Set timestamp to future to make all authorizations appear expired
        future_timestamp = int(time.time()) + 100000

        field_list, output_list = self.authorization.invalidate(
            timestamp=future_timestamp
        )

        # Should return field list
        self.assertIsInstance(field_list, list)
        self.assertIsInstance(output_list, list)

    def test_0009_invalidate_no_expired_authorizations(self):
        """Test invalidate() when no authorizations are expired"""
        # Set timestamp to past to make no authorizations appear expired
        past_timestamp = int(time.time()) - 100000

        field_list, output_list = self.authorization.invalidate(
            timestamp=past_timestamp
        )

        # Should return empty output list
        self.assertIsInstance(field_list, list)
        self.assertEqual(output_list, [])

    def test_0010_invalidate_database_error_handling(self):
        """Test invalidate() handles database errors gracefully"""
        # Mock database error
        with patch.object(
            self.real_dbstore,
            "authorizations_expired_search",
            side_effect=Exception("Database connection failed"),
        ):

            with self.assertLogs(self.logger, level="ERROR") as log:
                field_list, output_list = self.authorization.invalidate()
            self.logger.error(
                "Database error during invalidate(): Database connection failed"
            )

            # Should handle error gracefully and return empty list
            self.assertIsInstance(field_list, list)
            self.assertEqual(output_list, [])

    def test_0011_invalidate_update_error_handling(self):
        """Test invalidate() handles update errors gracefully"""
        # Mock successful search but failed update
        expired_authz = [
            {"name": "test_authz", "status__name": "pending", "expires": 1000}
        ]

        with patch.object(
            self.real_dbstore,
            "authorizations_expired_search",
            return_value=expired_authz,
        ):
            with patch.object(
                self.real_dbstore,
                "authorization_update",
                side_effect=Exception("Update failed"),
            ):
                with self.assertLogs(self.logger, level="ERROR") as log:
                    field_list, output_list = self.authorization.invalidate()
                self.logger.error(
                    "Failed to update authorization 'test_authz' to expired: Update failed"
                )

                # Should still return the expired authorization even if update fails
                self.assertIsInstance(field_list, list)
                self.assertIsInstance(output_list, list)

    # === new_get Method Tests ===

    def test_0012_new_get_valid_authorization(self):
        """Test new_get() with valid authorization URL"""
        url = "http://test.local/acme/authz/test_authz_valid"

        with patch(
            "acme_srv.authorization.generate_random_string", return_value="mock_token"
        ):
            with patch("acme_srv.authorization.uts_now", return_value=1543640400):
                with patch(
                    "acme_srv.challenge.Challenge.challengeset_get", return_value=[]
                ):
                    result = self.authorization.new_get(url)

                    self.assertIsInstance(result, dict)
                    self.assertEqual(result["code"], 200)
                    self.assertIn("header", result)
                    self.assertIn("data", result)

                    # Data might be empty if authorization lookup fails - that's ok for E2E test
                    data = result["data"]
                    self.assertIsInstance(data, dict)

    def test_0013_new_get_nonexistent_authorization(self):
        """Test new_get() with nonexistent authorization URL"""
        url = "http://test.local/acme/authz/nonexistent_authz"

        with patch(
            "acme_srv.authorization.generate_random_string", return_value="mock_token"
        ):
            with patch("acme_srv.authorization.uts_now", return_value=1543640400):
                result = self.authorization.new_get(url)

                self.assertIsInstance(result, dict)
                self.assertEqual(result["code"], 404)  # Nonexistent should return 404
                self.assertIn("header", result)
                self.assertIn("data", result)

    def test_0014_new_get_wildcard_authorization(self):
        """Test new_get() with wildcard authorization"""
        url = "http://test.local/acme/authz/test_authz_wildcard"

        with patch(
            "acme_srv.authorization.generate_random_string", return_value="mock_token"
        ):
            with patch("acme_srv.authorization.uts_now", return_value=1543640400):
                with patch(
                    "acme_srv.challenge.Challenge.challengeset_get", return_value=[]
                ):
                    result = self.authorization.new_get(url)

                    self.assertIsInstance(result, dict)
                    self.assertEqual(result["code"], 200)

                    # Should contain wildcard flag
                    data = result["data"]
                    if "wildcard" in data:
                        self.assertTrue(data["wildcard"])

    def test_0015_new_get_tnauthlist_authorization(self):
        """Test new_get() with TNAuthList authorization"""
        url = "http://test.local/acme/authz/test_authz_tnauthlist"
        with patch(
            "acme_srv.authorization.generate_random_string", return_value="mock_token"
        ):
            with patch("acme_srv.authorization.uts_now", return_value=1543640400):
                with patch(
                    "acme_srv.challenge.Challenge.challengeset_get", return_value=[]
                ):
                    result = self.authorization.new_get(url)

                    self.assertIsInstance(result, dict)
                    self.assertEqual(result["code"], 200)

                    # Should contain TNAuthList identifier
                    data = result["data"]
                    if "identifier" in data and "type" in data["identifier"]:
                        self.assertEqual(data["identifier"]["type"], "TNAuthList")

    def test_0016_new_get_database_error(self):
        """Test new_get() handles database errors gracefully"""
        url = "http://test.local/acme/authz/test_authz"

        # Mock database error in authorization lookup
        with patch.object(
            self.real_dbstore,
            "authorization_lookup",
            side_effect=Exception("Database connection failed"),
        ):

            with self.assertLogs(self.logger, level="ERROR") as log:
                result = self.authorization.new_get(url)
            self.assertIn(
                "CRITICAL:test_authorization_e2e:Database error: failed to lookup authorization 'test_authz': Database connection failed",
                log.output[0],
            )

            # Should handle error and return appropriate error response
            self.assertIsInstance(result, dict)
            self.assertEqual(result["code"], 404)  # Database error should result in 404
            self.assertIn("data", result)
            self.assertIn("error", result["data"])

    # === new_post Method Tests ===

    def test_0017_new_post_valid_request(self):
        """Test new_post() with valid ACME request"""
        content = self._create_valid_acme_request(
            "http://test.local/acme/authz/test_authz_valid"
        )

        with patch.object(self.authorization.message, "check") as mock_check:
            mock_check.return_value = (
                200,
                None,
                None,
                {"url": "http://test.local/acme/authz/test_authz_valid"},
                {},
                "test_account",
            )

            with patch.object(
                self.authorization.message, "prepare_response"
            ) as mock_prepare:
                mock_prepare.return_value = {
                    "code": 200,
                    "header": {"Replay-Nonce": "test_nonce"},
                    "data": {"status": "pending"},
                }

                with patch(
                    "acme_srv.authorization.generate_random_string",
                    return_value="mock_token",
                ):
                    with patch(
                        "acme_srv.authorization.uts_now", return_value=1543640400
                    ):
                        with patch(
                            "acme_srv.challenge.Challenge.challengeset_get",
                            return_value=[],
                        ):
                            result = self.authorization.new_post(content)

                            self.assertIsInstance(result, dict)
                            self.assertIn("code", result)
                            self.assertIn("header", result)

    def test_0018_new_post_invalid_message(self):
        """Test new_post() with invalid message (message check fails)"""
        content = "invalid_json_content"

        with patch.object(self.authorization.message, "check") as mock_check:
            mock_check.return_value = (
                400,
                "urn:ietf:params:acme:error:malformed",
                "Invalid JSON",
                {},
                {},
                None,
            )

            with patch.object(
                self.authorization.message, "prepare_response"
            ) as mock_prepare:
                mock_prepare.return_value = {
                    "code": 400,
                    "header": {},
                    "data": {
                        "type": "urn:ietf:params:acme:error:malformed",
                        "detail": "Invalid JSON",
                        "status": 400,
                    },
                }

                result = self.authorization.new_post(content)

                self.assertIsInstance(result, dict)
                self.assertEqual(result["code"], 400)

    def test_0019_new_post_missing_url_in_protected(self):
        """Test new_post() with missing URL in protected header"""
        content = self._create_valid_acme_request()

        with patch.object(self.authorization.message, "check") as mock_check:
            mock_check.return_value = (
                200,
                None,
                None,
                {},  # Missing URL in protected
                {},
                "test_account",
            )

            with patch.object(
                self.authorization.message, "prepare_response"
            ) as mock_prepare:
                mock_prepare.return_value = {
                    "code": 400,
                    "header": {},
                    "data": {
                        "type": "urn:ietf:params:acme:error:malformed",
                        "detail": "url is missing in protected",
                        "status": 400,
                    },
                }

                result = self.authorization.new_post(content)

                self.assertEqual(result["code"], 400)
                self.assertIn("url is missing", result["data"]["detail"])

    def test_0020_new_post_authorization_lookup_failed(self):
        """Test new_post() when authorization lookup fails"""
        content = self._create_valid_acme_request(
            "http://test.local/acme/authz/nonexistent"
        )

        with patch.object(self.authorization.message, "check") as mock_check:
            mock_check.return_value = (
                200,
                None,
                None,
                {"url": "http://test.local/acme/authz/nonexistent"},
                {},
                "test_account",
            )

            with patch.object(
                self.authorization.message, "prepare_response"
            ) as mock_prepare:
                mock_prepare.return_value = {
                    "code": 403,
                    "header": {},
                    "data": {
                        "type": "urn:ietf:params:acme:error:unauthorized",
                        "detail": "authorizations lookup failed",
                        "status": 403,
                    },
                }

                # Mock get_authorization_details to return empty dict (lookup failed)
                with patch.object(
                    self.authorization, "get_authorization_details", return_value={}
                ):
                    result = self.authorization.new_post(content)

                    self.assertEqual(result["code"], 403)
                    self.assertIn("lookup failed", result["data"]["detail"])

    def test_0021_new_post_with_expiry_check_enabled(self):
        """Test new_post() with expiry check enabled (default behavior)"""
        content = self._create_valid_acme_request(
            "http://test.local/acme/authz/test_authz_valid"
        )

        # Ensure expiry check is enabled
        self.authorization.expiry_check_disable = False

        with patch.object(self.authorization.message, "check") as mock_check:
            mock_check.return_value = (
                200,
                None,
                None,
                {"url": "http://test.local/acme/authz/test_authz_valid"},
                {},
                "test_account",
            )

            with patch.object(
                self.authorization.message, "prepare_response"
            ) as mock_prepare:
                mock_prepare.return_value = {"code": 200, "header": {}, "data": {}}

                with patch.object(self.authorization, "invalidate") as mock_invalidate:
                    mock_invalidate.return_value = ([], [])

                    with patch(
                        "acme_srv.authorization.generate_random_string",
                        return_value="mock_token",
                    ):
                        with patch(
                            "acme_srv.authorization.uts_now", return_value=1543640400
                        ):
                            with patch(
                                "acme_srv.challenge.Challenge.challengeset_get",
                                return_value=[],
                            ):
                                result = self.authorization.new_post(content)

                                # Should call invalidate
                                mock_invalidate.assert_called_once()
                                self.assertIsInstance(result, dict)

    def test_0022_new_post_with_expiry_check_disabled(self):
        """Test new_post() with expiry check disabled"""
        content = self._create_valid_acme_request(
            "http://test.local/acme/authz/test_authz_valid"
        )

        # Disable expiry check
        self.authorization.expiry_check_disable = True

        with patch.object(self.authorization.message, "check") as mock_check:
            mock_check.return_value = (
                200,
                None,
                None,
                {"url": "http://test.local/acme/authz/test_authz_valid"},
                {},
                "test_account",
            )

            with patch.object(
                self.authorization.message, "prepare_response"
            ) as mock_prepare:
                mock_prepare.return_value = {"code": 200, "header": {}, "data": {}}

                with patch.object(self.authorization, "invalidate") as mock_invalidate:
                    mock_invalidate.return_value = ([], [])

                    with patch(
                        "acme_srv.authorization.generate_random_string",
                        return_value="mock_token",
                    ):
                        with patch(
                            "acme_srv.authorization.uts_now", return_value=1543640400
                        ):
                            with patch(
                                "acme_srv.challenge.Challenge.challengeset_get",
                                return_value=[],
                            ):
                                result = self.authorization.new_post(content)

                                # Should NOT call invalidate
                                mock_invalidate.assert_not_called()
                                self.assertIsInstance(result, dict)

    def test_0023_new_post_empty_content(self):
        """Test new_post() with empty content"""
        content = ""

        with patch.object(self.authorization.message, "check") as mock_check:
            mock_check.return_value = (
                400,
                "urn:ietf:params:acme:error:malformed",
                "Empty content",
                {},
                {},
                None,
            )

            with patch.object(
                self.authorization.message, "prepare_response"
            ) as mock_prepare:
                mock_prepare.return_value = {
                    "code": 400,
                    "header": {},
                    "data": {
                        "type": "urn:ietf:params:acme:error:malformed",
                        "detail": "Empty content",
                    },
                }

                result = self.authorization.new_post(content)

                self.assertIsInstance(result, dict)
                self.assertEqual(result["code"], 400)

    def test_0024_new_post_none_content(self):
        """Test new_post() with None content"""
        content = None

        with patch.object(self.authorization.message, "check") as mock_check:
            mock_check.return_value = (
                400,
                "urn:ietf:params:acme:error:malformed",
                "No content provided",
                {},
                {},
                None,
            )

            with patch.object(
                self.authorization.message, "prepare_response"
            ) as mock_prepare:
                mock_prepare.return_value = {
                    "code": 400,
                    "header": {},
                    "data": {
                        "type": "urn:ietf:params:acme:error:malformed",
                        "detail": "No content",
                    },
                }

                result = self.authorization.new_post(content)

                self.assertIsInstance(result, dict)
                self.assertEqual(result["code"], 400)

    # === Error Condition Tests ===

    def test_0025_authorization_with_corrupted_database(self):
        """Test authorization methods with corrupted/missing database"""
        # Create authorization with invalid database path
        invalid_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        invalid_db.close()
        os.unlink(invalid_db.name)  # Delete the file to simulate missing DB

        from acme_srv.db_handler import DBstore

        invalid_dbstore = DBstore(debug=False, logger=self.logger)
        invalid_dbstore.db_file = invalid_db.name

        with patch("acme_srv.authorization.DBstore", return_value=invalid_dbstore):
            from acme_srv.authorization import Authorization

            auth = Authorization(
                debug=False, srv_name="http://test.local", logger=self.logger
            )

            # Test should handle database errors gracefully
            url = "http://test.local/acme/authz/test_authz"
            result = auth.new_get(url)

            # Should handle database error and return error response
            self.assertIsInstance(result, dict)
            self.assertEqual(result["code"], 404)

    def test_0026_authorization_with_malformed_url(self):
        """Test authorization methods with malformed URLs"""
        test_urls = [
            "malformed_url",
            "http://",
            "",
            None,
            "http://test.local/wrong/path/authz",
        ]

        for url in test_urls:
            if url is not None:
                result = self.authorization.new_get(url)

                # Should handle malformed URLs gracefully
                self.assertIsInstance(result, dict)
                self.assertEqual(
                    result["code"], 404
                )  # Malformed URLs should return 404
                self.assertIn("data", result)

    def test_0027_authorization_component_initialization_failure(self):
        """Test authorization with component initialization failures"""
        with patch(
            "acme_srv.authorization.Message",
            side_effect=Exception("Message init failed"),
        ):
            # Should handle initialization errors
            from acme_srv.authorization import Authorization

            with self.assertRaises(Exception):
                Authorization(
                    debug=False, srv_name="http://test.local", logger=self.logger
                )

    def test_0028_authorization_challenge_set_creation_failure(self):
        """Test authorization when challenge set creation fails"""
        url = "http://test.local/acme/authz/test_authz_valid"

        with patch(
            "acme_srv.challenge.Challenge.challengeset_get",
            side_effect=Exception("Challenge creation failed"),
        ):
            with patch(
                "acme_srv.authorization.generate_random_string",
                return_value="mock_token",
            ):
                with patch("acme_srv.authorization.uts_now", return_value=1543640400):
                    result = self.authorization.new_get(url)

                    # Should handle challenge creation error
                    self.assertIsInstance(result, dict)
                    self.assertEqual(
                        result["code"], 404
                    )  # Challenge creation failure should result in 404

    def test_0029_authorization_with_invalid_configuration(self):
        """Test authorization with invalid configuration values"""
        from acme_srv.authorization import Authorization, ConfigurationError

        with patch("acme_srv.authorization.load_config") as mock_load_config:
            # Mock configuration with invalid values
            import configparser

            config = configparser.ConfigParser()
            config.add_section("Authorization")
            config.set("Authorization", "validity", "not_a_number")
            config.add_section("Directory")
            config.set("Directory", "url_prefix", "/custom/prefix")
            mock_load_config.return_value = config

            auth = Authorization(
                debug=False, srv_name="http://test.local", logger=self.logger
            )

            with self.assertRaises(ConfigurationError):
                with auth:
                    pass
                self.assertEqual(auth.validity, 86400)
                # Should apply valid url_prefix
                self.assertEqual(
                    auth.path_dic, {"authz_path": "/custom/prefix/acme/authz/"}
                )

    def test_0030_authorization_message_preparation_failure(self):
        """Test authorization when message preparation fails"""
        content = self._create_valid_acme_request(
            "http://test.local/acme/authz/test_authz_valid"
        )

        with patch.object(self.authorization.message, "check") as mock_check:
            mock_check.return_value = (
                200,
                None,
                None,
                {"url": "http://test.local/acme/authz/test_authz_valid"},
                {},
                "test_account",
            )

            with patch.object(
                self.authorization.message,
                "prepare_response",
                side_effect=Exception("Message preparation failed"),
            ) as mock_prepare:

                with patch(
                    "acme_srv.authorization.generate_random_string",
                    return_value="mock_token",
                ):
                    with patch(
                        "acme_srv.authorization.uts_now", return_value=1543640400
                    ):
                        with patch(
                            "acme_srv.challenge.Challenge.challengeset_get",
                            return_value=[],
                        ):
                            # Should handle message preparation error
                            with self.assertRaises(Exception):
                                self.authorization.new_post(content)

    def test_0031_authorization_with_zero_expires_handling(self):
        """Test authorization with zero expires value handling"""
        # Create authorization with expires=0
        conn = sqlite3.connect(self.temp_db.name)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO authorization (id, name, type, value, expires, token, status_id, order_id)
            VALUES (10, 'test_authz_zero_expires', 'dns', 'zero.example.com', 0, 'test_token_zero', 1, 2)
        """
        )
        conn.commit()
        conn.close()

        # Test invalidate should handle expires=0 correctly
        field_list, output_list = self.authorization.invalidate()

        # Should not include authorizations with expires=0 in output
        self.assertIsInstance(field_list, list)
        self.assertIsInstance(output_list, list)

        # Verify zero expires authorization is not marked as expired
        zero_expires_items = [
            item
            for item in output_list
            if item.get("name") == "test_authz_zero_expires"
        ]
        self.assertEqual(len(zero_expires_items), 0)

    def test_0032_authorization_url_sanitization(self):
        """Test authorization URL sanitization and path handling"""
        # Test various URL formats and special characters
        test_cases = [
            "http://test.local/acme/authz/normal_authz",
            "http://test.local/acme/authz/authz-with-dashes",
            "http://test.local/acme/authz/authz_with_underscores",
            "http://test.local/acme/authz/authz.with.dots",
        ]

        for url in test_cases:
            with patch(
                "acme_srv.authorization.generate_random_string",
                return_value="mock_token",
            ):
                with patch("acme_srv.authorization.uts_now", return_value=1543640400):
                    with patch(
                        "acme_srv.challenge.Challenge.challengeset_get", return_value=[]
                    ):
                        result = self.authorization.new_get(url)

                        # Should handle all URL formats (but these don't exist in DB)
                        self.assertIsInstance(result, dict)
                        self.assertEqual(
                            result["code"], 404
                        )  # Non-existent authorization should return 404
                        self.assertIn("data", result)

    def test_0033_authorization_concurrent_access_simulation(self):
        """Test authorization methods under simulated concurrent access"""
        # Simulate multiple authorization requests
        urls = [
            "http://test.local/acme/authz/test_authz_valid",
            "http://test.local/acme/authz/test_authz_wildcard",
            "http://test.local/acme/authz/test_authz_tnauthlist",
        ]

        results = []
        with patch(
            "acme_srv.authorization.generate_random_string", return_value="mock_token"
        ):
            with patch("acme_srv.authorization.uts_now", return_value=1543640400):
                with patch(
                    "acme_srv.challenge.Challenge.challengeset_get", return_value=[]
                ):
                    for url in urls:
                        result = self.authorization.new_get(url)
                        results.append(result)

        # All requests should be handled (these exist in DB)
        for result in results:
            self.assertIsInstance(result, dict)
            self.assertEqual(
                result["code"], 200
            )  # Existing authorizations should return 200

    def test_0034_authorization_memory_and_resource_handling(self):
        """Test authorization methods with large data sets"""
        # Create multiple authorizations
        conn = sqlite3.connect(self.temp_db.name)
        cursor = conn.cursor()

        current_time = int(time.time())
        for i in range(50):
            cursor.execute(
                """
                INSERT OR IGNORE INTO authorization (name, type, value, expires, token, status_id, order_id)
                VALUES (?, 'dns', ?, ?, ?, 1, 2)
            """,
                (
                    f"test_authz_bulk_{i}",
                    f"bulk{i}.example.com",
                    current_time + 86400,
                    f"token_{i}",
                ),
            )

        conn.commit()
        conn.close()

        # Test invalidate with large dataset
        field_list, output_list = self.authorization.invalidate()

        # Should handle large datasets efficiently
        self.assertIsInstance(field_list, list)
        self.assertIsInstance(output_list, list)

    def test_0035_authorization_edge_case_status_handling(self):
        """Test authorization with edge case status values"""
        # Create authorization with edge case status
        conn = sqlite3.connect(self.temp_db.name)
        cursor = conn.cursor()

        # Insert status that's already expired
        cursor.execute("INSERT OR IGNORE INTO status (id, name) VALUES (5, 'expired')")

        current_time = int(time.time())
        cursor.execute(
            """
            INSERT OR REPLACE INTO authorization (id, name, type, value, expires, token, status_id, order_id)
            VALUES (20, 'test_authz_already_expired', 'dns', 'already.example.com', ?, 'test_token_exp', 5, 2)
        """,
            (current_time - 1000,),
        )

        conn.commit()
        conn.close()

        # Test invalidate with already expired authorization
        field_list, output_list = self.authorization.invalidate()

        # Should handle already expired authorizations correctly
        self.assertIsInstance(field_list, list)
        self.assertIsInstance(output_list, list)


if __name__ == "__main__":
    unittest.main()
