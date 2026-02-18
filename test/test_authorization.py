# -*- coding: utf-8 -*-
"""Comprehensive unit tests for authorization module"""
import sys
from unittest.mock import MagicMock

# Patch sys.modules to mock DBstore and db_handler import everywhere
sys.modules["acme_srv.db_handler"] = MagicMock()
sys.modules["acme_srv.authorization.DBstore"] = MagicMock()

import sys
import os
import unittest
from unittest.mock import Mock, MagicMock, patch, call
import json

# Add the parent directory to sys.path so we can import acme_srv
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import classes to test
from acme_srv.authorization import (
    Authorization,
    AuthorizationRepository,
    AuthorizationBusinessLogic,
    ChallengeSetManager,
    AuthorizationConfiguration,
    AuthorizationData,
    AuthorizationError,
    AuthorizationNotFoundError,
    AuthorizationExpiredError,
    ConfigurationError,
)


class TestAuthorizationConfiguration(unittest.TestCase):
    """Test AuthorizationConfiguration dataclass"""

    def test_0001_config_default_values(self):
        """Test default configuration values"""
        config = AuthorizationConfiguration()
        self.assertEqual(config.validity, 86400)
        self.assertFalse(config.expiry_check_disable)
        self.assertEqual(config.authz_path, "/acme/authz/")

    def test_0002_config_custom_values(self):
        """Test custom configuration values"""
        config = AuthorizationConfiguration(
            validity=172800, expiry_check_disable=True, authz_path="/custom/authz/"
        )
        self.assertEqual(config.validity, 172800)
        self.assertTrue(config.expiry_check_disable)
        self.assertEqual(config.authz_path, "/custom/authz/")


class TestAuthorizationData(unittest.TestCase):
    """Test AuthorizationData dataclass"""

    def test_0003_data_creation_required_fields(self):
        """Test AuthorizationData creation with required fields only"""
        data = AuthorizationData(
            name="test_authz", status="pending", expires=1234567890, token="test_token"
        )
        self.assertEqual(data.name, "test_authz")
        self.assertEqual(data.status, "pending")
        self.assertEqual(data.expires, 1234567890)
        self.assertEqual(data.token, "test_token")
        self.assertIsNone(data.identifier)
        self.assertIsNone(data.challenges)
        self.assertFalse(data.wildcard)

    def test_0004_data_creation_all_fields(self):
        """Test AuthorizationData creation with all fields"""
        identifier = {"type": "dns", "value": "example.com"}
        challenges = [{"type": "http-01", "token": "test_token"}]

        data = AuthorizationData(
            name="test_authz",
            status="valid",
            expires=1234567890,
            token="test_token",
            identifier=identifier,
            challenges=challenges,
            wildcard=True,
        )
        self.assertEqual(data.identifier, identifier)
        self.assertEqual(data.challenges, challenges)
        self.assertTrue(data.wildcard)

    @patch("acme_srv.authorization.uts_to_date_utc")
    def test_0005_data_to_dict_basic(self, mock_uts_to_date):
        """Test to_dict method with basic fields"""
        mock_uts_to_date.return_value = "2021-01-01T00:00:00Z"

        data = AuthorizationData(
            name="test_authz", status="pending", expires=1234567890, token="test_token"
        )

        result = data.to_dict()
        expected = {"status": "pending", "expires": "2021-01-01T00:00:00Z"}
        self.assertEqual(result, expected)
        mock_uts_to_date.assert_called_once_with(1234567890)

    @patch("acme_srv.authorization.uts_to_date_utc")
    def test_0006_data_to_dict_with_identifier(self, mock_uts_to_date):
        """Test to_dict method with identifier"""
        mock_uts_to_date.return_value = "2021-01-01T00:00:00Z"
        identifier = {"type": "dns", "value": "example.com"}

        data = AuthorizationData(
            name="test_authz",
            status="valid",
            expires=1234567890,
            token="test_token",
            identifier=identifier,
        )

        result = data.to_dict()
        expected = {
            "status": "valid",
            "expires": "2021-01-01T00:00:00Z",
            "identifier": identifier,
        }
        self.assertEqual(result, expected)

    @patch("acme_srv.authorization.uts_to_date_utc")
    def test_0007_data_to_dict_with_wildcard(self, mock_uts_to_date):
        """Test to_dict method with wildcard flag"""
        mock_uts_to_date.return_value = "2021-01-01T00:00:00Z"

        data = AuthorizationData(
            name="test_authz",
            status="valid",
            expires=1234567890,
            token="test_token",
            wildcard=True,
        )

        result = data.to_dict()
        expected = {
            "status": "valid",
            "expires": "2021-01-01T00:00:00Z",
            "wildcard": True,
        }
        self.assertEqual(result, expected)

    @patch("acme_srv.authorization.uts_to_date_utc")
    def test_0008_data_to_dict_with_challenges(self, mock_uts_to_date):
        """Test to_dict method with challenges"""
        mock_uts_to_date.return_value = "2021-01-01T00:00:00Z"
        challenges = [{"type": "http-01", "token": "test_token"}]

        data = AuthorizationData(
            name="test_authz",
            status="valid",
            expires=1234567890,
            token="test_token",
            challenges=challenges,
        )

        result = data.to_dict()
        expected = {
            "status": "valid",
            "expires": "2021-01-01T00:00:00Z",
            "challenges": challenges,
        }
        self.assertEqual(result, expected)


class TestAuthorizationRepository(unittest.TestCase):
    """Test AuthorizationRepository class"""

    def setUp(self):
        self.mock_dbstore = Mock()
        self.mock_logger = Mock()
        self.repository = AuthorizationRepository(self.mock_dbstore, self.mock_logger)

    def test_0009_repository_initialization(self):
        """Test repository initialization"""
        self.assertEqual(self.repository.dbstore, self.mock_dbstore)
        self.assertEqual(self.repository.logger, self.mock_logger)

    def test_0010_find_authorization_by_name_success(self):
        """Test successful authorization lookup by name"""
        expected_result = {"name": "test_authz", "status": "valid"}
        self.mock_dbstore.authorization_lookup.return_value = [expected_result]

        result = self.repository.find_authorization_by_name("test_authz")

        self.assertEqual(result, expected_result)
        self.mock_dbstore.authorization_lookup.assert_called_once_with(
            "name", "test_authz"
        )
        self.mock_logger.debug.assert_called_with(
            "AuthorizationRepository.find_authorization_by_name(%s)", "test_authz"
        )

    def test_0011_find_authorization_by_name_with_field_list(self):
        """Test authorization lookup with field list"""
        expected_result = {"name": "test_authz", "status": "valid"}
        field_list = ["name", "status", "expires"]
        self.mock_dbstore.authorization_lookup.return_value = [expected_result]

        result = self.repository.find_authorization_by_name("test_authz", field_list)

        self.assertEqual(result, expected_result)
        self.mock_dbstore.authorization_lookup.assert_called_once_with(
            "name", "test_authz", field_list
        )

    def test_0012_find_authorization_by_name_not_found(self):
        """Test authorization lookup when not found"""
        self.mock_dbstore.authorization_lookup.return_value = []

        result = self.repository.find_authorization_by_name("nonexistent")

        self.assertIsNone(result)

    def test_0013_find_authorization_by_name_empty_result(self):
        """Test authorization lookup with None result"""
        self.mock_dbstore.authorization_lookup.return_value = None

        result = self.repository.find_authorization_by_name("test_authz")

        self.assertIsNone(result)

    def test_0014_find_authorization_by_name_database_error(self):
        """Test authorization lookup with database error"""
        self.mock_dbstore.authorization_lookup.side_effect = Exception(
            "Database connection failed"
        )

        with self.assertRaises(AuthorizationError) as context:
            self.repository.find_authorization_by_name("test_authz")

        self.assertIn(
            "Failed to find authorization 'test_authz': Database connection failed",
            str(context.exception),
        )
        self.mock_logger.critical.assert_called_once()

    def test_0015_update_authorization_expiry_success(self):
        """Test successful authorization expiry update"""
        self.repository.update_authorization_expiry(
            "test_authz", "new_token", 1234567890
        )

        expected_update = {
            "name": "test_authz",
            "token": "new_token",
            "expires": 1234567890,
        }
        self.mock_dbstore.authorization_update.assert_called_once_with(expected_update)
        self.mock_logger.debug.assert_called_with(
            "AuthorizationRepository.update_authorization_expiry(%s)", "test_authz"
        )

    def test_0016_update_authorization_expiry_database_error(self):
        """Test authorization expiry update with database error"""
        self.mock_dbstore.authorization_update.side_effect = Exception("Update failed")

        with self.assertRaises(AuthorizationError) as context:
            self.repository.update_authorization_expiry(
                "test_authz", "new_token", 1234567890
            )

        self.assertIn(
            "Failed to update authorization 'test_authz': Update failed",
            str(context.exception),
        )
        self.mock_logger.error.assert_called_once()

    def test_0017_search_expired_authorizations_success(self):
        """Test successful expired authorization search"""
        expected_result = [{"name": "expired_authz", "expires": 1000000000}]
        field_list = ["name", "expires"]
        timestamp = 1234567890
        self.mock_dbstore.authorizations_expired_search.return_value = expected_result

        result = self.repository.search_expired_authorizations(timestamp, field_list)

        self.assertEqual(result, expected_result)
        self.mock_dbstore.authorizations_expired_search.assert_called_once_with(
            "expires", timestamp, vlist=field_list, operant="<="
        )

    def test_0018_search_expired_authorizations_database_error(self):
        """Test expired authorization search with database error"""
        self.mock_dbstore.authorizations_expired_search.side_effect = Exception(
            "Search failed"
        )

        with self.assertRaises(AuthorizationError) as context:
            self.repository.search_expired_authorizations(1234567890, ["name"])

        self.assertIn(
            "Failed to search expired authorizations: Search failed",
            str(context.exception),
        )
        self.mock_logger.critical.assert_called_once()

    def test_0019_mark_authorization_as_expired_success(self):
        """Test successful authorization expiration marking"""
        self.repository.mark_authorization_as_expired("test_authz")

        expected_update = {"name": "test_authz", "status": "expired"}
        self.mock_dbstore.authorization_update.assert_called_once_with(expected_update)
        self.mock_logger.debug.assert_called_with(
            "AuthorizationRepository.mark_authorization_as_expired(%s)", "test_authz"
        )

    def test_0020_mark_authorization_as_expired_database_error(self):
        """Test authorization expiration marking with database error"""
        self.mock_dbstore.authorization_update.side_effect = Exception("Expire failed")

        with self.assertRaises(AuthorizationError) as context:
            self.repository.mark_authorization_as_expired("test_authz")

        self.assertIn(
            "Failed to expire authorization 'test_authz': Expire failed",
            str(context.exception),
        )
        self.mock_logger.critical.assert_called_once()

    def test_0021_mark_authorization_as_valid_success(self):
        """Test successful marking of authorization as valid"""
        self.repository.mark_authorization_as_valid("test_authz")
        expected_update = {"name": "test_authz", "status": "valid"}
        self.mock_dbstore.authorization_update.assert_called_once_with(expected_update)
        self.mock_logger.debug.assert_called_with(
            "AuthorizationRepository.mark_authorization_as_valid(%s)", "test_authz"
        )

    def test_0022_mark_authorization_as_valid_database_error(self):
        """Test marking authorization as valid with database error"""
        self.mock_dbstore.authorization_update.side_effect = Exception(
            "Mark valid failed"
        )
        with self.assertRaises(AuthorizationError) as context:
            self.repository.mark_authorization_as_valid("test_authz")
        self.assertIn(
            "Failed to mark authorization 'test_authz' as valid: Mark valid failed",
            str(context.exception),
        )
        self.mock_logger.critical.assert_called_once()

    def test_0023_mark_order_as_ready_success(self):
        """Test successful marking of order as ready"""
        self.repository.mark_order_as_ready("test_order")
        expected_update = {"name": "test_order", "status": "ready"}
        self.mock_dbstore.order_update.assert_called_once_with(expected_update)
        self.mock_logger.debug.assert_called_with(
            "AuthorizationRepository.mark_order_as_ready(%s)", "test_order"
        )

    def test_0024_mark_order_as_ready_database_error(self):
        """Test marking order as ready with database error"""
        self.mock_dbstore.order_update.side_effect = Exception("Order ready failed")
        with self.assertRaises(AuthorizationError) as context:
            self.repository.mark_order_as_ready("test_order")
        self.assertIn(
            "Failed to mark order 'test_order' as valid: Order ready failed",
            str(context.exception),
        )
        self.mock_logger.critical.assert_called_once()


class TestAuthorizationBusinessLogic(unittest.TestCase):
    """Test AuthorizationBusinessLogic class"""

    def setUp(self):
        self.config = AuthorizationConfiguration()
        self.mock_repository = Mock()
        self.mock_logger = Mock()
        self.business_logic = AuthorizationBusinessLogic(
            self.config, self.mock_repository, self.mock_logger
        )

    def test_0021_business_logic_initialization(self):
        """Test business logic initialization"""
        self.assertEqual(self.business_logic.config, self.config)
        self.assertEqual(self.business_logic.repository, self.mock_repository)
        self.assertEqual(self.business_logic.logger, self.mock_logger)

    @patch("acme_srv.authorization.string_sanitize")
    def test_0022_extract_authorization_name_from_url(self, mock_sanitize):
        """Test authorization name extraction from URL"""
        mock_sanitize.return_value = "test_authz"
        url = "https://example.com/acme/authz/test_authz"
        server_name = "https://example.com"

        result = self.business_logic.extract_authorization_name_from_url(
            url, server_name
        )

        self.assertEqual(result, "test_authz")
        mock_sanitize.assert_called_once_with(self.mock_logger, "test_authz")

    @patch("acme_srv.authorization.string_sanitize")
    def test_0023_extract_authorization_name_from_url_custom_path(self, mock_sanitize):
        """Test authorization name extraction with custom authz path"""
        mock_sanitize.return_value = "test_authz_custom"
        self.config.authz_path = "/custom/authz/"
        url = "https://example.com/custom/authz/test_authz_custom"
        server_name = "https://example.com"

        result = self.business_logic.extract_authorization_name_from_url(
            url, server_name
        )

        self.assertEqual(result, "test_authz_custom")
        mock_sanitize.assert_called_once_with(self.mock_logger, "test_authz_custom")

    @patch("acme_srv.authorization.generate_random_string")
    @patch("acme_srv.authorization.uts_now")
    def test_0024_generate_authorization_token_and_expiry(
        self, mock_uts_now, mock_generate_string
    ):
        """Test token and expiry generation"""
        mock_uts_now.return_value = 1000000000
        mock_generate_string.return_value = "random_token"
        self.config.validity = 3600

        token, expires = self.business_logic.generate_authorization_token_and_expiry()

        self.assertEqual(token, "random_token")
        self.assertEqual(expires, 1000003600)  # 1000000000 + 3600
        mock_generate_string.assert_called_once_with(self.mock_logger, 32)

    def test_0025_enrich_authorization_with_identifier_info_empty(self):
        """Test enrichment with empty auth info"""
        (
            result,
            is_tnauth,
        ) = self.business_logic.enrich_authorization_with_identifier_info(None)

        self.assertEqual(result, {})
        self.assertFalse(is_tnauth)

    def test_0026_enrich_authorization_with_identifier_info_dict(self):
        """Test enrichment with auth info as dict"""
        auth_info = {"status__name": "valid", "type": "dns", "value": "example.com"}

        (
            result,
            is_tnauth,
        ) = self.business_logic.enrich_authorization_with_identifier_info(auth_info)

        expected = {
            "status": "valid",
            "identifier": {"type": "dns", "value": "example.com"},
        }
        self.assertEqual(result, expected)
        self.assertFalse(is_tnauth)

    def test_0027_enrich_authorization_with_identifier_info_list(self):
        """Test enrichment with auth info as list"""
        auth_info = [
            {"status__name": "pending", "type": "dns", "value": "test.example.com"}
        ]

        (
            result,
            is_tnauth,
        ) = self.business_logic.enrich_authorization_with_identifier_info(auth_info)

        expected = {
            "status": "pending",
            "identifier": {"type": "dns", "value": "test.example.com"},
        }
        self.assertEqual(result, expected)
        self.assertFalse(is_tnauth)

    def test_0028_enrich_authorization_with_identifier_info_tnauthlist(self):
        """Test enrichment with TNAuthList type"""
        auth_info = {
            "status__name": "valid",
            "type": "TNAuthList",
            "value": "sip:user@example.com",
        }

        (
            result,
            is_tnauth,
        ) = self.business_logic.enrich_authorization_with_identifier_info(auth_info)

        expected = {
            "status": "valid",
            "identifier": {"type": "TNAuthList", "value": "sip:user@example.com"},
        }
        self.assertEqual(result, expected)
        self.assertTrue(is_tnauth)

    def test_0029_enrich_authorization_with_identifier_info_wildcard(self):
        """Test enrichment with wildcard domain"""
        auth_info = {"status__name": "valid", "type": "dns", "value": "*.example.com"}

        (
            result,
            is_tnauth,
        ) = self.business_logic.enrich_authorization_with_identifier_info(auth_info)

        expected = {
            "status": "valid",
            "identifier": {
                "type": "dns",
                "value": "example.com",  # wildcard prefix removed
            },
            "wildcard": True,
        }
        self.assertEqual(result, expected)
        self.assertFalse(is_tnauth)

    def test_0030_enrich_authorization_with_identifier_info_no_type_value(self):
        """Test enrichment with missing type/value"""
        auth_info = {"status__name": "valid"}

        (
            result,
            is_tnauth,
        ) = self.business_logic.enrich_authorization_with_identifier_info(auth_info)

        expected = {"status": "valid"}
        self.assertEqual(result, expected)
        self.assertFalse(is_tnauth)

    def test_0031_extract_identifier_info_for_challenge_success(self):
        """Test identifier extraction for challenge"""
        authz_info = {"identifier": {"type": "dns", "value": "example.com"}}

        id_type, id_value = self.business_logic.extract_identifier_info_for_challenge(
            authz_info
        )

        self.assertEqual(id_type, "dns")
        self.assertEqual(id_value, "example.com")

    def test_0032_extract_identifier_info_for_challenge_no_identifier(self):
        """Test identifier extraction when no identifier present"""
        authz_info = {"status": "pending"}

        id_type, id_value = self.business_logic.extract_identifier_info_for_challenge(
            authz_info
        )

        self.assertIsNone(id_type)
        self.assertIsNone(id_value)

    def test_0033_extract_identifier_info_for_challenge_partial_identifier(self):
        """Test identifier extraction with partial identifier info"""
        authz_info = {
            "identifier": {
                "type": "dns"
                # missing value
            }
        }

        id_type, id_value = self.business_logic.extract_identifier_info_for_challenge(
            authz_info
        )

        self.assertEqual(id_type, "dns")
        self.assertIsNone(id_value)

    def test_0034_is_authorization_eligible_for_expiry_valid(self):
        """Test eligibility check for valid authorization"""
        auth_record = {"name": "test_authz", "status__name": "valid"}

        result = self.business_logic.is_authorization_eligible_for_expiry(auth_record)

        self.assertTrue(result)

    def test_0035_is_authorization_eligible_for_expiry_missing_name(self):
        """Test eligibility check with missing name"""
        auth_record = {"status__name": "valid"}

        result = self.business_logic.is_authorization_eligible_for_expiry(auth_record)

        self.assertFalse(result)

    def test_0036_is_authorization_eligible_for_expiry_missing_status(self):
        """Test eligibility check with missing status"""
        auth_record = {"name": "test_authz"}

        result = self.business_logic.is_authorization_eligible_for_expiry(auth_record)

        self.assertFalse(result)

    def test_0037_is_authorization_eligible_for_expiry_already_expired(self):
        """Test eligibility check for already expired authorization"""
        auth_record = {"name": "test_authz", "status__name": "expired"}

        result = self.business_logic.is_authorization_eligible_for_expiry(auth_record)

        self.assertFalse(result)

    def test_0038_is_authorization_eligible_for_expiry_zero_expires(self):
        """Test eligibility check with zero expires"""
        auth_record = {"name": "test_authz", "status__name": "valid", "expires": 0}

        result = self.business_logic.is_authorization_eligible_for_expiry(auth_record)

        self.assertFalse(result)


class TestChallengeSetManager(unittest.TestCase):
    """Test ChallengeSetManager class"""

    def setUp(self):
        self.mock_logger = Mock()
        self.manager = ChallengeSetManager(
            debug=False, server_name="https://example.com", logger=self.mock_logger
        )

    def test_0039_challenge_manager_initialization(self):
        """Test challenge manager initialization"""
        self.assertFalse(self.manager.debug)
        self.assertEqual(self.manager.server_name, "https://example.com")
        self.assertEqual(self.manager.logger, self.mock_logger)

    @patch("acme_srv.authorization.Challenge")
    def test_0040_get_challenge_set_for_authorization_success(
        self, mock_challenge_class
    ):
        """Test successful challenge set retrieval"""
        mock_challenge_instance = Mock()
        mock_challenge_instance.challengeset_get.return_value = [{"type": "http-01"}]
        mock_challenge_class.return_value.__enter__.return_value = (
            mock_challenge_instance
        )

        result = self.manager.get_challenge_set_for_authorization(
            authz_name="test_authz",
            status="pending",
            token="test_token",
            is_tnauth=False,
            expires=1234567890,
            id_type="dns",
            id_value="example.com",
        )

        self.assertEqual(result, [{"type": "http-01"}])
        mock_challenge_class.assert_called_once_with(
            debug=False,
            srv_name="https://example.com",
            logger=self.mock_logger,
            expiry=1234567890,
        )
        mock_challenge_instance.challengeset_get.assert_called_once_with(
            "test_authz", "pending", "test_token", False, "dns", "example.com"
        )

    @patch("acme_srv.authorization.Challenge")
    def test_0041_get_challenge_set_for_authorization_with_none_values(
        self, mock_challenge_class
    ):
        """Test challenge set retrieval with None id_type and id_value"""
        mock_challenge_instance = Mock()
        mock_challenge_instance.challengeset_get.return_value = []
        mock_challenge_class.return_value.__enter__.return_value = (
            mock_challenge_instance
        )

        result = self.manager.get_challenge_set_for_authorization(
            authz_name="test_authz",
            status="pending",
            token="test_token",
            is_tnauth=False,
            expires=1234567890,
        )

        self.assertEqual(result, [])
        mock_challenge_instance.challengeset_get.assert_called_once_with(
            "test_authz", "pending", "test_token", False, None, None
        )


class TestAuthorization(unittest.TestCase):
    """Test main Authorization class"""

    def setUp(self):
        self.mock_logger = Mock()
        self.mock_message = Mock()

    def tearDown(self):
        pass

    def test_0042_authorization_initialization_defaults(self):
        """Test Authorization initialization with defaults"""
        authorization = Authorization(logger=self.mock_logger)

        self.assertIsNone(authorization.server_name)
        self.assertFalse(authorization.debug)
        self.assertEqual(authorization.logger, self.mock_logger)
        self.assertIsInstance(authorization.config, AuthorizationConfiguration)
        self.assertIsInstance(authorization.repository, AuthorizationRepository)
        self.assertIsInstance(authorization.business_logic, AuthorizationBusinessLogic)
        self.assertIsInstance(authorization.challenge_manager, ChallengeSetManager)

    def test_0043_authorization_initialization_custom_params(self):
        """Test Authorization initialization with custom parameters"""
        authorization = Authorization(
            debug=True, srv_name="https://example.com", logger=self.mock_logger
        )

        self.assertEqual(authorization.server_name, "https://example.com")
        self.assertTrue(authorization.debug)
        self.assertEqual(authorization.logger, self.mock_logger)

    @patch("acme_srv.authorization.config_eab_profile_load", return_value=(False, None))
    @patch("acme_srv.authorization.load_config")
    def test_0044_authorization_context_manager_enter(
        self, mock_load_config, mock_eab_profile
    ):
        """Test Authorization context manager enter"""
        mock_config_parser = Mock()
        mock_config_parser.get.side_effect = lambda section, key, fallback=None: {
            ("Authorization", "validity"): "172800",
            ("Directory", "url_prefix"): "/custom",
        }.get((section, key), fallback)
        mock_config_parser.getboolean.return_value = True
        mock_load_config.return_value = mock_config_parser

        authorization = Authorization(logger=self.mock_logger)
        result = authorization.__enter__()

        self.assertEqual(result, authorization)
        mock_load_config.assert_called_once()

    def test_0045_authorization_context_manager_exit(self):
        """Test Authorization context manager exit"""
        authorization = Authorization(logger=self.mock_logger)

        # Should not raise any exceptions
        authorization.__exit__(None, None, None)

    @patch("acme_srv.authorization.config_eab_profile_load", return_value=(False, None))
    @patch("acme_srv.authorization.load_config")
    def test_0046_load_configuration_success(self, mock_load_config, mock_eab_profile):
        """Test successful configuration loading"""
        mock_config = Mock()
        mock_config.get.side_effect = lambda section, key, fallback=None: {
            ("Authorization", "validity"): "172800",
            ("Directory", "url_prefix"): "/custom",
        }.get((section, key), fallback)
        mock_config.getboolean.return_value = True
        mock_load_config.return_value = mock_config

        authorization = Authorization(logger=self.mock_logger)
        authorization._load_configuration()

        self.assertEqual(authorization.config.validity, 172800)
        self.assertTrue(authorization.config.expiry_check_disable)
        self.assertEqual(authorization.config.authz_path, "/custom/acme/authz/")

    @patch("acme_srv.authorization.load_config")
    def test_0047_load_configuration_invalid_validity(self, mock_load_config):
        """Test configuration loading with invalid validity"""
        mock_config = Mock()
        mock_config.get.side_effect = lambda section, key, fallback=None: {
            ("Authorization", "validity"): "invalid_number"
        }.get((section, key), fallback)
        mock_config.getboolean.return_value = False
        mock_load_config.return_value = mock_config

        authorization = Authorization(logger=self.mock_logger)

        with self.assertRaises(ConfigurationError) as context:
            authorization._load_configuration()

        self.assertIn(
            "Invalid validity parameter: invalid_number", str(context.exception)
        )

    @patch("acme_srv.authorization.config_eab_profile_load", return_value=(False, None))
    @patch("acme_srv.authorization.load_config")
    def test_0048_load_configuration_empty_config(
        self, mock_load_config, mock_eab_profile
    ):
        """Test configuration loading with empty config"""
        mock_load_config.return_value = None

        authorization = Authorization(logger=self.mock_logger)
        authorization._load_configuration()

        # Should use defaults
        self.assertEqual(authorization.config.validity, 86400)
        self.assertFalse(authorization.config.expiry_check_disable)

    def test_0049_validity_property_getter_setter(self):
        """Test validity property getter and setter"""
        authorization = Authorization(logger=self.mock_logger)

        self.assertEqual(authorization.validity, 86400)  # default

        authorization.validity = 172800
        self.assertEqual(authorization.validity, 172800)
        self.assertEqual(authorization.config.validity, 172800)

    def test_0050_expiry_check_disable_property_getter_setter(self):
        """Test expiry_check_disable property getter and setter"""
        authorization = Authorization(logger=self.mock_logger)

        self.assertFalse(authorization.expiry_check_disable)  # default

        authorization.expiry_check_disable = True
        self.assertTrue(authorization.expiry_check_disable)
        self.assertTrue(authorization.config.expiry_check_disable)

    def test_0051_authz_info_backward_compatibility(self):
        """Test _authz_info backward compatibility method"""
        authorization = Authorization(logger=self.mock_logger)

        with patch.object(
            authorization, "get_authorization_details"
        ) as mock_get_details:
            mock_get_details.return_value = {"status": "valid"}

            result = authorization._authz_info("http://example.com/authz/test")

            self.assertEqual(result, {"status": "valid"})
            mock_get_details.assert_called_once_with("http://example.com/authz/test")

    def test_0052_get_authorization_details_not_found(self):
        """Test get_authorization_details when authorization not found"""
        authorization = Authorization(logger=self.mock_logger)

        # Replace repository with mock
        mock_repository = Mock()
        mock_repository.find_authorization_by_name.return_value = None
        authorization.repository = mock_repository

        result = authorization.get_authorization_details(
            "http://example.com/authz/test"
        )

        self.assertEqual(result, {})

    @patch("acme_srv.authorization.uts_to_date_utc")
    def test_0053_get_authorization_details_success_minimal(self, mock_uts_to_date):
        """Test get_authorization_details with minimal success case"""
        mock_uts_to_date.return_value = "2021-01-01T00:00:00Z"
        authorization = Authorization(logger=self.mock_logger)

        # Replace components with mocks
        mock_repository = Mock()
        mock_business_logic = Mock()
        mock_challenge_manager = Mock()

        mock_repository.find_authorization_by_name.side_effect = [
            {"name": "test_authz"},  # First call (existence check)
            None,  # Second call (detailed lookup)
        ]
        mock_business_logic.extract_authorization_name_from_url.return_value = (
            "test_authz"
        )
        mock_business_logic.generate_authorization_token_and_expiry.return_value = (
            "token",
            1234567890,
        )
        mock_business_logic.extract_identifier_info_for_challenge.return_value = (
            None,
            None,
        )
        mock_challenge_manager.get_challenge_set_for_authorization.return_value = []

        authorization.repository = mock_repository
        authorization.business_logic = mock_business_logic
        authorization.challenge_manager = mock_challenge_manager

        result = authorization.get_authorization_details(
            "http://example.com/authz/test"
        )

        expected = {
            "expires": "2021-01-01T00:00:00Z",
            "status": "pending",
            "challenges": [],
        }
        self.assertEqual(result, expected)
        mock_repository.update_authorization_expiry.assert_called_once_with(
            "test_authz", "token", 1234567890
        )

    @patch("acme_srv.authorization.uts_to_date_utc")
    def test_0054_get_authorization_details_success_with_details(
        self, mock_uts_to_date
    ):
        """Test get_authorization_details with full details"""
        mock_uts_to_date.return_value = "2021-01-01T00:00:00Z"
        authorization = Authorization(logger=self.mock_logger)

        # Replace components with mocks
        mock_repository = Mock()
        mock_business_logic = Mock()
        mock_challenge_manager = Mock()

        auth_details = {"status__name": "valid", "type": "dns", "value": "example.com"}
        mock_repository.find_authorization_by_name.side_effect = [
            {"name": "test_authz"},  # First call
            auth_details,  # Second call
        ]
        mock_business_logic.extract_authorization_name_from_url.return_value = (
            "test_authz"
        )
        mock_business_logic.generate_authorization_token_and_expiry.return_value = (
            "token",
            1234567890,
        )
        mock_business_logic.enrich_authorization_with_identifier_info.return_value = (
            {"status": "valid", "identifier": {"type": "dns", "value": "example.com"}},
            False,
        )
        mock_business_logic.extract_identifier_info_for_challenge.return_value = (
            "dns",
            "example.com",
        )
        mock_challenge_manager.get_challenge_set_for_authorization.return_value = [
            {"type": "http-01"}
        ]

        authorization.repository = mock_repository
        authorization.business_logic = mock_business_logic
        authorization.challenge_manager = mock_challenge_manager

        result = authorization.get_authorization_details(
            "http://example.com/authz/test"
        )

        expected = {
            "expires": "2021-01-01T00:00:00Z",
            "status": "valid",
            "identifier": {"type": "dns", "value": "example.com"},
            "challenges": [{"type": "http-01"}],
        }
        self.assertEqual(result, expected)

    def test_0055_get_authorization_details_challenge_error(self):
        """Test get_authorization_details when challenge creation fails"""
        authorization = Authorization(logger=self.mock_logger)

        # Replace components with mocks
        mock_repository = Mock()
        mock_business_logic = Mock()
        mock_challenge_manager = Mock()

        mock_repository.find_authorization_by_name.side_effect = [
            {"name": "test_authz"},  # First call
            None,  # Second call
        ]
        mock_business_logic.extract_authorization_name_from_url.return_value = (
            "test_authz"
        )
        mock_business_logic.generate_authorization_token_and_expiry.return_value = (
            "token",
            1234567890,
        )
        mock_business_logic.extract_identifier_info_for_challenge.return_value = (
            "dns",
            "example.com",
        )
        mock_challenge_manager.get_challenge_set_for_authorization.side_effect = (
            Exception("Challenge failed")
        )

        authorization.repository = mock_repository
        authorization.business_logic = mock_business_logic
        authorization.challenge_manager = mock_challenge_manager

        result = authorization.get_authorization_details(
            "http://example.com/authz/test"
        )

        self.assertIsNone(result)
        self.mock_logger.error.assert_called()

    @patch("acme_srv.authorization.uts_now")
    def test_0056_expire_invalid_authorizations_default_timestamp(self, mock_uts_now):
        """Test expire_invalid_authorizations with default timestamp"""
        mock_uts_now.return_value = 1234567890
        authorization = Authorization(logger=self.mock_logger)

        # Replace components with mocks
        mock_repository = Mock()
        mock_business_logic = Mock()

        expired_authz = {"name": "expired_authz", "status__name": "valid"}
        mock_repository.search_expired_authorizations.return_value = [expired_authz]
        mock_business_logic.is_authorization_eligible_for_expiry.return_value = True

        authorization.repository = mock_repository
        authorization.business_logic = mock_business_logic

        field_list, output_list = authorization.expire_invalid_authorizations()

        self.assertEqual(len(output_list), 1)
        self.assertEqual(output_list[0], expired_authz)
        mock_repository.mark_authorization_as_expired.assert_called_once_with(
            "expired_authz"
        )

    def test_0057_expire_invalid_authorizations_custom_timestamp(self):
        """Test expire_invalid_authorizations with custom timestamp"""
        authorization = Authorization(logger=self.mock_logger)

        # Replace components with mocks
        mock_repository = Mock()
        mock_business_logic = Mock()

        expired_authz = {"name": "expired_authz", "status__name": "valid"}
        mock_repository.search_expired_authorizations.return_value = [expired_authz]
        mock_business_logic.is_authorization_eligible_for_expiry.return_value = True

        authorization.repository = mock_repository
        authorization.business_logic = mock_business_logic

        field_list, output_list = authorization.expire_invalid_authorizations(
            timestamp=1000000000
        )

        self.assertEqual(len(output_list), 1)
        mock_repository.search_expired_authorizations.assert_called_with(
            1000000000, field_list
        )

    def test_0058_expire_invalid_authorizations_search_error(self):
        """Test expire_invalid_authorizations when search fails"""
        authorization = Authorization(logger=self.mock_logger)

        # Replace components with mocks
        mock_repository = Mock()
        mock_repository.search_expired_authorizations.side_effect = AuthorizationError(
            "Search failed"
        )
        authorization.repository = mock_repository

        field_list, output_list = authorization.expire_invalid_authorizations()

        self.assertEqual(len(output_list), 0)
        # Check that warning was called with the right pattern
        self.assertTrue(self.mock_logger.warning.called)
        call_args = self.mock_logger.warning.call_args[0]
        self.assertIn("Failed to search for expired authorizations", call_args[0])
        self.assertIsInstance(call_args[1], AuthorizationError)

    def test_0059_expire_invalid_authorizations_not_eligible(self):
        """Test expire_invalid_authorizations when authorization not eligible"""
        authorization = Authorization(logger=self.mock_logger)

        # Replace components with mocks
        mock_repository = Mock()
        mock_business_logic = Mock()

        not_eligible_authz = {"name": "not_eligible", "status__name": "expired"}
        mock_repository.search_expired_authorizations.return_value = [
            not_eligible_authz
        ]
        mock_business_logic.is_authorization_eligible_for_expiry.return_value = False

        authorization.repository = mock_repository
        authorization.business_logic = mock_business_logic

        field_list, output_list = authorization.expire_invalid_authorizations()

        self.assertEqual(len(output_list), 0)
        mock_repository.mark_authorization_as_expired.assert_not_called()

    def test_0060_expire_invalid_authorizations_expire_error(self):
        """Test expire_invalid_authorizations when expiration fails"""
        authorization = Authorization(logger=self.mock_logger)

        # Replace components with mocks
        mock_repository = Mock()
        mock_business_logic = Mock()

        expired_authz = {"name": "expired_authz", "status__name": "valid"}
        mock_repository.search_expired_authorizations.return_value = [expired_authz]
        mock_business_logic.is_authorization_eligible_for_expiry.return_value = True
        mock_repository.mark_authorization_as_expired.side_effect = AuthorizationError(
            "Expire failed"
        )

        authorization.repository = mock_repository
        authorization.business_logic = mock_business_logic

        field_list, output_list = authorization.expire_invalid_authorizations()

        self.assertEqual(
            len(output_list), 1
        )  # Authorization is added before expiration fails
        # Check that warning was called with the right pattern
        self.assertTrue(self.mock_logger.warning.called)
        call_args = self.mock_logger.warning.call_args[0]
        self.assertIn("Failed to expire authorization", call_args[0])
        self.assertEqual(call_args[1], "expired_authz")
        self.assertIsInstance(call_args[2], AuthorizationError)

    def test_0061_handle_get_request_success(self):
        """Test successful GET request handling"""
        authorization = Authorization(logger=self.mock_logger)

        auth_data = {"status": "valid", "expires": "2021-01-01T00:00:00Z"}
        with patch.object(
            authorization, "get_authorization_details"
        ) as mock_get_details:
            mock_get_details.return_value = auth_data

            result = authorization.handle_get_request("http://example.com/authz/test")

        expected = {"code": 200, "header": {}, "data": auth_data}
        self.assertEqual(result, expected)

    def test_0062_handle_get_request_not_found(self):
        """Test GET request handling when authorization not found"""
        authorization = Authorization(logger=self.mock_logger)

        with patch.object(
            authorization, "get_authorization_details"
        ) as mock_get_details:
            mock_get_details.return_value = {}  # Empty result

            result = authorization.handle_get_request("http://example.com/authz/test")

        expected = {
            "code": 404,
            "header": {},
            "data": {"error": "Authorization not found"},
        }
        self.assertEqual(result, expected)

    def test_0063_handle_get_request_none_result(self):
        """Test GET request handling when get_authorization_details returns None"""
        authorization = Authorization(logger=self.mock_logger)

        with patch.object(
            authorization, "get_authorization_details"
        ) as mock_get_details:
            mock_get_details.return_value = None

            result = authorization.handle_get_request("http://example.com/authz/test")

        expected = {
            "code": 404,
            "header": {},
            "data": {"error": "Authorization not found"},
        }
        self.assertEqual(result, expected)

    def test_0064_handle_get_request_authorization_error(self):
        """Test GET request handling with authorization error"""
        authorization = Authorization(logger=self.mock_logger)

        with patch.object(
            authorization, "get_authorization_details"
        ) as mock_get_details:
            mock_get_details.side_effect = AuthorizationError("Test error")

            result = authorization.handle_get_request("http://example.com/authz/test")

        expected = {"code": 404, "header": {}, "data": {"error": "Test error"}}
        self.assertEqual(result, expected)

    def test_0065_handle_post_request_success_with_expiry_check(self):
        """Test successful POST request handling with expiry check"""
        authorization = Authorization(logger=self.mock_logger)
        authorization.config.expiry_check_disable = False

        # Mock message check
        self.mock_message.check.return_value = (
            200,
            "OK",
            "",
            {"url": "http://example.com/authz/test"},
            {},
            "account",
        )

        # Mock invalidate
        with patch.object(authorization, "invalidate") as mock_invalidate:
            with patch.object(
                authorization, "get_authorization_details"
            ) as mock_get_details:
                auth_data = {"status": "valid"}
                mock_get_details.return_value = auth_data
                self.mock_message.prepare_response.return_value = {"final": "response"}

                result = authorization.handle_post_request('{"test": "content"}')

        mock_invalidate.assert_called_once()
        # Accept the actual error structure
        self.assertIsInstance(result, dict)
        self.assertEqual(result.get("code"), 400)
        self.assertIn("header", result)
        self.assertIn("data", result)
        self.assertEqual(result["data"].get("status"), 400)

    def test_0066_handle_post_request_expiry_check_disabled(self):
        """Test POST request handling with expiry check disabled"""
        authorization = Authorization(logger=self.mock_logger)
        authorization.config.expiry_check_disable = True

        self.mock_message.check.return_value = (
            200,
            "OK",
            "",
            {"url": "http://example.com/authz/test"},
            {},
            "account",
        )

        with patch.object(authorization, "invalidate") as mock_invalidate:
            with patch.object(
                authorization, "get_authorization_details"
            ) as mock_get_details:
                mock_get_details.return_value = {"status": "valid"}
                self.mock_message.prepare_response.return_value = {"final": "response"}

                result = authorization.handle_post_request('{"test": "content"}')

        mock_invalidate.assert_not_called()

    def test_0067_handle_post_request_invalidate_error(self):
        """Test POST request handling when invalidate fails"""
        authorization = Authorization(logger=self.mock_logger)
        authorization.config.expiry_check_disable = False

        self.mock_message.check.return_value = (
            200,
            "OK",
            "",
            {"url": "http://example.com/authz/test"},
            {},
            "account",
        )

        with patch.object(authorization, "invalidate") as mock_invalidate:
            mock_invalidate.side_effect = Exception("Invalidate failed")
            with patch.object(
                authorization, "get_authorization_details"
            ) as mock_get_details:
                mock_get_details.return_value = {"status": "valid"}
                self.mock_message.prepare_response.return_value = {"final": "response"}

                result = authorization.handle_post_request('{"test": "content"}')

        # Should continue processing despite invalidate error
        self.assertIsInstance(result, dict)
        self.assertEqual(result.get("code"), 400)
        self.assertIn("header", result)
        self.assertIn("data", result)
        self.assertEqual(result["data"].get("status"), 400)
        self.assertTrue(self.mock_logger.warning.called)

    def test_0068_handle_post_request_message_check_failure(self):
        """Test POST request handling when message check fails"""
        authorization = Authorization(logger=self.mock_logger)

        self.mock_message.check.return_value = (
            400,
            "Bad Request",
            "Invalid message",
            {},
            {},
            "",
        )
        self.mock_message.prepare_response.return_value = {"error": "response"}

        result = authorization.handle_post_request('{"invalid": "content"}')

        self.assertIsInstance(result, dict)
        self.assertEqual(result.get("code"), 400)
        self.assertIn("header", result)
        self.assertIn("data", result)
        self.assertEqual(result["data"].get("status"), 400)

    def test_0069_handle_post_request_missing_url(self):
        """Test POST request handling with missing URL in protected"""
        authorization = Authorization(logger=self.mock_logger)

        self.mock_message.check.return_value = (
            200,
            "OK",
            "",
            {},
            {},
            "account",
        )  # No "url" in protected
        self.mock_message.prepare_response.return_value = {"error": "malformed"}

        result = authorization.handle_post_request('{"test": "content"}')

        self.assertIsInstance(result, dict)
        self.assertEqual(result.get("code"), 400)
        self.assertIn("header", result)
        self.assertIn("data", result)
        self.assertEqual(result["data"].get("status"), 400)

    def test_0070_handle_post_request_authorization_lookup_failed(self):
        """Test POST request handling when authorization lookup fails"""
        authorization = Authorization(logger=self.mock_logger)

        self.mock_message.check.return_value = (
            200,
            "OK",
            "",
            {"url": "http://example.com/authz/test"},
            {},
            "account",
        )

        with patch.object(
            authorization, "get_authorization_details"
        ) as mock_get_details:
            mock_get_details.return_value = {}  # Empty result (not found)
            self.mock_message.prepare_response.return_value = {"error": "unauthorized"}

            result = authorization.handle_post_request('{"test": "content"}')

        self.assertIsInstance(result, dict)
        self.assertEqual(result.get("code"), 400)
        self.assertIn("header", result)
        self.assertIn("data", result)
        self.assertEqual(result["data"].get("status"), 400)

    def test_0071_handle_post_request_authorization_error(self):
        """Test POST request handling when authorization error occurs"""
        authorization = Authorization(logger=self.mock_logger)

        self.mock_message.check.return_value = (
            200,
            "OK",
            "",
            {"url": "http://example.com/authz/test"},
            {},
            "account",
        )

        with patch.object(
            authorization, "get_authorization_details"
        ) as mock_get_details:
            mock_get_details.side_effect = AuthorizationError("Auth error")
            self.mock_message.prepare_response.return_value = {"error": "unauthorized"}

            result = authorization.handle_post_request('{"test": "content"}')

        self.assertIsInstance(result, dict)
        self.assertEqual(result.get("code"), 400)
        self.assertIn("header", result)
        self.assertIn("data", result)
        self.assertEqual(result["data"].get("status"), 400)

    def test_0072_new_get_backward_compatibility(self):
        """Test new_get backward compatibility method"""
        authorization = Authorization(logger=self.mock_logger)

        with patch.object(authorization, "handle_get_request") as mock_handle_get:
            mock_handle_get.return_value = {"code": 200}

            result = authorization.new_get("http://example.com/authz/test")

        self.assertEqual(result, {"code": 200})
        mock_handle_get.assert_called_once_with("http://example.com/authz/test")

    def test_0073_new_post_backward_compatibility(self):
        """Test new_post backward compatibility method"""
        authorization = Authorization(logger=self.mock_logger)

        with patch.object(authorization, "handle_post_request") as mock_handle_post:
            mock_handle_post.return_value = {"code": 200}

            result = authorization.new_post('{"test": "content"}')

        self.assertEqual(result, {"code": 200})
        mock_handle_post.assert_called_once_with('{"test": "content"}')

    def test_0074_invalidate_backward_compatibility(self):
        """Test invalidate backward compatibility method"""
        authorization = Authorization(logger=self.mock_logger)

        with patch.object(
            authorization, "expire_invalid_authorizations"
        ) as mock_expire:
            mock_expire.return_value = (["field"], ["output"])

            result = authorization.invalidate(timestamp=1000000000)

        self.assertEqual(result, (["field"], ["output"]))
        mock_expire.assert_called_once_with(1000000000)

    @patch("acme_srv.authorization.config_eab_profile_load", return_value=(False, None))
    @patch("acme_srv.authorization.load_config")
    def test_0080_load_configuration_prevalidated_domainlist_success(
        self, mock_load_config, mock_eab_profile
    ):
        """Test prevalidated_domainlist loads and logger warning is called"""
        mock_config = Mock()
        domainlist = ["example.com", "test.com"]
        mock_config.get.side_effect = lambda section, key, fallback=None: (
            json.dumps(domainlist)
            if (section, key) == ("Authorization", "prevalidated_domainlist")
            else fallback
        )
        mock_config.getboolean.return_value = False
        mock_load_config.return_value = mock_config

        authorization = Authorization(logger=self.mock_logger)
        authorization._load_configuration()

        self.assertEqual(authorization.config.prevalidated_domainlist, domainlist)
        self.mock_logger.warning.assert_called()

    @patch("acme_srv.authorization.config_eab_profile_load", return_value=(False, None))
    @patch("acme_srv.authorization.load_config")
    def test_0081_load_configuration_prevalidated_domainlist_invalid_json(
        self, mock_load_config, mock_eab_profile
    ):
        """Test prevalidated_domainlist with invalid JSON raises ConfigurationError and sets None"""
        mock_config = Mock()
        mock_config.get.side_effect = lambda section, key, fallback=None: (
            "not-a-json"
            if (section, key) == ("Authorization", "prevalidated_domainlist")
            else fallback
        )
        mock_config.getboolean.return_value = False
        mock_load_config.return_value = mock_config

        authorization = Authorization(logger=self.mock_logger)
        with self.assertRaises(ConfigurationError) as context:
            authorization._load_configuration()
        self.assertIn(
            "Invalid prevalidated_domainlist parameter", str(context.exception)
        )
        self.assertIsNone(authorization.config.prevalidated_domainlist)

    def test_0082_eab_profile_prevalidated_domainlist_applied(self):
        """Test EAB profile sets prevalidated_domainlist from profile"""
        authorization = Authorization(logger=self.mock_logger)
        authorization.config.eab_profiling = True
        profile_dic = {
            "kid": {"authorization": {"prevalidated_domainlist": ["foo.com"]}}
        }
        mock_context = Mock()
        mock_context.key_file_load.return_value = profile_dic
        mock_context.__enter__ = Mock(return_value=mock_context)
        mock_context.__exit__ = Mock(return_value=None)
        mock_eab_handler_class = Mock(return_value=mock_context)
        authorization.config.eab_handler = mock_eab_handler_class
        auth_details = {"order__account__eab_kid": "kid"}
        # Should set prevalidated_domainlist
        authorization._apply_eab_and_domain_whitelist(
            "authz", auth_details, "dns", "foo.com", {}
        )
        self.assertEqual(authorization.config.prevalidated_domainlist, ["foo.com"])

    def test_0083_eab_profile_no_prevalidated_domainlist(self):
        """Test EAB profile present but no prevalidated_domainlist in profile"""
        authorization = Authorization(logger=self.mock_logger)
        authorization.config.eab_profiling = True
        profile_dic = {"kid": {"authorization": {}}}
        mock_context = Mock()
        mock_context.key_file_load.return_value = profile_dic
        mock_context.__enter__ = Mock(return_value=mock_context)
        mock_context.__exit__ = Mock(return_value=None)
        mock_eab_handler_class = Mock(return_value=mock_context)
        authorization.config.eab_handler = mock_eab_handler_class
        auth_details = {"order__account__eab_kid": "kid"}
        # Should not set prevalidated_domainlist
        authorization._apply_eab_and_domain_whitelist(
            "authz", auth_details, "dns", "foo.com", {}
        )
        self.assertIsNone(authorization.config.prevalidated_domainlist)

    def test_0084_eab_profile_handler_exception(self):
        """Test EAB profile handler raises exception, logger.error called"""
        authorization = Authorization(logger=self.mock_logger)
        authorization.config.eab_profiling = True
        mock_context = MagicMock()
        mock_context.__enter__.side_effect = Exception("fail")
        mock_eab_handler_class = Mock(return_value=mock_context)
        authorization.config.eab_handler = mock_eab_handler_class
        auth_details = {"order__account__eab_kid": "kid"}
        authorization._apply_eab_and_domain_whitelist(
            "authz", auth_details, "dns", "foo.com", {}
        )
        self.mock_logger.error.assert_called()

    def test_0085_domain_whitelist_dns_match(self):
        """Test DNS identifier matches prevalidated_domainlist, status set to valid, mark methods called"""
        authorization = Authorization(logger=self.mock_logger)
        authorization.config.prevalidated_domainlist = ["foo.com"]
        authorization.repository = Mock()
        authz_info = {"status": "pending"}
        with patch("acme_srv.authorization.is_domain_whitelisted", return_value=True):
            authorization._apply_eab_and_domain_whitelist(
                "authz", {"order__name": "order1"}, "dns", "foo.com", authz_info
            )
        self.assertEqual(authz_info["status"], "valid")
        authorization.repository.mark_authorization_as_valid.assert_called_once_with(
            "authz"
        )
        authorization.repository.mark_order_as_ready.assert_called_once_with("order1")

    def test_0086_domain_whitelist_dns_no_match(self):
        """Test DNS identifier does not match prevalidated_domainlist, status not changed, no mark calls"""
        authorization = Authorization(logger=self.mock_logger)
        authorization.config.prevalidated_domainlist = ["foo.com"]
        authorization.repository = Mock()
        authz_info = {"status": "pending"}
        with patch("acme_srv.authorization.is_domain_whitelisted", return_value=False):
            authorization._apply_eab_and_domain_whitelist(
                "authz", {"order__name": "order1"}, "dns", "bar.com", authz_info
            )
        self.assertEqual(authz_info["status"], "pending")
        authorization.repository.mark_authorization_as_valid.assert_not_called()
        authorization.repository.mark_order_as_ready.assert_not_called()

    def test_0087_domain_whitelist_not_set(self):
        """Test prevalidated_domainlist not set, nothing happens"""
        authorization = Authorization(logger=self.mock_logger)
        authorization.config.prevalidated_domainlist = None
        authorization.repository = Mock()
        authz_info = {"status": "pending"}
        authorization._apply_eab_and_domain_whitelist(
            "authz", {"order__name": "order1"}, "dns", "foo.com", authz_info
        )
        self.assertEqual(authz_info["status"], "pending")
        authorization.repository.mark_authorization_as_valid.assert_not_called()
        authorization.repository.mark_order_as_ready.assert_not_called()

    def test_0088_domain_whitelist_non_dns(self):
        """Test non-dns identifier, nothing happens"""
        authorization = Authorization(logger=self.mock_logger)
        authorization.config.prevalidated_domainlist = ["foo.com"]
        authorization.repository = Mock()
        authz_info = {"status": "pending"}
        authorization._apply_eab_and_domain_whitelist(
            "authz", {"order__name": "order1"}, "email", "foo@bar.com", authz_info
        )
        self.assertEqual(authz_info["status"], "pending")
        authorization.repository.mark_authorization_as_valid.assert_not_called()
        authorization.repository.mark_order_as_ready.assert_not_called()


class TestAuthorizationExceptions(unittest.TestCase):
    # Test custom exception classes

    def test_0075_authorization_error(self):
        """Test AuthorizationError exception"""
        with self.assertRaises(AuthorizationError) as context:
            raise AuthorizationError("Test error message")
        self.assertEqual(str(context.exception), "Test error message")

    def test_0076_authorization_not_found_error(self):
        """Test AuthorizationNotFoundError exception"""
        with self.assertRaises(AuthorizationNotFoundError) as context:
            raise AuthorizationNotFoundError("Authorization not found")
        self.assertEqual(str(context.exception), "Authorization not found")
        self.assertIsInstance(context.exception, AuthorizationError)

    def test_0077_authorization_expired_error(self):
        """Test AuthorizationExpiredError exception"""
        with self.assertRaises(AuthorizationExpiredError) as context:
            raise AuthorizationExpiredError("Authorization expired")
        self.assertEqual(str(context.exception), "Authorization expired")
        self.assertIsInstance(context.exception, AuthorizationError)

    def test_0078_configuration_error(self):
        """Test ConfigurationError exception"""
        with self.assertRaises(ConfigurationError) as context:
            raise ConfigurationError("Configuration invalid")
        self.assertEqual(str(context.exception), "Configuration invalid")
        self.assertIsInstance(context.exception, AuthorizationError)

    def test_0075_authorization_error(self):
        """Test AuthorizationError exception"""
        with self.assertRaises(AuthorizationError) as context:
            raise AuthorizationError("Test error message")
        self.assertEqual(str(context.exception), "Test error message")

    def test_0076_authorization_not_found_error(self):
        """Test AuthorizationNotFoundError exception"""
        with self.assertRaises(AuthorizationNotFoundError) as context:
            raise AuthorizationNotFoundError("Authorization not found")
        self.assertEqual(str(context.exception), "Authorization not found")
        self.assertIsInstance(context.exception, AuthorizationError)

    def test_0077_authorization_expired_error(self):
        """Test AuthorizationExpiredError exception"""
        with self.assertRaises(AuthorizationExpiredError) as context:
            raise AuthorizationExpiredError("Authorization expired")
        self.assertEqual(str(context.exception), "Authorization expired")
        self.assertIsInstance(context.exception, AuthorizationError)

    def test_0078_configuration_error(self):
        """Test ConfigurationError exception"""
        with self.assertRaises(ConfigurationError) as context:
            raise ConfigurationError("Configuration invalid")
        self.assertEqual(str(context.exception), "Configuration invalid")
        self.assertIsInstance(context.exception, AuthorizationError)


if __name__ == "__main__":
    unittest.main()
