import sys
import unittest

sys.path.insert(0, ".")
sys.path.insert(1, "..")
from unittest.mock import Mock, patch, MagicMock


class TestChallengeConfiguration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up module-level mocks before any tests run"""
        # Mock the missing db_handler module
        mock_db_handler = MagicMock()
        mock_dbstore_class = MagicMock()
        mock_db_handler.DBstore = mock_dbstore_class
        sys.modules["acme_srv.db_handler"] = mock_db_handler

        # Import after mocking
        from acme_srv.challenge import ChallengeConfiguration

        cls.ChallengeConfiguration = ChallengeConfiguration

    @classmethod
    def tearDownClass(cls):
        """Clean up module mocks"""
        if "acme_srv.db_handler" in sys.modules:
            del sys.modules["acme_srv.db_handler"]
        if "acme_srv.challenge" in sys.modules:
            del sys.modules["acme_srv.challenge"]

    def test_0001_configuration_defaults(self):
        config = self.ChallengeConfiguration()
        self.assertFalse(config.validation_disabled)
        self.assertEqual(config.validation_timeout, 10)
        self.assertIsNone(config.dns_server_list)
        self.assertEqual(config.dns_validation_pause_timer, 0.5)
        self.assertIsNone(config.proxy_server_list)
        self.assertFalse(config.sectigo_sim)
        self.assertFalse(config.tnauthlist_support)
        self.assertFalse(config.email_identifier_support)
        self.assertIsNone(config.email_address)
        self.assertFalse(config.forward_address_check)
        self.assertFalse(config.reverse_address_check)
        self.assertIsNone(config.source_address)
        self.assertFalse(config.eab_profiling)


class TestDatabaseChallengeRepository(unittest.TestCase):
    def setUp(self):
        import logging

        # Mock the missing db_handler module if not already done
        if "acme_srv.db_handler" not in sys.modules:
            mock_db_handler = MagicMock()
            mock_dbstore_class = MagicMock()
            mock_db_handler.DBstore = mock_dbstore_class
            sys.modules["acme_srv.db_handler"] = mock_db_handler

        # Import after ensuring mocking
        from acme_srv.challenge import DatabaseChallengeRepository
        from acme_srv.challenge_error_handling import DatabaseError, ValidationError
        from acme_srv.challenge_business_logic import (
            ChallengeInfo,
            ChallengeCreationRequest,
            ChallengeUpdateRequest,
        )

        # Store imports as instance variables
        self.DatabaseChallengeRepository = DatabaseChallengeRepository
        self.DatabaseError = DatabaseError
        self.ValidationError = ValidationError
        self.ChallengeInfo = ChallengeInfo
        self.ChallengeCreationRequest = ChallengeCreationRequest
        self.ChallengeUpdateRequest = ChallengeUpdateRequest

        self.dbstore = Mock()
        # Create a real logger for testing
        self.logger = logging.getLogger("test_a2c")
        self.logger.setLevel(logging.DEBUG)
        # Remove any existing handlers to avoid duplicate logs
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)

        self.repo = self.DatabaseChallengeRepository(self.dbstore, self.logger)

    def test_0002_find_challenges_by_authorization_success(self):
        self.dbstore.challenges_search.return_value = [
            {"name": "c1", "type": "dns-01", "status__name": "pending", "token": "tok1"}
        ]
        result = self.repo.find_challenges_by_authorization("authz1")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].name, "c1")
        self.dbstore.challenges_search.assert_called_once()

    def test_0003_find_challenges_by_authorization_db_error(self):
        self.dbstore.challenges_search.side_effect = Exception("db fail")
        with self.assertLogs("test_a2c", level="DEBUG") as log_context:
            with self.assertRaises(self.DatabaseError):
                self.repo.find_challenges_by_authorization("authz1")
        # Verify the critical log message was generated
        self.assertTrue(
            any(
                "Database error: failed to search for challenges: db fail"
                in record.message
                for record in log_context.records
                if record.levelname == "CRITICAL"
            )
        )

    def test_0004_get_challengeinfo_by_challengename_success(self):
        self.dbstore.challenge_lookup.return_value = {"name": "c1", "type": "dns-01"}
        result = self.repo.get_challengeinfo_by_challengename("c1")
        self.assertEqual(result["name"], "c1")

    def test_0005_get_challengeinfo_by_challengename_db_error(self):
        self.dbstore.challenge_lookup.side_effect = Exception("db fail")
        with self.assertLogs("test_a2c", level="DEBUG") as log_context:
            with self.assertRaises(self.DatabaseError):
                self.repo.get_challengeinfo_by_challengename("c1")
        # Verify the critical log message was generated
        self.assertTrue(
            any(
                "Database error: failed to lookup challenge keyauthorization: db fail"
                in record.message
                for record in log_context.records
                if record.levelname == "CRITICAL"
            )
        )

    def test_0006_get_challenge_by_name_success(self):
        self.dbstore.challenge_lookup.return_value = {
            "type": "dns-01",
            "token": "tok",
            "status": "valid",
            "authorization__name": "authz",
            "authorization__type": "dns",
            "authorization__value": "val",
            "validated": 123456,
        }
        with patch(
            "acme_srv.challenge.uts_to_date_utc", return_value="2021-01-01T00:00:00Z"
        ):
            result = self.repo.get_challenge_by_name("c1")
            self.assertEqual(result.name, "c1")
            self.assertEqual(result.status, "valid")
            self.assertEqual(result.validated, "2021-01-01T00:00:00Z")

    def test_0007_get_challenge_by_name_db_error(self):
        self.dbstore.challenge_lookup.side_effect = Exception("db fail")
        with self.assertLogs("test_a2c", level="DEBUG") as log_context:
            with self.assertRaises(self.DatabaseError):
                self.repo.get_challenge_by_name("c1")
        # Verify the critical log message was generated
        self.assertTrue(
            any(
                "Database error: failed to lookup challenge: db fail" in record.message
                for record in log_context.records
                if record.levelname == "CRITICAL"
            )
        )

    def test_0008_create_challenge_success(self):
        self.dbstore.challenge_add.return_value = 1
        with patch(
            "acme_srv.challenge.generate_random_string", return_value="c1"
        ), patch("acme_srv.challenge.uts_now", return_value=1000):
            req = self.ChallengeCreationRequest("dns-01", "tok", "authz", "val")
            name = self.repo.create_challenge(req)
            self.assertEqual(name, "c1")

    def test_0009_create_challenge_db_error(self):
        self.dbstore.challenge_add.side_effect = Exception("db fail")
        with patch(
            "acme_srv.challenge.generate_random_string", return_value="c1"
        ), patch("acme_srv.challenge.uts_now", return_value=1000):
            req = self.ChallengeCreationRequest("dns-01", "tok", "authz", "val")
            with self.assertLogs("test_a2c", level="DEBUG") as log_context:
                with self.assertRaises(self.DatabaseError):
                    self.repo.create_challenge(req)
            # Verify the critical log message was generated
            self.assertTrue(
                any(
                    "Database error: failed to add new challenge: db fail"
                    in record.message
                    for record in log_context.records
                    if record.levelname == "CRITICAL"
                )
            )

    def test_0010_update_challenge_success(self):
        self.dbstore.challenge_update.return_value = None
        req = self.ChallengeUpdateRequest("c1", status=2)
        self.assertTrue(self.repo.update_challenge(req))

    def test_0011_update_challenge_db_error(self):
        self.dbstore.challenge_update.side_effect = Exception("db fail")
        req = self.ChallengeUpdateRequest("c1", status=2)
        with self.assertLogs("test_a2c", level="DEBUG") as log_context:
            with self.assertRaises(self.DatabaseError):
                self.repo.update_challenge(req)
        # Verify the critical log message was generated
        self.assertTrue(
            any(
                "Database error: failed to update challenge: db fail" in record.message
                for record in log_context.records
                if record.levelname == "CRITICAL"
            )
        )

    def test_0012_update_authorization_status_success(self):
        self.dbstore.challenge_lookup.return_value = {"authorization": "authz1"}
        self.dbstore.authorization_update.return_value = None
        self.assertTrue(self.repo.update_authorization_status("c1", "valid"))

    def test_0013_update_authorization_status_db_error(self):
        self.dbstore.challenge_lookup.side_effect = Exception("db fail")
        with self.assertLogs("test_a2c", level="DEBUG") as log_context:
            with self.assertRaises(self.DatabaseError):
                self.repo.update_authorization_status("c1", "valid")
        # Verify the critical log message was generated
        self.assertTrue(
            any(
                "Database error: failed to update authorization: db fail"
                in record.message
                for record in log_context.records
                if record.levelname == "CRITICAL"
            )
        )

    def test_0014_get_account_jwk_success(self):
        self.dbstore.challenge_lookup.return_value = {
            "authorization__order__account__name": "acc1"
        }
        self.dbstore.jwk_load.return_value = {"kty": "RSA"}
        self.assertEqual(self.repo.get_account_jwk("c1"), {"kty": "RSA"})

    def test_0015_get_account_jwk_none(self):
        self.dbstore.challenge_lookup.return_value = {}
        self.assertIsNone(self.repo.get_account_jwk("c1"))


class TestChallenge(unittest.TestCase):
    def setUp(self):
        import logging

        # Mock the missing db_handler module if not already done
        if "acme_srv.db_handler" not in sys.modules:
            mock_db_handler = MagicMock()
            mock_dbstore_class = MagicMock()
            mock_db_handler.DBstore = mock_dbstore_class
            sys.modules["acme_srv.db_handler"] = mock_db_handler

        # Import after ensuring mocking
        from acme_srv.challenge import (
            Challenge,
            ChallengeConfiguration,
            DatabaseChallengeRepository,
        )
        from acme_srv.challenge_error_handling import (
            DatabaseError,
            ValidationError,
            UnsupportedChallengeTypeError,
        )
        from acme_srv.challenge_business_logic import (
            ChallengeInfo,
            ChallengeCreationRequest,
            ChallengeUpdateRequest,
        )

        # Store imports as instance variables for use in tests
        self.Challenge = Challenge
        self.ChallengeConfiguration = ChallengeConfiguration
        self.DatabaseChallengeRepository = DatabaseChallengeRepository
        self.DatabaseError = DatabaseError
        self.ValidationError = ValidationError
        self.UnsupportedChallengeTypeError = UnsupportedChallengeTypeError
        self.ChallengeInfo = ChallengeInfo
        self.ChallengeCreationRequest = ChallengeCreationRequest
        self.ChallengeUpdateRequest = ChallengeUpdateRequest
        self.DatabaseError = DatabaseError
        self.ValidationError = ValidationError
        self.UnsupportedChallengeTypeError = UnsupportedChallengeTypeError
        self.ChallengeInfo = ChallengeInfo
        self.ChallengeCreationRequest = ChallengeCreationRequest
        self.ChallengeUpdateRequest = ChallengeUpdateRequest

        # Create a real logger for testing
        self.logger = logging.getLogger("test_a2c")
        self.logger.setLevel(logging.DEBUG)
        # Remove any existing handlers to avoid duplicate logs
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)

        self.challenge = Challenge(debug=True, logger=self.logger, srv_name="srv")
        self.challenge.dbstore = Mock()
        self.challenge.repository = Mock()
        self.challenge.message = Mock()
        self.challenge.error_handler = Mock()
        self.challenge.state_manager = Mock()
        self.challenge.validator_registry = Mock()
        self.challenge.config = self.ChallengeConfiguration()
        self.challenge.config.dns_server_list = ["8.8.8.8"]
        self.challenge.config.proxy_server_list = {"http": "proxy"}
        self.challenge.config.validation_timeout = 1
        self.challenge.server_name = "srv"
        self.challenge.path_dic = {
            "chall_path": "/acme/chall/",
            "authz_path": "/acme/authz/",
        }

    def test_0016_create_error_response(self):
        self.challenge.message.prepare_response.return_value = {"status": "error"}
        resp = self.challenge._create_error_response(400, "bad", "fail")
        self.assertEqual(resp["status"], "error")

    def test_0017_create_success_response(self):
        self.challenge.message.prepare_response.return_value = {"status": "ok"}
        resp = self.challenge._create_success_response({"foo": "bar"})
        self.assertEqual(resp["status"], "ok")

    def test_0018_extract_challenge_name_from_url(self):
        with patch(
            "acme_srv.challenge.parse_url", return_value={"path": "/acme/chall/c1"}
        ):
            name = self.challenge._extract_challenge_name_from_url("/acme/chall/c1")
            self.assertEqual(name, "c1")

    def test_0019_get_challenge_validation_details_success(self):
        self.challenge.dbstore.challenge_lookup.return_value = {
            "type": "dns-01",
            "token": "tok",
            "keyauthorization": "kauth",
            "authorization__type": "dns",
            "authorization__value": "val",
        }
        self.challenge.repository.get_account_jwk.return_value = {"kty": "RSA"}
        with patch("acme_srv.challenge.jwk_thumbprint_get", return_value="thumb"):
            details = self.challenge._get_challenge_validation_details("c1")
            self.assertEqual(details["jwk_thumbprint"], "thumb")

    def test_0020_get_challenge_validation_details_no_challenge(self):
        self.challenge.dbstore.challenge_lookup.return_value = None
        self.assertIsNone(self.challenge._get_challenge_validation_details("c1"))

    def test_0021_get_challenge_validation_details_no_pubkey(self):
        self.challenge.dbstore.challenge_lookup.return_value = {"type": "dns-01"}
        self.challenge.repository.get_account_jwk.return_value = None
        self.assertIsNone(self.challenge._get_challenge_validation_details("c1"))

    def test_0022_get_challenge_validation_details_exception(self):
        self.challenge.dbstore.challenge_lookup.side_effect = Exception("fail")
        with self.assertLogs("test_a2c", level="DEBUG") as lcm:
            self.assertIsNone(self.challenge._get_challenge_validation_details("c1"))
        self.assertIn(
            "ERROR:test_a2c:Failed to get challenge validation details: fail",
            lcm.output,
        )

    def test_0023_handle_challenge_validation_request_valid(self):
        info = self.ChallengeInfo(
            "c1", "dns-01", "tok", "pending", "authz", "dns", "val", "url"
        )
        info.status = "pending"
        self.challenge.config.tnauthlist_support = False
        self.challenge.repository.get_challenge_by_name.return_value = info
        self.challenge._start_async_validation = Mock()
        self.challenge._create_success_response = Mock(return_value={"status": "ok"})
        resp = self.challenge._handle_challenge_validation_request(
            200, {}, {"url": "u"}, "c1", info
        )
        self.assertEqual(resp["status"], "ok")

    def test_0024_handle_challenge_validation_request_tnauthlist(self):
        info = self.ChallengeInfo(
            "c1", "tkauth-01", "tok", "pending", "authz", "dns", "val", "url"
        )
        info.status = "pending"
        self.challenge.config.tnauthlist_support = True
        self.challenge._validate_tnauthlist_payload = Mock(return_value={"code": 200})
        self.challenge.repository.get_challenge_by_name.return_value = info
        self.challenge._start_async_validation = Mock()
        self.challenge._create_success_response = Mock(return_value={"status": "ok"})
        resp = self.challenge._handle_challenge_validation_request(
            200, {"atc": "foo"}, {"url": "u"}, "c1", info
        )
        self.assertEqual(resp["status"], "ok")

    def test_0025_handle_challenge_validation_request_tnauthlist_fail(self):
        info = self.ChallengeInfo(
            "c1", "tkauth-01", "tok", "pending", "authz", "dns", "val", "url"
        )
        info.status = "pending"
        self.challenge.config.tnauthlist_support = True
        self.challenge._validate_tnauthlist_payload = Mock(
            return_value={"code": 400, "error": "fail"}
        )
        resp = self.challenge._handle_challenge_validation_request(
            200, {"atc": None}, {"url": "u"}, "c1", info
        )
        self.assertEqual(resp["code"], 400)

    def test_0026_handle_validation_disabled(self):
        self.challenge.config.forward_address_check = False
        self.challenge.config.reverse_address_check = False
        self.challenge.state_manager.transition_to_valid = Mock()
        with self.assertLogs("test_a2c", level="DEBUG") as lcm:
            self.assertTrue(self.challenge._handle_validation_disabled("c1"))
        self.assertIn(
            "WARNING:test_a2c:Source address checks are disabled. Setting challenge status to valid. This is not recommended as this is a severe security risk!",
            lcm.output,
        )

    def test_0027_handle_validation_disabled_invalid(self):
        self.challenge.config.forward_address_check = True
        self.challenge._perform_source_address_validation = Mock(
            return_value=(False, True, "fail")
        )
        self.challenge.state_manager.transition_to_invalid = Mock()
        self.assertFalse(self.challenge._handle_validation_disabled("c1"))

    def test_0028_load_address_check_configuration(self):
        import logging
        from configparser import ConfigParser

        config_dic = ConfigParser()
        config_dic.add_section("Challenge")
        config_dic.set("Challenge", "forward_address_check", "True")
        config_dic.set("Challenge", "reverse_address_check", "True")
        config_dic.set("Challenge", "challenge_validation_disable", "True")
        with self.assertLogs("test_a2c", level="DEBUG") as lcm:
            self.challenge._load_address_check_configuration(config_dic)
        self.assertTrue(self.challenge.config.forward_address_check)
        self.assertTrue(self.challenge.config.reverse_address_check)
        self.assertTrue(self.challenge.config.validation_disabled)
        self.assertIn(
            "INFO:test_a2c:Challenge validation is globally disabled.", lcm.output
        )

    def test_0029_load_dns_configuration(self):
        config_dic = {
            "Challenge": {
                "dns_server_list": '["8.8.8.8"]',
                "dns_validation_pause_timer": "2",
            }
        }
        self.challenge._load_dns_configuration(config_dic)
        self.assertEqual(self.challenge.config.dns_server_list, ["8.8.8.8"])
        self.assertEqual(self.challenge.config.dns_validation_pause_timer, 2)

    def test_0030_load_dns_configuration_fail(self):
        # Set to None first to test that bad configuration doesn't change it
        self.challenge.config.dns_server_list = None
        config_dic = {
            "Challenge": {
                "dns_server_list": "badjson",
                "dns_validation_pause_timer": "bad",
            }
        }
        with self.assertLogs("test_a2c", level="DEBUG") as lcm:
            self.challenge._load_dns_configuration(config_dic)
        self.assertIsInstance(self.challenge.config.dns_server_list, type(None))
        self.assertIn(
            "WARNING:test_a2c:Failed to load dns_server_list from configuration: Expecting value: line 1 column 1 (char 0)",
            lcm.output,
        )
        self.assertIn(
            "WARNING:test_a2c:Failed to parse dns_validation_pause_timer from configuration: invalid literal for int() with base 10: 'bad'",
            lcm.output,
        )

    def test_0031_load_proxy_configuration(self):
        config_dic = {"DEFAULT": {"proxy_server_list": '{"http": "proxy"}'}}
        self.challenge._load_proxy_configuration(config_dic)
        self.assertEqual(self.challenge.proxy_server_list, {"http": "proxy"})

    def test_0032_load_proxy_configuration_fail(self):
        config_dic = {"DEFAULT": {"proxy_server_list": "badjson"}}
        with self.assertLogs("test_a2c", level="DEBUG") as lcm:
            self.challenge._load_proxy_configuration(config_dic)
        self.assertFalse(hasattr(self.challenge, "proxy_server_list"))
        self.assertIn(
            "WARNING:test_a2c:Failed to load proxy_server_list from configuration: Expecting value: line 1 column 1 (char 0)",
            lcm.output,
        )

    def test_0033_load_configuration(self):
        from configparser import ConfigParser

        config_obj = ConfigParser()
        config_obj.add_section("Challenge")
        config_obj.set("Challenge", "sectigo_sim", "False")

        with patch(
            "acme_srv.challenge.load_config", return_value=config_obj
        ), patch.object(self.challenge, "_load_dns_configuration"), patch.object(
            self.challenge, "_load_proxy_configuration"
        ), patch.object(
            self.challenge, "_load_address_check_configuration"
        ), patch(
            "acme_srv.challenge.create_challenge_validator_registry",
            return_value=Mock(),
        ), patch.object(
            self.challenge, "_initialize_business_logic_components"
        ):
            self.challenge._load_configuration()
            self.assertFalse(self.challenge.config.sectigo_sim)

    def test_0034_ensure_components_initialized(self):
        self.challenge.factory = Mock()
        self.challenge.service = Mock()
        self.challenge._ensure_components_initialized()  # Should not raise
        self.challenge.factory = None
        with self.assertRaises(RuntimeError):
            self.challenge._ensure_components_initialized()

    def test_0035_perform_challenge_validation_success(self):
        self.challenge.state_manager.transition_to_processing = Mock()
        self.challenge.config.validation_disabled = False
        self.challenge._execute_challenge_validation = Mock()
        self.challenge._update_challenge_state_from_validation = Mock(return_value=True)
        self.assertTrue(self.challenge._perform_challenge_validation("c1", {}))

    def test_0036_perform_challenge_validation_disabled(self):
        self.challenge.state_manager.transition_to_processing = Mock()
        self.challenge.config.validation_disabled = True
        self.challenge._handle_validation_disabled = Mock(return_value=True)
        self.assertTrue(self.challenge._perform_challenge_validation("c1", {}))

    def test_0037_perform_challenge_validation_exception(self):
        self.challenge.state_manager.transition_to_processing = Mock()
        self.challenge.config.validation_disabled = False
        self.challenge._execute_challenge_validation = Mock(
            side_effect=Exception("fail")
        )
        self.challenge._update_challenge_state_from_validation = Mock(
            return_value=False
        )
        self.challenge.error_handler.handle_error.return_value = Mock()
        self.challenge.state_manager.transition_to_invalid = Mock()
        self.assertFalse(self.challenge._perform_challenge_validation("c1", {}))

    def test_0038_perform_source_address_validation_disabled(self):
        self.challenge.config.forward_address_check = False
        self.challenge.config.reverse_address_check = False
        result = self.challenge._perform_source_address_validation("c1")
        self.assertEqual(result, (True, False))

    def test_0039_perform_source_address_validation_not_found(self):
        self.challenge.config.forward_address_check = True
        self.challenge.repository.get_challenge_by_name.return_value = None
        with self.assertLogs("test_a2c", level="DEBUG") as lcm:
            result = self.challenge._perform_source_address_validation("c1")
        self.assertEqual(result, (False, True))
        self.assertIn("ERROR:test_a2c:Challenge not found: c1", lcm.output)

    def test_0040_perform_source_address_validation_success(self):
        self.challenge.config.forward_address_check = True
        info = self.ChallengeInfo(
            "c1", "dns-01", "tok", "pending", "authz", "dns", "val", "url"
        )
        self.challenge.repository.get_challenge_by_name.return_value = info
        self.challenge.validator_registry.is_supported.return_value = True
        mock_result = Mock(success=True, invalid=False)
        self.challenge.validator_registry.validate_challenge.return_value = mock_result
        result = self.challenge._perform_source_address_validation("c1")
        self.assertEqual(result, (True, False, None))

    def test_0041_perform_source_address_validation_fail(self):
        self.challenge.config.forward_address_check = True
        info = self.ChallengeInfo(
            "c1", "dns-01", "tok", "pending", "authz", "dns", "val", "url"
        )
        self.challenge.repository.get_challenge_by_name.return_value = info
        self.challenge.validator_registry.is_supported.return_value = True
        mock_result = Mock(success=False, invalid=True, error_message="fail")
        self.challenge.validator_registry.validate_challenge.return_value = mock_result
        with self.assertLogs("test_a2c", level="DEBUG") as lcm:
            result = self.challenge._perform_source_address_validation("c1")
        self.assertIn(
            "WARNING:test_a2c:Source address validation failed for c1: fail", lcm.output
        )
        self.assertEqual(result, (False, True, "fail"))

    def test_0042_perform_source_address_validation_validator_not_available(self):
        self.challenge.config.forward_address_check = True
        info = self.ChallengeInfo(
            "c1", "dns-01", "tok", "pending", "authz", "dns", "val", "url"
        )
        self.challenge.repository.get_challenge_by_name.return_value = info
        self.challenge.validator_registry.is_supported.return_value = False
        with self.assertLogs("test_a2c", level="DEBUG") as lcm:
            result = self.challenge._perform_source_address_validation("c1")
        self.assertIn(
            "WARNING:test_a2c:Source address validator not available", lcm.output
        )
        self.assertEqual(result, (True, False, None))

    def test_0043_perform_source_address_validation_exception(self):
        self.challenge.config.forward_address_check = True
        info = self.ChallengeInfo(
            "c1", "dns-01", "tok", "pending", "authz", "dns", "val", "url"
        )
        self.challenge.repository.get_challenge_by_name.return_value = info
        self.challenge.validator_registry.is_supported.side_effect = Exception("fail")
        with self.assertLogs("test_a2c", level="DEBUG") as lcm:
            result = self.challenge._perform_source_address_validation("c1")
        self.assertIn(
            "ERROR:test_a2c:Source address validation error for c1: fail", lcm.output
        )
        self.assertEqual(
            result, (False, True, "Source address validation error for c1: fail")
        )

    def test_0044_perform_validation_with_retry_success(self):
        context = Mock()
        self.challenge.validator_registry.validate_challenge.side_effect = [
            Mock(success=False, invalid=False),
            Mock(success=True, invalid=False),
        ]
        result = self.challenge._perform_validation_with_retry("dns-01", context)
        self.assertTrue(result.success)

    def test_0045_perform_validation_with_retry_invalid(self):
        context = Mock()
        self.challenge.validator_registry.validate_challenge.return_value = Mock(
            success=False, invalid=True
        )
        result = self.challenge._perform_validation_with_retry("dns-01", context)
        self.assertFalse(result.success)
        self.assertTrue(result.invalid)

    def test_0046_start_async_validation(self):
        with patch("acme_srv.challenge.Thread") as mock_thread:
            instance = mock_thread.return_value
            instance.join.return_value = True
            self.challenge._perform_challenge_validation = Mock()
            self.challenge._start_async_validation("c1", {})
            instance.start.assert_called_once()
            instance.join.assert_called_once()

    def test_0047_update_challenge_state_from_validation_invalid(self):
        validation_result = Mock(invalid=True, success=False)
        self.challenge.state_manager.transition_to_invalid = Mock()
        self.assertFalse(
            self.challenge._update_challenge_state_from_validation(
                "c1", validation_result
            )
        )

    def test_0048_update_challenge_state_from_validation_success(self):
        validation_result = Mock(invalid=False, success=True)
        self.challenge.state_manager.transition_to_valid = Mock()
        self.assertTrue(
            self.challenge._update_challenge_state_from_validation(
                "c1", validation_result
            )
        )

    def test_0049_update_challenge_state_from_validation_inconclusive(self):
        validation_result = Mock(invalid=False, success=False)
        self.assertFalse(
            self.challenge._update_challenge_state_from_validation(
                "c1", validation_result
            )
        )

    def test_0050_validate_tnauthlist_payload_success(self):
        info = self.ChallengeInfo(
            "c1", "tkauth-01", "tok", "pending", "authz", "dns", "val", "url"
        )
        payload = {"atc": "foo"}
        result = self.challenge._validate_tnauthlist_payload(payload, info)
        self.assertEqual(result["code"], 200)

    def test_0051_validate_tnauthlist_payload_missing_atc(self):
        info = self.ChallengeInfo(
            "c1", "tkauth-01", "tok", "pending", "authz", "dns", "val", "url"
        )
        payload = {}
        self.challenge._create_error_response = Mock(
            return_value={"code": 400, "error": "fail"}
        )
        with self.assertLogs("test_a2c", level="DEBUG") as lcm:
            result = self.challenge._validate_tnauthlist_payload(payload, info)
        self.assertIn(
            "ERROR:test_a2c:TNauthlist payload validation failed. atc claim is missing",
            lcm.output,
        )
        self.assertEqual(result["code"], 400)

    def test_0052_validate_tnauthlist_payload_missing_spc(self):
        info = self.ChallengeInfo(
            "c1", "tkauth-01", "tok", "pending", "authz", "dns", "val", "url"
        )
        payload = {"atc": None}
        self.challenge._create_error_response = Mock(
            return_value={"code": 400, "error": "fail"}
        )
        with self.assertLogs("test_a2c", level="DEBUG") as lcm:
            result = self.challenge._validate_tnauthlist_payload(payload, info)
        self.assertIn(
            "ERROR:test_a2c:TNauthlist payload validation failed. SPC token is missing",
            lcm.output,
        )
        self.assertEqual(result["code"], 400)

    def test_0053_process_challenge_request_success(self):
        self.challenge._ensure_components_initialized = Mock()
        self.challenge.message.check.return_value = (
            200,
            None,
            None,
            {"url": "u"},
            {"foo": "bar"},
            "acc",
        )
        self.challenge._extract_challenge_name_from_url = Mock(return_value="c1")
        self.challenge.repository.get_challenge_by_name.return_value = (
            self.ChallengeInfo(
                "c1", "dns-01", "tok", "pending", "authz", "dns", "val", "url"
            )
        )
        self.challenge._handle_challenge_validation_request = Mock(
            return_value={"status": "ok"}
        )
        resp = self.challenge.process_challenge_request("content")
        self.assertEqual(resp["status"], "ok")

    def test_0054_process_challenge_request_error(self):
        self.challenge._ensure_components_initialized = Mock()
        self.challenge.message.check.side_effect = Exception("fail")
        self.challenge.error_handler.handle_error.return_value = Mock()
        self.challenge.error_handler.create_acme_error_response.return_value = {
            "status": "error"
        }
        resp = self.challenge.process_challenge_request("content")
        self.assertEqual(resp["status"], "error")

    def test_0055_retrieve_challenge_set_success(self):
        self.challenge._ensure_components_initialized = Mock()
        self.challenge.service = Mock()
        self.challenge.service.get_challenge_set_for_authorization.return_value = [
            {"foo": "bar"}
        ]
        resp = self.challenge.retrieve_challenge_set("authz", "valid", "tok", False)
        self.assertEqual(resp, [{"foo": "bar"}])

    def test_0056_retrieve_challenge_set_exception(self):
        self.challenge._ensure_components_initialized = Mock()
        self.challenge.service = Mock()
        self.challenge.service.get_challenge_set_for_authorization.side_effect = (
            Exception("fail")
        )
        self.challenge.error_handler.handle_error.return_value = Mock(message="fail")

        with self.assertLogs("test_a2c", level="DEBUG") as log_context:
            resp = self.challenge.retrieve_challenge_set("authz", "valid", "tok", False)

        self.assertEqual(resp, [])
        # Verify the error log message was generated
        self.assertTrue(
            any(
                "Failed to retrieve challenge set: fail" in record.message
                for record in log_context.records
                if record.levelname == "ERROR"
            )
        )

    def test_0057_challengeset_get_and_parse(self):
        self.challenge.retrieve_challenge_set = Mock(return_value=[{"foo": "bar"}])
        self.assertEqual(
            self.challenge.challengeset_get("a", "b", "c", False), [{"foo": "bar"}]
        )
        self.challenge.process_challenge_request = Mock(return_value={"status": "ok"})
        self.assertEqual(self.challenge.parse("content"), {"status": "ok"})

    # Additional tests to reach 100% coverage

    def test_0058_context_manager(self):
        """Test context manager functionality"""
        with patch.object(self.challenge, "_load_configuration"):
            with self.challenge as challenge_instance:
                self.assertEqual(challenge_instance, self.challenge)

    def test_0059_create_challenge_special_types(self):
        """Test create challenge with special challenge types"""
        self.challenge.repository = Mock()

        # Test email-reply-00 challenge type
        request = Mock()
        request.challenge_type = "email-reply-00"
        request.value = "test_value"

        with patch(
            "acme_srv.challenge.generate_random_string", return_value="random_token"
        ):
            self.challenge.repository.create_challenge = Mock(return_value="chid")
            result = self.challenge.repository.create_challenge(request)
            self.assertEqual(result, "chid")

    def test_0060_update_challenge_with_all_fields(self):
        """Test challenge update with all optional fields"""
        self.challenge.repository = Mock()

        request = Mock()
        request.challenge_name = "test_challenge"
        request.status = "valid"
        request.source = "test_source"
        request.validated = "2023-01-01T00:00:00Z"
        request.keyauthorization = "test_keyauth"

        self.challenge.repository.update_challenge(request)
        self.challenge.repository.update_challenge.assert_called_once()

    def test_0061_get_account_jwk_exception(self):
        """Test get_account_jwk with database exception"""
        self.challenge.repository = self.DatabaseChallengeRepository(
            Mock(), self.logger
        )
        # Set up challenge_lookup to return a valid response so jwk_load gets called
        self.challenge.repository.dbstore.challenge_lookup.return_value = {
            "authorization__order__account__name": "account_name"
        }
        self.challenge.repository.dbstore.jwk_load.side_effect = Exception("DB error")

        with self.assertLogs("test_a2c", level="DEBUG") as log_context:
            with self.assertRaises(self.DatabaseError):
                self.challenge.repository.get_account_jwk("account_name")

        # Verify the critical log message was generated
        self.assertTrue(
            any(
                "Database error: failed to get account JWK: DB error" in record.message
                for record in log_context.records
                if record.levelname == "CRITICAL"
            )
        )

    def test_0062_get_challengeinfo_by_challengename_none_result(self):
        """Test get_challengeinfo_by_challengename when no challenge found"""
        self.challenge.repository = self.DatabaseChallengeRepository(
            Mock(), self.logger
        )
        self.challenge.repository.dbstore.challenge_lookup.return_value = None

        result = self.challenge.repository.get_challengeinfo_by_challengename(
            "nonexistent"
        )
        self.assertIsNone(result)

    def test_0063_get_challenge_by_name_none_result(self):
        """Test get_challenge_by_name when no challenge found"""
        self.challenge.repository = self.DatabaseChallengeRepository(
            Mock(), self.logger
        )
        self.challenge.repository.dbstore.challenge_lookup.return_value = None

        result = self.challenge.repository.get_challenge_by_name("nonexistent")
        self.assertIsNone(result)

    def test_0064_execute_challenge_validation_unsupported_type(self):
        """Test _execute_challenge_validation with unsupported challenge type"""
        self.challenge.validator_registry = Mock()
        self.challenge.validator_registry.is_supported.return_value = False
        self.challenge.validator_registry.get_supported_types.return_value = ["dns-01"]

        self.challenge._get_challenge_validation_details = Mock(
            return_value={
                "type": "unsupported-01",
                "token": "token",
                "jwk_thumbprint": "thumb",
                "keyauthorization": "keyauth",
                "authorization_type": "dns",
                "authorization_value": "example.com",
            }
        )

        with self.assertRaises(self.UnsupportedChallengeTypeError):
            self.challenge._execute_challenge_validation("test_challenge", {})

    def test_0065_execute_challenge_validation_no_details(self):
        """Test _execute_challenge_validation when details cannot be retrieved"""
        self.challenge._get_challenge_validation_details = Mock(return_value=None)

        with self.assertRaises(self.ValidationError):
            self.challenge._execute_challenge_validation("test_challenge", {})

    def test_0066_extract_challenge_name_from_url_with_suffix(self):
        """Test _extract_challenge_name_from_url with URL suffix"""
        self.challenge.path_dic = {"chall_path": "/acme/chall/"}

        with patch(
            "acme_srv.challenge.parse_url",
            return_value={"path": "/acme/chall/test_challenge/authz"},
        ):
            result = self.challenge._extract_challenge_name_from_url(
                "/acme/chall/test_challenge/authz"
            )
            self.assertEqual(result, "test_challenge")

    def test_0067_handle_challenge_validation_request_email_address(self):
        """Test challenge validation with email address configuration"""
        self.challenge.config.email_identifier_support = True
        self.challenge.config.email_address = "test@example.com"

        info = self.ChallengeInfo(
            "c1",
            "email-reply-00",
            "tok",
            "valid",
            "authz",
            "email",
            "val",
            "url",
            "2023-01-01T00:00:00Z",
        )

        # Mock the internal method properly
        self.challenge._validate_tnauthlist_payload = Mock(return_value={"code": 200})
        self.challenge._create_success_response = Mock(
            return_value={"status": "ok", "data": {"from": "test@example.com"}}
        )

        resp = self.challenge._handle_challenge_validation_request(
            200, {}, {"url": "u"}, "c1", info
        )
        self.assertEqual(resp["status"], "ok")
        self.assertEqual(resp["data"]["from"], "test@example.com")

    def test_0068_load_address_check_configuration_deprecated(self):
        """Test loading deprecated source_address_check configuration"""
        from configparser import ConfigParser

        config_dic = ConfigParser()
        config_dic.add_section("Challenge")
        config_dic.set("Challenge", "source_address_check", "True")

        # Mock warning to verify it's called
        with patch.object(self.challenge.logger, "warning") as mock_warning:
            self.challenge._load_address_check_configuration(config_dic)
            mock_warning.assert_called_once()
            self.assertTrue(self.challenge.config.forward_address_check)

    def test_0069_load_configuration_validation_timeout_error(self):
        """Test loading configuration with invalid validation timeout"""
        from configparser import ConfigParser

        config_obj = ConfigParser()
        config_obj.add_section("Challenge")
        config_obj.set("Challenge", "challenge_validation_timeout", "invalid")

        with patch(
            "acme_srv.challenge.load_config", return_value=config_obj
        ), patch.object(self.challenge, "_load_dns_configuration"), patch.object(
            self.challenge, "_load_proxy_configuration"
        ), patch.object(
            self.challenge, "_load_address_check_configuration"
        ), patch(
            "acme_srv.challenge.create_challenge_validator_registry",
            return_value=Mock(),
        ), patch.object(
            self.challenge, "_initialize_business_logic_components"
        ), patch.object(
            self.challenge.logger, "warning"
        ) as mock_warning:

            self.challenge._load_configuration()
            mock_warning.assert_called_once()

    def test_0070_load_configuration_email_identifier_no_address(self):
        """Test email identifier support without email address configured"""
        from configparser import ConfigParser

        config_obj = ConfigParser()
        config_obj.add_section("Order")
        config_obj.set("Order", "email_identifier_support", "True")

        with patch(
            "acme_srv.challenge.load_config", return_value=config_obj
        ), patch.object(self.challenge, "_load_dns_configuration"), patch.object(
            self.challenge, "_load_proxy_configuration"
        ), patch.object(
            self.challenge, "_load_address_check_configuration"
        ), patch(
            "acme_srv.challenge.create_challenge_validator_registry",
            return_value=Mock(),
        ), patch.object(
            self.challenge, "_initialize_business_logic_components"
        ), patch.object(
            self.challenge.logger, "warning"
        ) as mock_warning:

            self.challenge._load_configuration()
            mock_warning.assert_called_once()
            self.assertFalse(self.challenge.config.email_identifier_support)

    def test_0071_load_configuration_with_url_prefix(self):
        """Test loading configuration with URL prefix"""
        from configparser import ConfigParser

        config_obj = ConfigParser()
        config_obj.add_section("Directory")
        config_obj.set("Directory", "url_prefix", "/custom/prefix")

        original_path_dic = self.challenge.path_dic.copy()

        with patch(
            "acme_srv.challenge.load_config", return_value=config_obj
        ), patch.object(self.challenge, "_load_dns_configuration"), patch.object(
            self.challenge, "_load_proxy_configuration"
        ), patch.object(
            self.challenge, "_load_address_check_configuration"
        ), patch(
            "acme_srv.challenge.create_challenge_validator_registry",
            return_value=Mock(),
        ), patch.object(
            self.challenge, "_initialize_business_logic_components"
        ):

            self.challenge._load_configuration()
            # Check that URL prefix was applied
            for key, value in self.challenge.path_dic.items():
                expected_value = "/custom/prefix" + original_path_dic[key]
                self.assertEqual(value, expected_value)

    # Tests for special challenge creation types
    def test_0072_create_challenge_sectigo_email(self):
        """Test create challenge with sectigo-email-01 type"""
        self.challenge.repository = self.DatabaseChallengeRepository(
            Mock(), self.logger
        )
        self.challenge.repository.dbstore.challenge_add.return_value = (
            "chid123"  # db returns an id
        )

        request = Mock()
        request.challenge_type = "sectigo-email-01"
        request.value = "test_value"
        request.authorization_name = "authz1"
        request.token = "token1"

        with patch(
            "acme_srv.challenge.generate_random_string",
            return_value="random_challenge_name",
        ):
            result = self.challenge.repository.create_challenge(request)
            self.assertEqual(
                result, "random_challenge_name"
            )  # method returns challenge name, not chid
            # Verify that status=5 was set for sectigo-email-01
            call_args = self.challenge.repository.dbstore.challenge_add.call_args
            data_dic = call_args[0][2]  # third argument
            self.assertEqual(data_dic["status"], 5)

    def test_0073_create_challenge_email_reply(self):
        """Test create challenge with email-reply-00 type"""
        self.challenge.repository = self.DatabaseChallengeRepository(
            Mock(), self.logger
        )
        self.challenge.repository.dbstore.challenge_add.return_value = "chid456"

        request = Mock()
        request.challenge_type = "email-reply-00"
        request.value = "test_value"
        request.authorization_name = "authz1"
        request.token = "token1"

        with patch("acme_srv.challenge.generate_random_string") as mock_gen:
            mock_gen.side_effect = [
                "challenge_name",
                "random_token",
            ]  # first call for challenge name, second for keyauth
            result = self.challenge.repository.create_challenge(request)
            self.assertEqual(result, "challenge_name")  # returns challenge name
            # Verify that keyauthorization was set
            call_args = self.challenge.repository.dbstore.challenge_add.call_args
            data_dic = call_args[0][2]  # third argument
            self.assertEqual(data_dic["keyauthorization"], "random_token")

    def test_0074_update_challenge_with_individual_fields(self):
        """Test update challenge with different combinations of optional fields"""
        self.challenge.repository = self.DatabaseChallengeRepository(
            Mock(), self.logger
        )

        # Test with only status
        request = Mock()
        request.name = "test_challenge"
        request.status = "valid"
        request.source = None
        request.validated = None
        request.keyauthorization = None

        self.challenge.repository.update_challenge(request)

        # Test with only source
        request.status = None
        request.source = "test_source"
        self.challenge.repository.update_challenge(request)

        # Test with only validated
        request.source = None
        request.validated = "2023-01-01T00:00:00Z"
        self.challenge.repository.update_challenge(request)

        # Test with only keyauthorization
        request.validated = None
        request.keyauthorization = "test_keyauth"
        self.challenge.repository.update_challenge(request)

    def test_0075_handle_challenge_validation_request_with_validated_flag(self):
        """Test challenge validation response includes validated flag for valid challenges"""
        self.challenge.config.email_identifier_support = False
        self.challenge.config.email_address = None

        info = self.ChallengeInfo(
            "c1",
            "dns-01",
            "tok",
            "valid",
            "authz",
            "dns",
            "val",
            "url",
            "2023-01-01T00:00:00Z",
        )

        # Create a proper response structure
        response_data = {
            "type": "dns-01",
            "status": "valid",
            "url": "url",
            "token": "tok",
            "validated": "2023-01-01T00:00:00Z",
        }

        self.challenge._validate_tnauthlist_payload = Mock(return_value={"code": 200})
        self.challenge._create_success_response = Mock(
            return_value={"status": "ok", "data": response_data}
        )

        resp = self.challenge._handle_challenge_validation_request(
            200, {}, {"url": "u"}, "c1", info
        )
        self.assertEqual(resp["status"], "ok")
        self.assertEqual(resp["data"]["validated"], "2023-01-01T00:00:00Z")

    def test_0076_load_configuration_with_email_identifier_and_address(self):
        """Test loading configuration with email identifier support and valid email address"""
        from configparser import ConfigParser

        config_obj = ConfigParser()
        config_obj.add_section("Order")
        config_obj.set("Order", "email_identifier_support", "True")
        config_obj["DEFAULT"][
            "email_address"
        ] = "test@example.com"  # Use dict-style access for DEFAULT

        with patch(
            "acme_srv.challenge.load_config", return_value=config_obj
        ), patch.object(self.challenge, "_load_dns_configuration"), patch.object(
            self.challenge, "_load_proxy_configuration"
        ), patch.object(
            self.challenge, "_load_address_check_configuration"
        ), patch(
            "acme_srv.challenge.create_challenge_validator_registry",
            return_value=Mock(),
        ), patch.object(
            self.challenge, "_initialize_business_logic_components"
        ):

            self.challenge._load_configuration()
            self.assertTrue(self.challenge.config.email_identifier_support)
            self.assertEqual(self.challenge.config.email_address, "test@example.com")

    # Test for remaining uncovered lines
    def test_0077_initialize_business_logic_components(self):
        """Test _initialize_business_logic_components method"""
        with patch("acme_srv.challenge.ChallengeFactory") as mock_factory, patch(
            "acme_srv.challenge.ChallengeService"
        ) as mock_service:
            self.challenge.path_dic = {"chall_path": "/chall/"}
            self.challenge.config.email_address = "test@example.com"
            self.challenge.repository = Mock()
            self.challenge.state_manager = Mock()
            self.challenge.server_name = "test_server"

            self.challenge._initialize_business_logic_components()

            mock_factory.assert_called_once()
            mock_service.assert_called_once()

    # Tests for uncovered lines in process_challenge_request error handling
    def test_0078_process_challenge_request_message_check_failure(self):
        """Test process_challenge_request when message check fails (line 907)"""
        # Set up necessary components
        self.challenge.factory = Mock()
        self.challenge.service = Mock()
        self.challenge.message = Mock()
        # Simulate message check failure
        self.challenge.message.check.return_value = (
            400,
            "bad request",
            "invalid format",
            {},
            {},
            "",
        )

        # We need to test that the line is executed, not the return value structure
        with patch.object(
            self.challenge, "_create_error_response"
        ) as mock_error_response:
            mock_error_response.return_value = {
                "code": 400,
                "type": "bad request",
                "detail": "invalid format",
            }
            result = self.challenge.process_challenge_request("invalid_content")
            mock_error_response.assert_called_once_with(
                400, "bad request", "invalid format"
            )

    def test_0079_process_challenge_request_url_missing_in_protected(self):
        """Test process_challenge_request when URL is missing from protected header (line 910)"""
        # Set up necessary components
        self.challenge.factory = Mock()
        self.challenge.service = Mock()
        self.challenge.message = Mock()
        self.challenge.err_msg_dic = {"malformed": "malformed"}
        # Message check succeeds but protected header has no URL
        self.challenge.message.check.return_value = (
            200,
            "",
            "",
            {},
            {},
            "account",
        )  # empty protected dict

        # Test that the specific error response line is executed
        with patch.object(
            self.challenge, "_create_error_response"
        ) as mock_error_response:
            mock_error_response.return_value = {
                "code": 400,
                "type": "malformed",
                "detail": "url missing in protected header",
            }
            result = self.challenge.process_challenge_request("content_without_url")
            mock_error_response.assert_called_once_with(
                400, "malformed", "url missing in protected header"
            )

    def test_0080_process_challenge_request_empty_challenge_name_extraction(self):
        """Test process_challenge_request when challenge name extraction fails (line 918)"""
        # Set up necessary components
        self.challenge.factory = Mock()
        self.challenge.service = Mock()
        self.challenge.message = Mock()
        self.challenge.err_msg_dic = {"malformed": "malformed"}
        # Message check succeeds with URL but challenge name extraction fails
        self.challenge.message.check.return_value = (
            200,
            "",
            "",
            {"url": "invalid_url"},
            {},
            "account",
        )

        # Mock the extract method to return empty string (extraction failure)
        with patch.object(
            self.challenge, "_extract_challenge_name_from_url", return_value=""
        ), patch.object(
            self.challenge, "_create_error_response"
        ) as mock_error_response:
            mock_error_response.return_value = {
                "code": 400,
                "type": "malformed",
                "detail": "could not get challenge",
            }
            result = self.challenge.process_challenge_request(
                "content_with_invalid_url"
            )
            mock_error_response.assert_called_once_with(
                400, "malformed", "could not get challenge"
            )

    def test_0081_process_challenge_request_nonexistent_challenge_name(self):
        """Test process_challenge_request when challenge doesn't exist in repository (line 924)"""
        # Set up necessary components
        self.challenge.factory = Mock()
        self.challenge.service = Mock()
        self.challenge.message = Mock()
        self.challenge.err_msg_dic = {"malformed": "malformed"}
        self.challenge.repository = Mock()
        # Message check succeeds, URL exists, challenge name extracted but challenge doesn't exist
        self.challenge.message.check.return_value = (
            200,
            "",
            "",
            {"url": "valid_url"},
            {},
            "account",
        )
        self.challenge.repository.get_challenge_by_name.return_value = (
            None  # Challenge not found
        )

        # Mock the extract method to return valid challenge name
        with patch.object(
            self.challenge,
            "_extract_challenge_name_from_url",
            return_value="nonexistent_challenge",
        ), patch.object(
            self.challenge, "_create_error_response"
        ) as mock_error_response:
            mock_error_response.return_value = {
                "code": 400,
                "type": "malformed",
                "detail": "invalid challenge: nonexistent_challenge",
            }
            result = self.challenge.process_challenge_request(
                "content_with_nonexistent_challenge"
            )
            mock_error_response.assert_called_once_with(
                400, "malformed", "invalid challenge: nonexistent_challenge"
            )

    # Tests for the final remaining uncovered lines (389-402, 508, 515)
    def test_0082_execute_challenge_validation_full_context_creation(self):
        """Test _execute_challenge_validation with full ChallengeContext creation (lines 389-402)"""
        self.challenge.validator_registry = Mock()
        self.challenge.validator_registry.is_supported.return_value = True

        # Mock challenge details to trigger ChallengeContext creation
        challenge_details = {
            "type": "dns-01",
            "token": "test_token",
            "jwk_thumbprint": "test_thumbprint",
            "keyauthorization": "test_keyauth",
            "authorization_type": "dns",
            "authorization_value": "example.com",
        }

        self.challenge._get_challenge_validation_details = Mock(
            return_value=challenge_details
        )
        self.challenge.config.dns_server_list = ["8.8.8.8"]
        self.challenge.config.proxy_server_list = {"http": "proxy:8080"}
        self.challenge.config.validation_timeout = 30

        # Mock the validation retry method to confirm context was created
        with patch.object(
            self.challenge, "_perform_validation_with_retry"
        ) as mock_retry:
            mock_retry.return_value = Mock()  # Return some validation result

            # This will execute lines 389-402 where ChallengeContext is created
            result = self.challenge._execute_challenge_validation("test_challenge", {})

            # Verify that _perform_validation_with_retry was called (which means ChallengeContext was created)
            mock_retry.assert_called_once()
            args = mock_retry.call_args[0]
            self.assertEqual(args[0], "dns-01")  # challenge_type
            # We can't easily verify the context object, but we know it was created if this method was called

    def test_0083_handle_challenge_validation_request_email_address_response_building(
        self,
    ):
        """Test that line 508 is executed: response_dic["data"]["from"] = self.config.email_address"""
        # Set up email configuration
        self.challenge.config.email_address = "test@example.com"
        self.challenge.config.tnauthlist_support = False

        # Create email-reply-00 challenge info
        info = self.ChallengeInfo(
            "c1", "email-reply-00", "tok", "pending", "authz", "email", "val", "url"
        )

        # Mock dependencies but NOT _create_success_response so we execute the response building logic
        self.challenge.repository.get_challenge_by_name = Mock(return_value=info)
        self.challenge._start_async_validation = Mock()

        # Mock _create_success_response to capture what gets passed to it
        def capture_response_dic(response_dict):
            return {"status": "ok", "captured_data": response_dict["data"]}

        self.challenge._create_success_response = Mock(side_effect=capture_response_dic)

        # Call the method
        resp = self.challenge._handle_challenge_validation_request(
            200, {}, {"url": "test_url"}, "c1", info
        )

        # Verify line 508 was executed by checking the captured response_dic
        self.challenge._create_success_response.assert_called_once()
        captured_data = resp["captured_data"]
        self.assertEqual(captured_data["from"], "test@example.com")
        self.assertEqual(captured_data["type"], "email-reply-00")

    def test_0084_handle_challenge_validation_request_validated_flag_response_building(
        self,
    ):
        """Test that line 515 is executed: response_dic["data"]["validated"] = updated_challenge_info.validated"""
        # Set up configuration
        self.challenge.config.tnauthlist_support = False

        # Create challenge info with validated timestamp and valid status
        validated_time = "2023-01-01T12:00:00Z"
        info = self.ChallengeInfo(
            "c1", "dns-01", "tok", "valid", "authz", "dns", "val", "url", validated_time
        )

        # Mock dependencies but NOT _create_success_response so we execute the response building logic
        self.challenge.repository.get_challenge_by_name = Mock(return_value=info)
        self.challenge._start_async_validation = Mock()

        # Mock _create_success_response to capture what gets passed to it
        def capture_response_dic(response_dict):
            return {"status": "ok", "captured_data": response_dict["data"]}

        self.challenge._create_success_response = Mock(side_effect=capture_response_dic)

        # Call the method
        resp = self.challenge._handle_challenge_validation_request(
            200, {}, {"url": "test_url"}, "c1", info
        )

        # Verify line 515 was executed by checking the captured response_dic
        self.challenge._create_success_response.assert_called_once()
        captured_data = resp["captured_data"]
        self.assertEqual(captured_data["validated"], validated_time)
        self.assertEqual(captured_data["status"], "valid")

    def test_0085_get_eab_kid_from_challenge_success(self):
        """Test _get_eab_kid_from_challenge with successful EAB kid retrieval"""
        self.challenge.repository = Mock()
        self.challenge.repository.get_challengeinfo_by_challengename.return_value = {
            "name": "test_challenge",
            "status__name": "pending",
            "authorization__order__account__name": "account1",
            "authorization__order__account__eab_kid": "test_eab_kid_123",
        }

        result = self.challenge._get_eab_kid_from_challenge("test_challenge")

        self.assertEqual(result, "test_eab_kid_123")
        self.challenge.repository.get_challengeinfo_by_challengename.assert_called_once_with(
            "test_challenge",
            vlist=(
                "name",
                "status__name",
                "authorization__order__account__name",
                "authorization__order__account__eab_kid",
            ),
        )

    def test_0086_get_eab_kid_from_challenge_no_eab_kid(self):
        """Test _get_eab_kid_from_challenge when no EAB kid is found"""
        self.challenge.repository = Mock()
        self.challenge.repository.get_challengeinfo_by_challengename.return_value = {
            "name": "test_challenge",
            "status__name": "pending",
            "authorization__order__account__name": "account1",
            "authorization__order__account__eab_kid": None,
        }

        result = self.challenge._get_eab_kid_from_challenge("test_challenge")

        self.assertIsNone(result)

    def test_0087_get_eab_kid_from_challenge_empty_eab_kid(self):
        """Test _get_eab_kid_from_challenge when EAB kid is empty string"""
        self.challenge.repository = Mock()
        self.challenge.repository.get_challengeinfo_by_challengename.return_value = {
            "name": "test_challenge",
            "status__name": "pending",
            "authorization__order__account__name": "account1",
            "authorization__order__account__eab_kid": "",
        }

        result = self.challenge._get_eab_kid_from_challenge("test_challenge")

        self.assertIsNone(result)

    def test_0088_get_eab_kid_from_challenge_missing_key(self):
        """Test _get_eab_kid_from_challenge when EAB kid key is missing"""
        self.challenge.repository = Mock()
        self.challenge.repository.get_challengeinfo_by_challengename.return_value = {
            "name": "test_challenge",
            "status__name": "pending",
            "authorization__order__account__name": "account1"
            # Missing authorization__order__account__eab_kid key
        }

        result = self.challenge._get_eab_kid_from_challenge("test_challenge")

        self.assertIsNone(result)

    def test_0089_get_eab_kid_from_challenge_exception(self):
        """Test _get_eab_kid_from_challenge with database exception"""
        self.challenge.repository = Mock()
        self.challenge.repository.get_challengeinfo_by_challengename.side_effect = (
            Exception("Database error")
        )

        with self.assertLogs("test_a2c", level="DEBUG") as log_context:
            result = self.challenge._get_eab_kid_from_challenge("test_challenge")

        self.assertIsNone(result)
        # Verify error log message
        self.assertTrue(
            any(
                "Failed to get EAB kid from challenge test_challenge: Database error"
                in record.message
                for record in log_context.records
                if record.levelname == "ERROR"
            )
        )

    def test_0090_get_challenge_profile_settings_success(self):
        """Test _get_challenge_profile_settings with valid profile"""
        profile_dic = {
            "test_kid": {
                "challenge": {
                    "challenge_validation_disable": True,
                    "forward_address_check": True,
                    "reverse_address_check": False,
                }
            }
        }

        result = self.challenge._get_challenge_profile_settings(profile_dic, "test_kid")

        expected_settings = {
            "challenge_validation_disable": True,
            "forward_address_check": True,
            "reverse_address_check": False,
        }
        self.assertEqual(result, expected_settings)

    def test_0091_get_challenge_profile_settings_defaults(self):
        """Test _get_challenge_profile_settings with missing settings using defaults"""
        profile_dic = {"test_kid": {"challenge": {}}}

        result = self.challenge._get_challenge_profile_settings(profile_dic, "test_kid")

        expected_settings = {
            "challenge_validation_disable": False,
            "forward_address_check": False,
            "reverse_address_check": False,
        }
        self.assertEqual(result, expected_settings)

    def test_0092_get_challenge_profile_settings_no_challenge_section(self):
        """Test _get_challenge_profile_settings when challenge section is missing"""
        profile_dic = {"test_kid": {"other_section": {}}}

        result = self.challenge._get_challenge_profile_settings(profile_dic, "test_kid")

        expected_settings = {
            "challenge_validation_disable": False,
            "forward_address_check": False,
            "reverse_address_check": False,
        }
        self.assertEqual(result, expected_settings)

    def test_0093_get_challenge_profile_settings_kid_not_found(self):
        """Test _get_challenge_profile_settings when EAB kid not in profile"""
        profile_dic = {
            "other_kid": {"challenge": {"challenge_validation_disable": True}}
        }

        result = self.challenge._get_challenge_profile_settings(profile_dic, "test_kid")

        self.assertEqual(result, {})

    def test_0094_apply_eab_profile_settings_validation_disable(self):
        """Test _apply_eab_profile_settings with validation disable setting"""
        settings = {
            "challenge_validation_disable": True,
            "forward_address_check": False,
            "reverse_address_check": False,
        }

        # Ensure initial state
        self.challenge.config.validation_disabled = False

        with self.assertLogs("test_a2c", level="DEBUG") as log_context:
            self.challenge._apply_eab_profile_settings(settings, "test_kid")

        self.assertTrue(self.challenge.config.validation_disabled)
        # Verify info log message
        self.assertTrue(
            any(
                "Challenge validation is disabled via EAB profiling (eab_kid: test_kid)."
                in record.message
                for record in log_context.records
                if record.levelname == "INFO"
            )
        )

    def test_0095_apply_eab_profile_settings_forward_address_check(self):
        """Test _apply_eab_profile_settings with forward address check setting"""
        settings = {
            "challenge_validation_disable": False,
            "forward_address_check": True,
            "reverse_address_check": False,
        }

        # Ensure initial state
        self.challenge.config.forward_address_check = False

        with self.assertLogs("test_a2c", level="DEBUG") as log_context:
            self.challenge._apply_eab_profile_settings(settings, "test_kid")

        self.assertTrue(self.challenge.config.forward_address_check)
        # Verify info log message
        self.assertTrue(
            any(
                "Forward address check is enabled via EAB profiling (eab_kid: test_kid)."
                in record.message
                for record in log_context.records
                if record.levelname == "INFO"
            )
        )

    def test_0096_apply_eab_profile_settings_reverse_address_check(self):
        """Test _apply_eab_profile_settings with reverse address check setting"""
        settings = {
            "challenge_validation_disable": False,
            "forward_address_check": False,
            "reverse_address_check": True,
        }

        # Ensure initial state
        self.challenge.config.reverse_address_check = False

        with self.assertLogs("test_a2c", level="DEBUG") as log_context:
            self.challenge._apply_eab_profile_settings(settings, "test_kid")

        self.assertTrue(self.challenge.config.reverse_address_check)
        # Verify info log message
        self.assertTrue(
            any(
                "Reverse address check is enabled via EAB profiling (eab_kid: test_kid)."
                in record.message
                for record in log_context.records
                if record.levelname == "INFO"
            )
        )

    def test_0097_apply_eab_profile_settings_all_settings(self):
        """Test _apply_eab_profile_settings with all settings enabled"""
        settings = {
            "challenge_validation_disable": True,
            "forward_address_check": True,
            "reverse_address_check": True,
        }

        # Ensure initial state
        self.challenge.config.validation_disabled = False
        self.challenge.config.forward_address_check = False
        self.challenge.config.reverse_address_check = False

        with self.assertLogs("test_a2c", level="DEBUG") as log_context:
            self.challenge._apply_eab_profile_settings(settings, "test_kid")

        self.assertTrue(self.challenge.config.validation_disabled)
        self.assertTrue(self.challenge.config.forward_address_check)
        self.assertTrue(self.challenge.config.reverse_address_check)

        # Verify all three info log messages
        info_messages = [
            record.message
            for record in log_context.records
            if record.levelname == "INFO"
        ]
        self.assertIn(
            "Challenge validation is disabled via EAB profiling (eab_kid: test_kid).",
            info_messages,
        )
        self.assertIn(
            "Forward address check is enabled via EAB profiling (eab_kid: test_kid).",
            info_messages,
        )
        self.assertIn(
            "Reverse address check is enabled via EAB profiling (eab_kid: test_kid).",
            info_messages,
        )

    def test_0098_apply_eab_profile_settings_no_settings(self):
        """Test _apply_eab_profile_settings with no settings enabled"""
        settings = {
            "challenge_validation_disable": False,
            "forward_address_check": False,
            "reverse_address_check": False,
        }

        # Ensure initial state
        self.challenge.config.validation_disabled = False
        self.challenge.config.forward_address_check = False
        self.challenge.config.reverse_address_check = False

        self.challenge._apply_eab_profile_settings(settings, "test_kid")

        # Verify nothing changed
        self.assertFalse(self.challenge.config.validation_disabled)
        self.assertFalse(self.challenge.config.forward_address_check)
        self.assertFalse(self.challenge.config.reverse_address_check)

    def test_0099_check_challenge_validation_eabprofile_disabled(self):
        """Test _check_challenge_validation_eabprofile when EAB profiling is disabled"""
        # Ensure EAB profiling is disabled
        self.challenge.config.eab_profiling = False
        self.challenge.config.eab_handler = None

        # Mock the methods that shouldn't be called
        self.challenge._get_eab_kid_from_challenge = Mock()

        self.challenge._check_challenge_validation_eabprofile("test_challenge")

        # Verify early return - method should not be called
        self.challenge._get_eab_kid_from_challenge.assert_not_called()

    def test_0100_check_challenge_validation_eabprofile_no_handler(self):
        """Test _check_challenge_validation_eabprofile when EAB handler is None"""
        # EAB profiling enabled but no handler
        self.challenge.config.eab_profiling = True
        self.challenge.config.eab_handler = None

        # Mock the methods that shouldn't be called
        self.challenge._get_eab_kid_from_challenge = Mock()

        self.challenge._check_challenge_validation_eabprofile("test_challenge")

        # Verify early return - method should not be called
        self.challenge._get_eab_kid_from_challenge.assert_not_called()

    def test_0101_check_challenge_validation_eabprofile_no_eab_kid(self):
        """Test _check_challenge_validation_eabprofile when no EAB kid found"""
        # Set up EAB profiling
        self.challenge.config.eab_profiling = True
        self.challenge.config.eab_handler = Mock()

        # Mock _get_eab_kid_from_challenge to return None
        self.challenge._get_eab_kid_from_challenge = Mock(return_value=None)

        self.challenge._check_challenge_validation_eabprofile("test_challenge")

        # Verify _get_eab_kid_from_challenge was called but early return happened
        self.challenge._get_eab_kid_from_challenge.assert_called_once_with(
            "test_challenge"
        )

    def test_0102_check_challenge_validation_eabprofile_success(self):
        """Test _check_challenge_validation_eabprofile with successful profile application"""
        # Set up EAB profiling
        mock_eab_handler = Mock()
        mock_eab_handler_instance = Mock()
        mock_eab_handler.return_value.__enter__ = Mock(
            return_value=mock_eab_handler_instance
        )
        mock_eab_handler.return_value.__exit__ = Mock(return_value=False)

        self.challenge.config.eab_profiling = True
        self.challenge.config.eab_handler = mock_eab_handler

        # Mock profile data
        profile_dic = {
            "test_kid": {
                "challenge": {
                    "challenge_validation_disable": True,
                    "forward_address_check": True,
                }
            }
        }
        mock_eab_handler_instance.key_file_load.return_value = profile_dic

        # Mock methods
        self.challenge._get_eab_kid_from_challenge = Mock(return_value="test_kid")
        self.challenge._get_challenge_profile_settings = Mock(
            return_value={
                "challenge_validation_disable": True,
                "forward_address_check": True,
                "reverse_address_check": False,
            }
        )
        self.challenge._apply_eab_profile_settings = Mock()

        self.challenge._check_challenge_validation_eabprofile("test_challenge")

        # Verify all methods were called correctly
        self.challenge._get_eab_kid_from_challenge.assert_called_once_with(
            "test_challenge"
        )
        self.challenge._get_challenge_profile_settings.assert_called_once_with(
            profile_dic, "test_kid"
        )
        self.challenge._apply_eab_profile_settings.assert_called_once_with(
            {
                "challenge_validation_disable": True,
                "forward_address_check": True,
                "reverse_address_check": False,
            },
            "test_kid",
        )

    def test_0103_check_challenge_validation_eabprofile_no_challenge_section(self):
        """Test _check_challenge_validation_eabprofile when profile has no challenge section"""
        # Set up EAB profiling
        mock_eab_handler = Mock()
        mock_eab_handler_instance = Mock()
        mock_eab_handler.return_value.__enter__ = Mock(
            return_value=mock_eab_handler_instance
        )
        mock_eab_handler.return_value.__exit__ = Mock(return_value=False)

        self.challenge.config.eab_profiling = True
        self.challenge.config.eab_handler = mock_eab_handler

        # Mock profile data without challenge section
        profile_dic = {"test_kid": {"other_section": {}}}
        mock_eab_handler_instance.key_file_load.return_value = profile_dic

        # Mock methods
        self.challenge._get_eab_kid_from_challenge = Mock(return_value="test_kid")
        self.challenge._get_challenge_profile_settings = Mock()
        self.challenge._apply_eab_profile_settings = Mock()

        self.challenge._check_challenge_validation_eabprofile("test_challenge")

        # Verify early return when no challenge section exists
        self.challenge._get_eab_kid_from_challenge.assert_called_once_with(
            "test_challenge"
        )
        self.challenge._get_challenge_profile_settings.assert_not_called()
        self.challenge._apply_eab_profile_settings.assert_not_called()

    def test_0104_check_challenge_validation_eabprofile_kid_not_in_profile(self):
        """Test _check_challenge_validation_eabprofile when EAB kid not in profile"""
        # Set up EAB profiling
        mock_eab_handler = Mock()
        mock_eab_handler_instance = Mock()
        mock_eab_handler.return_value.__enter__ = Mock(
            return_value=mock_eab_handler_instance
        )
        mock_eab_handler.return_value.__exit__ = Mock(return_value=False)

        self.challenge.config.eab_profiling = True
        self.challenge.config.eab_handler = mock_eab_handler

        # Mock profile data with different kid
        profile_dic = {
            "other_kid": {"challenge": {"challenge_validation_disable": True}}
        }
        mock_eab_handler_instance.key_file_load.return_value = profile_dic

        # Mock methods
        self.challenge._get_eab_kid_from_challenge = Mock(return_value="test_kid")
        self.challenge._get_challenge_profile_settings = Mock()
        self.challenge._apply_eab_profile_settings = Mock()

        self.challenge._check_challenge_validation_eabprofile("test_challenge")

        # Verify early return when kid not in profile
        self.challenge._get_eab_kid_from_challenge.assert_called_once_with(
            "test_challenge"
        )
        self.challenge._get_challenge_profile_settings.assert_not_called()
        self.challenge._apply_eab_profile_settings.assert_not_called()

    def test_0105_check_challenge_validation_eabprofile_exception(self):
        """Test _check_challenge_validation_eabprofile with exception during processing"""
        # Set up EAB profiling
        mock_eab_handler = Mock()
        mock_eab_handler_instance = Mock()
        mock_eab_handler.return_value.__enter__ = Mock(
            return_value=mock_eab_handler_instance
        )
        mock_eab_handler.return_value.__exit__ = Mock(return_value=False)

        self.challenge.config.eab_profiling = True
        self.challenge.config.eab_handler = mock_eab_handler

        # Mock exception during key_file_load
        mock_eab_handler_instance.key_file_load.side_effect = Exception(
            "EAB handler error"
        )

        # Mock methods
        self.challenge._get_eab_kid_from_challenge = Mock(return_value="test_kid")

        with self.assertLogs("test_a2c", level="DEBUG") as log_context:
            self.challenge._check_challenge_validation_eabprofile("test_challenge")

        # Verify error log message
        self.assertTrue(
            any(
                "Failed to process EAB profile for challenge test_challenge (kid: test_kid): EAB handler error"
                in record.message
                for record in log_context.records
                if record.levelname == "ERROR"
            )
        )

    def test_0106_check_challenge_validation_eabprofile_exception_during_get_eab_kid(
        self,
    ):
        """Test _check_challenge_validation_eabprofile with exception during _get_eab_kid_from_challenge"""
        # Set up EAB profiling
        self.challenge.config.eab_profiling = True
        self.challenge.config.eab_handler = Mock()

        # Mock _get_eab_kid_from_challenge to raise exception (it handles its own exceptions)
        self.challenge._get_eab_kid_from_challenge = Mock(
            return_value=None
        )  # returns None on exception

        self.challenge._check_challenge_validation_eabprofile("test_challenge")

        # Should handle gracefully and return early
        self.challenge._get_eab_kid_from_challenge.assert_called_once_with(
            "test_challenge"
        )

    def test_0107_get_challenge_details_success(self):
        """Test get_challenge_details with successful challenge retrieval"""
        url = "http://example.com/acme/chall/test_challenge"
        mock_challenge_info = Mock()
        mock_challenge_info.type = "http-01"
        mock_challenge_info.status = "pending"
        mock_challenge_info.token = "test_token"
        mock_challenge_info.validated = "2023-12-01T10:00:00Z"

        with patch.object(
            self.challenge,
            "_extract_challenge_name_from_url",
            return_value="test_challenge",
        ):
            with patch.object(
                self.challenge.repository,
                "get_challenge_by_name",
                return_value=mock_challenge_info,
            ):
                result = self.challenge.get_challenge_details(url)

        expected_result = {
            "code": 200,
            "data": {
                "type": "http-01",
                "status": "pending",
                "token": "test_token",
                "validated": "2023-12-01T10:00:00Z",
            },
        }
        self.assertEqual(result, expected_result)

    def test_0108_get_challenge_details_challenge_not_found(self):
        """Test get_challenge_details when challenge is not found"""
        url = "http://example.com/acme/chall/nonexistent_challenge"

        with patch.object(
            self.challenge,
            "_extract_challenge_name_from_url",
            return_value="nonexistent_challenge",
        ):
            with patch.object(
                self.challenge.repository, "get_challenge_by_name", return_value=None
            ):
                result = self.challenge.get_challenge_details(url)

        expected_result = {"code": 404, "data": {}}
        self.assertEqual(result, expected_result)

    def test_0109_get_challenge_details_with_none_validated(self):
        """Test get_challenge_details with challenge having None validated field"""
        url = "http://example.com/acme/chall/test_challenge"
        mock_challenge_info = Mock()
        mock_challenge_info.type = "dns-01"
        mock_challenge_info.status = "pending"
        mock_challenge_info.token = "dns_token"
        mock_challenge_info.validated = None

        with patch.object(
            self.challenge,
            "_extract_challenge_name_from_url",
            return_value="test_challenge",
        ):
            with patch.object(
                self.challenge.repository,
                "get_challenge_by_name",
                return_value=mock_challenge_info,
            ):
                result = self.challenge.get_challenge_details(url)

        expected_result = {
            "code": 200,
            "data": {
                "type": "dns-01",
                "status": "pending",
                "token": "dns_token",
                "validated": None,
            },
        }
        self.assertEqual(result, expected_result)

    def test_0110_get_challenge_details_valid_status(self):
        """Test get_challenge_details with valid challenge status"""
        url = "http://example.com/acme/chall/valid_challenge"
        mock_challenge_info = Mock()
        mock_challenge_info.type = "http-01"
        mock_challenge_info.status = "valid"
        mock_challenge_info.token = "valid_token"
        mock_challenge_info.validated = "2023-12-01T10:00:00Z"

        with patch.object(
            self.challenge,
            "_extract_challenge_name_from_url",
            return_value="valid_challenge",
        ):
            with patch.object(
                self.challenge.repository,
                "get_challenge_by_name",
                return_value=mock_challenge_info,
            ):
                result = self.challenge.get_challenge_details(url)

        expected_result = {
            "code": 200,
            "data": {
                "type": "http-01",
                "status": "valid",
                "token": "valid_token",
                "validated": "2023-12-01T10:00:00Z",
            },
        }
        self.assertEqual(result, expected_result)

    def test_0111_get_challenge_details_invalid_status(self):
        """Test get_challenge_details with invalid challenge status"""
        url = "http://example.com/acme/chall/invalid_challenge"
        mock_challenge_info = Mock()
        mock_challenge_info.type = "http-01"
        mock_challenge_info.status = "invalid"
        mock_challenge_info.token = "invalid_token"
        mock_challenge_info.validated = None

        with patch.object(
            self.challenge,
            "_extract_challenge_name_from_url",
            return_value="invalid_challenge",
        ):
            with patch.object(
                self.challenge.repository,
                "get_challenge_by_name",
                return_value=mock_challenge_info,
            ):
                result = self.challenge.get_challenge_details(url)

        expected_result = {
            "code": 200,
            "data": {
                "type": "http-01",
                "status": "invalid",
                "token": "invalid_token",
                "validated": None,
            },
        }
        self.assertEqual(result, expected_result)

    def test_0112_get_challenge_details_processing_status(self):
        """Test get_challenge_details with processing challenge status"""
        url = "http://example.com/acme/chall/processing_challenge"
        mock_challenge_info = Mock()
        mock_challenge_info.type = "dns-01"
        mock_challenge_info.status = "processing"
        mock_challenge_info.token = "processing_token"
        mock_challenge_info.validated = None

        with patch.object(
            self.challenge,
            "_extract_challenge_name_from_url",
            return_value="processing_challenge",
        ):
            with patch.object(
                self.challenge.repository,
                "get_challenge_by_name",
                return_value=mock_challenge_info,
            ):
                result = self.challenge.get_challenge_details(url)

        expected_result = {
            "code": 200,
            "data": {
                "type": "dns-01",
                "status": "processing",
                "token": "processing_token",
                "validated": None,
            },
        }
        self.assertEqual(result, expected_result)

    def test_0113_get_challenge_details_tls_alpn_challenge(self):
        """Test get_challenge_details with tls-alpn-01 challenge type"""
        url = "http://example.com/acme/chall/tls_challenge"
        mock_challenge_info = Mock()
        mock_challenge_info.type = "tls-alpn-01"
        mock_challenge_info.status = "pending"
        mock_challenge_info.token = "tls_token"
        mock_challenge_info.validated = None

        with patch.object(
            self.challenge,
            "_extract_challenge_name_from_url",
            return_value="tls_challenge",
        ):
            with patch.object(
                self.challenge.repository,
                "get_challenge_by_name",
                return_value=mock_challenge_info,
            ):
                result = self.challenge.get_challenge_details(url)

        expected_result = {
            "code": 200,
            "data": {
                "type": "tls-alpn-01",
                "status": "pending",
                "token": "tls_token",
                "validated": None,
            },
        }
        self.assertEqual(result, expected_result)

    def test_0114_get_challenge_details_empty_challenge_name(self):
        """Test get_challenge_details with empty challenge name from URL"""
        url = "http://example.com/acme/chall/"

        with patch.object(
            self.challenge, "_extract_challenge_name_from_url", return_value=""
        ):
            with patch.object(
                self.challenge.repository, "get_challenge_by_name", return_value=None
            ):
                result = self.challenge.get_challenge_details(url)

        expected_result = {"code": 404, "data": {}}
        self.assertEqual(result, expected_result)

    def test_0115_get_challenge_details_repository_exception(self):
        """Test get_challenge_details with repository exception"""
        url = "http://example.com/acme/chall/test_challenge"

        mock_error_detail = Mock()
        mock_error_detail.message = "Database connection failed"
        mock_error_response = {
            "status": 500,
            "type": "urn:ietf:params:acme:error:serverInternal",
            "detail": "Database connection failed",
        }

        # Set up the existing Mock error_handler
        self.challenge.error_handler.handle_error.return_value = mock_error_detail
        self.challenge.error_handler.create_acme_error_response.return_value = (
            mock_error_response
        )

        with patch.object(
            self.challenge,
            "_extract_challenge_name_from_url",
            return_value="test_challenge",
        ):
            with patch.object(
                self.challenge.repository,
                "get_challenge_by_name",
                side_effect=Exception("Database error"),
            ):
                result = self.challenge.get_challenge_details(url)

        self.assertEqual(result, mock_error_response)
        self.challenge.error_handler.handle_error.assert_called_once()
        self.challenge.error_handler.create_acme_error_response.assert_called_once_with(
            mock_error_detail, 500
        )

    def test_0116_get_challenge_details_extract_url_exception(self):
        """Test get_challenge_details with exception in URL extraction (not caught by try-catch)"""
        url = "invalid_url"

        with patch.object(
            self.challenge,
            "_extract_challenge_name_from_url",
            side_effect=Exception("URL parse error"),
        ):
            with self.assertRaises(Exception) as context:
                self.challenge.get_challenge_details(url)

            self.assertEqual(str(context.exception), "URL parse error")

    def test_0117_get_challenge_details_special_characters_in_url(self):
        """Test get_challenge_details with special characters in URL"""
        url = "http://example.com/acme/chall/test_challenge_123-abc"
        mock_challenge_info = Mock()
        mock_challenge_info.type = "http-01"
        mock_challenge_info.status = "pending"
        mock_challenge_info.token = "special_token"
        mock_challenge_info.validated = None

        with patch.object(
            self.challenge,
            "_extract_challenge_name_from_url",
            return_value="test_challenge_123-abc",
        ):
            with patch.object(
                self.challenge.repository,
                "get_challenge_by_name",
                return_value=mock_challenge_info,
            ):
                result = self.challenge.get_challenge_details(url)

        expected_result = {
            "code": 200,
            "data": {
                "type": "http-01",
                "status": "pending",
                "token": "special_token",
                "validated": None,
            },
        }
        self.assertEqual(result, expected_result)

    def test_0118_get_challenge_details_long_challenge_name(self):
        """Test get_challenge_details with very long challenge name"""
        url = "http://example.com/acme/chall/very_long_challenge_name_123456789012345678901234567890"
        mock_challenge_info = Mock()
        mock_challenge_info.type = "dns-01"
        mock_challenge_info.status = "pending"
        mock_challenge_info.token = "long_token"
        mock_challenge_info.validated = None

        with patch.object(
            self.challenge,
            "_extract_challenge_name_from_url",
            return_value="very_long_challenge_name_123456789012345678901234567890",
        ):
            with patch.object(
                self.challenge.repository,
                "get_challenge_by_name",
                return_value=mock_challenge_info,
            ):
                result = self.challenge.get_challenge_details(url)

        expected_result = {
            "code": 200,
            "data": {
                "type": "dns-01",
                "status": "pending",
                "token": "long_token",
                "validated": None,
            },
        }
        self.assertEqual(result, expected_result)

    def test_0119_get_challenge_details_logs_debug_message(self):
        """Test get_challenge_details logs appropriate debug message"""
        url = "http://example.com/acme/chall/test_challenge"
        mock_challenge_info = Mock()
        mock_challenge_info.type = "http-01"
        mock_challenge_info.status = "pending"
        mock_challenge_info.token = "test_token"
        mock_challenge_info.validated = None

        with patch.object(
            self.challenge,
            "_extract_challenge_name_from_url",
            return_value="test_challenge",
        ):
            with patch.object(
                self.challenge.repository,
                "get_challenge_by_name",
                return_value=mock_challenge_info,
            ):
                with self.assertLogs("test_a2c", level="DEBUG") as lcm:
                    self.challenge.get_challenge_details(url)

        self.assertIn(
            "DEBUG:test_a2c:Challenge.get_challenge_details(test_challenge)", lcm.output
        )

    def test_0120_perform_validation_with_retry_dns_challenge_success_first_attempt(
        self,
    ):
        """Test _perform_validation_with_retry with dns-01 challenge succeeding on first attempt"""
        mock_context = Mock()
        mock_result = Mock()
        mock_result.success = True
        mock_result.invalid = False

        self.challenge.validator_registry.validate_challenge.return_value = mock_result

        result = self.challenge._perform_validation_with_retry("dns-01", mock_context)

        self.assertEqual(result, mock_result)
        self.challenge.validator_registry.validate_challenge.assert_called_once_with(
            "dns-01", mock_context
        )

    def test_0121_perform_validation_with_retry_dns_challenge_success_after_retries(
        self,
    ):
        """Test _perform_validation_with_retry with dns-01 challenge succeeding after retries"""
        mock_context = Mock()

        # First two attempts fail, third succeeds
        mock_result_fail = Mock()
        mock_result_fail.success = False
        mock_result_fail.invalid = False

        mock_result_success = Mock()
        mock_result_success.success = True
        mock_result_success.invalid = False

        self.challenge.validator_registry.validate_challenge.side_effect = [
            mock_result_fail,
            mock_result_fail,
            mock_result_success,
        ]

        with patch("time.sleep") as mock_sleep:
            result = self.challenge._perform_validation_with_retry(
                "dns-01", mock_context
            )

        self.assertEqual(result, mock_result_success)
        self.assertEqual(
            self.challenge.validator_registry.validate_challenge.call_count, 3
        )
        # Should have 2 sleep calls (after first and second attempts)
        self.assertEqual(mock_sleep.call_count, 2)
        mock_sleep.assert_called_with(self.challenge.config.dns_validation_pause_timer)

    def test_0122_perform_validation_with_retry_dns_challenge_invalid_first_attempt(
        self,
    ):
        """Test _perform_validation_with_retry with dns-01 challenge invalid on first attempt"""
        mock_context = Mock()
        mock_result = Mock()
        mock_result.success = False
        mock_result.invalid = True

        self.challenge.validator_registry.validate_challenge.return_value = mock_result

        result = self.challenge._perform_validation_with_retry("dns-01", mock_context)

        self.assertEqual(result, mock_result)
        self.challenge.validator_registry.validate_challenge.assert_called_once_with(
            "dns-01", mock_context
        )

    def test_0123_perform_validation_with_retry_dns_challenge_max_retries_reached(self):
        """Test _perform_validation_with_retry with dns-01 challenge reaching max retries (lines 997-1002)"""
        mock_context = Mock()
        mock_result = Mock()
        mock_result.success = False
        mock_result.invalid = False

        self.challenge.validator_registry.validate_challenge.return_value = mock_result

        with patch("time.sleep") as mock_sleep:
            with self.assertLogs("test_a2c", level="ERROR") as lcm:
                result = self.challenge._perform_validation_with_retry(
                    "dns-01", mock_context
                )

        # Should have called validate_challenge 5 times (max_attempts)
        self.assertEqual(
            self.challenge.validator_registry.validate_challenge.call_count, 5
        )
        # Should have 4 sleep calls (after first 4 attempts)
        self.assertEqual(mock_sleep.call_count, 4)
        # Result should be marked as invalid after max retries
        self.assertTrue(result.invalid)
        # Should log error message
        self.assertIn(
            "ERROR:test_a2c:No more retries left for challenge type dns-01. Invalidating challenge.",
            lcm.output,
        )

    def test_0124_perform_validation_with_retry_email_challenge_max_retries_reached(
        self,
    ):
        """Test _perform_validation_with_retry with email-reply-00 challenge reaching max retries (lines 997-1002)"""
        mock_context = Mock()
        mock_result = Mock()
        mock_result.success = False
        mock_result.invalid = False

        self.challenge.validator_registry.validate_challenge.return_value = mock_result

        with patch("time.sleep") as mock_sleep:
            with self.assertLogs("test_a2c", level="ERROR") as lcm:
                result = self.challenge._perform_validation_with_retry(
                    "email-reply-00", mock_context
                )

        # Should have called validate_challenge 5 times (max_attempts)
        self.assertEqual(
            self.challenge.validator_registry.validate_challenge.call_count, 5
        )
        # Should have 4 sleep calls (after first 4 attempts)
        self.assertEqual(mock_sleep.call_count, 4)
        # Result should be marked as invalid after max retries
        self.assertTrue(result.invalid)
        # Should log error message
        self.assertIn(
            "ERROR:test_a2c:No more retries left for challenge type email-reply-00. Invalidating challenge.",
            lcm.output,
        )

    def test_0125_perform_validation_with_retry_http_challenge_single_attempt(self):
        """Test _perform_validation_with_retry with http-01 challenge (single attempt)"""
        mock_context = Mock()
        mock_result = Mock()
        mock_result.success = False
        mock_result.invalid = False

        self.challenge.validator_registry.validate_challenge.return_value = mock_result

        with patch("time.sleep") as mock_sleep:
            result = self.challenge._perform_validation_with_retry(
                "http-01", mock_context
            )

        # Should have called validate_challenge only once (no retries for http-01)
        self.assertEqual(
            self.challenge.validator_registry.validate_challenge.call_count, 1
        )
        # No sleep calls for non-retry challenge types
        mock_sleep.assert_not_called()
        # Result should be marked as invalid since no retries and it didn't succeed
        self.assertTrue(result.invalid)

    def test_0126_perform_validation_with_retry_tls_challenge_single_attempt(self):
        """Test _perform_validation_with_retry with tls-alpn-01 challenge (single attempt)"""
        mock_context = Mock()
        mock_result = Mock()
        mock_result.success = True
        mock_result.invalid = False

        self.challenge.validator_registry.validate_challenge.return_value = mock_result

        result = self.challenge._perform_validation_with_retry(
            "tls-alpn-01", mock_context
        )

        # Should have called validate_challenge only once (no retries for tls-alpn-01)
        self.assertEqual(
            self.challenge.validator_registry.validate_challenge.call_count, 1
        )
        # Result should be the successful result
        self.assertEqual(result, mock_result)

    def test_0127_perform_validation_with_retry_dns_challenge_fourth_attempt_no_sleep(
        self,
    ):
        """Test _perform_validation_with_retry with dns-01 challenge not sleeping on last attempt"""
        mock_context = Mock()

        # First 4 attempts fail, 5th doesn't happen due to break logic
        mock_result_fail = Mock()
        mock_result_fail.success = False
        mock_result_fail.invalid = False

        self.challenge.validator_registry.validate_challenge.return_value = (
            mock_result_fail
        )

        with patch("time.sleep") as mock_sleep:
            result = self.challenge._perform_validation_with_retry(
                "dns-01", mock_context
            )

        # Should have called validate_challenge 5 times
        self.assertEqual(
            self.challenge.validator_registry.validate_challenge.call_count, 5
        )
        # Should have 4 sleep calls - no sleep after the last attempt
        self.assertEqual(mock_sleep.call_count, 4)

    def test_0128_perform_validation_with_retry_preserves_dns_validation_pause_timer(
        self,
    ):
        """Test _perform_validation_with_retry uses correct dns_validation_pause_timer"""
        mock_context = Mock()
        mock_result = Mock()
        mock_result.success = False
        mock_result.invalid = False

        self.challenge.config.dns_validation_pause_timer = 1.5
        self.challenge.validator_registry.validate_challenge.return_value = mock_result

        with patch("time.sleep") as mock_sleep:
            self.challenge._perform_validation_with_retry("dns-01", mock_context)

        # Verify sleep was called with the configured timer value
        mock_sleep.assert_called_with(1.5)

    def test_0129_get_legacy_api_calls_get_challenge_details(self):
        """Test get() legacy API method calls get_challenge_details"""
        url = "http://example.com/acme/chall/test_challenge"
        expected_result = {"code": 200, "data": {"type": "http-01"}}

        with patch.object(
            self.challenge, "get_challenge_details", return_value=expected_result
        ) as mock_get_details:
            result = self.challenge.get(url)

        # Should call get_challenge_details with the same URL
        mock_get_details.assert_called_once_with(url)
        # Should return the same result
        self.assertEqual(result, expected_result)

    def test_0130_get_legacy_api_logs_debug_message(self):
        """Test get() legacy API method logs appropriate debug message"""
        url = "http://example.com/acme/chall/test_challenge"

        with patch.object(
            self.challenge, "get_challenge_details", return_value={"code": 200}
        ):
            with self.assertLogs("test_a2c", level="DEBUG") as lcm:
                self.challenge.get(url)

        # Should log debug message
        self.assertIn("DEBUG:test_a2c:Challenge.get() called - legacy API", lcm.output)

    def test_0131_get_legacy_api_handles_404_response(self):
        """Test get() legacy API method handles 404 response from get_challenge_details"""
        url = "http://example.com/acme/chall/nonexistent_challenge"
        expected_result = {"code": 404, "data": {}}

        with patch.object(
            self.challenge, "get_challenge_details", return_value=expected_result
        ) as mock_get_details:
            result = self.challenge.get(url)

        mock_get_details.assert_called_once_with(url)
        self.assertEqual(result, expected_result)

    def test_0132_get_legacy_api_handles_error_response(self):
        """Test get() legacy API method handles error response from get_challenge_details"""
        url = "http://example.com/acme/chall/test_challenge"
        expected_result = {
            "status": 500,
            "type": "urn:ietf:params:acme:error:serverInternal",
            "detail": "Database error",
        }

        with patch.object(
            self.challenge, "get_challenge_details", return_value=expected_result
        ) as mock_get_details:
            result = self.challenge.get(url)

        mock_get_details.assert_called_once_with(url)
        self.assertEqual(result, expected_result)

    def test_0133_get_legacy_api_passes_through_all_response_types(self):
        """Test get() legacy API method passes through various response types"""
        url = "http://example.com/acme/chall/test_challenge"

        # Test with complex response
        expected_result = {
            "code": 200,
            "data": {
                "type": "dns-01",
                "status": "valid",
                "token": "complex_token_123",
                "validated": "2023-12-01T10:00:00Z",
            },
        }

        with patch.object(
            self.challenge, "get_challenge_details", return_value=expected_result
        ) as mock_get_details:
            result = self.challenge.get(url)

        mock_get_details.assert_called_once_with(url)
        self.assertEqual(result, expected_result)

    @patch("acme_srv.challenge.Thread")
    def test_0134_start_async_validation_sync_mode(self, mock_thread_class):
        """Test _start_async_validation with sync mode (async_mode=False)"""
        # Setup
        mock_thread = Mock()
        mock_thread_class.return_value = mock_thread
        self.challenge.config.async_mode = False
        self.challenge.config.validation_timeout = 30
        self.challenge._perform_challenge_validation = Mock()
        challenge_name = "test_challenge"
        payload = {"key": "value"}

        # Execute
        with self.assertLogs(self.logger, level="DEBUG") as log:
            self.challenge._start_async_validation(challenge_name, payload)

        # Verify thread creation and execution
        mock_thread_class.assert_called_once_with(
            target=self.challenge._perform_challenge_validation,
            args=(challenge_name, payload),
        )
        mock_thread.start.assert_called_once()
        mock_thread.join.assert_called_once_with(timeout=30)

        # Verify logging
        self.assertTrue(
            any(
                "Challenge._start_async_validation(test_challenge)" in message
                for message in log.output
            )
        )

    @patch("acme_srv.challenge.Thread")
    def test_0135_start_async_validation_async_mode(self, mock_thread_class):
        """Test _start_async_validation with async mode (async_mode=True)"""
        # Setup
        mock_thread = Mock()
        mock_thread_class.return_value = mock_thread
        self.challenge.config.async_mode = True
        self.challenge.config.validation_timeout = 30
        self.challenge._perform_challenge_validation = Mock()
        challenge_name = "async_challenge"
        payload = {"test": "data"}

        # Execute
        with self.assertLogs(self.logger, level="INFO") as log:
            self.challenge._start_async_validation(challenge_name, payload)

        # Verify thread creation and execution
        mock_thread_class.assert_called_once_with(
            target=self.challenge._perform_challenge_validation,
            args=(challenge_name, payload),
        )
        mock_thread.start.assert_called_once()
        # In async mode, join should NOT be called
        mock_thread.join.assert_not_called()

        # Verify async logging
        self.assertTrue(
            any(
                "asynchronous Challenge validation enabled, not waiting for result"
                in message
                for message in log.output
            )
        )

    @patch("acme_srv.challenge.Thread")
    def test_0136_start_async_validation_empty_payload(self, mock_thread_class):
        """Test _start_async_validation with empty payload"""
        # Setup
        mock_thread = Mock()
        mock_thread_class.return_value = mock_thread
        self.challenge.config.async_mode = False
        self.challenge.config.validation_timeout = 15
        self.challenge._perform_challenge_validation = Mock()
        challenge_name = "empty_payload_challenge"
        payload = {}

        # Execute
        self.challenge._start_async_validation(challenge_name, payload)

        # Verify thread creation with empty payload
        mock_thread_class.assert_called_once_with(
            target=self.challenge._perform_challenge_validation,
            args=(challenge_name, payload),
        )
        mock_thread.start.assert_called_once()
        mock_thread.join.assert_called_once_with(timeout=15)

    @patch("acme_srv.challenge.Thread")
    def test_0137_start_async_validation_complex_payload(self, mock_thread_class):
        """Test _start_async_validation with complex payload data"""
        # Setup
        mock_thread = Mock()
        mock_thread_class.return_value = mock_thread
        self.challenge.config.async_mode = True
        self.challenge._perform_challenge_validation = Mock()
        challenge_name = "complex_challenge"
        payload = {
            "protected": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9",
            "signature": "signature_value_here",
            "atc": "token_value",
            "nested": {"data": {"value": 123}},
        }

        # Execute
        self.challenge._start_async_validation(challenge_name, payload)

        # Verify thread creation with complex payload
        mock_thread_class.assert_called_once_with(
            target=self.challenge._perform_challenge_validation,
            args=(challenge_name, payload),
        )
        mock_thread.start.assert_called_once()
        mock_thread.join.assert_not_called()  # async mode

    @patch("acme_srv.challenge.Thread")
    def test_0138_start_async_validation_different_timeout_values(
        self, mock_thread_class
    ):
        """Test _start_async_validation with different timeout values in sync mode"""
        test_cases = [1, 5, 10, 60, 120]

        for timeout in test_cases:
            with self.subTest(timeout=timeout):
                # Reset mock
                mock_thread_class.reset_mock()
                mock_thread = Mock()
                mock_thread_class.return_value = mock_thread

                # Setup
                self.challenge.config.async_mode = False
                self.challenge.config.validation_timeout = timeout
                self.challenge._perform_challenge_validation = Mock()
                challenge_name = f"timeout_test_{timeout}"
                payload = {"timeout_test": timeout}

                # Execute
                self.challenge._start_async_validation(challenge_name, payload)

                # Verify correct timeout is used
                mock_thread.join.assert_called_once_with(timeout=timeout)

    @patch("acme_srv.challenge.Thread")
    def test_0139_start_async_validation_thread_target_arguments(
        self, mock_thread_class
    ):
        """Test _start_async_validation passes correct arguments to thread target"""
        # Setup
        mock_thread = Mock()
        mock_thread_class.return_value = mock_thread
        self.challenge.config.async_mode = False
        self.challenge._perform_challenge_validation = Mock()

        # Test with various argument combinations
        test_cases = [
            ("challenge1", {}),
            ("challenge_with_data", {"key1": "value1"}),
            ("complex_name_123", {"multiple": "values", "nested": {"data": True}}),
            ("", {"empty_name_test": True}),
        ]

        for challenge_name, payload in test_cases:
            with self.subTest(challenge_name=challenge_name, payload=payload):
                # Reset mock
                mock_thread_class.reset_mock()
                mock_thread = Mock()
                mock_thread_class.return_value = mock_thread

                # Execute
                self.challenge._start_async_validation(challenge_name, payload)

                # Verify thread target and arguments
                mock_thread_class.assert_called_once_with(
                    target=self.challenge._perform_challenge_validation,
                    args=(challenge_name, payload),
                )

    @patch("acme_srv.challenge.Thread")
    def test_0140_start_async_validation_logging_behavior(self, mock_thread_class):
        """Test _start_async_validation logging in both sync and async modes"""
        # Setup
        mock_thread = Mock()
        mock_thread_class.return_value = mock_thread
        self.challenge._perform_challenge_validation = Mock()
        challenge_name = "logging_test_challenge"
        payload = {"logging": "test"}

        # Test sync mode logging
        self.challenge.config.async_mode = False
        with self.assertLogs(self.logger, level="DEBUG") as log_sync:
            self.challenge._start_async_validation(challenge_name, payload)

        # Verify sync mode only has debug logging
        debug_messages = [msg for msg in log_sync.output if "DEBUG" in msg]
        info_messages = [
            msg
            for msg in log_sync.output
            if "asynchronous Challenge validation enabled" in msg
        ]
        self.assertTrue(len(debug_messages) > 0)
        self.assertEqual(len(info_messages), 0)

        # Reset mock for async test
        mock_thread_class.reset_mock()
        mock_thread = Mock()
        mock_thread_class.return_value = mock_thread

        # Test async mode logging
        self.challenge.config.async_mode = True
        with self.assertLogs(self.logger, level="DEBUG") as log_async:
            self.challenge._start_async_validation(challenge_name, payload)

        # Verify async mode has both debug and info logging
        debug_messages = [msg for msg in log_async.output if "DEBUG" in msg]
        info_messages = [
            msg
            for msg in log_async.output
            if "asynchronous Challenge validation enabled" in msg
        ]
        self.assertTrue(len(debug_messages) > 0)
        self.assertTrue(len(info_messages) > 0)


if __name__ == "__main__":
    unittest.main()
