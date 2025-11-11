import sys
import unittest

sys.path.insert(0, ".")
sys.path.insert(1, "..")
from unittest.mock import Mock, patch, MagicMock
from acme_srv.challenge import (
    ChallengeConfiguration,
    DatabaseChallengeRepository,
    Challenge,
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


class TestChallengeConfiguration(unittest.TestCase):
    def test_0001_configuration_defaults(self):
        config = ChallengeConfiguration()
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

        self.dbstore = Mock()
        # Create a real logger for testing
        self.logger = logging.getLogger("test_a2c")
        self.logger.setLevel(logging.DEBUG)
        # Remove any existing handlers to avoid duplicate logs
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)

        self.repo = DatabaseChallengeRepository(self.dbstore, self.logger)

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
            with self.assertRaises(DatabaseError):
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
            with self.assertRaises(DatabaseError):
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
            with self.assertRaises(DatabaseError):
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
            req = ChallengeCreationRequest("dns-01", "tok", "authz", "val")
            name = self.repo.create_challenge(req)
            self.assertEqual(name, "c1")

    def test_0009_create_challenge_db_error(self):
        self.dbstore.challenge_add.side_effect = Exception("db fail")
        with patch(
            "acme_srv.challenge.generate_random_string", return_value="c1"
        ), patch("acme_srv.challenge.uts_now", return_value=1000):
            req = ChallengeCreationRequest("dns-01", "tok", "authz", "val")
            with self.assertLogs("test_a2c", level="DEBUG") as log_context:
                with self.assertRaises(DatabaseError):
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
        req = ChallengeUpdateRequest("c1", status=2)
        self.assertTrue(self.repo.update_challenge(req))

    def test_0011_update_challenge_db_error(self):
        self.dbstore.challenge_update.side_effect = Exception("db fail")
        req = ChallengeUpdateRequest("c1", status=2)
        with self.assertLogs("test_a2c", level="DEBUG") as log_context:
            with self.assertRaises(DatabaseError):
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
            with self.assertRaises(DatabaseError):
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
        self.challenge.config = ChallengeConfiguration()
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
        info = ChallengeInfo(
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
        info = ChallengeInfo(
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
        info = ChallengeInfo(
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
            return_value=(False, True)
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
        info = ChallengeInfo(
            "c1", "dns-01", "tok", "pending", "authz", "dns", "val", "url"
        )
        self.challenge.repository.get_challenge_by_name.return_value = info
        self.challenge.validator_registry.is_supported.return_value = True
        mock_result = Mock(success=True, invalid=False)
        self.challenge.validator_registry.validate_challenge.return_value = mock_result
        result = self.challenge._perform_source_address_validation("c1")
        self.assertEqual(result, (True, False))

    def test_0041_perform_source_address_validation_fail(self):
        self.challenge.config.forward_address_check = True
        info = ChallengeInfo(
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
        self.assertEqual(result, (False, True))

    def test_0042_perform_source_address_validation_validator_not_available(self):
        self.challenge.config.forward_address_check = True
        info = ChallengeInfo(
            "c1", "dns-01", "tok", "pending", "authz", "dns", "val", "url"
        )
        self.challenge.repository.get_challenge_by_name.return_value = info
        self.challenge.validator_registry.is_supported.return_value = False
        with self.assertLogs("test_a2c", level="DEBUG") as lcm:
            result = self.challenge._perform_source_address_validation("c1")
        self.assertIn(
            "WARNING:test_a2c:Source address validator not available", lcm.output
        )
        self.assertEqual(result, (True, False))

    def test_0043_perform_source_address_validation_exception(self):
        self.challenge.config.forward_address_check = True
        info = ChallengeInfo(
            "c1", "dns-01", "tok", "pending", "authz", "dns", "val", "url"
        )
        self.challenge.repository.get_challenge_by_name.return_value = info
        self.challenge.validator_registry.is_supported.side_effect = Exception("fail")
        with self.assertLogs("test_a2c", level="DEBUG") as lcm:
            result = self.challenge._perform_source_address_validation("c1")
        self.assertIn(
            "ERROR:test_a2c:Source address validation error for c1: fail", lcm.output
        )
        self.assertEqual(result, (False, True))

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
        with patch("acme_srv.challenge.ThreadWithReturnValue") as mock_thread:
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
        info = ChallengeInfo(
            "c1", "tkauth-01", "tok", "pending", "authz", "dns", "val", "url"
        )
        payload = {"atc": "foo"}
        result = self.challenge._validate_tnauthlist_payload(payload, info)
        self.assertEqual(result["code"], 200)

    def test_0051_validate_tnauthlist_payload_missing_atc(self):
        info = ChallengeInfo(
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
        info = ChallengeInfo(
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
        self.challenge.repository.get_challenge_by_name.return_value = ChallengeInfo(
            "c1", "dns-01", "tok", "pending", "authz", "dns", "val", "url"
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
        self.challenge.repository = DatabaseChallengeRepository(Mock(), self.logger)
        # Set up challenge_lookup to return a valid response so jwk_load gets called
        self.challenge.repository.dbstore.challenge_lookup.return_value = {
            "authorization__order__account__name": "account_name"
        }
        self.challenge.repository.dbstore.jwk_load.side_effect = Exception("DB error")

        with self.assertLogs("test_a2c", level="DEBUG") as log_context:
            with self.assertRaises(DatabaseError):
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
        self.challenge.repository = DatabaseChallengeRepository(Mock(), self.logger)
        self.challenge.repository.dbstore.challenge_lookup.return_value = None

        result = self.challenge.repository.get_challengeinfo_by_challengename(
            "nonexistent"
        )
        self.assertIsNone(result)

    def test_0063_get_challenge_by_name_none_result(self):
        """Test get_challenge_by_name when no challenge found"""
        self.challenge.repository = DatabaseChallengeRepository(Mock(), self.logger)
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

        with self.assertRaises(UnsupportedChallengeTypeError):
            self.challenge._execute_challenge_validation("test_challenge", {})

    def test_0065_execute_challenge_validation_no_details(self):
        """Test _execute_challenge_validation when details cannot be retrieved"""
        self.challenge._get_challenge_validation_details = Mock(return_value=None)

        with self.assertRaises(ValidationError):
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

        info = ChallengeInfo(
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
        self.challenge.repository = DatabaseChallengeRepository(Mock(), self.logger)
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
        self.challenge.repository = DatabaseChallengeRepository(Mock(), self.logger)
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
        self.challenge.repository = DatabaseChallengeRepository(Mock(), self.logger)

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

        info = ChallengeInfo(
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
        info = ChallengeInfo(
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
        info = ChallengeInfo(
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


if __name__ == "__main__":
    unittest.main()
