#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for account.py"""
# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212
import unittest
from unittest.mock import patch, MagicMock, call, ANY

import logging
import types
import json
import os
import sys
import importlib
import configparser
from unittest.mock import patch, MagicMock

# Inject a mock acme_srv.db_handler.DBstore into sys.modules if missing
import types as _types

mock_db_handler = _types.ModuleType("acme_srv.db_handler")
mock_db_handler.DBstore = MagicMock(name="DBstore")
sys.modules["acme_srv.db_handler"] = mock_db_handler


# Add the parent directory to sys.path so we can import acme_srv
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# Patch DBstore globally for all tests in this module
with patch("acme_srv.db_handler.DBstore", new=MagicMock()):
    from acme_srv.order import (
        Order,
        OrderRepository,
        OrderDatabaseError,
        OrderValidationError,
        OrderConfiguration,
    )


class TestOrderRepository(unittest.TestCase):
    def setUp(self):
        """setup unittest"""
        models_mock = MagicMock()
        models_mock.acme_srv.db_handler.DBstore.return_value = FakeDBStore
        modules = {"acme_srv.db_handler": models_mock}
        patch.dict("sys.modules", modules).start()
        import logging

    def test_001_add_order_success(self):
        self.mock_db.order_add.return_value = "oid"
        self.assertEqual(self.repo.add_order({"foo": "bar"}), "oid")

    def test_002_add_order_failure(self):
        self.mock_db.order_add.side_effect = Exception("fail")
        with self.assertRaises(OrderDatabaseError):
            self.repo.add_order({"foo": "bar"})

    def test_021__enter_(self):
        """test enter"""
        self.order.__enter__()

    def test_022__enter_(self):
        """test enter"""
        self.order.__exit__()

    def test_023_are_identifiers_allowed_logging(self):

    def test_006_update_authorization_failure(self):
        self.mock_db.authorization_update.side_effect = Exception("fail")
        with self.assertRaises(OrderDatabaseError):
            self.repo.update_authorization({"foo": "bar"})

    def test_007_order_lookup_success(self):
        self.mock_db.order_lookup.return_value = {"name": "order1"}
        self.assertEqual(self.repo.order_lookup("name", "order1"), {"name": "order1"})

    def test_008_order_lookup_failure(self):
        self.mock_db.order_lookup.side_effect = Exception("fail")
        with self.assertRaises(OrderDatabaseError):
            self.repo.order_lookup("name", "order1")

    def test_009_order_update_success(self):
        self.mock_db.order_update.return_value = "ok"
        self.assertEqual(self.repo.order_update({"foo": "bar"}), "ok")

    def test_010_order_update_failure(self):
        self.mock_db.order_update.side_effect = Exception("fail")
        with self.assertRaises(OrderDatabaseError):
            self.repo.order_update({"foo": "bar"})

    def test_011_authorization_lookup_success(self):
        self.mock_db.authorization_lookup.return_value = [{"name": "auth1"}]
        self.assertEqual(
            self.repo.authorization_lookup("key", "val", ["name"]), [{"name": "auth1"}]
        )

    def test_024_is_profile_valid_profile_check_disabled(self):
        self.order.config.profiles_check_disable = False
        self.order.config.profiles = {"foo": {}}
        result = self.order.is_profile_valid("foo")
        self.assertIsNone(result)

    def test_025_is_profile_valid_invalid(self):
        self.order.config.profiles_check_disable = False
        self.order.config.profiles = {"bar": {}}
        self.logger.setLevel(logging.WARNING)
        result = self.order.is_profile_valid("foo")
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertEqual(result, "urn:ietf:params:acme:error:invalidProfile")
        self.assertIn(
            "WARNING:Profile 'foo' is not valid. Ignoring submitted profile.",
            log_contents,
        )

    def test_026_is_profile_valid_valid_profile(self):

        self.order.config.profiles_check_disable = True
        self.order.config.profiles = {"foo": {}}
        result = self.order.is_profile_valid("foo")
        self.assertIsNone(result)
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn("DEBUG:Order.is_profile_valid(foo)", log_contents)
        self.assertIn("DEBUG:Order.is_profile_valid() ended with None", log_contents)
        self.assertIn(
            "DEBUG:Order.is_profile_valid(): profile check disabled", log_contents
        )
        self.assertNotIn(
            "WARNING:Profile 'foo' is not valid. Ignoring submitted profile.",
            log_contents,
        )

    def test_027_add_profile_to_order_valid(self):
        self.order.config.profiles = {"foo": {}}
        self.order.config.profiles_check_disable = False
        data_dic = {}
        payload = {"profile": "foo"}
        error, updated_dic = self.order.add_profile_to_order(data_dic, payload)
        self.assertIsNone(error)
        self.assertEqual(updated_dic["profile"], "foo")

    def test_028_add_profile_to_order_invalid(self):
        self.order.config.profiles = {}
        self.order.config.profiles_check_disable = False
        data_dic = {}
        payload = {"profile": "foo"}
        error, updated_dic = self.order.add_profile_to_order(data_dic, payload)
        self.assertEqual(error, "urn:ietf:params:acme:error:invalidProfile")
        self.assertNotIn("profile", updated_dic)

    def test_029_add_profile_to_order_no_profiles_configured(self):
        self.order.config.profiles = {}
        self.order.config.profiles_check_disable = False
        data_dic = {}
        payload = {"profile": "foo"}
        # Patch is_profile_valid to return None (simulate valid profile)
        with patch.object(self.order, "is_profile_valid", return_value=None):
            error, updated_dic = self.order.add_profile_to_order(data_dic, payload)
            self.assertIsNone(error)
            self.assertNotIn("profile", updated_dic)
            self.handler.flush()
            log_contents = self.log_stream.getvalue()
            self.assertIn(
                "WARNING:Ignore submitted profile 'foo' as no profiles are configured.",
                log_contents,
            )

    def test_030_process_order_request_db_error_logging(self):
        self.order.repository.certificate_lookup.side_effect = Exception("DB error")
        with self.assertLogs("test_a2c", level="CRITICAL") as log_cm:
            result = self.order._process_order_request(
                "order1", {"url": "poll"}, {}, None
            )
        self.assertIn(
            "CRITICAL:test_a2c:Database error: Certificate lookup failed: DB error",
            log_cm.output,
        )

    def test_031_edge_case_empty_identifiers(self):
        # _check_identifiers_validity with empty list
        result = self.order._check_identifiers_validity(
            []
        )  # Edge case with empty identifiers
        self.assertEqual(
            result,
            (self.order.error_msg_dic["malformed"], "malformed identifiers list"),
        )

    def test_032_edge_case_too_many_identifiers(self):
        # _check_identifiers_validity with too many identifiers
        self.order.config.identifier_limit = 1  # Set identifier limit to 1 for testing
        result = self.order._check_identifiers_validity(
            [{"type": "dns", "value": "a"}, {"type": "dns", "value": "b"}]
        )
        self.assertEqual(
            result,
            (
                self.order.error_msg_dic["rejectedidentifier"],
                "identifier limit exceeded",
            ),
        )

    def test_033_edge_case_invalid_identifier_type(self):
        # are_identifiers_allowed with unsupported type
        self.order.config.tnauthlist_support = False
        self.order.config.email_identifier_support = False
        result = self.order.are_identifiers_allowed([{"type": "foo", "value": "bar"}])
        self.assertEqual(
            result,
            (
                self.order.error_msg_dic["unsupportedidentifier"],
                "identifier type foo not supported",
            ),
        )

    def test_034_edge_case_missing_type(self):
        # are_identifiers_allowed with missing type
        result = self.order.are_identifiers_allowed([{"value": "bar"}])
        self.assertEqual(
            result,
            (self.order.error_msg_dic["malformed"], "identifier type is missing"),
        )

    def test_035_edge_case_invalid_profile_config(self):
        # _set_profiles_from_db with invalid JSON
        with patch.object(self.order.logger, "error") as mock_log:
            self.order._set_profiles_from_db("notjson")
            mock_log.assert_called()

    def test_036_order_dic_create_all_fields(self):
        # test _order_dic_create with all fields
        tmp_dic = {
            "status": "pending",
            "expires": 1234567890,
            "notbefore": 1234567891,
            "notafter": 1234567892,
            "identifiers": json.dumps([{"type": "dns", "value": "a"}]),
        }
        result = self.order._order_dic_create(tmp_dic)
        self.assertEqual(result["status"], "pending")
        self.assertEqual(result["expires"], "2009-02-13T23:31:30Z")
        self.assertEqual(result["notBefore"], "2009-02-13T23:31:31Z")
        self.assertEqual(result["notAfter"], "2009-02-13T23:31:32Z")
        self.assertIsInstance(result["identifiers"], list)

    def test_037_order_dic_create_invalid_identifiers(self):
        # test _order_dic_create with invalid JSON in identifiers
        tmp_dic = {"identifiers": "notjson"}
        with patch.object(self.order.logger, "error") as mock_log:
            result = self.order._order_dic_create(tmp_dic)
            self.assertIsNone(result.get("identifiers"))
            self.assertIn("identifiers", tmp_dic)
            mock_log.assert_called()

    def test_038_get_authorization_list_db_error(self):
        # test _get_authorization_list with DB error
        self.mock_repo.authorization_lookup.side_effect = OrderDatabaseError("fail")
        with patch.object(self.order.logger, "critical") as mock_log:
            result = self.order._get_authorization_list("order")
            self.assertEqual(result, [])
            mock_log.assert_called()

    def test_039_update_validity_list_ready(self):
        # test _update_validity_list sets order to ready
        authz_list = [{"name": "auth1", "status__name": "valid"}]
        order_dic = {"status": "pending", "authorizations": []}
        with patch.object(self.order.repository, "order_update") as mock_update:
            self.order._update_validity_list(authz_list, order_dic, "_")
            mock_update.assert_called_with({"name": "_", "status": "ready"})

    def test_040_update_validity_list_not_ready(self):
        # test _update_validity_list does not set order to ready
        authz_list = [{"name": "auth1", "status__name": "pending"}]
        order_dic = {"status": "pending", "authorizations": []}
        with patch.object(self.order.repository, "order_update") as mock_update:
            self.order._update_validity_list(authz_list, order_dic, "_")
            mock_update.assert_not_called()

    def test_041_get_order_details_with_authz(self):
        # test get_order_details with authorizations
        self.mock_repo.order_lookup.return_value = {
            "status": "pending",
            "identifiers": json.dumps([{"type": "dns", "value": "a"}]),
        }
        self.mock_repo.authorization_lookup.return_value = [
            {"name": "auth1", "status__name": "valid"}
        ]
        with patch.object(self.order, "_update_validity_list") as mock_update:
            result = self.order.get_order_details("order1")
            mock_update.assert_called()
            self.assertIn("status", result)

    def test_042_invalidate_expired_orders(self):
        # test invalidate_expired_orders with valid and invalid orders
        self.mock_repo.orders_invalid_search.return_value = [
            {"name": "order1", "status__name": "pending"},
            {"name": "order2", "status__name": "invalid"},
        ]
        with patch.object(self.order.repository, "order_update") as mock_update:
            _, output = self.order.invalidate_expired_orders(1234567890)
            self.assertIn("order1", [o["name"] for o in output])
            self.assertNotIn("order2", [o["name"] for o in output])
            mock_update.assert_called_once_with({"name": "order1", "status": "invalid"})

    def test_043_create_from_content_success(self):
        # test create_from_content with successful order creation
        with patch.object(
            self.order.message,
            "check",
            return_value=(
                200,
                None,
                None,
                None,
                {"identifiers": [{"type": "dns", "value": "a"}]},
                "account",
            ),
        ):
            with patch.object(
                self.order,
                "create_order",
                return_value=(
                    None,
                    "detail",
                    "order",
                    {"auth1": {"type": "dns", "value": "a"}},
                    "2026-01-01T00:00:00Z",
                ),
            ):
                with patch.object(
                    self.order.message,
                    "prepare_response",
                    side_effect=lambda resp, stat: resp,
                ):
                    result = self.order.create_from_content("content")
                    self.assertIn("header", result)
                    self.assertIn("data", result)

    def test_044_create_from_content_rejected(self):
        # test create_from_content with rejected identifier
        with patch.object(
            self.order.message,
            "check",
            return_value=(
                200,
                None,
                None,
                None,
                {"identifiers": [{"type": "dns", "value": "a"}]},
                "account",
            ),
        ):
            with patch.object(
                self.order,
                "create_order",
                return_value=(
                    "rejectedidentifier",
                    "detail",
                    "order",
                    {},
                    "2026-01-01T00:00:00Z",
                ),
            ):
                with patch.object(
                    self.order.message,
                    "prepare_response",
                    side_effect=lambda resp, stat: resp,
                ):
                    result = self.order.create_from_content("content")
                    self.assertTrue(
                        "data" not in result or result.get("data", {}) == {}
                    )

    def test_045_create_from_content_error(self):
        # test create_from_content with generic error
        with patch.object(
            self.order.message,
            "check",
            return_value=(
                200,
                None,
                None,
                None,
                {"identifiers": [{"type": "dns", "value": "a"}]},
                "account",
            ),
        ):
            with patch.object(
                self.order,
                "create_order",
                return_value=(
                    "someerror",
                    "detail",
                    "order",
                    {},
                    "2026-01-01T00:00:00Z",
                ),
            ):
                with patch.object(
                    self.order.message,
                    "prepare_response",
                    side_effect=lambda resp, stat: resp,
                ):
                    result = self.order.create_from_content("content")
                    self.assertTrue(
                        "data" not in result or result.get("data", {}) == {}
                    )

    def test_046_create_from_content_check_fail(self):
        # test create_from_content with check returning error
        with patch.object(
            self.order.message,
            "check",
            return_value=(400, "err", "detail", None, None, None),
        ):
            with patch.object(
                self.order.message,
                "prepare_response",
                side_effect=lambda resp, stat: resp,
            ):
                result = self.order.create_from_content("content")
                self.assertIsInstance(result, dict)

    def test_047_parse_order_message_all_paths(self):
        # test _parse_order_message for all code paths
        # url in protected, order_name, order_dic, process_order_request
        with patch.object(self.order, "_name_get", return_value="order"):
            with patch.object(
                self.order, "get_order_details", return_value={"status": "ok"}
            ):
                with patch.object(
                    self.order,
                    "_process_order_request",
                    return_value=(
                        200,
                        "msg",
                        "detail",
                        "cert",
                    ),
                ):
                    (
                        code,
                        _msg,
                        _detail,
                        _cert,
                        _order,
                    ) = self.order._parse_order_message({"url": "url"}, {}, None)
                    self.assertEqual(code, 200)
            # url in protected, order_name, no order_dic
            with patch.object(self.order, "get_order_details", return_value={}):
                code, _msg, _detail, _cert, _order = self.order._parse_order_message(
                    {"url": "url"}, {}, None
                )
                self.assertEqual(code, 403)
            # url in protected, no order_name
            with patch.object(self.order, "_name_get", return_value=None):
                code, _msg, _detail, _cert, _order = self.order._parse_order_message(
                    {"url": "url"}, {}, None
                )
                self.assertEqual(code, 400)
        # no url in protected
        code, _msg, _detail, _cert, _order = self.order._parse_order_message(
            {}, {}, None
        )
        self.assertEqual(code, 400)

    def test_048_parse_order_content_success(self):
        # test parse_order_content with code 200 and status processing
        with patch.object(
            self.order.message,
            "check",
            return_value=(200, None, None, {"url": "url"}, {}, "account"),
        ):
            with patch.object(
                self.order,
                "_parse_order_message",
                return_value=(200, None, None, None, "order"),
            ):
                with patch.object(
                    self.order,
                    "get_order_details",
                    return_value={"status": "processing"},
                ):
                    with patch.object(
                        self.order.message,
                        "prepare_response",
                        side_effect=lambda resp, stat: resp,
                    ):
                        result = self.order.parse_order_content("content")
                        self.assertIn("header", result)
                        self.assertIn("data", result)

    def test_049_parse_order_content_expiry_disabled(self):
        # test parse_order_content with expiry_check_disable True
        self.order.config.expiry_check_disable = True
        with patch.object(
            self.order.message,
            "check",
            return_value=(200, None, None, {"url": "url"}, {}, "account"),
        ):
            with patch.object(
                self.order,
                "_parse_order_message",
                return_value=(200, None, None, None, "order"),
            ):
                with patch.object(
                    self.order,
                    "get_order_details",
                    return_value={"status": "processing"},
                ):
                    with patch.object(
                        self.order.message,
                        "prepare_response",
                        side_effect=lambda resp, stat: resp,
                    ):
                        result = self.order.parse_order_content("content")
                        self.assertIn("header", result)
                        self.assertIn("data", result)

    def test_050_legacy_api_compatibility(self):
        # test legacy API wrappers
        with patch.object(
            self.order, "invalidate_expired_orders", return_value=([], [])
        ):
            self.assertEqual(self.order.invalidate(), ([], []))
        with patch.object(
            self.order, "create_from_content", return_value={"foo": "bar"}
        ):
            self.assertEqual(self.order.new("content"), {"foo": "bar"})
        with patch.object(
            self.order, "parse_order_content", return_value={"foo": "bar"}
        ):
            self.assertEqual(self.order.parse("content"), {"foo": "bar"})

    def test_051_add_order_and_authorizations_success(self):
        # Order and authorizations added successfully
        self.mock_repo.add_order.return_value = "oid"
        self.mock_repo.add_authorization.return_value = None
        payload = {"identifiers": [{"type": "dns", "value": "example.com"}]}
        data_dic = {"foo": "bar"}
        auth_dic = {}
        error = None
        with patch.object(
            self.order,
            "_add_authorizations_to_db",
            wraps=self.order._add_authorizations_to_db,
        ) as mock_add_authz:
            result = self.order._add_order_and_authorizations(
                data_dic, auth_dic, payload, error
            )
            self.assertIsNone(result)
            self.handler.flush()
            log_contents = self.log_stream.getvalue()
            self.assertIn("DEBUG:Order._add_order_and_authorizations()", log_contents)
            self.assertIn(
                "DEBUG:Order._add_order_and_authorizations() ended with None",
                log_contents,
            )
            mock_add_authz.assert_called_once()

    def test_052_add_order_and_authorizations_order_db_error(self):
        # Adding order raises DB error
        self.mock_repo.add_order.side_effect = OrderDatabaseError("fail")
        payload = {"identifiers": [{"type": "dns", "value": "example.com"}]}
        data_dic = {"foo": "bar"}
        auth_dic = {}
        error = None
        with patch.object(
            self.order,
            "_add_authorizations_to_db",
            wraps=self.order._add_authorizations_to_db,
        ) as mock_add_authz:
            result = self.order._add_order_and_authorizations(
                data_dic, auth_dic, payload, error
            )
            self.assertEqual(
                result, "urn:ietf:params:acme:error:malformed"
            )  # error is set to 'malformed' if oid is None
            self.handler.flush()
            log_contents = self.log_stream.getvalue()
            self.assertIn(
                "CRITICAL:Database error: failed to add order: fail", log_contents
            )
            self.assertIn(
                "DEBUG:Order._add_order_and_authorizations() ended with urn:ietf:params:acme:error:malformed",
                log_contents,
            )
            mock_add_authz.assert_called_once_with(None, payload, auth_dic)

    def test_053_add_order_and_authorizations_authz_db_error(self):
        # Adding authorization raises DB error
        self.mock_repo.add_order.return_value = "oid"
        self.mock_repo.add_authorization.side_effect = OrderDatabaseError("fail")
        payload = {"identifiers": [{"type": "dns", "value": "example.com"}]}
        data_dic = {"foo": "bar"}
        auth_dic = {}
        error = None
        # Patch _add_authorizations_to_db to call the real method
        with patch.object(
            self.order,
            "_add_authorizations_to_db",
            wraps=self.order._add_authorizations_to_db,
        ) as mock_add_authz:
            result = self.order._add_order_and_authorizations(
                data_dic, auth_dic, payload, error
            )
            self.assertIsNone(result)  # error is None, but DB error is logged
            self.handler.flush()
            log_contents = self.log_stream.getvalue()
            self.assertIn(
                "CRITICAL:Database error: failed to add authorization: fail",
                log_contents,
            )
            self.assertIn(
                "DEBUG:Order._add_order_and_authorizations() ended with None",
                log_contents,
            )
            mock_add_authz.assert_called_once()

    def test_053_add_authorizations_to_db_sectigo_sim_sets_valid(self):
        # Covers: sectigo_sim True triggers status 'valid' and update_authorization
        self.log_stream.truncate(0)
        self.log_stream.seek(0)
        self.logger.setLevel(logging.DEBUG)
        self.order.config.sectigo_sim = True
        payload = {"identifiers": [{"type": "dns", "value": "example.com"}]}
        auth_dic = {}
        with patch(
            "acme_srv.order.generate_random_string", return_value="authname"
        ), patch("acme_srv.helper.uts_now", return_value=1000), patch.object(
            self.order.repository, "add_authorization"
        ) as _mock_add_auth, patch.object(
            self.order.repository, "update_authorization"
        ) as mock_update_auth:
            error = self.order._add_authorizations_to_db("oid123", payload, auth_dic)
            self.assertIsNone(error)
            self.assertIn("authname", auth_dic)
            # Ensure update_authorization called with status 'valid'
            self.assertTrue(mock_update_auth.called)
            called_args, _called_kwargs = mock_update_auth.call_args
            self.assertEqual(called_args[0]["status"], "valid")
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn("DEBUG:Order._add_authorizations_to_db(oid123)", log_contents)
        self.assertIn(
            "DEBUG:Order._add_authorizations_to_db() ended with None", log_contents
        )

    def test_054_add_order_and_authorizations_with_error_input(self):
        # If error is already set, should skip adding order/authorizations
        payload = {"identifiers": [{"type": "dns", "value": "example.com"}]}
        data_dic = {"foo": "bar"}
        auth_dic = {}
        error = "someerror"
        with patch.object(
            self.order,
            "_add_authorizations_to_db",
            wraps=self.order._add_authorizations_to_db,
        ) as mock_add_authz:
            result = self.order._add_order_and_authorizations(
                data_dic, auth_dic, payload, error
            )
            self.assertEqual(result, "someerror")
            self.handler.flush()
            log_contents = self.log_stream.getvalue()
            self.assertIn("DEBUG:Order._add_order_and_authorizations()", log_contents)
            self.assertIn(
                "DEBUG:Order._add_order_and_authorizations() ended with someerror",
                log_contents,
            )
            mock_add_authz.assert_not_called()

    def test_055_add_order_and_authorizations_logging(self):
        # Check all log messages with severity DEBUG and higher using unified logger
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            self.mock_repo.add_order.return_value = "oid"
            self.mock_repo.add_authorization.return_value = None
            payload = {"identifiers": [{"type": "dns", "value": "example.com"}]}
            data_dic = {"foo": "bar"}
            auth_dic = {}
            error = None
            order._add_order_and_authorizations(data_dic, auth_dic, payload, error)
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn("DEBUG:Order._add_order_and_authorizations()", log_contents)
        self.assertIn(
            "DEBUG:Order._add_order_and_authorizations() ended with None", log_contents
        )

    def test_056_load_header_info_config_valid(self):
        config_dic = {"Order": {"header_info_list": '["X-Header1", "X-Header2"]'}}
        self.order.config.header_info_list = []
        self.order._load_header_info_config(config_dic)
        self.assertEqual(self.order.config.header_info_list, ["X-Header1", "X-Header2"])

    def test_057_load_header_info_config_invalid_json(self):
        config_dic = {"Order": {"header_info_list": "notjson"}}
        with patch.object(self.order.logger, "warning") as mock_warn:
            self.order._load_header_info_config(config_dic)
            mock_warn.assert_called()

    def test_058_load_header_info_config_missing_key(self):
        config_dic = {"Order": {}}
        self.order.config.header_info_list = ["shouldnotchange"]
        self.order._load_header_info_config(config_dic)
        self.assertEqual(self.order.config.header_info_list, ["shouldnotchange"])

    def test_059_load_header_info_config_logging(self):
        # Use unified logger and log_stream
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            order = Order(debug=True, server_name="_", logger=self.logger)
            config_dic = {"Order": {"header_info_list": '["X-Header1"]'}}
            order._load_header_info_config(config_dic)
            config_dic = {"Order": {"header_info_list": "notjson"}}
            order._load_header_info_config(config_dic)
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn("DEBUG:Order._load_header_info_config()", log_contents)
        self.assertIn("DEBUG:Order._load_header_info_config() ended", log_contents)
        self.assertIn(
            "WARNING:Failed to parse header_info_list from configuration:", log_contents
        )

    def test_060_load_order_config_all_options(self):
        import configparser

        config_dic = configparser.ConfigParser()
        config_dic.add_section("Challenge")
        config_dic.set("Challenge", "sectigo_sim", "True")
        config_dic.add_section("Order")
        config_dic.set("Order", "tnauthlist_support", "True")
        config_dic.set("Order", "email_identifier_support", "True")
        config_dic.set("Order", "email_identifier_rewrite", "True")
        config_dic.set("Order", "expiry_check_disable", "True")
        config_dic.set("Order", "idempotent_finalize", "True")
        config_dic.set("Order", "retry_after_timeout", "123")
        config_dic.set("Order", "validity", "456")
        config_dic.set("Order", "identifier_limit", "7")
        self.order._load_order_config(config_dic)
        self.assertTrue(self.order.config.sectigo_sim)
        self.assertTrue(self.order.config.tnauthlist_support)
        self.assertTrue(self.order.config.email_identifier_support)
        self.assertTrue(self.order.config.email_identifier_rewrite)
        self.assertTrue(self.order.config.expiry_check_disable)
        self.assertTrue(self.order.config.idempotent_finalize)
        self.assertEqual(self.order.config.retry_after, 123)
        self.assertEqual(self.order.config.validity, 456)
        self.assertEqual(self.order.config.identifier_limit, 7)

    def test_061_load_order_config_invalid_ints(self):
        import configparser

        config_dic = configparser.ConfigParser()
        config_dic.add_section("Challenge")
        config_dic.set("Challenge", "sectigo_sim", "True")
        config_dic.add_section("Order")
        config_dic.set("Order", "retry_after_timeout", "notint")
        config_dic.set("Order", "validity", "notint")
        config_dic.set("Order", "identifier_limit", "notint")
        with patch.object(self.order.logger, "warning") as mock_warn:
            self.order._load_order_config(config_dic)
            self.assertGreaterEqual(mock_warn.call_count, 3)

    def test_062_load_order_config_missing_sections(self):
        import configparser

        config_dic = configparser.ConfigParser()
        # Should not raise, should use fallbacks
        self.order._load_order_config(config_dic)
        # All config values should remain at their defaults
        self.assertEqual(self.order.config.retry_after, 600)
        self.assertEqual(self.order.config.validity, 86400)
        self.assertEqual(self.order.config.identifier_limit, 20)

    def test_063_create_order_invalid_identifiers(self):
        # Identifiers are invalid, triggers error path
        payload = {"identifiers": [{"type": "dns", "value": "example.com"}]}
        account_name = "acct"
        with patch.object(
            self.order,
            "_check_identifiers_validity",
            return_value=("rejectedidentifier", None),
        ) as mock_check, patch.object(
            self.order, "_add_order_and_authorizations", return_value=None
        ) as mock_add_order_authz:
            error, _detail, _order_name, _auth_dic, _expires = self.order.create_order(
                payload, account_name
            )
            self.assertIsNone(error)  # _add_order_and_authorizations returns None
            mock_check.assert_called_once()
            mock_add_order_authz.assert_called_once()

    def test_064_create_order_profile_invalid(self):
        # Profile is present but invalid, triggers error path
        payload = {
            "identifiers": [{"type": "dns", "value": "example.com"}],
            "profile": "foo",
        }
        account_name = "acct"
        with patch.object(
            self.order, "_check_identifiers_validity", return_value=(None, None)
        ) as mock_check, patch.object(
            self.order,
            "add_profile_to_order",
            return_value=(
                "invalidprofile",
                {
                    "status": 2,
                    "expires": 1234567890,
                    "account": account_name,
                    "name": "randomstring",
                    "identifiers": '[{"type": "dns", "value": "example.com"}]',
                },
            ),
        ) as mock_add_profile, patch.object(
            self.order, "_add_order_and_authorizations", return_value=None
        ) as mock_add_order_authz:
            error, _detail, _order_name, _auth_dic, _expires = self.order.create_order(
                payload, account_name
            )
            self.assertIsNone(error)
            mock_check.assert_called_once()
            mock_add_profile.assert_called_once()
            mock_add_order_authz.assert_called_once()

    def test_065_create_order_add_order_and_authz_error(self):
        # Error occurs in _add_order_and_authorizations
        payload = {"identifiers": [{"type": "dns", "value": "example.com"}]}
        account_name = "acct"
        with patch.object(
            self.order, "_check_identifiers_validity", return_value=(None, None)
        ) as mock_check, patch.object(
            self.order, "_add_order_and_authorizations", return_value="someerror"
        ) as mock_add_order_authz:
            error, _detail, _order_name, _auth_dic, _expires = self.order.create_order(
                payload, account_name
            )
            self.assertEqual(error, "someerror")
            mock_check.assert_called_once()
            mock_add_order_authz.assert_called_once()

    def test_066_create_order_no_identifiers(self):
        # Payload missing 'identifiers', triggers unsupportedidentifier error
        payload = {"profile": "foo"}
        account_name = "acct"
        with patch(
            "acme_srv.order.generate_random_string", return_value="randomstring"
        ), patch("acme_srv.order.uts_now", return_value=1234567890):
            error, detail, order_name, auth_dic, expires = self.order.create_order(
                payload, account_name
            )
            self.assertEqual(error, "urn:ietf:params:acme:error:unsupportedIdentifier")
            self.assertEqual(order_name, "randomstring")
            self.assertIsInstance(auth_dic, dict)
            self.assertEqual(expires, "2009-02-14T23:31:30Z")
            self.assertFalse(detail)

    def test_067_create_order_logging(self):
        # Check all log messages with severity INFO and higher
        # Use unified logger and log_stream
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ), patch(
            "acme_srv.helper.generate_random_string", return_value="randomstring"
        ), patch(
            "acme_srv.helper.uts_now", return_value=1234567890
        ), patch(
            "acme_srv.helper.uts_to_date_utc", return_value="2026-01-01T00:00:00Z"
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            with patch.object(
                order, "_check_identifiers_validity", return_value=(None, None)
            ), patch.object(
                order,
                "add_profile_to_order",
                return_value=(
                    None,
                    {
                        "status": 2,
                        "expires": 1234567890,
                        "account": "acct",
                        "name": "randomstring",
                        "identifiers": '[{"type": "dns", "value": "example.com"}]',
                        "profile": "foo",
                    },
                ),
            ), patch.object(
                order, "_add_order_and_authorizations", return_value=None
            ):
                payload = {
                    "identifiers": [{"type": "dns", "value": "example.com"}],
                    "profile": "foo",
                }
                account_name = "acct"
                order.create_order(payload, account_name)
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn("DEBUG:Order.create_order(acct)", log_contents)
        self.assertIn("DEBUG:Order.create_order() ended", log_contents)

    def test_068_load_profile_config_all_paths(self):
        # Test all code paths, including logging
        # Use unified logger and log_stream
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            with patch.object(order, "_load_profiles_from_config") as m1, patch.object(
                order, "_load_profiles_from_db_if_sync"
            ) as m2, patch.object(order, "_maybe_disable_profile_check") as m3:
                order._load_profile_config({"Order": {}, "CAhandler": {}})
                m1.assert_called_once()
                m2.assert_called_once()
                m3.assert_called_once()
        self.assertIn("DEBUG:test_a2c:Order._load_profile_config()", log_cm.output)
        self.assertIn(
            "DEBUG:test_a2c:Order._load_profile_config() ended", log_cm.output
        )

    def test_069_load_profile_config_all_paths(self):
        with patch.object(self.order, "_load_profiles_from_config") as m1, patch.object(
            self.order, "_load_profiles_from_db_if_sync"
        ) as m2, patch.object(self.order, "_maybe_disable_profile_check") as m3:
            with self.assertLogs("test_a2c", level="DEBUG") as log_cm:
                self.order._load_profile_config({"Order": {}, "CAhandler": {}})
                m1.assert_called_once()
                m2.assert_called_once()
                m3.assert_called_once()

        self.assertIn("DEBUG:test_a2c:Order._load_profile_config()", log_cm.output)
        self.assertIn(
            "DEBUG:test_a2c:Order._load_profile_config() ended", log_cm.output
        )

    def test_070_load_profiles_from_config_with_profiles(self):
        # Should load profiles and set profiles_check_disable to False
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ), patch(
            "acme_srv.order.config_profile_load", return_value={"foo": {}}
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            config_dic = {"Order": {"profiles": "something"}}
            order._load_profiles_from_config(config_dic)
            self.assertFalse(order.config.profiles_check_disable)
            self.assertEqual(order.config.profiles, {"foo": {}})

    def test_071_load_profiles_from_config_no_profiles(self):
        # Should not set profiles or change profiles_check_disable
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            config_dic = {"Order": {}}
            order.config.profiles = {"bar": {}}
            order.config.profiles_check_disable = True
            order._load_profiles_from_config(config_dic)
            self.assertEqual(order.config.profiles, {"bar": {}})
            self.assertTrue(order.config.profiles_check_disable)

    def test_072_load_profiles_from_db_if_sync_profiles_sync_true(self):
        # Should load profiles from DB if profiles_sync is set and True
        import configparser

        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            config_dic = configparser.ConfigParser()
            config_dic.add_section("CAhandler")
            config_dic.set("CAhandler", "profiles_sync", "True")
            order.repository.hkparameter_get = MagicMock(
                return_value='{"profiles": {"foo": {}}}'
            )
            order._set_profiles_from_db = MagicMock()
            order._load_profiles_from_db_if_sync(config_dic)
            self.assertTrue(order.config.profiles_sync)
            order._set_profiles_from_db.assert_called_once_with(
                '{"profiles": {"foo": {}}}'
            )

    def test_073_load_profiles_from_db_if_sync_profiles_sync_false(self):
        # Should not load profiles from DB if profiles_sync is False
        import configparser

        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            config_dic = configparser.ConfigParser()
            config_dic.add_section("CAhandler")
            config_dic.set("CAhandler", "profiles_sync", "False")
            order.repository.hkparameter_get = MagicMock()
            order._set_profiles_from_db = MagicMock()
            order._load_profiles_from_db_if_sync(config_dic)
            self.assertFalse(order.config.profiles_sync)
            order._set_profiles_from_db.assert_not_called()

    def test_074_load_profiles_from_db_if_sync_no_profiles_sync(self):
        # Should not load profiles from DB if profiles_sync key is missing
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            config_dic = {"CAhandler": {}}
            order.repository.hkparameter_get = MagicMock()
            order._set_profiles_from_db = MagicMock()
            order._load_profiles_from_db_if_sync(config_dic)
            self.assertFalse(
                hasattr(order.config, "profiles_sync") and order.config.profiles_sync
            )
            order._set_profiles_from_db.assert_not_called()

    def test_075_load_profiles_from_db_if_sync_db_error(self):
        # Should log and handle DB error
        import configparser
        import io

        # Use unified logger and log_stream
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            self.order.repository.hkparameter_get = MagicMock(
                side_effect=OrderDatabaseError("fail")
            )
            self.order._set_profiles_from_db = MagicMock()
            config_dic = configparser.ConfigParser()
            config_dic.add_section("CAhandler")
            config_dic.set("CAhandler", "profiles_sync", "True")
            self.order._load_profiles_from_db_if_sync(config_dic)
            self.order._set_profiles_from_db.assert_not_called()
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn(
            "CRITICAL:Database error: failed to get profile list: fail", log_contents
        )

    def test_076_set_profiles_from_db_valid_json(self):
        # Should set profiles from valid JSON string
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            order._set_profiles_from_db('{"profiles": {"foo": {}}}')
            self.assertEqual(order.config.profiles, {"foo": {}})

    def test_077_set_profiles_from_db_invalid_json(self):
        # Should log error on invalid JSON
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            with patch.object(order.logger, "error") as mock_log:
                order._set_profiles_from_db("notjson")
                mock_log.assert_called()

    def test_078_maybe_disable_profile_check_true(self):
        # Should set profiles_check_disable to True if config says so
        import configparser

        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            order.config.profiles = {"foo": {}}
            config_dic = configparser.ConfigParser()
            config_dic.add_section("Order")
            config_dic.set("Order", "profiles_check_disable", "True")
            order._maybe_disable_profile_check(config_dic)
            self.assertTrue(order.config.profiles_check_disable)

    def test_079_maybe_disable_profile_check_false(self):
        # Should set profiles_check_disable to False if config says so
        import configparser

        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            order.config.profiles = {"foo": {}}
            config_dic = configparser.ConfigParser()
            config_dic.add_section("Order")
            config_dic.set("Order", "profiles_check_disable", "False")
            order._maybe_disable_profile_check(config_dic)
            self.assertFalse(order.config.profiles_check_disable)

    def test_080_maybe_disable_profile_check_no_profiles(self):
        # Should not change profiles_check_disable if no profiles
        import configparser

        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            order.config.profiles = {}
            config_dic = configparser.ConfigParser()
            config_dic.add_section("Order")
            config_dic.set("Order", "profiles_check_disable", "True")
            order.config.profiles_check_disable = False
            order._maybe_disable_profile_check(config_dic)
            self.assertFalse(order.config.profiles_check_disable)

    def test_080_load_configuration_all_paths(self):
        # Test _load_configuration with all config sections, log validation, and error handling
        # Use unified logger and log_stream
        import configparser

        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ), patch(
            "acme_srv.order.load_config"
        ) as mock_load_config:
            config_dic = configparser.ConfigParser()
            config_dic.add_section("Challenge")
            config_dic.set("Challenge", "sectigo_sim", "True")
            config_dic.add_section("Order")
            config_dic.set("Order", "tnauthlist_support", "True")
            config_dic.set("Order", "email_identifier_support", "True")
            config_dic.set("Order", "email_identifier_rewrite", "True")
            config_dic.set("Order", "expiry_check_disable", "True")
            config_dic.set("Order", "idempotent_finalize", "True")
            config_dic.set("Order", "retry_after_timeout", "123")
            config_dic.set("Order", "validity", "456")
            config_dic.set("Order", "identifier_limit", "7")
            config_dic.add_section("Authorization")
            config_dic.set("Authorization", "validity", "789")
            config_dic.add_section("Directory")
            config_dic.set("Directory", "url_prefix", "/api")
            mock_load_config.return_value = config_dic
            order = Order(debug=True, server_name="test", logger=self.logger)
            with patch.object(order, "_load_order_config") as m1, patch.object(
                order, "_load_header_info_config"
            ) as m2, patch.object(order, "_load_profile_config") as m3:
                order._load_configuration()
                m1.assert_called_once()
                m2.assert_called_once()
                m3.assert_called_once()
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn("DEBUG:Order._load_configuration()", log_contents)
        self.assertIn("DEBUG:Order._config_load() ended.", log_contents)

    def test_081_load_configuration_authz_validity_error(self):
        # Test _load_configuration with invalid Authorization validity (should log warning)
        # Use unified logger and log_stream
        import configparser

        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ), patch(
            "acme_srv.order.load_config"
        ) as mock_load_config:
            config_dic = configparser.ConfigParser()
            config_dic.add_section("Authorization")
            config_dic.set("Authorization", "validity", "notint")
            mock_load_config.return_value = config_dic
            order = Order(debug=True, server_name="test", logger=self.logger)
            with patch.object(order, "_load_order_config"), patch.object(
                order, "_load_header_info_config"
            ), patch.object(order, "_load_profile_config"):
                order._load_configuration()
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn(
            "WARNING:Failed to parse authz validity from configuration: notint",
            log_contents,
        )

    def test_082_load_configuration_without_ordersection(self):
        # Test _load_configuration without oder section in config (should use defaults and log warnings for missing options)
        import configparser

        with patch("acme_srv.order.load_config") as mock_load_config:
            config_dic = configparser.ConfigParser()
            config_dic.add_section("CAhandler")
            config_dic.set("CAhandler", "foo", "bar")
            mock_load_config.return_value = config_dic
            self.order._load_configuration()
            # All Order config values should be at their defaults
            self.assertEqual(self.order.config.retry_after, 600)
            self.assertEqual(self.order.config.validity, 86400)
            self.assertEqual(self.order.config.identifier_limit, 20)


    def test_083_name_get_logging(self):
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ), patch(
            "acme_srv.order.parse_url", return_value={"path": "/acme/order/ord123"}
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            result = order._name_get("/acme/order/ord123")
            self.assertEqual(result, "ord123")

    def test_084_name_get_with_slash(self):
        # Should split and return first part if slash in order name
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ), patch(
            "acme_srv.order.parse_url",
            return_value={"path": "/acme/order/ord456/extra"},
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            result = order._name_get("/acme/order/ord456/extra")
            self.assertEqual(result, "ord456")

    def test_085_name_get_logging(self):
        # Should log debug messages using central logger and log_stream
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ), patch(
            "acme_srv.order.parse_url", return_value={"path": "/acme/order/ord789"}
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            order._name_get("/acme/order/ord789")
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn("DEBUG:Order._name_get(/acme/order/ord789)", log_contents)
        self.assertIn("DEBUG:Order._name_get() ended", log_contents)

    def test_086_are_identifiers_allowed_valid(self):
        # Should return None for valid identifiers
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ), patch(
            "acme_srv.order.validate_identifier", return_value=True
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            result = order.are_identifiers_allowed(
                [{"type": "dns", "value": "foo.com"}]
            )
            self.assertEqual(result, (None, None))

    def test_087_are_identifiers_allowed_invalid_type(self):
        # Should return unsupportedidentifier for unknown type
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ), patch(
            "acme_srv.order.validate_identifier", return_value=True
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            result = order.are_identifiers_allowed([{"type": "foo", "value": "bar"}])
            self.assertEqual(
                result,
                (
                    order.error_msg_dic["unsupportedidentifier"],
                    "identifier type foo not supported",
                ),
            )

    def test_088_are_identifiers_allowed_invalid_value(self):
        # Should return rejectedidentifier if validate_identifier returns False
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ), patch(
            "acme_srv.order.validate_identifier", return_value=False
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            result = order.are_identifiers_allowed(
                [{"type": "dns", "value": "foo.com"}]
            )
            self.assertEqual(
                result,
                (
                    order.error_msg_dic["rejectedidentifier"],
                    "identifier value foo.com not allowed",
                ),
            )

    def test_089_are_identifiers_allowed_missing_type(self):
        # Should return malformed if type is missing
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            result = order.are_identifiers_allowed([{"value": "foo.com"}])
            self.assertEqual(
                result, (order.error_msg_dic["malformed"], "identifier type is missing")
            )

    def test_090_are_identifiers_allowed_tnauthlist_and_email(self):
        # Should allow tnauthlist and email if config enabled
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ), patch(
            "acme_srv.order.validate_identifier", return_value=True
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            order.config.tnauthlist_support = True
            order.config.email_identifier_support = True
            result = order.are_identifiers_allowed(
                [
                    {"type": "tnauthlist", "value": "foo"},
                    {"type": "email", "value": "bar"},
                ]
            )
            self.assertEqual(result, (None, None))

    def test_091_rewrite_email_identifiers_basic(self):
        # Should rewrite DNS with @ to email
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            order.config.email_identifier_support = True
            order.config.email_identifier_rewrite = True
            input_list = [{"type": "dns", "value": "foo@bar.com"}]
            result = order._rewrite_email_identifiers(input_list)
            self.assertEqual(result[0]["type"], "email")
            self.assertEqual(
                result[0]["value"], "foo@bar.com"
            )  # Additional assertion to differentiate

    def test_090_rewrite_email_identifiers_disabled(self):
        # Should rewrite DNS with @ to email
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            order.config.email_identifier_support = True
            order.config.email_identifier_rewrite = False
            input_list = [{"type": "dns", "value": "foo@bar.com"}]
            result = order._rewrite_email_identifiers(input_list)
            self.assertEqual(result[0]["type"], "dns")
            self.assertEqual(
                result[0]["value"], "foo@bar.com"
            )  # Additional assertion to differentiate

    def test_092_rewrite_email_identifiers_no_rewrite(self):
        # Should not rewrite if no @ in value
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            input_list = [{"type": "dns", "value": "foobar.com"}]
            result = order._rewrite_email_identifiers(input_list)
            self.assertEqual(result[0]["type"], "dns")
            self.assertEqual(
                result[0]["value"], "foobar.com"
            )  # Additional assertion to differentiate

    def test_093_rewrite_email_identifiers_other_types(self):
        # Should not rewrite if type is not dns
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            input_list = [{"type": "email", "value": "foo@bar.com"}]
            result = order._rewrite_email_identifiers(input_list)
            self.assertEqual(result[0]["type"], "email")
            self.assertEqual(
                result[0]["value"], "foo@bar.com"
            )  # Additional assertion to differentiate

    def test_094_rewrite_email_identifiers_logging(self):
        # Should log info and debug messages using the unified logger
        self.log_stream.truncate(0)
        self.log_stream.seek(0)
        self.logger.setLevel(logging.DEBUG)
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            order.config.email_identifier_support = True
            order.config.email_identifier_rewrite = True
            input_list = [{"type": "dns", "value": "foo@bar.com"}]
            order._rewrite_email_identifiers(input_list)
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn("INFO:Rewrite DNS identifier", log_contents)
        self.assertIn("DEBUG:Order._rewrite_email_identifiers()", log_contents)
        self.assertIn("DEBUG:Order._rewrite_email_identifiers() ended", log_contents)

    def test_095_name_get_basic(self):
        # Should log debug messages using central logger and log_stream
        self.log_stream.truncate(0)
        self.log_stream.seek(0)
        self.logger.setLevel(logging.DEBUG)
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ), patch(
            "acme_srv.order.parse_url", return_value={"path": "/acme/order/ord123"}
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            order._name_get("/acme/order/ord123")
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn("DEBUG:Order._name_get(/acme/order/ord123)", log_contents)
        self.assertIn("DEBUG:Order._name_get() ended", log_contents)

    def test_096_process_csr_all_paths(self):
        # Covers: found, not found, error, logging
        self.log_stream.truncate(0)
        self.log_stream.seek(0)
        self.logger.setLevel(logging.DEBUG)
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ), patch(
            "acme_srv.helper.b64_url_recode", return_value="csrval"
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            # Found path
            order._get_order_info = MagicMock(return_value={"name": "order1"})
            cert_mock = MagicMock()
            cert_mock.store_csr.return_value = "cert1"
            cert_mock.enroll_and_store.return_value = (None, None)
            with patch("acme_srv.order.Certificate") as cert_class:
                cert_class.return_value.__enter__.return_value = cert_mock
                result = order._process_csr("order1", "csr", "header")
                self.assertEqual(result[0], 200)
            # Not found path
            order._get_order_info = MagicMock(return_value=None)
            result = order._process_csr("order1", "csr", "header")
            self.assertEqual(result[0], 400)
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn("DEBUG:Order._process_csr(", log_contents)
        self.assertIn("Order._process_csr() ended with order:", log_contents)

    def test_097_process_csr_rejected_identifier(self):
        # Covers: enroll_and_store returns rejectedIdentifier leading to 401
        self.log_stream.truncate(0)
        self.log_stream.seek(0)
        self.logger.setLevel(logging.DEBUG)
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ), patch(
            "acme_srv.helper.b64_url_recode", return_value="csrval"
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            order._get_order_info = MagicMock(return_value={"name": "order1"})
            cert_mock = MagicMock()
            cert_mock.store_csr.return_value = "cert1"
            rej = "urn:ietf:params:acme:error:rejectedIdentifier"
            cert_mock.enroll_and_store.return_value = (rej, "detailx")
            with patch("acme_srv.order.Certificate") as cert_class:
                cert_class.return_value.__enter__.return_value = cert_mock
                result = order._process_csr("order1", "csr", "header")
                self.assertEqual(result, (401, rej, "detailx"))
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn("DEBUG:Order._process_csr(", log_contents)
        self.assertIn("Order._process_csr() ended with order:", log_contents)

    def test_098_process_csr_serverinternal_error(self):
        # Covers: enroll_and_store returns serverinternal leading to 500
        self.log_stream.truncate(0)
        self.log_stream.seek(0)
        self.logger.setLevel(logging.DEBUG)
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ), patch(
            "acme_srv.helper.b64_url_recode", return_value="csrval"
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            order._get_order_info = MagicMock(return_value={"name": "order1"})
            cert_mock = MagicMock()
            cert_mock.store_csr.return_value = "cert1"
            cert_mock.enroll_and_store.return_value = (
                order.error_msg_dic["serverinternal"],
                "d",
            )
            with patch("acme_srv.order.Certificate") as cert_class:
                cert_class.return_value.__enter__.return_value = cert_mock
                result = order._process_csr("order1", "csr", "header")
                self.assertEqual(result[0], 500)
                self.assertEqual(result[1], order.error_msg_dic["serverinternal"])
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn("DEBUG:Order._process_csr(", log_contents)
        self.assertIn("Order._process_csr() ended with order:", log_contents)

    def test_099_process_csr_certificate_store_failure(self):
        # Covers: store_csr returns falsy leading to 500 and CSR processing failed detail
        self.log_stream.truncate(0)
        self.log_stream.seek(0)
        self.logger.setLevel(logging.DEBUG)
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ), patch(
            "acme_srv.helper.b64_url_recode", return_value="csrval"
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            order._get_order_info = MagicMock(return_value={"name": "order1"})
            cert_mock = MagicMock()
            cert_mock.store_csr.return_value = None
            with patch("acme_srv.order.Certificate") as cert_class:
                cert_class.return_value.__enter__.return_value = cert_mock
                result = order._process_csr("order1", "csr", "header")
                self.assertEqual(result[0], 500)
                self.assertEqual(result[1], order.error_msg_dic["serverinternal"])
                self.assertEqual(result[2], "CSR processing failed")
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn("DEBUG:Order._process_csr(", log_contents)
        self.assertIn("Order._process_csr() ended with order:", log_contents)

    def test_100_finalize_order_all_paths(self):
        # Covers: ready, valid/idempotent, not ready, logging
        self.log_stream.truncate(0)
        self.log_stream.seek(0)
        self.logger.setLevel(logging.DEBUG)
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            # Ready path
            order._get_order_info = MagicMock(return_value={"status": "ready"})
            order.repository.order_update = MagicMock()
            order._finalize_csr = MagicMock(return_value=(200, "msg", None, "cert"))
            result = order._finalize_order("order1", {"csr": "csrval"})
            self.assertEqual(result[0], 200)
            # Valid/idempotent path
            order._get_order_info = MagicMock(return_value={"status": "valid"})
            order.config.idempotent_finalize = True
            order.repository.certificate_lookup = MagicMock(
                return_value={"name": "cert1"}
            )
            result = order._finalize_order("order1", {"csr": "csrval"})
            self.assertEqual(result[0], 200)
            # Not ready path
            order._get_order_info = MagicMock(return_value={"status": "pending"})
            result = order._finalize_order("order1", {"csr": "csrval"})
            self.assertEqual(result[0], 403)
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn("DEBUG:Order._finalize_order()", log_contents)
        self.assertIn("DEBUG:Order._finalize_order() ended", log_contents)

    def test_101_finalize_csr_updates_status_when_no_detail(self):
        # When code==200 and no detail, order_status should update to valid
        self.log_stream.truncate(0)
        self.log_stream.seek(0)
        self.logger.setLevel(logging.DEBUG)
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            order.repository.order_update = MagicMock()
            order._header_info_lookup = MagicMock(return_value={})
            order._process_csr = MagicMock(return_value=(200, "cert1", None))
            result = order._finalize_csr("order1", {"csr": "csrval"})
            self.assertEqual(result, (200, None, None, "cert1"))
            order.repository.order_update.assert_called_once_with(
                {"name": "order1", "status": "valid"}
            )
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn("DEBUG:Order._finalize_csr(order1)", log_contents)
        self.assertIn("DEBUG:Order._finalize_csr() ended", log_contents)

    def test_102_finalize_csr_handles_timeout(self):
        # When certificate_name=='timeout', code is set to 200 and message=timeout
        self.log_stream.truncate(0)
        self.log_stream.seek(0)
        self.logger.setLevel(logging.DEBUG)
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            order.repository.order_update = MagicMock()
            order._header_info_lookup = MagicMock(return_value={})
            order._process_csr = MagicMock(return_value=(400, "timeout", "pollid"))
            result = order._finalize_csr("order1", {"csr": "csrval"})
            self.assertEqual(result, (200, "timeout", "pollid", "timeout"))
            order.repository.order_update.assert_not_called()
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn("DEBUG:Order._finalize_csr(order1)", log_contents)
        self.assertIn("DEBUG:Order._finalize_csr() ended", log_contents)

    def test_103_finalize_csr_handles_rejected_identifier(self):
        # When certificate_name=='urn:ietf:params:acme:error:rejectedIdentifier', code=401 and message set
        self.log_stream.truncate(0)
        self.log_stream.seek(0)
        self.logger.setLevel(logging.DEBUG)
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            order.repository.order_update = MagicMock()
            order._header_info_lookup = MagicMock(return_value={})
            rej = "urn:ietf:params:acme:error:rejectedIdentifier"
            order._process_csr = MagicMock(return_value=(400, rej, "detailx"))
            result = order._finalize_csr("order1", {"csr": "csrval"})
            self.assertEqual(result, (401, rej, "detailx", rej))
            order.repository.order_update.assert_not_called()
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn("DEBUG:Order._finalize_csr(order1)", log_contents)
        self.assertIn("DEBUG:Order._finalize_csr() ended", log_contents)

    def test_104_finalize_csr_enrollment_failed_else_branch(self):
        # Else branch: message set to certificate_name and detail='enrollment failed'
        self.log_stream.truncate(0)
        self.log_stream.seek(0)
        self.logger.setLevel(logging.DEBUG)
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            order.repository.order_update = MagicMock()
            order._header_info_lookup = MagicMock(return_value={})
            order._process_csr = MagicMock(return_value=(400, "error", "d"))
            result = order._finalize_csr("order1", {"csr": "csrval"})
            self.assertEqual(result, (400, "error", "enrollment failed", "error"))
            order.repository.order_update.assert_not_called()
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn("DEBUG:Order._finalize_csr(order1)", log_contents)
        self.assertIn("DEBUG:Order._finalize_csr() ended", log_contents)

    def test_105_order_dic_create_all_paths(self):
        # Covers: all fields, parse error, logging
        self.log_stream.truncate(0)
        self.log_stream.seek(0)
        self.logger.setLevel(logging.DEBUG)
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ), patch(
            "acme_srv.order.uts_to_date_utc", return_value="2026-01-01T00:00:00Z"
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            tmp_dic = {
                "status": "pending",
                "expires": 1234567890,
                "notbefore": 1234567890,
                "notafter": 1234567890,
                "identifiers": '[{"type": "dns", "value": "foo.com"}]',
            }
            result = order._order_dic_create(tmp_dic)
            self.assertEqual(result["status"], "pending")
            self.assertEqual(result["expires"], "2026-01-01T00:00:00Z")
            self.assertEqual(result["notBefore"], "2026-01-01T00:00:00Z")
            self.assertEqual(result["notAfter"], "2026-01-01T00:00:00Z")
            self.assertIsInstance(result["identifiers"], list)
            # Parse error path
            tmp_dic["identifiers"] = "notjson"
            result = order._order_dic_create(tmp_dic)
            self.assertNotIn("identifiers", result)
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn("DEBUG:Order._order_dic_create()", log_contents)
        self.assertIn("DEBUG:Order._order_dic_create() ended", log_contents)
        self.assertIn("Error while parsing the identifier", log_contents)

    def test_106_get_authorization_list_all_paths(self):
        self.order.repository.authorization_lookup.return_value = [
            {"name": "auth1", "status__name": "valid"}
        ]
        self.assertEqual(
            self.order._get_authorization_list("order1"),
            [{"name": "auth1", "status__name": "valid"}],
        )

    def test_107_get_authorization_list_all_paths(self):
        # DB error path
        self.log_stream.truncate(0)
        self.log_stream.seek(0)
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository"
        ) as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo.authorization_lookup.side_effect = OrderDatabaseError("fail")
            mock_repo_class.return_value = mock_repo
            order = Order(debug=True, server_name="test", logger=self.logger)
            result = order._get_authorization_list("order1")
            self.assertEqual(result, [])
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn("DEBUG:Order._get_authorization_list(", log_contents)
        self.assertIn("DEBUG:Order._get_authorization_list() ended", log_contents)
        self.assertIn(
            "CRITICAL:Database error: failed to look up authorization list:",
            log_contents,
        )

    def test_108_update_validity_list_all_paths(self):
        # Covers: all code paths, logging
        self.log_stream.truncate(0)
        self.log_stream.seek(0)
        self.logger.setLevel(logging.DEBUG)
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            # All valid
            authz_list = [{"name": "a", "status__name": "valid"}]
            order_dic = {"status": "pending", "authorizations": []}
            order._update_validity_list(authz_list, order_dic, "order1")
            # Some invalid
            authz_list = [{"name": "a", "status__name": "invalid"}]
            order_dic = {"status": "pending", "authorizations": []}
            order._update_validity_list(authz_list, order_dic, "order1")
            # No validities
            authz_list = []
            order_dic = {"status": "pending", "authorizations": []}
            order._update_validity_list(authz_list, order_dic, "order1")
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn("DEBUG:Order._update_validity_list()", log_contents)
        self.assertIn("Order.get_order_details() ended", log_contents)

    def test_109_get_order_details_all_paths(self):
        # Covers: found, not found, logging
        self.log_stream.truncate(0)
        self.log_stream.seek(0)
        self.logger.setLevel(logging.DEBUG)
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            order._get_order_info = MagicMock(return_value={"status": "pending"})
            result = order.get_order_details("order1")
            self.assertIsInstance(result, dict)
            order._get_order_info = MagicMock(return_value=None)
            result = order.get_order_details("order1")
            self.assertIsInstance(result, dict)
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn("DEBUG:Order.get_order_details(", log_contents)
        self.assertIn("DEBUG:Order.get_order_details() ended", log_contents)

    def test_110_invalidate_expired_orders_all_paths(self):
        # Covers: success, db error, logging
        self.log_stream.truncate(0)
        self.log_stream.seek(0)
        self.logger.setLevel(logging.DEBUG)
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository"
        ) as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo.orders_invalid_search.return_value = [
                {"name": "order1", "status__name": "pending"}
            ]
            mock_repo.order_update = MagicMock()
            mock_repo_class.return_value = mock_repo
            order = Order(debug=True, server_name="test", logger=self.logger)
            result = order.invalidate_expired_orders()
            self.assertIsInstance(result, tuple)

    def test_111_invalidate_expired_orders_all_paths(self):
        # DB error path
        self.log_stream.truncate(0)
        self.log_stream.seek(0)
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository"
        ) as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo.orders_invalid_search.side_effect = OrderDatabaseError("fail")
            mock_repo_class.return_value = mock_repo
            order = Order(debug=True, server_name="test", logger=self.logger)
            result = order.invalidate_expired_orders()
            self.assertIsInstance(result, tuple)
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn("DEBUG:Order.invalidate_expired_orders(", log_contents)
        self.assertIn("DEBUG:Order.invalidate_expired_orders() ended:", log_contents)
        self.assertIn(
            "CRITICAL:Database error: failed to search for expired orders:",
            log_contents,
        )

    def test_111_create_from_content_all_paths(self):
        # Covers: success, error, logging
        self.log_stream.truncate(0)
        self.log_stream.seek(0)
        self.logger.setLevel(logging.DEBUG)
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message") as mock_msg_class, patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            mock_msg = MagicMock()
            mock_msg.check.return_value = (200, "msg", "detail", {}, {}, "acct")
            mock_msg.prepare_response.return_value = {"header": {}, "data": {}}
            mock_msg_class.return_value = mock_msg
            order = Order(debug=True, server_name="test", logger=self.logger)
            order.message = mock_msg
            order.create_order = MagicMock(
                return_value=(None, "detail", "order1", {}, 1234567890)
            )
            result = order.create_from_content("content")
            self.assertIsInstance(result, dict)
            # Error path
            mock_msg.check.return_value = (400, "msg", "detail", {}, {}, "acct")
            result = order.create_from_content("content")
            self.assertIsInstance(result, dict)
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn("DEBUG:Order.create_from_content()", log_contents)

    def test_112_process_order_request_all_paths(self):
        # Covers: finalize, polling, cert found, cert not found, url missing, logging
        self.log_stream.truncate(0)
        self.log_stream.seek(0)
        self.logger.setLevel(logging.DEBUG)
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            order._finalize_order = MagicMock(return_value=(200, "msg", None, "cert"))
            order.repository.certificate_lookup = MagicMock(
                return_value={"name": "cert1"}
            )
            # Finalize path
            result = order._process_order_request(
                "order1", {"url": "finalize"}, {}, None
            )
            self.assertEqual(result[0], 200)
            # Polling path with cert found
            result = order._process_order_request("order1", {"url": "poll"}, {}, None)
            self.assertEqual(result[0], 200)
            # Polling path with cert not found
            order.repository.certificate_lookup = MagicMock(return_value={})
            result = order._process_order_request("order1", {"url": "poll"}, {}, None)
            self.assertEqual(result[0], 200)
            # url missing
            result = order._process_order_request("order1", {}, {}, None)
            self.assertEqual(result[0], 400)
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn("DEBUG:Order._process_order_request(", log_contents)
        self.assertIn(
            "DEBUG:Order._process_order_request() ended with order:", log_contents
        )

    def test_113_check_identifiers_validity_all_paths(self):
        # Covers: valid, too many, malformed, email rewrite, allowed, rejected, and logging
        self.log_stream.truncate(0)
        self.log_stream.seek(0)
        self.logger.setLevel(logging.DEBUG)
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ), patch(
            "acme_srv.order.validate_identifier", return_value=True
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            order.config.identifier_limit = 2
            order.config.email_identifier_support = True
            order.config.email_identifier_rewrite = True
            # Valid identifiers, triggers rewrite
            idents = [{"type": "dns", "value": "foo@bar.com"}]
            result = order._check_identifiers_validity(idents)
            self.assertEqual(result, (None, None))
            # Too many identifiers
            too_many = [{"type": "dns", "value": "a"}] * 3
            result = order._check_identifiers_validity(too_many)
            self.assertEqual(
                result,
                (
                    order.error_msg_dic["rejectedidentifier"],
                    "identifier limit exceeded",
                ),
            )
            # Malformed (not a list)
            result = order._check_identifiers_validity(None)
            self.assertEqual(
                result, (order.error_msg_dic["malformed"], "malformed identifiers list")
            )

    def test_114_check_identifiers_validity_all_paths(self):
        self.log_stream.truncate(0)
        self.log_stream.seek(0)
        self.logger.setLevel(logging.DEBUG)
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ), patch(
            "acme_srv.order.validate_identifier", return_value=False
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            order.config.identifier_limit = 2
            order.config.email_identifier_support = True
            order.config.email_identifier_rewrite = True
            idents = [{"type": "dns", "value": "foo@bar.com"}]
            result = order._check_identifiers_validity(idents)
            self.assertEqual(
                result,
                (
                    order.error_msg_dic["rejectedidentifier"],
                    "identifier value foo@bar.com not allowed",
                ),
            )
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn("DEBUG:Order._check_identifiers_validity(", log_contents)

    def test_115_get_order_info_all_paths(self):
        # Covers: successful lookup, DB error, logging
        self.log_stream.truncate(0)
        self.log_stream.seek(0)
        self.logger.setLevel(logging.DEBUG)
        # Success path
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository"
        ) as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo.order_lookup.return_value = {"name": "order1"}
            mock_repo_class.return_value = mock_repo
            order = Order(debug=True, server_name="test", logger=self.logger)
            result = order._get_order_info("order1")
            self.assertEqual(result, {"name": "order1"})
            self.handler.flush()
            log_contents = self.log_stream.getvalue()
            self.assertIn("DEBUG:Order._get_order_info(", log_contents)

    def test_116_get_order_info_all_paths(self):
        # Clear log buffer before error path
        self.log_stream.truncate(0)
        self.log_stream.seek(0)
        # DB error path
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository"
        ) as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo.order_lookup.side_effect = OrderDatabaseError("fail")
            mock_repo_class.return_value = mock_repo
            order = Order(debug=True, server_name="test", logger=self.logger)
            result = order._get_order_info("order1")
            self.assertIsNone(result)
            self.handler.flush()
            log_contents = self.log_stream.getvalue()
            self.assertIn("DEBUG:Order._get_order_info(", log_contents)
            self.assertIn(
                "CRITICAL:Database error: failed to look up order:", log_contents
            )

    def test_117_header_info_lookup_all_paths(self):
        # Covers: header present, header missing, header_info_list missing, logging
        # Use central logger and log_stream from setUp
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            order.config.header_info_list = ["X-Test", "X-Other"]
            # Header with matching keys
            header = {"X-Test": "foo", "X-Other": "bar", "X-Irrelevant": "baz"}
            result = order._header_info_lookup(header)
            self.assertEqual(json.loads(result), {"X-Test": "foo", "X-Other": "bar"})
            # Header with no matching keys
            header = {"X-Irrelevant": "baz"}
            result = order._header_info_lookup(header)
            self.assertIsNone(result)
            # No header_info_list
            order.config.header_info_list = None
            result = order._header_info_lookup({"X-Test": "foo"})
            self.assertIsNone(result)
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn("DEBUG:Order._header_info_lookup()", log_contents)
        self.assertIn("DEBUG:Order._header_info_lookup() ended with:", log_contents)

    def test_118_enter_loads_configuration_and_returns_self(self):
        # Covers __enter__: should call _load_configuration and return self
        with patch.object(self.order, "_load_configuration") as mock_load_config:
            result = self.order.__enter__()
            mock_load_config.assert_called_once()
            self.assertIs(result, self.order)

    def test_119_parse_order_content_adds_certificate(self):
        # Covers lines 976-978: certificate_name and status valid adds certificate path
        with patch.object(
            self.order.message,
            "check",
            return_value=(200, None, None, {"url": "url"}, {}, "account"),
        ):
            with patch.object(
                self.order,
                "_parse_order_message",
                return_value=(200, None, None, "cert123", "order1"),
            ):
                with patch.object(
                    self.order, "get_order_details", return_value={"status": "valid"}
                ):
                    with patch.object(
                        self.order.message,
                        "prepare_response",
                        side_effect=lambda resp, stat: resp,
                    ):
                        self.order.path_dic["cert_path"] = "/acme/cert/"
                        self.order.server_name = "https://example.com"
                        result = self.order.parse_order_content("content")
                        self.assertIn("certificate", result["data"])
                        self.assertEqual(
                            result["data"]["certificate"],
                            "https://example.com/acme/cert/cert123",
                        )

    def test_120_invalidate_expired_orders_update_error_logging(self):
        # Covers lines 831-840: order_update raises OrderDatabaseError and logs CRITICAL
        # Use central logger and log_stream from setUp
        self.order.logger = self.logger
        # Mock repository methods
        self.order.repository.orders_invalid_search = MagicMock(
            return_value=[{"name": "order1", "status__name": "pending"}]
        )
        self.order.repository.order_update = MagicMock(
            side_effect=OrderDatabaseError("fail")
        )
        # Run
        self.order.invalidate_expired_orders(1234567890)
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn(
            "CRITICAL:Database error: failed to update order status to invalid: fail",
            log_contents,
        )

    def test_121_process_csr_generic_error(self):
        # Covers lines 681-684: error is not rejectedIdentifier or serverinternal
        with patch.object(
            self.order, "_get_order_info", return_value={"name": "order1"}
        ):
            cert_mock = MagicMock()
            cert_mock.store_csr.return_value = "cert1"
            cert_mock.enroll_and_store.return_value = ("someerror", "detail")
            with patch("acme_srv.order.Certificate") as cert_class:
                cert_class.return_value.__enter__.return_value = cert_mock
                result = self.order._process_csr("order1", "csr", "header")
                self.assertEqual(result[0], 400)
                self.assertEqual(result[1], "someerror")

    def test_122_process_csr_serverinternal_error(self):
        # Covers lines 684-689: error == serverinternal triggers code=500
        with patch.object(
            self.order, "_get_order_info", return_value={"name": "order1"}
        ):
            cert_mock = MagicMock()
            cert_mock.store_csr.return_value = "cert1"
            cert_mock.enroll_and_store.return_value = (
                "urn:ietf:params:acme:error:serverInternal",
                "detail",
            )
            with patch("acme_srv.order.Certificate") as cert_class:
                cert_class.return_value.__enter__.return_value = cert_mock
                result = self.order._process_csr("order1", "csr", "header")
                self.assertEqual(result[0], 500)
                self.assertEqual(result[1], "urn:ietf:params:acme:error:serverInternal")

    def test_123_process_order_request_db_error_logging(self):
        # Covers: OrderDatabaseError in certificate_lookup and CRITICAL log
        self.log_stream.truncate(0)
        self.log_stream.seek(0)
        self.logger.setLevel(logging.DEBUG)
        mock_dbstore = MagicMock()
        mock_message = MagicMock()
        with patch("acme_srv.db_handler.DBstore", return_value=mock_dbstore), patch(
            "acme_srv.message.Message", return_value=mock_message
        ), patch("acme_srv.order.OrderRepository") as mock_repo_class:
            mock_repo = MagicMock()
            mock_repo.certificate_lookup.side_effect = OrderDatabaseError("fail")
            mock_repo_class.return_value = mock_repo
            order = Order(debug=True, server_name="test", logger=self.logger)
            # Should hit the exception path and log CRITICAL
            result = order._process_order_request("order1", {"url": "poll"}, {}, None)
            self.assertEqual(result[0], 200)
            self.assertIsNone(result[3])  # certificate_name should be None
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn(
            "CRITICAL:Database error: Certificate lookup failed: fail", log_contents
        )

    def test_124_process_order_request_no_url(self):
        # Covers lines 634-638: protected dict missing 'url' and checks log
        with patch.object(self.order.logger, "debug") as mock_debug:
            result = self.order._process_order_request("ordername", {}, {}, None)
            self.assertEqual(result[0], 400)
            self.assertEqual(result[1], "urn:ietf:params:acme:error:malformed")
            self.assertEqual(result[2], "url is missing in protected")
            self.assertIsNone(result[3])
            mock_debug.assert_any_call(
                "Order._process_order_request() ended with order:%s %s:%s:%s",
                "ordername",
                400,
                "urn:ietf:params:acme:error:malformed",
                "url is missing in protected",
            )

    def test_125_finalize_order_valid_OrderDatabaseError(self):
        # Covers lines 593-597: status not ready
        self.mock_repo.order_lookup.return_value = {"status": "valid"}
        self.order.config.idempotent_finalize = True
        self.order.repository.certificate_lookup.side_effect = OrderDatabaseError(
            "db error"
        )
        result = self.order._finalize_order("ordername", {}, None)
        self.assertEqual(result[0], 200)
        self.assertIsNone(result[1])
        self.assertIsNone(result[2])
        self.assertIsNone(result[3])
        # Extract critical log messages from the log stream
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertIn(
            "CRITICAL:Database error: Certificate lookup failed: db error", log_contents
        )

    def test_126_finalize_order_ready_nocsr(self):
        # Covers lines 593-597: status not ready
        self.mock_repo.order_lookup.return_value = {"status": "ready"}
        result = self.order._finalize_order("ordername", {}, None)
        self.assertEqual(result[0], 400)
        self.assertEqual(result[1], "urn:ietf:params:acme:error:badCSR")
        self.assertEqual(result[2], "csr is missing in payload")
        self.assertIsNone(result[3])

    def test_127_finalize_csr_timeout(self):
        # Patch _process_csr to return (200, 'timeout', 'not_none') so the elif branch is taken
        with patch.object(
            self.order, "_process_csr", return_value=(400, "timeout", "not_none")
        ):
            result = self.order._finalize_csr(
                "ordername", {"csr": "csrdata"}, header=None
            )
            self.assertEqual(result[0], 200)
            self.assertEqual(result[1], "timeout")
            self.assertEqual(result[2], "not_none")
            self.assertEqual(result[3], "timeout")

    def test_128_from_content_rejectedidentifier_with_detail(self):
        # Ensure the 'rejectedidentifier' error branch is covered
        rejected = self.order.error_msg_dic["rejectedidentifier"]
        with patch.object(
            self.order.message,
            "check",
            return_value=(
                200,
                None,
                None,
                None,
                {"identifiers": [{"type": "dns", "value": "a"}]},
                "account",
            ),
        ):
            with patch.object(
                self.order,
                "create_order",
                return_value=(rejected, "detail", "order", {}, "2026-01-01T00:00:00Z"),
            ):
                with patch.object(
                    self.order.message,
                    "prepare_response",
                    side_effect=lambda resp, stat: {**resp, **stat},
                ):
                    result = self.order.create_from_content("content")
                    self.assertEqual(result["code"], 403)
                    self.assertEqual(result["type"], rejected)
                    self.assertEqual(result["detail"], "detail")

    def test_129_from_content_rejectedidentifier_without_detail(self):
        # Ensure the 'rejectedidentifier' error branch is covered
        rejected = self.order.error_msg_dic["rejectedidentifier"]
        with patch.object(
            self.order.message,
            "check",
            return_value=(
                200,
                None,
                None,
                None,
                {"identifiers": [{"type": "dns", "value": "a"}]},
                "account",
            ),
        ):
            with patch.object(
                self.order,
                "create_order",
                return_value=(rejected, None, "order", {}, "2026-01-01T00:00:00Z"),
            ):
                with patch.object(
                    self.order.message,
                    "prepare_response",
                    side_effect=lambda resp, stat: {**resp, **stat},
                ):
                    result = self.order.create_from_content("content")
                    self.assertEqual(result["code"], 403)
                    self.assertEqual(result["type"], rejected)
                    self.assertEqual(
                        result["detail"],
                        "Some of the requested identifiers got rejected",
                    )

    def test_130_apply_eab_profile_eab_profiling_disabled(self):
        self.order.config.eab_profiling = False
        with patch.object(self.order, "_apply_eab_profile") as mock_apply_eab:
            payload = {"identifiers": [{"type": "dns", "value": "example.com"}]}
            account_name = "acct"
            with patch.object(
                self.order, "_check_identifiers_validity", return_value=(None, None)
            ), patch.object(
                self.order, "_add_order_and_authorizations", return_value=None
            ):
                self.order.create_order(payload, account_name)
                mock_apply_eab.assert_not_called()

    def test_131_apply_eab_profile_account_lookup_db_error(self):
        self.order.config.eab_profiling = True
        self.order.repository.account_lookup.side_effect = OrderDatabaseError("fail")
        with patch.object(self.order.logger, "critical") as mock_critical:
            self.order._apply_eab_profile("acct")
            mock_critical.assert_called()

    def test_132_apply_eab_profile_no_eab_kid(self):
        self.order.config.eab_profiling = True
        self.order.repository.account_lookup.return_value = {}
        with patch.object(self.order.logger, "debug") as mock_debug:
            self.order._apply_eab_profile("acct")
            mock_debug.assert_any_call(
                "Order._apply_eab_profile() - apply eab profile setting for account %s",
                "acct",
            )

    def test_133_apply_eab_profile_allowed_domainlist_order_section(self):
        self.order.config.eab_profiling = True
        self.order.repository.account_lookup.return_value = {"eab_kid": "kid1"}
        mock_eab_handler = MagicMock()
        profile_dic = {"kid1": {"order": {"allowed_domainlist": ["example.com"]}}}
        mock_eab_handler.__enter__.return_value.key_file_load.return_value = profile_dic
        self.order.config.eab_handler = MagicMock(return_value=mock_eab_handler)
        with patch.object(self.order.logger, "debug") as mock_debug:
            self.order._apply_eab_profile("acct")
            mock_debug.assert_any_call(
                "Order._apply_eab_profile() - apply allowed_domainlist from eab profile."
            )
        self.assertEqual(self.order.config.allowed_domainlist, ["example.com"])

    def test_134_apply_eab_profile_allowed_domainlist_cahandler_section(self):
        self.order.config.eab_profiling = True
        self.order.repository.account_lookup.return_value = {"eab_kid": "kid2"}
        mock_eab_handler = MagicMock()
        profile_dic = {"kid2": {"cahandler": {"allowed_domainlist": ["test.com"]}}}
        mock_eab_handler.__enter__.return_value.key_file_load.return_value = profile_dic
        self.order.config.eab_handler = MagicMock(return_value=mock_eab_handler)
        with patch.object(self.order.logger, "warning") as mock_warning, patch.object(
            self.order.logger, "debug"
        ) as mock_debug:
            self.order._apply_eab_profile("acct")
            mock_warning.assert_called_with(
                "allowed_domainlist parameter found in cahandler section of the eab-profile - this is deprecated, please use the order section"
            )
            mock_debug.assert_any_call(
                "Order._apply_eab_profile() - apply allowed_domainlist from eab profile."
            )
        self.assertEqual(self.order.config.allowed_domainlist, ["test.com"])

    def test_135_apply_eab_profile_generic_exception(self):
        self.order.config.eab_profiling = True
        self.order.repository.account_lookup.return_value = {"eab_kid": "kid3"}
        mock_eab_handler = MagicMock()
        mock_eab_handler.__enter__.return_value.key_file_load.side_effect = Exception(
            "fail"
        )
        self.order.config.eab_handler = MagicMock(return_value=mock_eab_handler)
        with patch.object(self.order.logger, "error") as mock_error:
            self.order._apply_eab_profile("acct")
            mock_error.assert_called()

    def test_136_create_order_eab_profiling_branch(self):
        # Covers: if self.config.eab_profiling and self.config.eab_handler
        self.order.config.eab_profiling = True
        self.order.config.eab_handler = MagicMock()
        with patch.object(self.order, "_apply_eab_profile") as mock_apply_eab:
            payload = {"identifiers": [{"type": "dns", "value": "example.com"}]}
            account_name = "acct"
            with patch.object(
                self.order, "_check_identifiers_validity", return_value=(None, None)
            ), patch.object(
                self.order, "_add_order_and_authorizations", return_value=None
            ):
                self.order.create_order(payload, account_name)
                mock_apply_eab.assert_called_once_with(account_name)

    def test_137_create_order_invalid_profile_detail(self):
        # Covers: if error == self.error_msg_dic["invalidprofile"]: detail = "Invalid profile specified"
        self.order.config.eab_profiling = False
        self.order.config.eab_handler = None
        self.order.config.profiles = {"bar": {}}
        payload = {
            "identifiers": [{"type": "dns", "value": "example.com"}],
            "profile": "foo",
        }
        account_name = "acct"
        with patch.object(
            self.order, "_check_identifiers_validity", return_value=(None, None)
        ), patch.object(
            self.order,
            "add_profile_to_order",
            return_value=(self.order.error_msg_dic["invalidprofile"], {}),
        ), patch.object(
            self.order, "_add_order_and_authorizations", return_value=None
        ):
            error, detail, order_name, auth_dic, expires = self.order.create_order(
                payload, account_name
            )
            self.assertIsNone(error)
            self.assertEqual(detail, "Invalid profile specified")

    def test_138_are_identifiers_allowed_fqdn_not_whitelisted(self):
        # Covers: FQDN/SAN not allowed by configuration (lines 551-566)
        with patch(
            "acme_srv.db_handler.DBstore", return_value=self.mock_dbstore
        ), patch("acme_srv.message.Message", return_value=self.mock_message), patch(
            "acme_srv.order.OrderRepository", return_value=self.mock_repo
        ), patch(
            "acme_srv.order.validate_identifier", return_value=True
        ), patch(
            "acme_srv.order.is_domain_whitelisted", return_value=False
        ):
            order = Order(debug=True, server_name="test", logger=self.logger)
            order.config.allowed_domainlist = ["allowed.com"]
            result = order.are_identifiers_allowed(
                [{"type": "dns", "value": "notallowed.com"}]
            )
            self.assertEqual(
                result,
                (
                    order.error_msg_dic["rejectedidentifier"],
                    "FQDN/SAN notallowed.com not allowed by configuration",
                ),
            )

    def test_139_apply_eab_profile_disabled(self):
        # Covers: logger.critical branch in _apply_eab_profile (line 270)
        self.order.config.eab_profiling = False
        self.order.config.eab_handler = MagicMock()
        with patch.object(
            self.order.repository, "account_lookup"
        ) as mock_account_lookup, patch.object(
            self.order.logger, "critical"
        ) as mock_critical:
            self.assertFalse(self.order._apply_eab_profile("acct"))
            self.assertFalse(mock_account_lookup.called)
            self.assertFalse(mock_critical.called)

    def test_140_check_single_identifier_missing_type(self):
        # Covers error message for missing 'type' (line 556)
        self.log_stream.truncate(0)
        self.log_stream.seek(0)
        self.logger.setLevel(logging.INFO)
        identifier = {"value": "bar"}
        allowed_identifiers = ["dns", "ip"]
        error, detail = self.order._check_single_identifier(
            identifier, allowed_identifiers
        )
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertEqual(error, self.order.error_msg_dic["malformed"])
        self.assertEqual(detail, "identifier type is missing")
        self.assertIn("ERROR:Identifier type is missing\n", log_contents)

    def test_141_check_single_identifier_wrong_type(self):
        # Covers error message for missing 'type' (line 556)
        self.log_stream.truncate(0)
        self.log_stream.seek(0)
        self.logger.setLevel(logging.INFO)
        identifier = {"type": "unknown", "value": "bar"}
        allowed_identifiers = ["dns", "ip"]
        error, detail = self.order._check_single_identifier(
            identifier, allowed_identifiers
        )
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertEqual(error, self.order.error_msg_dic["unsupportedidentifier"])
        self.assertEqual(detail, "identifier type unknown not supported")
        self.assertIn("ERROR:Identifier type unknown not supported\n", log_contents)

    def test_142_check_single_identifier_invalid_value(self):
        # Covers error message for invalid value (line 571)
        self.log_stream.truncate(0)
        self.log_stream.seek(0)
        self.logger.setLevel(logging.INFO)
        identifier = {"type": "dns", "value": "foo"}
        allowed_identifiers = ["dns", "ip"]
        with patch("acme_srv.order.validate_identifier", return_value=False):
            error, detail = self.order._check_single_identifier(
                identifier, allowed_identifiers
            )
        self.handler.flush()
        log_contents = self.log_stream.getvalue()
        self.assertEqual(error, self.order.error_msg_dic["rejectedidentifier"])
        self.assertEqual(detail, "identifier value foo not allowed")
        self.assertIn(
            "ERROR:Identifier value foo not allowed for type dns\n", log_contents
        )
        self.assertIn("ERROR:", log_contents)


if __name__ == "__main__":
    unittest.main()
