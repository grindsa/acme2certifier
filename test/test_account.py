#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for account.py"""

# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212
import unittest
import importlib
import configparser
import sys
from unittest.mock import patch, MagicMock, Mock

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class FakeDBStore(object):
    """face DBStore class needed for mocking"""

    # pylint: disable=W0107, R0903
    pass


class TestAccountRepository(unittest.TestCase):
    """test class for AccountRepository"""

    def setUp(self):
        """setup unittest"""
        models_mock = MagicMock()
        modules = {"acme2certifier.acme_srv.db_handler": models_mock}
        patch.dict("sys.modules", modules).start()
        import logging

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        self.dbstore = MagicMock()
        from acme2certifier.acme_srv.account import AccountRepository

        self.account_repository = AccountRepository(self.dbstore, self.logger)

    def test_001_lookup_account_success(self):
        """test enter"""
        self.account_repository.dbstore.account_lookup.return_value = {
            "account": "account"
        }
        self.assertEqual(
            self.account_repository.lookup_account("field", "value"),
            {"account": "account"},
        )

    def test_002_lookup_account_exception(self):
        """test enter"""
        self.account_repository.dbstore.account_lookup.side_effect = Exception(
            "DB error"
        )
        with self.assertRaises(Exception) as context:
            with self.assertLogs("test_a2c", level="CRITICAL") as log_cm:
                self.account_repository.lookup_account("field", "value")
        self.assertIn(
            "Failed to look up account: DB error",
            str(context.exception),
        )
        self.assertIn(
            "CRITICAL:test_a2c:Database error during account lookup: DB error",
            log_cm.output,
        )

    def test_003_add_account_success(self):
        """test add_account success"""
        self.account_repository.dbstore.account_add.return_value = (
            "test_account",
            True,
        )
        self.assertEqual(
            self.account_repository.add_account({"name": "test_account"}),
            ("test_account", True),
        )

    def test_004_add_account_exception(self):
        """test add_account exception"""
        self.account_repository.dbstore.account_add.side_effect = Exception("DB error")
        with self.assertRaises(Exception) as context:
            with self.assertLogs("test_a2c", level="CRITICAL") as log_cm:
                self.account_repository.add_account({"name": "test_account"})
        self.assertIn("Failed to add account: DB error", str(context.exception))
        self.assertIn(
            "CRITICAL:test_a2c:Database error while adding account: DB error",
            log_cm.output,
        )

    def test_005_update_account_success(self):
        """test update_account success"""
        self.account_repository.dbstore.account_update.return_value = True
        self.assertTrue(
            self.account_repository.update_account({"name": "test_account"})
        )

    def test_006_update_account_exception(self):
        """test update_account exception"""
        self.account_repository.dbstore.account_update.side_effect = Exception(
            "DB error"
        )
        with self.assertRaises(Exception) as context:
            with self.assertLogs("test_a2c", level="CRITICAL") as log_cm:
                self.account_repository.update_account({"name": "test_account"})
        self.assertIn("Failed to update account: DB error", str(context.exception))
        self.assertIn(
            "CRITICAL:test_a2c:Database error while updating account: DB error",
            log_cm.output,
        )

    def test_007_delete_account_success(self):
        """test delete_account success"""
        self.account_repository.dbstore.account_delete.return_value = True
        self.assertTrue(self.account_repository.delete_account("test_account"))

    def test_008_delete_account_exception(self):
        """test delete_account exception"""
        self.account_repository.dbstore.account_delete.side_effect = Exception(
            "DB error"
        )
        with self.assertRaises(Exception) as context:
            with self.assertLogs("test_a2c", level="CRITICAL") as log_cm:
                self.account_repository.delete_account("test_account")
        self.assertIn("Failed to delete account: DB error", str(context.exception))
        self.assertIn(
            "CRITICAL:test_a2c:Database error while deleting account: DB error",
            log_cm.output,
        )

    def test_009_load_jwk_success(self):
        """test load_jwk success"""
        self.account_repository.dbstore.jwk_load.return_value = {"jwk": "value"}
        self.assertEqual(
            self.account_repository.load_jwk("test_account"), {"jwk": "value"}
        )

    def test_010_load_jwk_exception(self):
        """test load_jwk exception"""
        self.account_repository.dbstore.jwk_load.side_effect = Exception("DB error")
        with self.assertRaises(Exception) as context:
            with self.assertLogs("test_a2c", level="CRITICAL") as log_cm:
                self.account_repository.load_jwk("test_account")
        self.assertIn("Failed to load JWK: DB error", str(context.exception))
        self.assertIn(
            "CRITICAL:test_a2c:Database error while loading JWK: DB error",
            log_cm.output,
        )


class TestExternalAccountBinding(unittest.TestCase):
    """test class for ExternalAccountBinding"""

    def setUp(self):
        """setup unittest"""
        models_mock = MagicMock()
        modules = {"acme2certifier.acme_srv.db_handler": models_mock}
        patch.dict("sys.modules", modules).start()
        import logging

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        self.eabhandler = MagicMock()
        from acme2certifier.acme_srv.account import ExternalAccountBinding

        self.eab = ExternalAccountBinding(
            self.logger, self.eabhandler, "http://tester.local"
        )

    def test_001_get_kid_success(self):
        """test get_kid success"""
        # Simulate a valid protected header (base64 encoded JSON)
        import base64

        protected = base64.b64encode(b'{"kid": "test_kid"}').decode()
        self.assertEqual(self.eab.get_kid(protected), "test_kid")

    def test_002_get_kid_invalid(self):
        """test get_kid invalid input"""
        # Simulate invalid base64 or JSON
        with self.assertLogs("test_a2c", level="ERROR") as log_cm:
            self.assertIsNone(self.eab.get_kid("invalid_base64"))
        self.assertIn(
            "ERROR:test_a2c:Failed to decode protected header:", log_cm.output[0]
        )

    def test_003_compare_jwk_success(self):
        """test compare_jwk success"""
        import base64

        protected = {"jwk": {"kty": "oct", "k": "abc"}}
        payload = base64.b64encode(b'{"kty": "oct", "k": "abc"}').decode()
        self.assertTrue(self.eab.compare_jwk(protected, payload))

    def test_004_compare_jwk_mismatch(self):
        """test compare_jwk mismatch"""
        import base64

        protected = {"jwk": {"kty": "oct", "k": "abc"}}
        payload = base64.b64encode(b'{"kty": "oct", "k": "xyz"}').decode()
        self.assertFalse(self.eab.compare_jwk(protected, payload))

    def test_005_compare_jwk_no_jwk(self):
        """test compare_jwk no jwk in protected"""
        self.assertFalse(self.eab.compare_jwk({}, "payload"))

    def test_006_compare_jwk_invalid_payload(self):
        """test compare_jwk with invalid base64 or JSON payload"""
        protected = {"jwk": {"kty": "oct", "k": "abc"}}
        with self.assertLogs("test_a2c", level="ERROR") as log_cm:
            self.assertFalse(self.eab.compare_jwk(protected, "invalid_base64"))
        self.assertIn(
            "ERROR:test_a2c:Failed to decode EAB JWK payload:",
            log_cm.output[0],
        )

    def test_007_compare_jwk_non_json_payload(self):
        """test compare_jwk with base64 payload that is not JSON"""
        import base64

        protected = {"jwk": {"kty": "oct", "k": "abc"}}
        payload = base64.b64encode(b"not json").decode()
        with self.assertLogs("test_a2c", level="ERROR") as log_cm:
            self.assertFalse(self.eab.compare_jwk(protected, payload))
        self.assertIn(
            "ERROR:test_a2c:Failed to decode EAB JWK payload:",
            log_cm.output[0],
        )

    def test_008_compare_jwk_payload_not_object(self):
        """test compare_jwk when decoded payload is JSON but not an object"""
        import base64

        protected = {"jwk": {"kty": "oct", "k": "abc"}}
        payload = base64.b64encode(b'["not", "an", "object"]').decode()
        with self.assertLogs("test_a2c", level="ERROR") as log_cm:
            self.assertFalse(self.eab.compare_jwk(protected, payload))
        self.assertIn(
            "ERROR:test_a2c:EAB JWK payload is not a JSON object",
            log_cm.output,
        )

    def test_009_verify_signature_success(self):
        """test verify_signature success"""
        content = {"foo": "bar"}
        mac_key = "key"
        # Patch Signature.eab_check to return (True, None)
        with patch(
            "acme2certifier.acme_srv.signature.Signature.eab_check",
            return_value=(True, None),
        ):
            result, error = self.eab.verify_signature(content, mac_key)
            self.assertTrue(result)
            self.assertIsNone(error)

    def test_010_verify_signature_failure(self):
        """test verify_signature failure"""
        content = {"foo": "bar"}
        mac_key = "key"
        with patch(
            "acme2certifier.acme_srv.signature.Signature.eab_check",
            return_value=(False, "error"),
        ):
            result, error = self.eab.verify_signature(content, mac_key)
            self.assertFalse(result)
            self.assertEqual(error, "error")

    def test_011_verify_signature_no_content(self):
        """test verify_signature with no content or mac_key"""
        result, error = self.eab.verify_signature(None, None)
        self.assertFalse(result)
        self.assertIsNone(error)

    def test_012_verify_success(self):
        """test verify success"""
        payload = {
            "externalaccountbinding": {"protected": "eyJraWQiOiAidGVzdF9raWQifQ=="}
        }
        self.eabhandler.return_value.__enter__.return_value.mac_key_get.return_value = (
            "key"
        )
        with patch(
            "acme2certifier.acme_srv.signature.Signature.eab_check",
            return_value=(True, None),
        ):
            code, message, detail = self.eab.verify(
                payload, {"unauthorized": "unauthorized"}
            )
            self.assertEqual(code, 200)
            self.assertIsNone(message)
            self.assertIsNone(detail)

    def test_013_verify_signature_error(self):
        """test verify signature error logs ERROR with kid"""
        payload = {
            "externalaccountbinding": {"protected": "eyJraWQiOiAidGVzdF9raWQifQ=="}
        }
        self.eabhandler.return_value.__enter__.return_value.mac_key_get.return_value = (
            "key"
        )
        with patch(
            "acme2certifier.acme_srv.signature.Signature.eab_check",
            return_value=(False, "error"),
        ):
            with self.assertLogs("test_a2c", level="ERROR") as log_cm:
                code, message, detail = self.eab.verify(
                    payload, {"unauthorized": "unauthorized"}
                )
            self.assertEqual(code, 403)
            self.assertEqual(message, "unauthorized")
            self.assertEqual(detail, "EAB signature verification failed")
            self.assertIn(
                "ERROR:test_a2c:EAB signature verification failed kid=test_kid error=error",
                log_cm.output,
            )

    def test_014_verify_no_mac_key(self):
        """test verify no mac_key found logs ERROR with kid"""
        payload = {
            "externalaccountbinding": {"protected": "eyJraWQiOiAidGVzdF9raWQifQ=="}
        }
        self.eabhandler.return_value.__enter__.return_value.mac_key_get.return_value = (
            None
        )
        with self.assertLogs("test_a2c", level="ERROR") as log_cm:
            code, message, detail = self.eab.verify(
                payload, {"unauthorized": "unauthorized"}
            )
        self.assertEqual(code, 403)
        self.assertEqual(message, "unauthorized")
        self.assertEqual(detail, "EAB kid lookup failed")
        self.assertIn(
            "ERROR:test_a2c:EAB kid lookup failed kid=test_kid",
            log_cm.output,
        )

    def test_015_check_success(self):
        """test check success"""
        import base64

        protected = {"jwk": {"kty": "oct", "k": "abc"}}
        payload = {
            "externalaccountbinding": {
                "payload": base64.b64encode(b'{"kty": "oct", "k": "abc"}').decode(),
                "protected": base64.b64encode(b'{"kid": "test_kid"}').decode(),
            }
        }
        self.eabhandler.return_value.__enter__.return_value.mac_key_get.return_value = (
            "key"
        )
        with patch(
            "acme2certifier.acme_srv.signature.Signature.eab_check",
            return_value=(True, None),
        ):
            code, message, detail = self.eab.check(
                protected,
                payload,
                {
                    "unauthorized": "unauthorized",
                    "malformed": "malformed",
                    "externalaccountrequired": "externalaccountrequired",
                },
            )
            self.assertEqual(code, 200)
            self.assertIsNone(message)
            self.assertIsNone(detail)

    def test_016_check_jwk_mismatch(self):
        """test check jwk mismatch logs WARNING"""
        import base64

        protected = {"jwk": {"kty": "oct", "k": "abc"}}
        payload = {
            "externalaccountbinding": {
                "payload": base64.b64encode(b'{"kty": "oct", "k": "xyz"}').decode(),
                "protected": base64.b64encode(b'{"kid": "test_kid"}').decode(),
            }
        }
        with self.assertLogs("test_a2c", level="WARNING") as log_cm:
            code, message, detail = self.eab.check(
                protected,
                payload,
                {
                    "unauthorized": "unauthorized",
                    "malformed": "malformed",
                    "externalaccountrequired": "externalaccountrequired",
                },
            )
        self.assertEqual(code, 403)
        self.assertEqual(message, "malformed")
        self.assertEqual(detail, "Malformed request")
        self.assertIn(
            "WARNING:test_a2c:EAB malformed: outer/inner JWK mismatch",
            log_cm.output,
        )

    def test_017_check_missing_protected(self):
        """test check missing protected in binding logs WARNING"""
        import base64

        protected = {"jwk": {"kty": "oct", "k": "abc"}}
        payload = {
            "externalaccountbinding": {
                "payload": base64.b64encode(b'{"kty": "oct", "k": "abc"}').decode(),
            }
        }
        with self.assertLogs("test_a2c", level="WARNING") as log_cm:
            code, message, detail = self.eab.check(
                protected,
                payload,
                {
                    "unauthorized": "unauthorized",
                    "malformed": "malformed",
                    "externalaccountrequired": "externalaccountrequired",
                },
            )
        self.assertEqual(code, 403)
        self.assertEqual(message, "malformed")
        self.assertEqual(detail, "Malformed request")
        self.assertIn(
            "WARNING:test_a2c:EAB malformed: missing protected header in binding",
            log_cm.output,
        )

    def test_018_check_no_externalaccountbinding(self):
        """test check no externalaccountbinding logs WARNING"""
        protected = {"jwk": {"kty": "oct", "k": "abc"}}
        payload = {}
        with self.assertLogs("test_a2c", level="WARNING") as log_cm:
            code, message, detail = self.eab.check(
                protected,
                payload,
                {
                    "unauthorized": "unauthorized",
                    "malformed": "malformed",
                    "externalaccountrequired": "externalaccountrequired",
                },
            )
        self.assertEqual(code, 403)
        self.assertEqual(message, "externalaccountrequired")
        self.assertEqual(detail, "External account binding required")
        self.assertIn(
            "WARNING:test_a2c:EAB required: externalAccountBinding missing or empty",
            log_cm.output,
        )

    def test_019_verify_no_kid(self):
        """test verify with no kid logs ERROR kid=None"""
        payload = {"externalaccountbinding": {"protected": "invalid_base64"}}
        with self.assertLogs("test_a2c", level="ERROR") as log_cm:
            code, message, detail = self.eab.verify(
                payload, {"unauthorized": "unauthorized"}
            )
        self.assertEqual(code, 403)
        self.assertEqual(message, "unauthorized")
        self.assertEqual(detail, "EAB kid lookup failed")
        self.assertTrue(
            any("EAB kid lookup failed kid=None" in line for line in log_cm.output),
            log_cm.output,
        )


class TestAccount(unittest.TestCase):
    """test class for Account"""

    @patch.dict("os.environ", {"ACME_SRV_CONFIGFILE": "ACME_SRV_CONFIGFILE"})
    def setUp(self):
        """setup unittest"""
        models_mock = MagicMock()
        modules = {"acme2certifier.acme_srv.db_handler": models_mock}
        patch.dict("sys.modules", modules).start()
        import logging

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        from acme2certifier.acme_srv.account import Account
        from acme2certifier.acme_srv.message import Message
        from acme2certifier.acme_srv.signature import Signature

        self.account = Account(False, "http://tester.local", self.logger)
        self.account.repository = MagicMock()
        self.message = Message(False, "http://tester.local", self.logger)
        self.signature = Signature(False, "http://tester.local", self.logger)

    def test_001__enter_(self):
        """test enter"""
        self.account.__enter__()

    def test_002__enter_(self):
        """test enter"""
        self.account.__exit__()

    def test_003_create_account_success(self):
        """test create_account success"""
        content = {"protected": {}, "payload": {}}
        with patch.object(self.account, "message") as mock_message:
            mock_message.check.return_value = (200, None, None, {}, {}, None)
            with patch.object(
                self.account,
                "_create_account",
                return_value=(200, "test_account", None),
            ) as mock_create_account:
                with patch.object(
                    self.account, "_build_response", return_value="build_response"
                ):
                    self.assertEqual(
                        self.account.create_account(content), "build_response"
                    )
                    mock_create_account.assert_called_once()

    def test_004_create_account_msg_check_failure(self):
        """test create_account failure"""
        content = {"protected": {}, "payload": {}}
        with patch.object(self.account, "message") as mock_message:
            mock_message.check.return_value = (400, "error", "detail", {}, {}, None)
            with patch.object(
                self.account,
                "_create_account",
                return_value=(200, "test_account", None),
            ) as mock_create_account:
                with patch.object(
                    self.account, "_build_response", return_value="build_response"
                ):
                    self.assertEqual(
                        self.account.create_account(content), "build_response"
                    )
                    mock_create_account.assert_not_called()

    def test_005_create_account_onlyreturnexisting(self):
        """test create_account onlyreturnexisting branch"""
        content = {"protected": {}, "payload": {"onlyreturnexisting": True}}
        with patch.object(self.account, "message") as mock_message:
            mock_message.check.return_value = (
                200,
                None,
                None,
                {},
                {"onlyreturnexisting": True},
                None,
            )
            with patch.object(
                self.account,
                "_onlyreturnexisting",
                return_value=(200, "test_account", None),
            ) as mock_onlyreturnexisting:
                with patch.object(
                    self.account, "_build_response", return_value="build_response"
                ):
                    self.assertEqual(
                        self.account.create_account(content), "build_response"
                    )
                    mock_onlyreturnexisting.assert_called_once()

    def test_006__validate_contact_missing(self):
        """test _validate_contact missing contact logs WARNING"""
        with self.assertLogs("test_a2c", level="WARNING") as log_cm:
            code, message, detail = self.account._validate_contact([])
        self.assertEqual(code, 400)
        self.assertEqual(message, self.account.err_msg_dic["malformed"])
        self.assertEqual(detail, "Contact information is missing")
        self.assertIn(
            "WARNING:test_a2c:Contact information is missing",
            log_cm.output,
        )

    def test_007__validate_contact_invalid(self):
        """test _validate_contact invalid contact logs WARNING"""
        with patch(
            "acme2certifier.acme_srv.account.validate_email", return_value=False
        ):
            with self.assertLogs("test_a2c", level="WARNING") as log_cm:
                code, message, detail = self.account._validate_contact(
                    ["invalid@contact"]
                )
            self.assertEqual(code, 400)
            self.assertEqual(message, self.account.err_msg_dic["invalidcontact"])
            self.assertEqual(detail, "Invalid contact information")
            self.assertIn(
                "WARNING:test_a2c:Invalid contact information",
                log_cm.output,
            )

    def test_008__validate_contact_valid(self):
        """test _validate_contact valid contact"""
        with patch("acme2certifier.acme_srv.account.validate_email", return_value=True):
            code, message, detail = self.account._validate_contact(["valid@contact"])
            self.assertEqual(code, 200)
            self.assertIsNone(message)

    def test_009__check_tos_agreed(self):
        """test _check_tos agreed"""
        content = {"termsofserviceagreed": True}
        code, message, detail = self.account._check_tos(content)
        self.assertEqual(code, 200)
        self.assertIsNone(message)

    def test_010__check_tos_not_agreed(self):
        """test _check_tos not agreed logs WARNING"""
        content = {"termsofserviceagreed": False}
        with self.assertLogs("test_a2c", level="WARNING") as log_cm:
            code, message, detail = self.account._check_tos(content)
        self.assertEqual(code, 403)
        self.assertEqual(message, self.account.err_msg_dic["useractionrequired"])
        self.assertEqual(detail, "Terms of service must be agreed")
        self.assertIn(
            "WARNING:test_a2c:Terms of service must be agreed",
            log_cm.output,
        )

    def test_011__check_tos_missing(self):
        """test _check_tos missing flag logs WARNING"""
        content = {}
        with self.assertLogs("test_a2c", level="WARNING") as log_cm:
            code, message, detail = self.account._check_tos(content)
        self.assertEqual(code, 403)
        self.assertEqual(message, self.account.err_msg_dic["useractionrequired"])
        self.assertEqual(detail, "termsofserviceagreed flag missing")
        self.assertIn(
            "WARNING:test_a2c:termsofserviceagreed flag missing",
            log_cm.output,
        )

    def test_012__add_account_to_db_success_new(self):
        """test _add_account_to_db success"""
        account_data = MagicMock()
        account_data.name = "test_account"
        account_data.jwk = {}
        account_data.contact = []
        with patch.object(
            self.account.repository, "add_account", return_value=("test_account", True)
        ):
            code, message, detail = self.account._add_account_to_db(account_data)
            self.assertEqual(code, 201)
            self.assertEqual(message, "test_account")

    def test_013__add_account_to_db_success_existing(self):
        """test _add_account_to_db success"""
        account_data = MagicMock()
        account_data.name = "test_account"
        account_data.jwk = {}
        account_data.contact = []
        with patch.object(
            self.account.repository, "add_account", return_value=("test_account", False)
        ):
            code, message, detail = self.account._add_account_to_db(account_data)
            self.assertEqual(code, 200)
            self.assertEqual(message, "test_account")

    def test_014__add_account_to_db_exception(self):
        """test _add_account_to_db exception"""
        account_data = MagicMock()
        account_data.name = "test_account"
        account_data.jwk = {}
        account_data.contact = []
        with patch.object(
            self.account.repository, "add_account", side_effect=Exception("DB error")
        ):
            with self.assertRaises(Exception) as context:
                with self.assertLogs("test_a2c", level="CRITICAL") as log_cm:
                    code, message, detail = self.account._add_account_to_db(
                        account_data
                    )
                    self.assertEqual(code, 500)
                    self.assertEqual(
                        message, self.account.err_msg_dic["serverinternal"]
                    )
                self.assertIn("DB error", str(context.exception))
                self.assertIn("Database error while adding account", log_cm.output[0])

    def test_015__parse_query_valid(self):
        """test _parse_query valid account"""
        with patch.object(
            self.account,
            "_lookup_account_by_name",
            return_value={
                "status": "valid",
                "jwk": "{}",
                "contact": "[]",
                "created_at": "2026-02-08",
            },
        ):
            data = self.account._parse_query("test_account")
            self.assertEqual(data["status"], "valid")

    def test_016__parse_query_invalid(self):
        """test _parse_query invalid account"""
        with patch.object(self.account, "_lookup_account_by_name", return_value=None):
            data = self.account._parse_query("test_account")
            self.assertEqual(data["status"], "invalid")

    def test_017__onlyreturnexisting_acc_lookup_success(self):
        """test _onlyreturnexisting success"""
        protected = {"jwk": {}}
        payload = {"onlyreturnexisting": True}
        with patch.object(
            self.account,
            "_lookup_account_by_field",
            return_value={"name": "test_account"},
        ):
            with patch.object(
                self.account, "_parse_query", return_value={"status": "valid"}
            ):
                code, message, detail = self.account._onlyreturnexisting(
                    protected, payload
                )
                self.assertEqual(code, 200)
                self.assertEqual(message, "test_account")
                self.assertEqual(detail, {"status": "valid"})

    def test_018__onlyreturnexisting_acc_lookup_failed(self):
        """test _onlyreturnexisting miss logs WARNING"""
        protected = {"jwk": {}}
        payload = {"onlyreturnexisting": True}
        with patch.object(self.account, "_lookup_account_by_field", return_value=None):
            with patch.object(
                self.account, "_parse_query", return_value={"status": "valid"}
            ):
                with self.assertLogs("test_a2c", level="WARNING") as log_cm:
                    code, message, detail = self.account._onlyreturnexisting(
                        protected, payload
                    )
                self.assertEqual(code, 400)
                self.assertEqual(
                    message, self.account.err_msg_dic["accountdoesnotexist"]
                )
                self.assertFalse(detail)
                self.assertIn(
                    "WARNING:test_a2c:onlyReturnExisting: account does not exist",
                    log_cm.output,
                )

    def test_019__onlyreturnexisting_no_jwk(self):
        """test _onlyreturnexisting no jwk logs WARNING"""
        protected = {}
        payload = {"onlyreturnexisting": True}
        with self.assertLogs("test_a2c", level="WARNING") as log_cm:
            code, message, detail = self.account._onlyreturnexisting(protected, payload)
        self.assertEqual(code, 400)
        self.assertEqual(message, self.account.err_msg_dic["malformed"])
        self.assertEqual(detail, "jwk structure missing")
        self.assertIn(
            "WARNING:test_a2c:onlyReturnExisting: jwk structure missing",
            log_cm.output,
        )

    def test_020__onlyreturnexisting_false(self):
        """test _onlyreturnexisting onlyreturnexisting false logs WARNING"""
        protected = {"jwk": {}}
        payload = {"onlyreturnexisting": False}
        with self.assertLogs("test_a2c", level="WARNING") as log_cm:
            code, message, detail = self.account._onlyreturnexisting(protected, payload)
        self.assertEqual(code, 400)
        self.assertEqual(message, self.account.err_msg_dic["useractionrequired"])
        self.assertEqual(detail, "onlyReturnExisting must be true")
        self.assertIn(
            "WARNING:test_a2c:onlyReturnExisting must be true",
            log_cm.output,
        )

    def test_021__onlyreturnexisting_missing(self):
        """test _onlyreturnexisting missing flag logs WARNING"""
        protected = {"jwk": {}}
        payload = {}
        with self.assertLogs("test_a2c", level="WARNING") as log_cm:
            code, message, detail = self.account._onlyreturnexisting(protected, payload)
        self.assertEqual(code, 400)
        self.assertEqual(message, self.account.err_msg_dic["malformed"])
        self.assertEqual(detail, "onlyReturnExisting without payload")
        self.assertIn(
            "WARNING:test_a2c:onlyReturnExisting without payload",
            log_cm.output,
        )

    def test_022__handle_deactivation_success(self):
        """test _handle_deactivation success"""
        payload = {"status": "deactivated"}
        account_obj = {
            "status": "valid",
            "jwk": '{"kty": "RSA", "n": "abc", "e": "AQAB"}',
            "contact": '["mailto:test@example.com"]',
            "created_at": "2026-02-08 12:00:00",
        }
        with patch.object(
            self.account, "_lookup_account_by_name", return_value=account_obj
        ):
            with patch.object(
                self.account, "_deactivate_account", return_value=(200, None, None)
            ):
                result = self.account._handle_deactivation("test_account", payload)
                self.assertIn("data", result)
                self.assertEqual(result["code"], 200)
                self.assertEqual(result["data"]["status"], "deactivated")
                self.assertEqual(result["data"]["contact"], ["mailto:test@example.com"])
                self.assertEqual(
                    result["data"]["key"], {"kty": "RSA", "n": "abc", "e": "AQAB"}
                )

    def test_023__handle_deactivation_fail(self):
        """test _handle_deactivation failure"""
        payload = {"status": "deactivated"}
        account_obj = {
            "status": "valid",
            "jwk": "{}",
            "contact": "[]",
            "created_at": "2026-02-08",
        }
        with patch.object(
            self.account, "_lookup_account_by_name", return_value=account_obj
        ):
            with patch.object(
                self.account,
                "_deactivate_account",
                return_value=(400, "deact_message", "deact_detail"),
            ):
                result = self.account._handle_deactivation("test_account", payload)
                self.assertIn("data", result)
                self.assertEqual(result["data"]["status"], 400)
                self.assertEqual(result["data"]["type"], "deact_message")
                self.assertEqual(result["data"]["detail"], "deact_detail")

    def test_024__handle_deactivation_account_not_found(self):
        """test _handle_deactivation when account lookup fails logs WARNING"""
        payload = {"status": "deactivated"}
        with patch.object(self.account, "_lookup_account_by_name", return_value=None):
            with patch.object(self.account, "_deactivate_account") as mock_deactivate:
                with self.assertLogs("test_a2c", level="WARNING") as log_cm:
                    result = self.account._handle_deactivation("test_account", payload)
                mock_deactivate.assert_not_called()
                self.assertEqual(result["data"]["status"], 400)
                self.assertEqual(
                    result["data"]["type"],
                    self.account.err_msg_dic["accountdoesnotexist"],
                )
                self.assertIn(
                    "WARNING:test_a2c:Deactivation failed: account does not exist account=test_account",
                    log_cm.output,
                )

    def test_025__handle_deactivation_status_invalid(self):
        """test _handle_deactivation invalid status logs WARNING"""
        payload = {"status": "active"}
        with self.assertLogs("test_a2c", level="WARNING") as log_cm:
            result = self.account._handle_deactivation("test_account", payload)
        self.assertEqual(result["data"]["status"], 400)
        self.assertEqual(result["data"]["type"], self.account.err_msg_dic["malformed"])
        self.assertEqual(result["data"]["detail"], "Invalid status for deactivation")
        self.assertIn(
            "WARNING:test_a2c:Invalid status for deactivation account=test_account status=active",
            log_cm.output,
        )

    def test_026__deactivate_account_success(self):
        """test _deactivate_account success"""
        with patch.object(self.account.repository, "update_account", return_value=True):
            code, message, detail = self.account._deactivate_account("test_account")
            self.assertEqual(code, 200)

    def test_027__deactivate_account_failure(self):
        """test _deactivate_account failure logs WARNING"""
        with patch.object(
            self.account.repository, "update_account", return_value=False
        ):
            with self.assertLogs("test_a2c", level="WARNING") as log_cm:
                code, message, detail = self.account._deactivate_account("test_account")
            self.assertEqual(code, 400)
            self.assertIn(
                "WARNING:test_a2c:Deactivation failed: account does not exist account=test_account",
                log_cm.output,
            )

    def test_028__deactivate_account_exception(self):
        """test _deactivate_account exception"""
        with patch.object(
            self.account.repository, "update_account", side_effect=Exception("DB error")
        ):
            with self.assertRaises(Exception) as context:
                with self.assertLogs("test_a2c", level="CRITICAL") as log_cm:
                    code, message, detail = self.account._deactivate_account(
                        "test_account"
                    )
                    self.assertEqual(code, 500)
                    self.assertEqual(
                        message, self.account.err_msg_dic["serverinternal"]
                    )
                    self.assertIn("DB error", str(context.exception))
                    self.assertIn(
                        "Database error while deactivating account", log_cm.output[0]
                    )

    def test_029__handle_contact_update_success(self):
        """test _handle_contact_update success"""
        with patch.object(
            self.account, "_update_account_contacts", return_value=(200, None, None)
        ):
            with patch.object(
                self.account,
                "_lookup_account_by_name",
                return_value={
                    "status": "valid",
                    "jwk": "{}",
                    "contact": "[]",
                    "created_at": "2026-02-08",
                },
            ):
                with patch.object(
                    self.account,
                    "_build_account_info",
                    return_value={"status": "valid"},
                ):
                    with patch.object(
                        self.account, "_build_response", return_value={"data": {}}
                    ):
                        result = self.account._handle_contact_update("test_account", {})
                        self.assertIn("data", result)

    def test_030__handle_contact_update_failure(self):
        """test _handle_contact_update failure"""
        with patch.object(
            self.account,
            "_update_account_contacts",
            return_value=(400, "error", "detail"),
        ):
            with patch.object(
                self.account, "_build_response", return_value={"data": {}}
            ):
                result = self.account._handle_contact_update("test_account", {})
                self.assertIn("data", result)

    def test_031__update_account_contacts_validation_failes(self):
        """test _update_account_contacts does not call update_account if validation fails"""
        with patch.object(self.account.repository, "update_account") as mock_update:
            with patch.object(
                self.account, "_validate_contact", return_value=(400, "foo", "bar")
            ):
                code, message, detail = self.account._update_account_contacts(
                    "test_account", {"contact": []}
                )
                self.assertEqual(code, 400)
                self.assertEqual(message, "foo")
                self.assertEqual(detail, "bar")
                mock_update.assert_not_called()

    def test_032__update_account_contacts_success(self):
        """test _update_account_contacts success"""
        self.account.repository.update_account.return_value = True
        with patch.object(
            self.account, "_validate_contact", return_value=(200, None, None)
        ):
            code, message, detail = self.account._update_account_contacts(
                "test_account", {"contact": []}
            )
            self.assertEqual(code, 200)

    def test_033__update_account_contacts_failure(self):
        """test _update_account_contacts failure logs WARNING with account="""
        self.account.repository.update_account.return_value = False
        with patch.object(
            self.account, "_validate_contact", return_value=(200, None, None)
        ):
            with self.assertLogs("test_a2c", level="WARNING") as log_cm:
                code, message, detail = self.account._update_account_contacts(
                    "test_account", {"contact": []}
                )
            self.assertEqual(code, 400)
            self.assertIn(
                "WARNING:test_a2c:Account does not exist for contact update account=test_account",
                log_cm.output,
            )

    def test_034__update_account_contacts_exception(self):
        """test _update_account_contacts exception"""
        self.account.repository.update_account.side_effect = Exception("DB error")
        with patch.object(
            self.account, "_validate_contact", return_value=(200, None, None)
        ):
            with self.assertLogs("test_a2c", level="CRITICAL") as log_cm:
                code, message, detail = self.account._update_account_contacts(
                    "test_account", {"contact": []}
                )
                self.assertEqual(code, 500)
                self.assertEqual(message, self.account.err_msg_dic["serverinternal"])
                self.assertIn(
                    "Database error while updating account contacts", log_cm.output[0]
                )

    def test_035__handle_key_change_success(self):
        """test _handle_key_change success"""
        with patch.object(self.account, "message") as mock_message:
            mock_message.check.return_value = (200, None, None, {}, {}, None)
            with patch.object(
                self.account, "_rollover_account_key", return_value=(200, None, None)
            ):
                with patch.object(
                    self.account, "_build_response", return_value={"data": {}}
                ):
                    result = self.account._handle_key_change("test_account", {}, {})
                    self.assertIn("data", result)

    def test_036__handle_key_change_failure(self):
        """test _handle_key_change without key-change url logs WARNING"""
        with self.assertLogs("test_a2c", level="WARNING") as log_cm:
            result = self.account._handle_key_change("test_account", {}, {})
        self.assertEqual(result["data"]["status"], 400)
        self.assertEqual(result["data"]["type"], self.account.err_msg_dic["malformed"])
        self.assertEqual(result["data"]["detail"], "Malformed key-change request")
        self.assertIn(
            "WARNING:test_a2c:Malformed key-change request account=test_account",
            log_cm.output,
        )

    def test_037__rollover_account_key_validation_success(self):
        """test _rollover_account_key success"""
        self.account.repository.update_account.return_value = True
        with patch.object(
            self.account, "_validate_key_change", return_value=(200, None, None)
        ):
            code, message, detail = self.account._rollover_account_key(
                "test_account", {}, {"jwk": {"foo": "bar"}}, {}
            )
            self.assertEqual(code, 200)

    def test_038__rollover_account_key_validation_failure(self):
        """test _rollover_account_key success"""
        self.account.repository.update_account.return_value = True
        with patch.object(
            self.account,
            "_validate_key_change",
            return_value=(400, "message", "detail"),
        ):
            self.assertEqual(
                (400, "message", "detail"),
                self.account._rollover_account_key(
                    "test_account", {}, {"jwk": {"foo": "bar"}}, {}
                ),
            )

    def test_039__rollover_account_key_failure(self):
        """test _rollover_account_key failure"""
        self.account.repository.update_account.return_value = False
        with patch.object(
            self.account, "_validate_key_change", return_value=(200, None, None)
        ):
            with self.assertLogs("test_a2c", level="ERROR") as log_cm:
                code, message, detail = self.account._rollover_account_key(
                    "test_account", {}, {"jwk": {"foo": "bar"}}, {}
                )
                self.assertEqual(code, 500)
                self.assertEqual(message, self.account.err_msg_dic["serverinternal"])
                self.assertIn(detail, "Key rollover failed")
            self.assertIn(
                "ERROR:test_a2c:Key rollover failed for account: test_account",
                log_cm.output[0],
            )

    def test_040__rollover_account_key_exception(self):
        """test _rollover_account_key exception"""
        self.account.repository.update_account.side_effect = Exception("DB error")
        with patch.object(
            self.account, "_validate_key_change", return_value=(200, None, None)
        ):
            with self.assertLogs("test_a2c", level="CRITICAL") as log_cm:
                code, message, detail = self.account._rollover_account_key(
                    "test_account", {}, {}, {}
                )
                self.assertEqual(code, 500)
                self.assertEqual(message, self.account.err_msg_dic["serverinternal"])
                self.assertIn(
                    "Database error while updating account key", log_cm.output[0]
                )

    def test_041__validate_key_change_success(self):
        """test _validate_key_change success"""
        protected = {"url": "test", "kid": "kid"}
        inner_protected = {"jwk": {}, "url": "test"}
        inner_payload = {"account": "kid"}
        with patch.object(self.account, "_lookup_account_by_field", return_value=None):
            code, message, detail = self.account._validate_key_change(
                "test_account", protected, inner_protected, inner_payload
            )
            self.assertEqual(code, 200)

    def test_042__validate_key_change_missing_jwk(self):
        """test _validate_key_change missing jwk logs WARNING"""
        protected = {"url": "test", "kid": "kid"}
        inner_protected = {"url": "test"}
        inner_payload = {"account": "kid"}
        with self.assertLogs("test_a2c", level="WARNING") as log_cm:
            code, message, detail = self.account._validate_key_change(
                "test_account", protected, inner_protected, inner_payload
            )
        self.assertEqual(code, 400)
        self.assertEqual(detail, "Inner JWS is missing JWK")
        self.assertIn(
            "WARNING:test_a2c:Key-change validation failed account=test_account detail=Inner JWS is missing JWK",
            log_cm.output,
        )

    def test_043__validate_key_change_key_exists(self):
        """test _validate_key_change key exists logs WARNING"""
        protected = {"url": "test", "kid": "kid"}
        inner_protected = {"jwk": {}, "url": "test"}
        inner_payload = {"account": "kid"}
        with patch.object(
            self.account,
            "_lookup_account_by_field",
            return_value={"name": "test_account"},
        ):
            with self.assertLogs("test_a2c", level="WARNING") as log_cm:
                code, message, detail = self.account._validate_key_change(
                    "test_account", protected, inner_protected, inner_payload
                )
            self.assertEqual(code, 400)
            self.assertEqual(detail, "Public key already exists")
            self.assertIn(
                "WARNING:test_a2c:Key-change validation failed account=test_account detail=Public key already exists",
                log_cm.output,
            )

    def test_044__validate_key_change_url_mismatch(self):
        """test _validate_key_change url mismatch logs WARNING"""
        protected = {"url": "test", "kid": "kid"}
        inner_protected = {"jwk": {}, "url": "other"}
        inner_payload = {"account": "kid"}
        with patch.object(self.account, "_lookup_account_by_field", return_value=None):
            with self.assertLogs("test_a2c", level="WARNING") as log_cm:
                code, message, detail = self.account._validate_key_change(
                    "test_account", protected, inner_protected, inner_payload
                )
            self.assertEqual(code, 400)
            self.assertEqual(detail, "URL mismatch in inner and outer JWS")
            self.assertIn(
                "WARNING:test_a2c:Key-change validation failed account=test_account detail=URL mismatch in inner and outer JWS",
                log_cm.output,
            )

    def test_045__validate_key_change_missing_url(self):
        """test _validate_key_change missing url logs WARNING"""
        protected = {"kid": "kid"}
        inner_protected = {"jwk": {}}
        inner_payload = {"account": "kid"}
        with patch.object(self.account, "_lookup_account_by_field", return_value=None):
            with self.assertLogs("test_a2c", level="WARNING") as log_cm:
                code, message, detail = self.account._validate_key_change(
                    "test_account", protected, inner_protected, inner_payload
                )
            self.assertEqual(code, 400)
            self.assertEqual(detail, "Missing URL in inner or outer JWS")
            self.assertIn(
                "WARNING:test_a2c:Key-change validation failed account=test_account detail=Missing URL in inner or outer JWS",
                log_cm.output,
            )

    def test_046__validate_key_change_kid_account_mismatch(self):
        """test _validate_key_change kid/account mismatch logs WARNING"""
        protected = {"url": "test", "kid": "kid"}
        inner_protected = {"jwk": {}, "url": "test"}
        inner_payload = {"account": "other"}
        with patch.object(self.account, "_lookup_account_by_field", return_value=None):
            with self.assertLogs("test_a2c", level="WARNING") as log_cm:
                code, message, detail = self.account._validate_key_change(
                    "test_account", protected, inner_protected, inner_payload
                )
            self.assertEqual(code, 400)
            self.assertEqual(detail, "KID and account do not match")
            self.assertIn(
                "WARNING:test_a2c:Key-change validation failed account=test_account detail=KID and account do not match",
                log_cm.output,
            )

    def test_047__validate_key_change_missing_kid_account(self):
        """test _validate_key_change missing kid/account logs WARNING"""
        protected = {"url": "test"}
        inner_protected = {"jwk": {}, "url": "test"}
        inner_payload = {}
        with patch.object(self.account, "_lookup_account_by_field", return_value=None):
            with self.assertLogs("test_a2c", level="WARNING") as log_cm:
                code, message, detail = self.account._validate_key_change(
                    "test_account", protected, inner_protected, inner_payload
                )
            self.assertEqual(code, 400)
            self.assertEqual(detail, "Missing KID or account in payload")
            self.assertIn(
                "WARNING:test_a2c:Key-change validation failed account=test_account detail=Missing KID or account in payload",
                log_cm.output,
            )

    def test_048__load_configuration(self):
        """test _load_configuration covers all config branches and error handling"""
        from acme2certifier.acme_srv.account import Account

        # Patch load_config to return a configparser-like mock
        # eab_strict_mode defaults to True in AccountConfig; here we explicitly test False.
        config_mock = MagicMock()
        config_mock.getboolean.side_effect = lambda section, key, fallback=False: {
            ("Account", "inner_header_nonce_allow"): True,
            ("Account", "ecc_only"): True,
            ("Account", "tos_check_disable"): True,
            ("Account", "contact_check_disable"): True,
            ("EABhandler", "eab_strict_mode"): False,
        }.get((section, key), fallback)
        config_mock.get.side_effect = lambda section, key, fallback=None: {
            ("Directory", "tos_url"): "http://tos.url",
            ("Directory", "url_prefix"): "/prefix",
        }.get((section, key), fallback)
        config_mock.__contains__.side_effect = lambda k: k in ["EABhandler"]
        config_mock.__getitem__.side_effect = lambda k: (
            {"eab_handler_file": "handler.py"} if k == "EABhandler" else {}
        )

        # Patch eab_handler_load to return a module with EABhandler
        eab_handler_module = MagicMock()
        eab_handler_module.EABhandler = "EABhandlerClass"

        with (
            patch(
                "acme2certifier.acme_srv.account.load_config", return_value=config_mock
            ),
            patch(
                "acme2certifier.acme_srv.account.eab_handler_load",
                return_value=eab_handler_module,
            ),
        ):
            account = Account(False, "http://tester.local", self.logger)
            account._load_configuration()
            self.assertTrue(account.config.inner_header_nonce_allow)
            self.assertTrue(account.config.ecc_only)
            self.assertTrue(account.config.tos_check_disable)
            self.assertTrue(account.config.contact_check_disable)
            self.assertEqual(account.config.tos_url, "http://tos.url")
            self.assertTrue(account.config.eab_check)
            self.assertFalse(account.config.eab_strict_mode)
            self.assertEqual(account.config.eab_handler, "EABhandlerClass")
            self.assertTrue(account.config.path_dic["acct_path"].startswith("/prefix"))

        # Test EABhandler config incomplete branch
        config_mock2 = MagicMock()
        config_mock2.getboolean.return_value = False
        config_mock2.get.return_value = None
        config_mock2.__contains__.side_effect = lambda k: k in ["EABhandler"]
        config_mock2.__getitem__.side_effect = lambda k: {} if k == "EABhandler" else {}
        with (
            patch(
                "acme2certifier.acme_srv.account.load_config", return_value=config_mock2
            ),
            patch(
                "acme2certifier.acme_srv.account.eab_handler_load", return_value=None
            ),
        ):
            account = Account(False, "http://tester.local", self.logger)
            with self.assertLogs("test_a2c", level="CRITICAL") as log_cm:
                account._load_configuration()
                self.assertIn(
                    "Configuration error: EABHandler incomplete",
                    " ".join(log_cm.output),
                )

        # Test EABhandler load failure branch
        config_mock3 = MagicMock()
        config_mock3.getboolean.return_value = False
        config_mock3.get.return_value = None
        config_mock3.__contains__.side_effect = lambda k: k in ["EABhandler"]
        config_mock3.__getitem__.side_effect = lambda k: (
            {"eab_handler_file": "handler.py"} if k == "EABhandler" else {}
        )
        with (
            patch(
                "acme2certifier.acme_srv.account.load_config", return_value=config_mock3
            ),
            patch(
                "acme2certifier.acme_srv.account.eab_handler_load", return_value=None
            ),
        ):
            account = Account(False, "http://tester.local", self.logger)
            with self.assertLogs("test_a2c", level="CRITICAL") as log_cm:
                account._load_configuration()
                self.assertIn(
                    "EABHandler could not get loaded", " ".join(log_cm.output)
                )

    def test_049_load_configuration_without_accountsection(self):
        from acme2certifier.acme_srv.account import Account

        config_mock = MagicMock()
        config_mock.getboolean.side_effect = lambda section, key, fallback=False: {
            ("CAhandler", "foo"): "bar",
        }.get((section, key), fallback)

        # Patch eab_handler_load to return a module with EABhandler
        eab_handler_module = MagicMock()
        eab_handler_module.EABhandler = "EABhandlerClass"

        with (
            patch(
                "acme2certifier.acme_srv.account.load_config", return_value=config_mock
            ),
            patch(
                "acme2certifier.acme_srv.account.eab_handler_load",
                return_value=eab_handler_module,
            ),
        ):
            account = Account(False, "http://tester.local", self.logger)
            account._load_configuration()
            self.assertFalse(
                account.config.tos_check_disable
            )  # Default value should be used
            self.assertTrue(
                account.config.eab_strict_mode
            )  # Default value should be used
            self.assertFalse(
                account.config.inner_header_nonce_allow
            )  # Default value should be used
            self.assertFalse(account.config.eab_check)  # Default value should be used

    def test_050__create_account_success(self):
        """test _create_account success (all checks pass, EAB off)"""
        self.account.config.tos_url = None
        self.account.config.tos_check_disable = False
        self.account.config.eab_check = False
        self.account.config.contact_check_disable = False
        payload = {"contact": ["test@example.com"]}
        protected = {"alg": "RS256", "jwk": {"kty": "RSA", "n": "abc", "e": "AQAB"}}
        with (
            patch.object(
                self.account, "_validate_contact", return_value=(200, None, None)
            ),
            patch.object(
                self.account,
                "_add_account_to_db",
                return_value=(201, "test_account", None),
            ) as mock_add_db,
        ):
            code, message, detail = self.account._create_account(payload, protected)
            self.assertEqual(code, 201)
            self.assertEqual(message, "test_account")
            mock_add_db.assert_called_once()

    def test_051__create_account_tos_check_fail(self):
        """test _create_account fails TOS check"""
        self.account.config.tos_url = "http://tos.url"
        self.account.config.tos_check_disable = False
        self.account.config.eab_check = False
        payload = {"contact": ["test@example.com"]}
        protected = {"alg": "RS256", "jwk": {}}
        with patch.object(
            self.account, "_check_tos", return_value=(403, "tos_error", "tos_detail")
        ):
            code, message, detail = self.account._create_account(payload, protected)
            self.assertEqual(code, 403)
            self.assertEqual(message, "tos_error")

    def test_052__create_account_eab_check_fail(self):
        """test _create_account fails EAB check"""
        self.account.config.tos_url = None
        self.account.config.tos_check_disable = False
        self.account.config.eab_check = True
        self.account.config.eab_handler = MagicMock()
        payload = {"contact": ["test@example.com"]}
        protected = {"alg": "RS256", "jwk": {}}
        with patch(
            "acme2certifier.acme_srv.account.ExternalAccountBinding"
        ) as mock_eab:
            mock_eab.return_value.check.return_value = (403, "eab_error", "eab_detail")
            code, message, detail = self.account._create_account(payload, protected)
            self.assertEqual(code, 403)
            self.assertEqual(message, "eab_error")

    def test_053__create_account_eab_check_strict_mode_off(self):
        """test _create_account skips EAB check in non-strict mode without EAB payload"""
        self.account.config.tos_url = None
        self.account.config.tos_check_disable = False
        self.account.config.eab_check = True
        self.account.config.eab_strict_mode = False
        self.account.config.eab_handler = MagicMock()
        payload = {"contact": ["test@example.com"]}
        protected = {"alg": "RS256", "jwk": {}}
        with (
            patch("acme2certifier.acme_srv.account.ExternalAccountBinding") as mock_eab,
            patch(
                "acme2certifier.acme_srv.account.generate_random_string",
                return_value="testaccount123",
            ),
            patch.object(
                self.account,
                "_add_account_to_db",
                return_value=(201, "test_account", None),
            ) as mock_add_db,
        ):
            with self.assertLogs("test_a2c", level="DEBUG") as log_cm:
                code, message, detail = self.account._create_account(payload, protected)
            self.assertEqual(code, 201)
            self.assertEqual(message, "test_account")
            mock_eab.assert_not_called()
            mock_add_db.assert_called_once()
            self.assertIn(
                "DEBUG:test_a2c:Account._create_account() EAB check skipped due to non-strict mode and missing EAB payload",
                log_cm.output,
            )
            self.assertIn(
                "DEBUG:test_a2c:Account._create_account() EAB binding skipped for account testaccount123 due to non-strict mode and missing EAB payload",
                log_cm.output,
            )

    def test_054__create_account_contact_check_fail(self):
        """test _create_account fails contact validation"""
        self.account.config.tos_url = None
        self.account.config.tos_check_disable = False
        self.account.config.eab_check = False
        self.account.config.contact_check_disable = False
        payload = {"contact": ["bad@example.com"]}
        protected = {"alg": "RS256", "jwk": {}}
        with patch.object(
            self.account,
            "_validate_contact",
            return_value=(400, "contact_error", "contact_detail"),
        ):
            code, message, detail = self.account._create_account(payload, protected)
            self.assertEqual(code, 400)
            self.assertEqual(message, "contact_error")

    def test_055__create_account_eab_kid_set(self):
        """test _create_account sets eab_kid if present"""
        self.account.config.tos_url = None
        self.account.config.tos_check_disable = False
        self.account.config.eab_check = True
        self.account.config.eab_handler = MagicMock()
        payload = {
            "contact": ["test@example.com"],
            "externalaccountbinding": {"protected": "protectedval"},
        }
        protected = {"alg": "RS256", "jwk": {}}
        with (
            patch("acme2certifier.acme_srv.account.ExternalAccountBinding") as mock_eab,
            patch.object(
                self.account, "_validate_contact", return_value=(200, None, None)
            ),
            patch.object(
                self.account,
                "_add_account_to_db",
                return_value=(201, "test_account", None),
            ) as mock_add_db,
        ):
            mock_eab.return_value.check.return_value = (200, None, None)
            mock_eab.return_value.get_kid.return_value = "eabkid123"
            code, message, detail = self.account._create_account(payload, protected)
            self.assertEqual(code, 201)
            self.assertEqual(message, "test_account")
            mock_add_db.assert_called_once()
            # Check that eab_kid was set in the AccountData passed to _add_account_to_db
            args, kwargs = mock_add_db.call_args
            self.assertEqual(args[0].eab_kid, "eabkid123")

    def test_056__handle_key_change_success(self):
        """test _handle_key_change success path (code==200)"""
        account_name = "test_account"
        payload = {"foo": "bar"}
        protected = {"url": "key-change/123"}
        with (
            patch.object(self.account, "message") as mock_message,
            patch.object(
                self.account, "_rollover_account_key", return_value=(200, None, None)
            ) as mock_rollover,
            patch.object(
                self.account, "_build_response", return_value={"data": {}}
            ) as mock_build_response,
        ):
            mock_message.check.return_value = (
                200,
                None,
                None,
                {"jwk": {}},
                {"account": "acc"},
                None,
            )
            result = self.account._handle_key_change(account_name, payload, protected)
            self.assertIn("data", result)
            mock_rollover.assert_called_once()
            mock_build_response.assert_called_once()

    def test_057__handle_key_change_check_fail(self):
        """test _handle_key_change when message.check returns code!=200 preserves detail"""
        account_name = "test_account"
        payload = {"foo": "bar"}
        protected = {"url": "key-change/123"}
        with (
            patch.object(
                self.account.message,
                "check",
                return_value=(
                    400,
                    self.account.err_msg_dic["malformed"],
                    "inner check failed",
                    {},
                    {},
                    None,
                ),
            ),
            patch.object(self.account, "_rollover_account_key") as mock_rollover,
        ):
            with self.assertLogs("test_a2c", level="WARNING") as log_cm:
                result = self.account._handle_key_change(
                    account_name, payload, protected
                )
            mock_rollover.assert_not_called()
            self.assertEqual(result["data"]["status"], 400)
            self.assertEqual(
                result["data"]["type"], self.account.err_msg_dic["malformed"]
            )
            self.assertEqual(result["data"]["detail"], "inner check failed")
            self.assertIn(
                "WARNING:test_a2c:Key-change inner JWS check failed account=test_account detail=inner check failed",
                log_cm.output,
            )

    def test_058__handle_key_change_rollover_fail(self):
        """test _handle_key_change when rollover returns code!=200 preserves message/detail"""
        account_name = "test_account"
        payload = {"foo": "bar"}
        protected = {"url": "key-change/123"}
        with (
            patch.object(
                self.account.message,
                "check",
                return_value=(
                    200,
                    None,
                    None,
                    {"jwk": {}},
                    {"account": "acc"},
                    None,
                ),
            ),
            patch.object(
                self.account,
                "_rollover_account_key",
                return_value=(
                    400,
                    self.account.err_msg_dic["badpubkey"],
                    "Public key already exists",
                ),
            ) as mock_rollover,
        ):
            with self.assertLogs("test_a2c", level="WARNING") as log_cm:
                result = self.account._handle_key_change(
                    account_name, payload, protected
                )
            mock_rollover.assert_called_once()
            self.assertEqual(result["data"]["status"], 400)
            self.assertEqual(
                result["data"]["type"], self.account.err_msg_dic["badpubkey"]
            )
            self.assertEqual(result["data"]["detail"], "Public key already exists")
            self.assertIn(
                "WARNING:test_a2c:Key rollover failed account=test_account detail=Public key already exists",
                log_cm.output,
            )

    def test_059__handle_key_change_url_missing(self):
        """test _handle_key_change with missing url in protected logs WARNING"""
        account_name = "test_account"
        payload = {"foo": "bar"}
        protected = {"noturl": "nope"}
        with self.assertLogs("test_a2c", level="WARNING") as log_cm:
            result = self.account._handle_key_change(account_name, payload, protected)
        self.assertEqual(result["data"]["status"], 400)
        self.assertEqual(result["data"]["type"], self.account.err_msg_dic["malformed"])
        self.assertEqual(result["data"]["detail"], "Malformed key-change request")
        self.assertIn(
            "WARNING:test_a2c:Malformed key-change request account=test_account",
            log_cm.output,
        )

    def test_060__handle_account_query_valid(self):
        """test _handle_account_query with valid account"""
        account_name = "test_account"
        account_obj = {
            "status": "valid",
            "jwk": "{}",
            "contact": "[]",
            "created_at": "2026-02-08",
        }
        with (
            patch.object(
                self.account, "_lookup_account_by_name", return_value=account_obj
            ),
            patch.object(
                self.account, "_build_account_info", return_value={"status": "valid"}
            ),
            patch.object(
                self.account, "_build_response", return_value={"data": {}}
            ) as mock_build_response,
        ):
            result = self.account._handle_account_query(account_name)
            self.assertIn("data", result)
            mock_build_response.assert_called_once()

    def test_061__handle_account_query_valid(self):
        """test _handle_account_query with valid account"""
        account_name = "test_account"
        account_obj = {
            "status": "valid",
            "jwk": "{}",
            "contact": "[]",
            "created_at": "2026-02-08",
        }
        with (
            patch.object(
                self.account, "_lookup_account_by_name", return_value=account_obj
            ),
            patch.object(
                self.account, "_build_account_info", return_value={"status": "valid"}
            ),
        ):
            result = self.account._handle_account_query(account_name)
            self.assertEqual(
                "http://tester.local/acme/acct/test_account",
                result["header"]["Location"],
            )

    def test_062__handle_account_query_invalid(self):
        """test _handle_account_query with invalid account (not found)"""
        account_name = "test_account"
        with (
            patch.object(self.account, "_lookup_account_by_name", return_value=None),
            patch.object(
                self.account, "_build_account_info", return_value={"status": "valid"}
            ) as mock_build_account_info,
            patch.object(
                self.account, "_build_response", return_value={"data": {}}
            ) as mock_build_response,
        ):
            result = self.account._handle_account_query(account_name)
            self.assertIn("data", result)
            mock_build_response.assert_called_once()
            mock_build_account_info.assert_not_called()

    def test_063__lookup_account_by_name_success(self):
        """test _lookup_account_by_name returns account on success"""
        with patch.object(
            self.account.repository,
            "lookup_account",
            return_value={"name": "test_account"},
        ) as mock_lookup:
            result = self.account._lookup_account_by_name("test_account")
            self.assertEqual(result, {"name": "test_account"})
            mock_lookup.assert_called_once_with("name", "test_account")

    def test_064__lookup_account_by_name_exception(self):
        """test _lookup_account_by_name returns None on AccountDatabaseError"""
        with patch.object(
            self.account.repository, "lookup_account", side_effect=Exception("DB error")
        ) as mock_lookup:
            with self.assertLogs("test_a2c", level="CRITICAL") as log_cm:
                result = self.account._lookup_account_by_name("test_account")
                self.assertIsNone(result)
                self.assertIn(
                    "Database error during account lookup", " ".join(log_cm.output)
                )

    def test_065__lookup_account_by_field_success(self):
        """test _lookup_account_by_name returns account on success"""
        with patch.object(
            self.account.repository,
            "lookup_account",
            return_value={"name": "test_account"},
        ) as mock_lookup:
            result = self.account._lookup_account_by_field("field", "value")
            self.assertEqual(result, {"name": "test_account"})
            mock_lookup.assert_called_once_with("value", "field")

    def test_066__lookup_account_by_field_exception(self):
        """test _lookup_account_by_name returns None on AccountDatabaseError"""
        with patch.object(
            self.account.repository, "lookup_account", side_effect=Exception("DB error")
        ) as mock_lookup:
            with self.assertLogs("test_a2c", level="CRITICAL") as log_cm:
                result = self.account._lookup_account_by_field("field", "value")
                self.assertIsNone(result)
                self.assertIn(
                    "Database error during account lookup", " ".join(log_cm.output)
                )

    def test_067__build_account_info_normal(self):
        """test _build_account_info with all fields present"""
        account_obj = {
            "status": "valid",
            "jwk": '{"kty": "RSA", "n": "abc", "e": "AQAB"}',
            "contact": '["mailto:test@example.com"]',
            "created_at": "2026-02-08 12:00:00",
        }
        with patch(
            "acme2certifier.acme_srv.account.date_to_datestr", return_value="date_str"
        ):
            result = self.account._build_account_info(account_obj)
            self.assertEqual(result["status"], "valid")
            self.assertEqual(result["key"], {"kty": "RSA", "n": "abc", "e": "AQAB"})
            self.assertEqual(result["contact"], ["mailto:test@example.com"])
            self.assertEqual(result["createdAt"], "date_str")

    def test_068__build_account_info_witheab(self):
        """test _build_account_info with all fields present"""
        account_obj = {
            "status": "valid",
            "jwk": '{"kty": "RSA", "n": "abc", "e": "AQAB"}',
            "contact": '["mailto:test@example.com"]',
            "created_at": "2026-02-08 12:00:00",
            "eab_kid": "kid123",
        }
        with patch(
            "acme2certifier.acme_srv.account.date_to_datestr", return_value="date_str"
        ):
            result = self.account._build_account_info(account_obj)
            self.assertEqual(result["status"], "valid")
            self.assertEqual(result["key"], {"kty": "RSA", "n": "abc", "e": "AQAB"})
            self.assertEqual(result["contact"], ["mailto:test@example.com"])
            self.assertEqual(result["createdAt"], "date_str")
            self.assertEqual(result["eab_kid"], "kid123")

    def test_069__build_account_info_missing_fields(self):
        """test _build_account_info with missing optional fields"""
        account_obj = {
            "jwk": "{}",
            "contact": "[]",
            "created_at": "2026-02-08 12:00:00",
        }
        with patch(
            "acme2certifier.acme_srv.account.date_to_datestr", return_value="date_str"
        ):
            result = self.account._build_account_info(account_obj)
            self.assertEqual(result["status"], "valid")  # default
            self.assertEqual(result["key"], {})
            self.assertEqual(result["contact"], [])
            self.assertEqual(result["createdAt"], "date_str")
            self.assertNotIn("eab_kid", result)

    def test_070__build_account_info_eab_kid_empty(self):
        """test _build_account_info with eab_kid present but empty"""
        account_obj = {
            "status": "valid",
            "jwk": "{}",
            "contact": "[]",
            "created_at": "2026-02-08 12:00:00",
            "eab_kid": "",
        }
        result = self.account._build_account_info(account_obj)
        self.assertNotIn("eab_kid", result)

    def test_071__build_response_201(self):
        """test _build_response for code 201 (account creation)"""
        code = 201
        message = "test_account"
        detail = None
        payload = {"contact": ["mailto:test@example.com"]}
        self.account.server_name = "http://tester.local"
        self.account.config.path_dic = {"acct_path": "/acme/acct/"}
        with patch.object(
            self.account.message,
            "prepare_response",
            return_value={"data": {"status": "valid"}, "header": {}},
        ) as mock_prepare:
            result = self.account._build_response(code, message, detail, payload)
            self.assertIn("data", result)
            self.assertIn("header", result)
            mock_prepare.assert_called_once()

    def test_072__build_response_200(self):
        """test _build_response for code 200 (success, detail contains status)"""
        code = 200
        message = "test_account"
        detail = {"status": "valid"}
        payload = {}
        self.account.server_name = "http://tester.local"
        self.account.config.path_dic = {"acct_path": "/acme/acct/"}
        with patch.object(
            self.account.message,
            "prepare_response",
            return_value={"data": {"status": "valid"}, "header": {}},
        ) as mock_prepare:
            result = self.account._build_response(code, message, detail, payload)
            self.assertIn("data", result)
            self.assertIn("header", result)
            mock_prepare.assert_called_once()

    def test_073__build_response_error(self):
        """test _build_response for error code (e.g. 400)"""
        code = 400
        message = "error"
        detail = "tosfalse"
        payload = {}
        with patch.object(
            self.account.message, "prepare_response", return_value={"error": "error"}
        ) as mock_prepare:
            result = self.account._build_response(code, message, detail, payload)
            self.assertIn("error", result)
            mock_prepare.assert_called_once()

    def test_074__build_response_eab_binding(self):
        """test _build_response with eab_check and externalaccountbinding in payload"""
        code = 201
        message = "test_account"
        detail = None
        payload = {
            "contact": ["mailto:test@example.com"],
            "externalaccountbinding": {"foo": "bar"},
        }
        self.account.server_name = "http://tester.local"
        self.account.config.path_dic = {"acct_path": "/acme/acct/"}
        self.account.config.eab_check = True
        with patch.object(
            self.account.message,
            "prepare_response",
            return_value={
                "data": {"status": "valid", "externalaccountbinding": {"foo": "bar"}},
                "header": {},
            },
        ) as mock_prepare:
            result = self.account._build_response(code, message, detail, payload)
            self.assertIn("data", result)
            self.assertIn("externalaccountbinding", result["data"])
            mock_prepare.assert_called_once()

    def test_075__build_response_200_eab_check_no_payload(self):
        """test _build_response with eab_check and no payload (e.g. key rollover)"""
        self.account.server_name = "http://tester.local"
        self.account.config.path_dic = {"acct_path": "/acme/acct/"}
        self.account.config.eab_check = True
        with patch.object(
            self.account.message,
            "prepare_response",
            side_effect=lambda response_dic, status_dic, **_kwargs: response_dic,
        ):
            result = self.account._build_response(200, "test_account", None)
        self.assertEqual(
            result["header"]["Location"],
            "http://tester.local/acme/acct/test_account",
        )
        self.assertNotIn("externalaccountbinding", result.get("data", {}))

    def test_076_parse_request_error(self):
        """test parse_request returns error response when message.check fails"""
        content = {"foo": "bar"}
        with (
            patch.object(
                self.account.message,
                "check",
                return_value=(400, "error", "fail", {}, {}, None),
            ),
            patch.object(
                self.account, "_build_response", return_value={"error": "fail"}
            ) as mock_build_response,
        ):
            result = self.account.parse_request(content)
            self.assertEqual(result, {"error": "fail"})
            mock_build_response.assert_called_once()

    def test_077_parse_request_deactivation(self):
        """test parse_request handles deactivation branch"""
        content = {"foo": "bar"}
        payload = {"status": "deactivated"}
        with (
            patch.object(
                self.account.message,
                "check",
                return_value=(200, None, None, {}, payload, "test_account"),
            ),
            patch.object(
                self.account,
                "_handle_deactivation",
                return_value={"data": {"status": "deactivated"}},
            ) as mock_handle,
        ):
            result = self.account.parse_request(content)
            self.assertIn("data", result)
            mock_handle.assert_called_once_with("test_account", payload)

    def test_078_parse_request_contact_update(self):
        """test parse_request handles contact update branch"""
        content = {"foo": "bar"}
        payload = {"contact": ["mailto:test@example.com"]}
        with (
            patch.object(
                self.account.message,
                "check",
                return_value=(200, None, None, {}, payload, "test_account"),
            ),
            patch.object(
                self.account,
                "_handle_contact_update",
                return_value={"data": {"contact": ["mailto:test@example.com"]}},
            ) as mock_handle,
        ):
            result = self.account.parse_request(content)
            self.assertIn("data", result)
            mock_handle.assert_called_once_with("test_account", payload)

    def test_079_parse_request_key_change(self):
        """test parse_request handles key change branch"""
        content = {"foo": "bar"}
        payload = {"payload": {}}
        protected = {"protected": {}}
        with (
            patch.object(
                self.account.message,
                "check",
                return_value=(200, None, None, protected, payload, "test_account"),
            ),
            patch.object(
                self.account,
                "_handle_key_change",
                return_value={"data": {"keychange": True}},
            ) as mock_handle,
        ):
            result = self.account.parse_request(content)
            self.assertIn("data", result)
            mock_handle.assert_called_once_with("test_account", payload, protected)

    def test_080_parse_request_account_query(self):
        """test parse_request handles account query branch (empty payload)"""
        content = {"foo": "bar"}
        with (
            patch.object(
                self.account.message,
                "check",
                return_value=(200, None, None, {}, {}, "test_account"),
            ),
            patch.object(
                self.account,
                "_handle_account_query",
                return_value={"data": {"status": "valid"}},
            ) as mock_handle,
        ):
            result = self.account.parse_request(content)
            self.assertIn("data", result)
            mock_handle.assert_called_once_with("test_account")

    def test_081_parse_request_unknown(self):
        """test parse_request handles unknown request branch and logs WARNING"""
        content = {"foo": "bar"}
        payload = {"unknown": True}
        with (
            patch.object(
                self.account.message,
                "check",
                return_value=(200, None, None, {}, payload, "test_account"),
            ),
            patch.object(
                self.account,
                "_build_response",
                return_value={"error": "Unknown request"},
            ) as mock_build_response,
        ):
            with self.assertLogs("test_a2c", level="WARNING") as log_cm:
                result = self.account.parse_request(content)
            self.assertEqual(result, {"error": "Unknown request"})
            mock_build_response.assert_called_once_with(
                400,
                self.account.err_msg_dic["malformed"],
                "Unknown request",
                account_name="test_account",
            )
            self.assertIn(
                "WARNING:test_a2c:Unknown request account=test_account",
                log_cm.output,
            )

    def test_082_new_calls_create_account(self):
        """test new() calls create_account and returns its result"""
        content = {"foo": "bar"}
        with patch.object(
            self.account, "create_account", return_value={"data": {"status": "valid"}}
        ) as mock_create:
            result = self.account.new(content)
            self.assertEqual(result, {"data": {"status": "valid"}})
            mock_create.assert_called_once_with(content)

    def test_083_parse_calls_parse_request(self):
        """test parse() calls parse_request and returns its result"""
        content = {"foo": "bar"}
        with patch.object(
            self.account, "parse_request", return_value={"data": {"status": "valid"}}
        ) as mock_parse_request:
            result = self.account.parse(content)
            self.assertEqual(result, {"data": {"status": "valid"}})
            mock_parse_request.assert_called_once_with(content)


if __name__ == "__main__":
    unittest.main()
