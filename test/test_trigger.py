#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for account.py"""

# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212
import unittest
import sys
import importlib
import configparser
from types import SimpleNamespace
from unittest.mock import patch, MagicMock, Mock

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class FakeDBStore(object):
    """face DBStore class needed for mocking"""

    # pylint: disable=W0107, R0903
    pass


class TestACMEHandler(unittest.TestCase):
    """test class for ACMEHandler"""

    acme = None

    def setUp(self):
        """setup unittest"""
        models_mock = MagicMock()
        modules = {"acme2certifier.acme_srv.db_handler": models_mock}
        patch.dict("sys.modules", modules).start()
        import logging

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        from acme2certifier.acme_srv.trigger import Trigger
        from acme2certifier.acme_srv.order import Order

        self.order = Order(False, "http://tester.local", self.logger)
        self.trigger = Trigger(False, "http://tester.local", self.logger)
        # Unit tests exercise parse/process when endpoint is enabled
        self.trigger.enabled = True
        self.trigger.auth_disabled = True
        self.trigger.hmac_keys = ["unit-test-key"]
        self.trigger.ca_cert = "/tmp/trigger-unit-ca.pem"
        self._chain_verify_patcher = patch(
            "acme2certifier.acme_srv.trigger.trigger_cert_chain_verify",
            return_value=True,
        )
        self._chain_verify_patcher.start()

    def tearDown(self):
        """stop patches"""
        try:
            self._chain_verify_patcher.stop()
        except RuntimeError:
            pass

    @patch("importlib.import_module")
    @patch("acme2certifier.acme_srv.certificate.Certificate.certlist_search")
    @patch("acme2certifier.acme_srv.trigger.cert_pubkey_get")
    def test_001_trigger__certname_lookup(
        self, mock_cert_pub, mock_search_list, mock_import
    ):
        """trigger._certname_lookup() failed bcs. of empty certificate list"""
        mock_cert_pub.return_value = "foo"
        mock_search_list.return_value = []
        mock_import.return_value = importlib.import_module(
            "acme2certifier.cahandlers.skeleton_ca_handler"
        )
        self.assertEqual([], self.trigger._certname_lookup("cert_pem"))

    @patch("importlib.import_module")
    @patch("acme2certifier.acme_srv.certificate.Certificate.certlist_search")
    @patch("acme2certifier.acme_srv.trigger.cert_pubkey_get")
    def test_002_trigger__certname_lookup(
        self, mock_cert_pub, mock_search_list, mock_import
    ):
        """trigger._certname_lookup() failed bcs. of wrong certificate list"""
        mock_cert_pub.return_value = "foo"
        mock_search_list.return_value = [{"foo": "bar"}]
        mock_import.return_value = importlib.import_module(
            "acme2certifier.cahandlers.skeleton_ca_handler"
        )
        self.assertEqual([], self.trigger._certname_lookup("cert_pem"))

    @patch("importlib.import_module")
    @patch("acme2certifier.acme_srv.certificate.Certificate.certlist_search")
    @patch("acme2certifier.acme_srv.trigger.cert_pubkey_get")
    def test_003_trigger__certname_lookup(
        self, mock_cert_pub, mock_search_list, mock_import
    ):
        """trigger._certname_lookup() failed bcs. of emty csr field"""
        mock_cert_pub.return_value = "foo"
        mock_search_list.return_value = [{"csr": None}]
        mock_import.return_value = importlib.import_module(
            "acme2certifier.cahandlers.skeleton_ca_handler"
        )
        self.assertEqual([], self.trigger._certname_lookup("cert_pem"))

    @patch("importlib.import_module")
    @patch("acme2certifier.acme_srv.trigger.csr_pubkey_get")
    @patch("acme2certifier.acme_srv.certificate.Certificate.certlist_search")
    @patch("acme2certifier.acme_srv.trigger.cert_pubkey_get")
    def test_004_trigger__certname_lookup(
        self, mock_cert_pub, mock_search_list, mock_csr_pub, mock_import
    ):
        """trigger._certname_lookup() failed bcs. of emty csr field"""
        mock_cert_pub.return_value = "foo"
        mock_csr_pub.return_value = "foo1"
        mock_search_list.return_value = [{"csr": None}]
        mock_import.return_value = importlib.import_module(
            "acme2certifier.cahandlers.skeleton_ca_handler"
        )
        self.assertEqual([], self.trigger._certname_lookup("cert_pem"))

    @patch("importlib.import_module")
    @patch("acme2certifier.acme_srv.trigger.csr_pubkey_get")
    @patch("acme2certifier.acme_srv.certificate.Certificate.certlist_search")
    @patch("acme2certifier.acme_srv.trigger.cert_pubkey_get")
    def test_005_trigger__certname_lookup(
        self, mock_cert_pub, mock_search_list, mock_csr_pub, mock_import
    ):
        """trigger._certname_lookup() failed bcs. of emty csr field"""
        mock_cert_pub.return_value = "foo"
        mock_csr_pub.return_value = "foo"
        mock_search_list.return_value = [
            {"csr": "csr", "name": "cert_name", "order__name": "order_name"}
        ]
        mock_import.return_value = importlib.import_module(
            "acme2certifier.cahandlers.skeleton_ca_handler"
        )
        self.assertEqual(
            [{"cert_name": "cert_name", "order_name": "order_name"}],
            self.trigger._certname_lookup("cert_pem"),
        )

    def test_006_trigger_parse(self):
        """Trigger.parse() with empty payload"""
        payload = ""
        result = {
            "header": {},
            "code": 400,
            "data": {"detail": "payload missing", "type": "malformed", "status": 400},
        }
        self.assertEqual(result, self.trigger.parse(payload))

    def test_007_trigger_parse_disabled(self):
        """Trigger.parse() returns 403 when endpoint is disabled"""
        self.trigger.enabled = False
        result = {
            "header": {},
            "code": 403,
            "data": {
                "status": 403,
                "type": "unauthorized",
                "detail": "trigger endpoint disabled",
            },
        }
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            self.assertEqual(result, self.trigger.parse('{"payload": "foo"}'))
        self.assertTrue(any("Trigger endpoint disabled" in line for line in lcm.output))

    def test_008_trigger_parse(self):
        """Trigger.parse() with wrong payload"""
        payload = '{"foo": "bar"}'
        result = {
            "header": {},
            "code": 400,
            "data": {"detail": "payload missing", "type": "malformed", "status": 400},
        }
        self.assertEqual(result, self.trigger.parse(payload))

    def test_009_trigger_parse(self):
        """Trigger.parse() with empty payload key"""
        payload = '{"payload": ""}'
        result = {
            "header": {},
            "code": 400,
            "data": {"detail": "payload empty", "type": "malformed", "status": 400},
        }
        self.assertEqual(result, self.trigger.parse(payload))

    @patch("acme2certifier.acme_srv.trigger.Trigger._payload_process")
    def test_010_trigger_parse(self, mock_process):
        """Trigger.parse() with payload mock result 400"""
        payload = '{"payload": "foo"}'
        mock_process.return_value = (400, "message", "detail")
        result = {
            "header": {},
            "code": 400,
            "data": {"detail": "detail", "type": "message", "status": 400},
        }
        self.assertEqual(result, self.trigger.parse(payload))

    @patch("acme2certifier.acme_srv.trigger.Trigger._payload_process")
    def test_011_trigger_parse(self, mock_process):
        """Trigger.parse() with payload mock result 200"""
        payload = '{"payload": "foo"}'
        mock_process.return_value = (200, "message", "detail")
        result = {
            "header": {},
            "code": 200,
            "data": {"detail": "detail", "type": "message", "status": 200},
        }
        self.assertEqual(result, self.trigger.parse(payload))

    def test_012_trigger__payload_process(self):
        """Trigger._payload_process() without payload"""
        payload = {}
        ca_handler_module = importlib.import_module(
            "acme2certifier.cahandlers.skeleton_ca_handler"
        )
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=("error", None, None))
        self.assertEqual(
            (400, "payload malformed", None), self.trigger._payload_process(payload)
        )

    def test_013_trigger__payload_process(self):
        """Trigger._payload_process() without certbunde and cert_raw"""
        payload = {"payload": "foo"}
        ca_handler_module = importlib.import_module(
            "acme2certifier.cahandlers.skeleton_ca_handler"
        )
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=("error", None, None))
        self.assertEqual((400, "error", None), self.trigger._payload_process(payload))

    def test_014_trigger__payload_process(self):
        """Trigger._payload_process() with bundle and without cart_raw"""
        payload = {"payload": "foo"}
        ca_handler_module = importlib.import_module(
            "acme2certifier.cahandlers.skeleton_ca_handler"
        )
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=("error", "bundle", None))
        self.assertEqual((400, "error", None), self.trigger._payload_process(payload))

    def test_015_trigger__payload_process(self):
        """Trigger._payload_process() with bundle and without cart_raw"""
        payload = {"payload": "foo"}
        ca_handler_module = importlib.import_module(
            "acme2certifier.cahandlers.skeleton_ca_handler"
        )
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=("error", None, "raw"))
        self.assertEqual((400, "error", None), self.trigger._payload_process(payload))

    @patch("acme2certifier.acme_srv.trigger.Trigger._certname_lookup")
    @patch("acme2certifier.acme_srv.trigger.b64_decode")
    @patch("acme2certifier.acme_srv.trigger.cert_der2pem")
    @patch("acme2certifier.acme_srv.trigger.convert_byte_to_string")
    def test_016_trigger__payload_process(
        self, mock_cobystr, mock_der2pem, mock_b64dec, mock_lookup
    ):
        """Trigger._payload_process() with certificae_name"""
        payload = {"payload": "foo"}
        ca_handler_module = importlib.import_module(
            "acme2certifier.cahandlers.skeleton_ca_handler"
        )
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=("error", "bundle", "raw"))
        mock_der2pem.return_value = "der2pem"
        mock_cobystr.return_value = "cert_pem"
        mock_b64dec.return_value = "b64dec"
        mock_lookup.return_value = [
            {"cert_name": "certificate_name", "order_name": None}
        ]
        self.assertEqual((200, "OK", None), self.trigger._payload_process(payload))

    @patch("acme2certifier.acme_srv.trigger.Trigger._certname_lookup")
    @patch("acme2certifier.acme_srv.trigger.b64_decode")
    @patch("acme2certifier.acme_srv.trigger.cert_der2pem")
    @patch("acme2certifier.acme_srv.trigger.convert_byte_to_string")
    def test_017_trigger__payload_process(
        self, mock_cobystr, mock_der2pem, mock_b64dec, mock_lookup
    ):
        """Trigger._payload_process() without certificate_name"""
        payload = {"payload": "foo"}
        ca_handler_module = importlib.import_module(
            "acme2certifier.cahandlers.skeleton_ca_handler"
        )
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=("error", "bundle", "raw"))
        mock_der2pem.return_value = "der2pem"
        mock_cobystr.return_value = "cert_pem"
        mock_b64dec.return_value = "b64dec"
        mock_lookup.return_value = [{"cert_name": None, "order_name": "order_name"}]
        self.assertEqual((200, "OK", None), self.trigger._payload_process(payload))

    @patch("acme2certifier.acme_srv.trigger.Trigger._certname_lookup")
    @patch("acme2certifier.acme_srv.trigger.b64_decode")
    @patch("acme2certifier.acme_srv.trigger.cert_der2pem")
    @patch("acme2certifier.acme_srv.trigger.convert_byte_to_string")
    def test_018_trigger__payload_process(
        self, mock_cobystr, mock_der2pem, mock_b64dec, mock_lookup
    ):
        """Trigger._payload_process() _certname.lookup() returned empty list"""
        payload = {"payload": "foo"}
        ca_handler_module = importlib.import_module(
            "acme2certifier.cahandlers.skeleton_ca_handler"
        )
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=("error", "bundle", "raw"))
        mock_der2pem.return_value = "der2pem"
        mock_cobystr.return_value = "cert_pem"
        mock_b64dec.return_value = "b64dec"
        mock_lookup.return_value = []
        self.assertEqual(
            (400, "certificate_name lookup failed", None),
            self.trigger._payload_process(payload),
        )

    @patch("acme2certifier.acme_srv.trigger.Trigger._certname_lookup")
    @patch("acme2certifier.acme_srv.trigger.b64_decode")
    @patch("acme2certifier.acme_srv.trigger.cert_der2pem")
    @patch("acme2certifier.acme_srv.trigger.convert_byte_to_string")
    def test_019_trigger__payload_process(
        self, mock_cobystr, mock_der2pem, mock_b64dec, mock_lookup
    ):
        """Trigger._payload_process() without certificate_name"""
        payload = {"payload": "foo"}
        ca_handler_module = importlib.import_module(
            "acme2certifier.cahandlers.skeleton_ca_handler"
        )
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=("error", "bundle", "raw"))
        mock_der2pem.return_value = "der2pem"
        mock_cobystr.return_value = "cert_pem"
        mock_b64dec.return_value = "b64dec"
        mock_lookup.return_value = [
            {"cert_name": "certificate_name", "order_name": "order_name"}
        ]
        self.order.dbstore.order_update.return_value = None
        self.assertEqual((200, "OK", None), self.trigger._payload_process(payload))

    @patch("acme2certifier.acme_srv.trigger.Trigger._certname_lookup")
    @patch("acme2certifier.acme_srv.trigger.b64_decode")
    @patch("acme2certifier.acme_srv.trigger.cert_der2pem")
    @patch("acme2certifier.acme_srv.trigger.convert_byte_to_string")
    def test_020_trigger__payload_process(
        self, mock_cobystr, mock_der2pem, mock_b64dec, mock_lookup
    ):
        """Trigger._payload_process() rejects ambiguous pubkey matches"""
        payload = {"payload": "foo"}
        ca_handler_module = importlib.import_module(
            "acme2certifier.cahandlers.skeleton_ca_handler"
        )
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=("error", "bundle", "raw"))
        mock_der2pem.return_value = "der2pem"
        mock_cobystr.return_value = "cert_pem"
        mock_b64dec.return_value = "b64dec"
        mock_lookup.return_value = [
            {"cert_name": "certificate_name1", "order_name": "order_name1"},
            {"cert_name": "certificate_name2", "order_name": "order_name2"},
        ]
        self.assertEqual(
            (409, "ambiguous certificate match", None),
            self.trigger._payload_process(payload),
        )

    @patch("acme2certifier.acme_srv.trigger.Trigger._certname_lookup")
    @patch("acme2certifier.acme_srv.trigger.b64_decode")
    @patch("acme2certifier.acme_srv.trigger.cert_der2pem")
    @patch("acme2certifier.acme_srv.trigger.convert_byte_to_string")
    def test_021_trigger__payload_process(
        self, mock_cobystr, mock_der2pem, mock_b64dec, mock_lookup
    ):
        """test Trigger._payload_process - dbstore.order_update() raises an exception"""
        ca_handler_module = importlib.import_module(
            "acme2certifier.cahandlers.skeleton_ca_handler"
        )
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(
            return_value=(None, "certificate", "certificate_raw")
        )
        mock_der2pem.return_value = "der2pem"
        mock_cobystr.return_value = "cert_pem"
        mock_b64dec.return_value = "b64dec"
        mock_lookup.return_value = [
            {"cert_name": "certificate_name1", "order_name": "order_name1"},
        ]
        self.trigger.dbstore.certificate_add.return_value = True
        self.trigger.dbstore.order_update.side_effect = Exception(
            "exc_trigger_order_upd"
        )
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.trigger._payload_process("payload")
        self.assertIn(
            "CRITICAL:test_a2c:Database error: failed to update order status during trigger processing: exc_trigger_order_upd",
            lcm.output,
        )

    @patch("acme2certifier.acme_srv.trigger.Trigger._certname_lookup")
    @patch("acme2certifier.acme_srv.trigger.b64_decode")
    @patch("acme2certifier.acme_srv.trigger.cert_der2pem")
    @patch("acme2certifier.acme_srv.trigger.convert_byte_to_string")
    def test_022_trigger__payload_process(
        self, mock_cobystr, mock_der2pem, mock_b64dec, mock_lookup
    ):
        """test Trigger._payload_process - dbstore.certificate_add() raises an exception"""
        ca_handler_module = importlib.import_module(
            "acme2certifier.cahandlers.skeleton_ca_handler"
        )
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(
            return_value=(None, "certificate", "certificate_raw")
        )
        mock_der2pem.return_value = "der2pem"
        mock_cobystr.return_value = "cert_pem"
        mock_b64dec.return_value = "b64dec"
        mock_lookup.return_value = [
            {"cert_name": "certificate_name1", "order_name": "order_name1"},
        ]
        self.trigger.dbstore.certificate_add.side_effect = Exception(
            "exc_trigger_order_add"
        )
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.trigger._payload_process("payload")
        self.assertIn(
            "CRITICAL:test_a2c:Database error: failed to add certificate during trigger processing: exc_trigger_order_add",
            lcm.output,
        )

    @patch("acme2certifier.acme_srv.trigger.load_config")
    def test_023_config_load(self, mock_load_cfg):
        """test _config_load missing ca_handler"""
        mock_load_cfg.return_value = {}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.trigger._config_load()
        self.assertIn(
            "ERROR:test_a2c:Configuration error: CAhandler configuration missing in config file",
            lcm.output,
        )
        self.assertFalse(self.trigger.enabled)

    @patch("acme2certifier.acme_srv.trigger.trigger_ca_cert_load")
    @patch("acme2certifier.acme_srv.trigger.trigger_hmac_keys_load")
    @patch("acme2certifier.acme_srv.trigger.ca_handler_load")
    @patch("acme2certifier.acme_srv.trigger.load_config")
    def test_024_config_load_trigger_enabled_with_support(
        self, mock_load_cfg, mock_ca_load, mock_keys, mock_ca_cert
    ):
        """_config_load sets enabled when config+supports_trigger+auth+ca_cert"""
        parser = configparser.ConfigParser()
        parser["Trigger"] = {"enabled": "True"}
        mock_load_cfg.return_value = parser
        mock_keys.return_value = (["k1"], False)
        mock_ca_cert.return_value = "/tmp/ca.pem"

        class _Handler:
            supports_trigger = True

        mock_ca_load.return_value = MagicMock(CAhandler=_Handler)
        self.trigger._config_load()
        self.assertTrue(self.trigger.enabled)

    @patch("acme2certifier.acme_srv.trigger.ca_handler_load")
    def test_025_resolve_trigger_endpoint_misconfig_warns(self, mock_ca_load):
        """config enabled without supports_trigger → False + warning"""
        from acme2certifier.acme_srv.trigger import resolve_trigger_endpoint

        parser = configparser.ConfigParser()
        parser["Trigger"] = {"enabled": "True"}

        class _Handler:
            pass

        mock_ca_load.return_value = MagicMock(CAhandler=_Handler)
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            self.assertFalse(
                resolve_trigger_endpoint(self.logger, parser, log_status=True)
            )
        self.assertTrue(any("supports_trigger=True" in line for line in lcm.output))

    def test_026_resolve_trigger_endpoint_default_off(self):
        """absent [Trigger] → False"""
        from acme2certifier.acme_srv.trigger import resolve_trigger_endpoint

        parser = configparser.ConfigParser()
        self.assertFalse(
            resolve_trigger_endpoint(self.logger, parser, log_status=False)
        )

    @patch("acme2certifier.acme_srv.trigger.Trigger._config_load")
    def test_027__enter__(self, mock_cfg):
        """test enter"""
        mock_cfg.return_value = True
        self.trigger.__enter__()
        self.assertTrue(mock_cfg.called)

    @patch("acme2certifier.acme_srv.trigger.load_config")
    def test_028_config_load(self, mock_load_cfg):
        """test _config_load empty config"""
        parser = configparser.ConfigParser()
        # parser['Account'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.trigger._config_load()
        self.assertFalse(self.trigger.tnauthlist_support)
        self.assertIn(
            "ERROR:test_a2c:Configuration error: CAhandler configuration missing in config file",
            lcm.output,
        )

    @patch("acme2certifier.acme_srv.trigger.load_config")
    def test_029_config_load(self, mock_load_cfg):
        """test _config_load bogus ca_handler"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"handler_file": "foo"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.trigger._config_load()
        self.assertIn(
            "CRITICAL:test_a2c:Loading CAhandler configured in cfg failed with err: Cannot load module 'CAhandler' from 'foo'",
            lcm.output,
        )

    @patch("importlib.import_module")
    @patch("acme2certifier.acme_srv.trigger.load_config")
    def test_030_config_load(self, mock_load_cfg, mock_imp):
        """test _config_load missing ca_handler"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"handler_file": "foo"}
        mock_load_cfg.return_value = parser
        mock_imp.return_value = Mock()
        self.trigger._config_load()
        self.assertTrue(self.trigger.cahandler)

    @patch("importlib.import_module")
    @patch("acme2certifier.acme_srv.trigger.load_config")
    def test_031_config_load(self, mock_load_cfg, mock_imp):
        """test _config_load missing ca_handler"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"foo": "bar"}
        mock_load_cfg.return_value = parser
        mock_imp.return_value = Mock()
        self.trigger._config_load()
        self.assertTrue(self.trigger.cahandler)

    @patch("acme2certifier.acme_srv.trigger.load_config")
    def test_032_config_load(self, mock_load_cfg):
        """test _config_load empty config"""
        parser = configparser.ConfigParser()
        parser["Order"] = {"tnauthlist_support": False}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.trigger._config_load()
        self.assertFalse(self.trigger.tnauthlist_support)

    @patch("acme2certifier.acme_srv.trigger.load_config")
    def test_033_config_load(self, mock_load_cfg):
        """test _config_load empty config"""
        parser = configparser.ConfigParser()
        parser["Order"] = {"tnauthlist_support": True}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.trigger._config_load()
        self.assertTrue(self.trigger.tnauthlist_support)

    @patch("acme2certifier.acme_srv.trigger.ca_handler_load")
    @patch("acme2certifier.acme_srv.trigger.load_config")
    def test_034_config_load(self, mock_load_cfg, mock_cahandler_load):
        """test _config_load()"""
        parser = configparser.ConfigParser()
        parser["Foo"] = {"foo": "bar"}
        mock_load_cfg.return_value = parser
        mock_cahandler_load.return_value = "foo"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.trigger._config_load()
        self.assertIn(
            "CRITICAL:test_a2c:Failed to load CA handler module: 'str' object has no attribute 'CAhandler'",
            lcm.output,
        )

    @patch("acme2certifier.acme_srv.trigger.ca_handler_load")
    @patch("acme2certifier.acme_srv.trigger.load_config")
    def test_035_config_load(self, mock_load_cfg, mock_cahandler_load):
        """test _config_load()"""
        parser = configparser.ConfigParser()
        parser["Foo"] = {"foo": "bar"}
        mock_load_cfg.return_value = parser
        self.trigger._config_load()
        self.assertTrue(self.trigger.cahandler)

    def test_036_trigger_config_enabled_dict_fallback(self):
        """trigger_config_enabled() handles dict-style configs"""
        from acme2certifier.acme_srv.trigger import trigger_config_enabled

        self.assertTrue(trigger_config_enabled({"Trigger": {"enabled": "on"}}))

    @patch("acme2certifier.acme_srv.trigger.ca_handler_load")
    def test_037_resolve_trigger_endpoint_handler_missing(self, mock_cahandler_load):
        """resolve_trigger_endpoint() logs warning when handler missing"""
        from acme2certifier.acme_srv.trigger import resolve_trigger_endpoint

        mock_cahandler_load.return_value = object()
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            self.assertFalse(
                resolve_trigger_endpoint(
                    self.logger,
                    {"Trigger": {"enabled": "true"}},
                    log_status=True,
                )
            )
        self.assertTrue(
            any(
                "Trigger enabled in config but CA handler could not be loaded" in line
                for line in lcm.output
            )
        )

    @patch("acme2certifier.acme_srv.trigger.trigger_ca_cert_load")
    @patch("acme2certifier.acme_srv.trigger.trigger_hmac_keys_load")
    @patch("acme2certifier.acme_srv.trigger.ca_handler_load")
    def test_038_resolve_trigger_endpoint_enabled(
        self, mock_cahandler_load, mock_keys, mock_ca_cert
    ):
        """resolve_trigger_endpoint() logs info when endpoint enabled"""
        from acme2certifier.acme_srv.trigger import resolve_trigger_endpoint

        cahandler_cls = type("FakeCAhandler", (), {"supports_trigger": True})
        mock_cahandler_load.return_value = SimpleNamespace(CAhandler=cahandler_cls)
        mock_keys.return_value = (["k1", "k2"], False)
        mock_ca_cert.return_value = "/tmp/ca.pem"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertTrue(
                resolve_trigger_endpoint(
                    self.logger,
                    {"Trigger": {"enabled": "true"}},
                    log_status=True,
                )
            )
        self.assertTrue(
            any("Trigger HTTP endpoint enabled" in line for line in lcm.output)
        )

    def test_039_parse_hmac_missing_signature(self):
        """parse() returns 403 when HMAC required and signature missing"""
        self.trigger.auth_disabled = False
        self.trigger.hmac_keys = ["secret"]
        result = self.trigger.parse(b'{"payload":"Zm9v"}', headers={})
        self.assertEqual(403, result["code"])
        self.assertEqual("trigger authentication failed", result["data"]["detail"])

    def test_040_parse_hmac_wrong_signature(self):
        """parse() returns 403 for wrong HMAC"""
        self.trigger.auth_disabled = False
        self.trigger.hmac_keys = ["secret"]
        body = b'{"payload":"Zm9v"}'
        result = self.trigger.parse(
            body, headers={"HTTP_X_A2C_TRIGGER_SIGNATURE": "00" * 32}
        )
        self.assertEqual(403, result["code"])

    def test_041_parse_hmac_accepts_any_configured_key(self):
        """parse() accepts HMAC from any key in hmac_keys list"""
        import hashlib
        import hmac as hm

        self.trigger.auth_disabled = False
        self.trigger.hmac_keys = ["new-key", "old-key"]
        body = b'{"payload":"Zm9v"}'
        sig = hm.new(b"old-key", body, hashlib.sha256).hexdigest()
        with patch.object(
            self.trigger, "_payload_process", return_value=(200, "OK", None)
        ):
            result = self.trigger.parse(
                body, headers={"HTTP_X_A2C_TRIGGER_SIGNATURE": sig}
            )
        self.assertEqual(200, result["code"])

    @patch("acme2certifier.acme_srv.helpers.trigger_auth.security_disable_acknowledged")
    def test_042_auth_disable_requires_gate(self, mock_ack):
        """auth_disable without gate keeps auth on"""
        from acme2certifier.acme_srv.helpers.trigger_auth import trigger_hmac_keys_load

        mock_ack.return_value = False
        parser = configparser.ConfigParser()
        parser["Trigger"] = {
            "hmac_keys": '["k1"]',
            "auth_disable": "True",
        }
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            keys, disabled = trigger_hmac_keys_load(self.logger, parser)
        self.assertEqual(["k1"], keys)
        self.assertFalse(disabled)
        self.assertTrue(any("auth_disable is set but ignored" in line for line in lcm.output))

    @patch("acme2certifier.acme_srv.helpers.trigger_auth.security_disable_acknowledged")
    def test_043_auth_disable_with_gate(self, mock_ack):
        """auth_disable with gate disables HMAC"""
        from acme2certifier.acme_srv.helpers.trigger_auth import trigger_hmac_keys_load

        mock_ack.return_value = True
        parser = configparser.ConfigParser()
        parser["Trigger"] = {"auth_disable": "True"}
        with self.assertLogs("test_a2c", level="CRITICAL") as lcm:
            _keys, disabled = trigger_hmac_keys_load(self.logger, parser)
        self.assertTrue(disabled)
        self.assertTrue(any("auth_disable" in line for line in lcm.output))

    def test_044_cert_store_rejects_failed_chain_verify(self):
        """_cert_store rejects when ca_cert chain verify fails"""
        self._chain_verify_patcher.stop()
        with patch(
            "acme2certifier.acme_srv.trigger.trigger_cert_chain_verify",
            return_value=False,
        ):
            code, message, _detail = self.trigger._cert_store(
                "bundle", "raw", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
            )
        self.assertEqual(400, code)
        self.assertEqual("certificate verification failed", message)
        self._chain_verify_patcher = patch(
            "acme2certifier.acme_srv.trigger.trigger_cert_chain_verify",
            return_value=True,
        )
        self._chain_verify_patcher.start()

    def test_045_trigger_hmac_keys_file_json(self):
        """hmac_keys_file JSON list is loaded"""
        import tempfile
        import os
        from acme2certifier.acme_srv.helpers.trigger_auth import trigger_hmac_keys_load

        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write('["file-key-1", "file-key-2"]\n')
            path = handle.name
        try:
            parser = configparser.ConfigParser()
            parser["Trigger"] = {"hmac_keys_file": path}
            keys, disabled = trigger_hmac_keys_load(self.logger, parser)
            self.assertEqual(["file-key-1", "file-key-2"], keys)
            self.assertFalse(disabled)
        finally:
            os.unlink(path)

    def test_046_trigger_signature_from_headers_variants(self):
        """header extraction covers META keys and case-insensitive fallback"""
        from acme2certifier.acme_srv.helpers.trigger_auth import (
            trigger_signature_from_headers,
        )

        self.assertIsNone(trigger_signature_from_headers(None))
        self.assertIsNone(trigger_signature_from_headers({}))
        self.assertEqual(
            "abc",
            trigger_signature_from_headers({"X-A2C-Trigger-Signature": " abc "}),
        )
        self.assertEqual(
            "def",
            trigger_signature_from_headers({"x-a2c-trigger-signature": "def"}),
        )
        self.assertEqual(
            "ghi",
            trigger_signature_from_headers({"X_A2C_Trigger_Signature": " ghi "}),
        )
        self.assertIsNone(
            trigger_signature_from_headers({"x-a2c-trigger-signature": ""})
        )
        self.assertIsNone(
            trigger_signature_from_headers({"X_A2C_Trigger_Signature": ""})
        )
        self.assertIsNone(trigger_signature_from_headers({"Other": "x"}))

    def test_047_normalize_and_load_keys_file_line_and_empty(self):
        """_load_keys_from_file handles empty, line format, comments, bad JSON list"""
        import tempfile
        import os
        from acme2certifier.acme_srv.helpers.trigger_auth import (
            _load_keys_from_file,
            _normalize_key_list,
        )

        self.assertEqual([], _normalize_key_list([None, "  "]))
        self.assertEqual(["a", "a"], _normalize_key_list([None, "  ", "a", "a"]))
        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write("\n")
            empty_path = handle.name
        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write("# comment\nkey-one\n\nkey-two\n")
            line_path = handle.name
        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write("[1, 2]\n")
            array_path = handle.name
        try:
            self.assertEqual([], _load_keys_from_file(self.logger, empty_path))
            self.assertEqual(
                ["key-one", "key-two"],
                _load_keys_from_file(self.logger, line_path),
            )
            with patch(
                "acme2certifier.acme_srv.helpers.trigger_auth.json.loads",
                return_value={"not": "list"},
            ):
                with self.assertRaises(ValueError):
                    _load_keys_from_file(self.logger, array_path)
        finally:
            os.unlink(empty_path)
            os.unlink(line_path)
            os.unlink(array_path)

    def test_048_hmac_keys_load_parse_errors_and_missing_file(self):
        """hmac_keys parse errors and missing hmac_keys_file are logged"""
        import configparser
        from acme2certifier.acme_srv.helpers.trigger_auth import trigger_hmac_keys_load

        parser = configparser.ConfigParser()
        parser["Trigger"] = {"hmac_keys": '{"not":"list"}'}
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            keys, disabled = trigger_hmac_keys_load(self.logger, parser)
        self.assertEqual([], keys)
        self.assertFalse(disabled)
        self.assertTrue(any("Failed to parse [Trigger] hmac_keys" in x for x in lcm.output))

        parser2 = configparser.ConfigParser()
        parser2["Trigger"] = {"hmac_keys_file": "/no/such/trigger_keys.json"}
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            keys, _disabled = trigger_hmac_keys_load(self.logger, parser2)
        self.assertEqual([], keys)
        self.assertTrue(any("hmac_keys_file" in x for x in lcm.output))

    def test_049_hmac_keys_load_file_read_error_and_dict_config(self):
        """hmac_keys_file load exception and plain-dict config path"""
        import tempfile
        import os
        from acme2certifier.acme_srv.helpers.trigger_auth import trigger_hmac_keys_load

        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write('["ok"]\n')
            path = handle.name
        try:
            with patch(
                "acme2certifier.acme_srv.helpers.trigger_auth._load_keys_from_file",
                side_effect=OSError("boom"),
            ):
                parser = configparser.ConfigParser()
                parser["Trigger"] = {"hmac_keys_file": path}
                with self.assertLogs("test_a2c", level="ERROR") as lcm:
                    keys, _d = trigger_hmac_keys_load(self.logger, parser)
                self.assertEqual([], keys)
                self.assertTrue(
                    any("Failed to load [Trigger] hmac_keys_file" in x for x in lcm.output)
                )
        finally:
            os.unlink(path)

        keys, disabled = trigger_hmac_keys_load(
            self.logger, {"Trigger": {"hmac_keys": '["dict-key"]'}}
        )
        self.assertEqual(["dict-key"], keys)
        self.assertFalse(disabled)
        self.assertEqual(
            ([], False), trigger_hmac_keys_load(self.logger, {"Other": {}})
        )

    def test_050_hmac_keys_getboolean_exception(self):
        """auth_disable getboolean exception falls back to False"""
        from acme2certifier.acme_srv.helpers.trigger_auth import trigger_hmac_keys_load

        class _BrokenBool(configparser.ConfigParser):
            def getboolean(self, section, option, **kwargs):
                raise ValueError("bad bool")

        parser = _BrokenBool()
        parser["Trigger"] = {"hmac_keys": '["k"]', "auth_disable": "maybe"}
        keys, disabled = trigger_hmac_keys_load(self.logger, parser)
        self.assertEqual(["k"], keys)
        self.assertFalse(disabled)

    def test_051_ca_cert_load_paths(self):
        """trigger_ca_cert_load covers missing get, missing file, success"""
        import tempfile
        import os
        from acme2certifier.acme_srv.helpers.trigger_auth import trigger_ca_cert_load

        self.assertIsNone(trigger_ca_cert_load(self.logger, object()))
        self.assertIsNone(trigger_ca_cert_load(self.logger, {"Trigger": {}}))
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            self.assertIsNone(
                trigger_ca_cert_load(
                    self.logger, {"Trigger": {"ca_cert": "/missing/ca.pem"}}
                )
            )
        self.assertTrue(any("[Trigger] ca_cert" in x for x in lcm.output))
        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
            path = handle.name
        try:
            parser = configparser.ConfigParser()
            parser["Trigger"] = {"ca_cert": path}
            self.assertEqual(path, trigger_ca_cert_load(self.logger, parser))
        finally:
            os.unlink(path)

    def test_052_hmac_verify_edge_cases(self):
        """trigger_hmac_verify rejects bad input and accepts matching key"""
        import hashlib
        import hmac as hm
        from acme2certifier.acme_srv.helpers.trigger_auth import trigger_hmac_verify

        body = b"payload"
        self.assertFalse(trigger_hmac_verify(body, None, ["k"]))
        self.assertFalse(trigger_hmac_verify(body, "ab", []))
        self.assertFalse(trigger_hmac_verify(None, "ab", ["k"]))
        self.assertFalse(trigger_hmac_verify(body, "zz", ["k"]))
        sig = hm.new(b"secret", body, hashlib.sha256).hexdigest()
        self.assertTrue(trigger_hmac_verify(body, sig, ["wrong", "secret"]))
        self.assertFalse(trigger_hmac_verify(body, sig, ["wrong"]))

    def test_053_verify_signed_by_branches(self):
        """_verify_signed_by covers issuer mismatch, RSA ok, EC path, failures"""
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
        from cryptography.x509.oid import NameOID
        from acme2certifier.acme_srv.helpers.trigger_auth import _verify_signed_by

        def _name(cn):
            return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

        ca_key = rsa.generate_private_key(65537, 2048)
        ee_key = rsa.generate_private_key(65537, 2048)
        ca = (
            x509.CertificateBuilder()
            .subject_name(_name("ca"))
            .issuer_name(_name("ca"))
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(
                datetime.datetime.now(datetime.timezone.utc)
                - datetime.timedelta(days=1)
            )
            .not_valid_after(
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=1)
            )
            .sign(ca_key, hashes.SHA256())
        )
        leaf = (
            x509.CertificateBuilder()
            .subject_name(_name("ee"))
            .issuer_name(_name("ca"))
            .public_key(ee_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(
                datetime.datetime.now(datetime.timezone.utc)
                - datetime.timedelta(days=1)
            )
            .not_valid_after(
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=1)
            )
            .sign(ca_key, hashes.SHA256())
        )
        self.assertTrue(_verify_signed_by(leaf, ca))
        self.assertFalse(_verify_signed_by(leaf, leaf))

        leaf_bad = MagicMock()
        leaf_bad.issuer = ca.subject
        leaf_bad.signature_hash_algorithm = None
        self.assertFalse(_verify_signed_by(leaf_bad, ca))

        ec_ca_key = ec.generate_private_key(ec.SECP256R1())
        ec_ee_key = ec.generate_private_key(ec.SECP256R1())
        ec_ca = (
            x509.CertificateBuilder()
            .subject_name(_name("ecca"))
            .issuer_name(_name("ecca"))
            .public_key(ec_ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(
                datetime.datetime.now(datetime.timezone.utc)
                - datetime.timedelta(days=1)
            )
            .not_valid_after(
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=1)
            )
            .sign(ec_ca_key, hashes.SHA256())
        )
        ec_leaf = (
            x509.CertificateBuilder()
            .subject_name(_name("ecee"))
            .issuer_name(_name("ecca"))
            .public_key(ec_ee_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(
                datetime.datetime.now(datetime.timezone.utc)
                - datetime.timedelta(days=1)
            )
            .not_valid_after(
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=1)
            )
            .sign(ec_ca_key, hashes.SHA256())
        )
        self.assertTrue(_verify_signed_by(ec_leaf, ec_ca))

        # wrong key type falls through
        weird_issuer = MagicMock()
        weird_issuer.subject = leaf.issuer
        weird_issuer.public_key.return_value = object()
        self.assertFalse(_verify_signed_by(leaf, weird_issuer))

        # verify exception path
        bad_issuer = MagicMock()
        bad_issuer.subject = leaf.issuer
        bad_rsa = MagicMock(spec=rsa.RSAPublicKey)
        bad_rsa.verify.side_effect = Exception("sig")
        bad_issuer.public_key.return_value = bad_rsa
        self.assertFalse(_verify_signed_by(leaf, bad_issuer))

    def test_054_cert_chain_verify_success_and_failures(self):
        """trigger_cert_chain_verify success, load fail, empty trust, bad bundle, no trust"""
        import datetime
        import tempfile
        import os
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        from acme2certifier.acme_srv.helpers.trigger_auth import (
            trigger_cert_chain_verify,
        )

        def _name(cn):
            return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

        def _build(subject, issuer_name, key, issuer_key, ca=False):
            return (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer_name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(
                    datetime.datetime.now(datetime.timezone.utc)
                    - datetime.timedelta(days=1)
                )
                .not_valid_after(
                    datetime.datetime.now(datetime.timezone.utc)
                    + datetime.timedelta(days=1)
                )
                .add_extension(
                    x509.BasicConstraints(ca=ca, path_length=None), critical=True
                )
                .sign(issuer_key, hashes.SHA256())
            )

        ik = rsa.generate_private_key(65537, 2048)
        inter = _build(_name("inter"), _name("inter"), ik, ik, ca=True)
        lk = rsa.generate_private_key(65537, 2048)
        leaf = _build(_name("leaf"), _name("inter"), lk, ik, ca=False)
        tk = rsa.generate_private_key(65537, 2048)
        trust_other = _build(_name("trust"), _name("trust"), tk, tk, ca=True)

        leaf_pem = leaf.public_bytes(serialization.Encoding.PEM).decode()
        inter_pem = inter.public_bytes(serialization.Encoding.PEM).decode()
        other_pem = trust_other.public_bytes(serialization.Encoding.PEM).decode()
        bundle = leaf_pem + inter_pem

        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            self.assertFalse(
                trigger_cert_chain_verify(
                    self.logger, "not-a-cert", None, "/no/ca.pem"
                )
            )
        self.assertTrue(any("Failed to load leaf or ca_cert" in x for x in lcm.output))

        with tempfile.NamedTemporaryFile("wb", delete=False) as handle:
            handle.write(b"")
            empty_path = handle.name
        try:
            with patch(
                "acme2certifier.acme_srv.helpers.trigger_auth.x509.load_pem_x509_certificates",
                return_value=[],
            ), patch(
                "acme2certifier.acme_srv.helpers.trigger_auth.x509.load_pem_x509_certificate",
                return_value=leaf,
            ):
                with self.assertLogs("test_a2c", level="ERROR") as lcm:
                    self.assertFalse(
                        trigger_cert_chain_verify(
                            self.logger, leaf_pem, None, empty_path
                        )
                    )
                self.assertTrue(
                    any("No certificates found" in x for x in lcm.output)
                )
        finally:
            os.unlink(empty_path)

        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write(inter_pem)
            trust_path = handle.name
        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write(other_pem)
            other_path = handle.name
        try:
            self.assertTrue(
                trigger_cert_chain_verify(self.logger, leaf_pem, bundle, trust_path)
            )
            # bytes leaf / bytes bundle
            self.assertTrue(
                trigger_cert_chain_verify(
                    self.logger,
                    leaf_pem.encode(),
                    bundle.encode(),
                    trust_path,
                )
            )
            with self.assertLogs("test_a2c", level="WARNING") as lcm:
                self.assertFalse(
                    trigger_cert_chain_verify(
                        self.logger, leaf_pem, "not-pem-bundle", other_path
                    )
                )
            self.assertTrue(
                any("Could not parse trigger cert_bundle" in x for x in lcm.output)
            )
            with self.assertLogs("test_a2c", level="WARNING") as lcm:
                self.assertFalse(
                    trigger_cert_chain_verify(
                        self.logger, leaf_pem, None, other_path
                    )
                )
            self.assertTrue(any("no issuer for leaf/cert" in x for x in lcm.output))
            with self.assertLogs("test_a2c", level="WARNING") as lcm:
                self.assertFalse(
                    trigger_cert_chain_verify(
                        self.logger, leaf_pem, bundle, other_path
                    )
                )
            self.assertTrue(
                any("trust anchor not reached" in x for x in lcm.output)
            )
        finally:
            os.unlink(trust_path)
            os.unlink(other_path)

    @patch("acme2certifier.acme_srv.trigger.trigger_ca_cert_load")
    @patch("acme2certifier.acme_srv.trigger.trigger_hmac_keys_load")
    @patch("acme2certifier.acme_srv.trigger.ca_handler_load")
    def test_055_resolve_trigger_missing_ca_cert(
        self, mock_cahandler_load, mock_keys, mock_ca_cert
    ):
        """resolve_trigger_endpoint errors when ca_cert missing"""
        from acme2certifier.acme_srv.trigger import resolve_trigger_endpoint

        cahandler_cls = type("FakeCAhandler", (), {"supports_trigger": True})
        mock_cahandler_load.return_value = SimpleNamespace(CAhandler=cahandler_cls)
        mock_keys.return_value = (["k"], False)
        mock_ca_cert.return_value = None
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            self.assertFalse(
                resolve_trigger_endpoint(
                    self.logger,
                    {"Trigger": {"enabled": "true"}},
                    log_status=True,
                )
            )
        self.assertTrue(any("ca_cert is missing" in x for x in lcm.output))

    @patch("acme2certifier.acme_srv.trigger.trigger_ca_cert_load")
    @patch("acme2certifier.acme_srv.trigger.trigger_hmac_keys_load")
    @patch("acme2certifier.acme_srv.trigger.ca_handler_load")
    def test_056_resolve_trigger_missing_hmac_keys(
        self, mock_cahandler_load, mock_keys, mock_ca_cert
    ):
        """resolve_trigger_endpoint errors when hmac keys missing"""
        from acme2certifier.acme_srv.trigger import resolve_trigger_endpoint

        cahandler_cls = type("FakeCAhandler", (), {"supports_trigger": True})
        mock_cahandler_load.return_value = SimpleNamespace(CAhandler=cahandler_cls)
        mock_keys.return_value = ([], False)
        mock_ca_cert.return_value = "/tmp/ca.pem"
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            self.assertFalse(
                resolve_trigger_endpoint(
                    self.logger,
                    {"Trigger": {"enabled": "true"}},
                    log_status=True,
                )
            )
        self.assertTrue(any("no hmac_keys" in x for x in lcm.output))

    def test_057_cert_store_missing_ca_cert(self):
        """_cert_store errors when ca_cert unset"""
        self.trigger.ca_cert = None
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            code, message, _detail = self.trigger._cert_store("b", "r", "pem")
        self.assertEqual(400, code)
        self.assertEqual("certificate verification failed", message)
        self.assertTrue(any("ca_cert not configured" in x for x in lcm.output))


if __name__ == "__main__":
    unittest.main()
