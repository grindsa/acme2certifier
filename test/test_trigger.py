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

    def test_006b_trigger_parse_disabled(self):
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

    def test_007_trigger_parse(self):
        """Trigger.parse() with wrong payload"""
        payload = '{"foo": "bar"}'
        result = {
            "header": {},
            "code": 400,
            "data": {"detail": "payload missing", "type": "malformed", "status": 400},
        }
        self.assertEqual(result, self.trigger.parse(payload))

    def test_008_trigger_parse(self):
        """Trigger.parse() with empty payload key"""
        payload = '{"payload": ""}'
        result = {
            "header": {},
            "code": 400,
            "data": {"detail": "payload empty", "type": "malformed", "status": 400},
        }
        self.assertEqual(result, self.trigger.parse(payload))

    @patch("acme2certifier.acme_srv.trigger.Trigger._payload_process")
    def test_009_trigger_parse(self, mock_process):
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
    def test_010_trigger_parse(self, mock_process):
        """Trigger.parse() with payload mock result 200"""
        payload = '{"payload": "foo"}'
        mock_process.return_value = (200, "message", "detail")
        result = {
            "header": {},
            "code": 200,
            "data": {"detail": "detail", "type": "message", "status": 200},
        }
        self.assertEqual(result, self.trigger.parse(payload))

    def test_011_trigger__payload_process(self):
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

    def test_012_trigger__payload_process(self):
        """Trigger._payload_process() without certbunde and cert_raw"""
        payload = {"payload": "foo"}
        ca_handler_module = importlib.import_module(
            "acme2certifier.cahandlers.skeleton_ca_handler"
        )
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=("error", None, None))
        self.assertEqual((400, "error", None), self.trigger._payload_process(payload))

    def test_013_trigger__payload_process(self):
        """Trigger._payload_process() with bundle and without cart_raw"""
        payload = {"payload": "foo"}
        ca_handler_module = importlib.import_module(
            "acme2certifier.cahandlers.skeleton_ca_handler"
        )
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=("error", "bundle", None))
        self.assertEqual((400, "error", None), self.trigger._payload_process(payload))

    def test_014_trigger__payload_process(self):
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
    def test_015_trigger__payload_process(
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
    def test_016_trigger__payload_process(
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
    def test_017_trigger__payload_process(
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
    def test_018_trigger__payload_process(
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
            {"cert_name": "certificate_name1", "order_name": "order_name1"},
            {"cert_name": "certificate_name2", "order_name": "order_name2"},
        ]
        self.assertEqual((200, "OK", None), self.trigger._payload_process(payload))

    @patch("acme2certifier.acme_srv.trigger.b64_decode")
    @patch("acme2certifier.acme_srv.trigger.cert_der2pem")
    @patch("acme2certifier.acme_srv.trigger.Trigger._certname_lookup")
    @patch("acme2certifier.acme_srv.trigger.convert_byte_to_string")
    def test_020_trigger__payload_process(
        self, mock_cobystr, mock_lookup, mock_der2pem, mock_b64dec
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
            {"cert_name": "certificate_name2", "order_name": "order_name2"},
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

    @patch("acme2certifier.acme_srv.trigger.b64_decode")
    @patch("acme2certifier.acme_srv.trigger.cert_der2pem")
    @patch("acme2certifier.acme_srv.trigger.Trigger._certname_lookup")
    @patch("acme2certifier.acme_srv.trigger.convert_byte_to_string")
    def test_021_trigger__payload_process(
        self, mock_cobystr, mock_lookup, mock_der2pem, mock_b64dec
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
            {"cert_name": "certificate_name2", "order_name": "order_name2"},
        ]
        self.trigger.dbstore.certificate_add.side_effect = Exception(
            "exc_trigger_order_add"
        )
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.trigger._payload_process("payload")
        self.assertIn(
            "CRITICAL:test_a2c:Database error: failed to update order status during trigger processing: exc_trigger_order_upd",
            lcm.output,
        )

    @patch("acme2certifier.acme_srv.trigger.load_config")
    def test_022_config_load(self, mock_load_cfg):
        """test _config_load missing ca_handler"""
        mock_load_cfg.return_value = {}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.trigger._config_load()
        self.assertIn(
            "ERROR:test_a2c:CAhandler configuration missing in config file", lcm.output
        )
        self.assertFalse(self.trigger.enabled)

    @patch("acme2certifier.acme_srv.trigger.ca_handler_load")
    @patch("acme2certifier.acme_srv.trigger.load_config")
    def test_022b_config_load_trigger_enabled_with_support(
        self, mock_load_cfg, mock_ca_load
    ):
        """_config_load sets enabled when config+supports_trigger"""
        parser = configparser.ConfigParser()
        parser["Trigger"] = {"enabled": "True"}
        mock_load_cfg.return_value = parser

        class _Handler:
            supports_trigger = True

        mock_ca_load.return_value = MagicMock(CAhandler=_Handler)
        self.trigger._config_load()
        self.assertTrue(self.trigger.enabled)

    @patch("acme2certifier.acme_srv.trigger.ca_handler_load")
    def test_022c_resolve_trigger_endpoint_misconfig_warns(self, mock_ca_load):
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

    def test_022d_resolve_trigger_endpoint_default_off(self):
        """absent [Trigger] → False"""
        from acme2certifier.acme_srv.trigger import resolve_trigger_endpoint

        parser = configparser.ConfigParser()
        self.assertFalse(
            resolve_trigger_endpoint(self.logger, parser, log_status=False)
        )

    @patch("acme2certifier.acme_srv.trigger.Trigger._config_load")
    def test_023__enter__(self, mock_cfg):
        """test enter"""
        mock_cfg.return_value = True
        self.trigger.__enter__()
        self.assertTrue(mock_cfg.called)

    @patch("acme2certifier.acme_srv.trigger.load_config")
    def test_024_config_load(self, mock_load_cfg):
        """test _config_load empty config"""
        parser = configparser.ConfigParser()
        # parser['Account'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.trigger._config_load()
        self.assertFalse(self.trigger.tnauthlist_support)
        self.assertIn(
            "ERROR:test_a2c:CAhandler configuration missing in config file", lcm.output
        )

    @patch("acme2certifier.acme_srv.trigger.load_config")
    def test_025_config_load(self, mock_load_cfg):
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
    def test_026_config_load(self, mock_load_cfg, mock_imp):
        """test _config_load missing ca_handler"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"handler_file": "foo"}
        mock_load_cfg.return_value = parser
        mock_imp.return_value = Mock()
        self.trigger._config_load()
        self.assertTrue(self.trigger.cahandler)

    @patch("importlib.import_module")
    @patch("acme2certifier.acme_srv.trigger.load_config")
    def test_027_config_load(self, mock_load_cfg, mock_imp):
        """test _config_load missing ca_handler"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"foo": "bar"}
        mock_load_cfg.return_value = parser
        mock_imp.return_value = Mock()
        self.trigger._config_load()
        self.assertTrue(self.trigger.cahandler)

    @patch("acme2certifier.acme_srv.trigger.load_config")
    def test_028_config_load(self, mock_load_cfg):
        """test _config_load empty config"""
        parser = configparser.ConfigParser()
        parser["Order"] = {"tnauthlist_support": False}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.trigger._config_load()
        self.assertFalse(self.trigger.tnauthlist_support)

    @patch("acme2certifier.acme_srv.trigger.load_config")
    def test_029_config_load(self, mock_load_cfg):
        """test _config_load empty config"""
        parser = configparser.ConfigParser()
        parser["Order"] = {"tnauthlist_support": True}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.trigger._config_load()
        self.assertTrue(self.trigger.tnauthlist_support)

    @patch("acme2certifier.acme_srv.trigger.ca_handler_load")
    @patch("acme2certifier.acme_srv.trigger.load_config")
    def test_030_config_load(self, mock_load_cfg, mock_cahandler_load):
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
    def test_031_config_load(self, mock_load_cfg, mock_cahandler_load):
        """test _config_load()"""
        parser = configparser.ConfigParser()
        parser["Foo"] = {"foo": "bar"}
        mock_load_cfg.return_value = parser
        self.trigger._config_load()
        self.assertTrue(self.trigger.cahandler)

    def test_032_trigger_config_enabled_dict_fallback(self):
        """trigger_config_enabled() handles dict-style configs"""
        from acme2certifier.acme_srv.trigger import trigger_config_enabled

        self.assertTrue(trigger_config_enabled({"Trigger": {"enabled": "on"}}))

    @patch("acme2certifier.acme_srv.trigger.ca_handler_load")
    def test_033_resolve_trigger_endpoint_handler_missing(self, mock_cahandler_load):
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

    @patch("acme2certifier.acme_srv.trigger.ca_handler_load")
    def test_034_resolve_trigger_endpoint_enabled(self, mock_cahandler_load):
        """resolve_trigger_endpoint() logs info when endpoint enabled"""
        from acme2certifier.acme_srv.trigger import resolve_trigger_endpoint

        cahandler_cls = type("FakeCAhandler", (), {"supports_trigger": True})
        mock_cahandler_load.return_value = SimpleNamespace(CAhandler=cahandler_cls)
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


if __name__ == "__main__":
    unittest.main()
