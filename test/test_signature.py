#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for account.py"""
# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212
import unittest
import sys
import configparser
from unittest.mock import patch, MagicMock

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
        models_mock.acme_srv.db_handler.DBstore.return_value = FakeDBStore
        modules = {"acme_srv.db_handler": models_mock}
        patch.dict("sys.modules", modules).start()
        import logging

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        from acme_srv.signature import Signature

        self.signature = Signature(False, "http://tester.local", self.logger)

    def test_001_signature__jwk_load(self):
        """test jwk load"""
        # Mock the dbstore instance on the existing signature object
        self.signature.dbstore = MagicMock()
        self.signature.dbstore.jwk_load.return_value = "foo"

        self.assertEqual("foo", self.signature._jwk_loader(1))

    def test_002_signature_check(self):
        """test Signature.check() without having content"""
        self.assertEqual(
            (False, "urn:ietf:params:acme:error:malformed", None),
            self.signature.check("foo", None),
        )

    @patch("acme_srv.signature.Signature._jwk_loader")
    def test_003_signature_check(self, mock_jwk):
        """test Signature.check() while pubkey lookup failed"""
        mock_jwk.return_value = {}
        self.assertEqual(
            (False, "urn:ietf:params:acme:error:accountDoesNotExist", None),
            self.signature.check("foo", 1),
        )

    @patch("acme_srv.signature.signature_check")
    @patch("acme_srv.signature.Signature._jwk_loader")
    def test_004_signature_check(self, mock_jwk, mock_sig):
        """test successful Signature.check()"""
        mock_jwk.return_value = {"foo": "bar"}
        mock_sig.return_value = (True, None)
        self.assertEqual((True, None, None), self.signature.check("foo", 1))

    def test_005_signature_check(self):
        """test successful Signature.check() without account_name and use_emb_key False"""
        self.assertEqual(
            (False, "urn:ietf:params:acme:error:accountDoesNotExist", None),
            self.signature.check(None, 1, False),
        )

    def test_006_signature_check(self):
        """test successful Signature.check() without account_name and use_emb_key True but having a corrupted protected header"""
        protected = {"foo": "foo"}
        self.assertEqual(
            (False, "urn:ietf:params:acme:error:accountDoesNotExist", None),
            self.signature.check(None, 1, True, protected),
        )

    @patch("acme_srv.signature.DBstore")
    @patch("acme_srv.signature.signature_check")
    def test_007_signature_check(self, mock_sig, mock_dbstore_class):
        """test successful Signature.check() with account_name and use_emb_key True, sigcheck returns something"""
        # Setup dbstore mock to return a key
        mock_dbstore_instance = MagicMock()
        mock_dbstore_instance.jwk_load.return_value = {"key": "value"}
        mock_dbstore_class.return_value = mock_dbstore_instance

        # Setup signature_check mock
        mock_sig.return_value = ("result", "error")

        # Create a new signature instance with the mocked dbstore
        from acme_srv.signature import Signature

        signature = Signature(False, "http://tester.local", self.logger)

        self.assertEqual(("result", "error", None), signature.check("foo", 1, True))

    @patch("acme_srv.signature.signature_check")
    def test_008_signature_check(self, mock_sig):
        """test successful Signature.check() without account_name and use_emb_key True, sigcheck returns something"""
        mock_sig.return_value = ("result", "error")
        protected = {"url": "url", "jwk": "jwk"}
        self.assertEqual(
            ("result", "error", None), self.signature.check(None, 1, True, protected)
        )

    @patch("acme_srv.signature.DBstore")
    def test_009_signature__jwk_load(self, mock_dbstore_class):
        """test jwk load  - dbstore.jwk_load() raises an exception"""
        # Setup mock to raise exception
        mock_dbstore_instance = MagicMock()
        mock_dbstore_instance.jwk_load.side_effect = Exception("exc_sig_jw_load")
        mock_dbstore_class.return_value = mock_dbstore_instance

        # Create a new signature instance with the mocked dbstore
        from acme_srv.signature import Signature

        signature = Signature(False, "http://tester.local", self.logger)

        with self.assertLogs("test_a2c", level="INFO") as lcm:
            signature._jwk_loader(1)
        self.assertIn(
            "CRITICAL:test_a2c:Database error: failed to load JWK for account id 1: exc_sig_jw_load",
            lcm.output,
        )

    @patch("acme_srv.signature.signature_check")
    def test_010_signature_eab_check(self, mock_sigchk):
        """test eab_check  -  result and error"""
        content = "content"
        mac_key = "mac_key"
        mock_sigchk.return_value = ("result", "error")
        self.assertEqual(
            ("result", "error"), self.signature.eab_check(content, mac_key)
        )

    @patch("acme_srv.signature.signature_check")
    def test_011_signature_eab_check(self, mock_sigchk):
        """test eab_check  -  result no error"""
        content = "content"
        mac_key = "mac_key"
        mock_sigchk.return_value = ("result", None)
        self.assertEqual(("result", None), self.signature.eab_check(content, mac_key))

    @patch("acme_srv.signature.signature_check")
    def test_012_signature_eab_check(self, mock_sigchk):
        """test eab_check  -  result false and  error"""
        content = "content"
        mac_key = "mac_key"
        mock_sigchk.return_value = (False, "error")
        self.assertEqual((False, "error"), self.signature.eab_check(content, mac_key))

    @patch("acme_srv.signature.signature_check")
    def test_013_signature_eab_check(self, mock_sigchk):
        """test eab_check  -  content None"""
        content = None
        mac_key = "mac_key"
        mock_sigchk.return_value = (False, "error")
        self.assertEqual(
            (False, "urn:ietf:params:acme:error:malformed"),
            self.signature.eab_check(content, mac_key),
        )

    @patch("acme_srv.signature.signature_check")
    def test_014_signature_eab_check(self, mock_sigchk):
        """test eab_check  -  mac_key None"""
        content = "content"
        mac_key = None
        mock_sigchk.return_value = (False, "error")
        self.assertEqual(
            (False, "urn:ietf:params:acme:error:malformed"),
            self.signature.eab_check(content, mac_key),
        )

    @patch("acme_srv.signature.signature_check")
    def test_015_signature_eab_check(self, mock_sigchk):
        """test eab_check  -  mac_key and content None"""
        content = None
        mac_key = None
        mock_sigchk.return_value = (False, "error")
        self.assertEqual(
            (False, "urn:ietf:params:acme:error:malformed"),
            self.signature.eab_check(content, mac_key),
        )

    @patch("acme_srv.signature.load_config")
    def test_016__init(self, mock_load_cfg):
        """test _config_load account with url prefix without tailing slash configured"""
        parser = configparser.ConfigParser()
        parser["Directory"] = {"foo": "bar", "url_prefix": "url_prefix"}
        mock_load_cfg.return_value = parser
        self.signature.__init__(False, "http://tester.local", self.logger)
        self.assertEqual("url_prefix/acme/revokecert", self.signature.revocation_path)

    @patch("acme_srv.signature.load_config")
    def test_017__init(self, mock_load_cfg):
        """test _config_load account with url prefix without tailing slash configured"""
        parser = configparser.ConfigParser()
        parser["Directory"] = {"foo": "bar"}
        mock_load_cfg.return_value = parser
        self.signature.__init__(False, "http://tester.local", self.logger)
        self.assertEqual("/acme/revokecert", self.signature.revocation_path)

    def test_018_signature_check(self):
        """test Signature.cli_check() without having aname"""
        self.assertEqual(
            (False, "urn:ietf:params:acme:error:accountDoesNotExist", None),
            self.signature.cli_check(None, "content"),
        )

    def test_019_signature_check(self):
        """test Signature.check() without having content"""
        self.assertEqual(
            (False, "urn:ietf:params:acme:error:malformed", None),
            self.signature.cli_check("foo", None),
        )

    @patch("acme_srv.signature.Signature._jwk_loader")
    def test_020_signature_check(self, mock_jwk):
        """test Signature.check() while pubkey lookup failed"""
        mock_jwk.return_value = {}
        self.assertEqual(
            (False, "urn:ietf:params:acme:error:accountDoesNotExist", None),
            self.signature.cli_check("foo", 1),
        )

    @patch("acme_srv.signature.signature_check")
    @patch("acme_srv.signature.Signature._jwk_loader")
    def test_021_signature_check(self, mock_jwk, mock_sig):
        """test successful Signature.check()"""
        mock_jwk.return_value = {"foo": "bar"}
        mock_sig.return_value = (True, None)
        self.assertEqual((True, None, None), self.signature.cli_check("foo", 1))

    @patch("acme_srv.signature.signature_check")
    @patch("acme_srv.signature.Signature._jwk_loader")
    def test_022_signature_check(self, mock_jwk, mock_sig):
        """test successful Signature.check() without account_name  sigcheck returns something"""
        mock_jwk.return_value = {"foo": "bar"}
        mock_sig.return_value = ("result", "error")
        self.assertEqual(("result", "error", None), self.signature.cli_check("foo", 1))

    def test_023_cli_check_no_content(self):
        """Signature.cli_check() returns malformed error if content is None"""
        self.assertEqual(
            (False, "urn:ietf:params:acme:error:malformed", None),
            self.signature.cli_check("foo", None),
        )

    def test_024_cli_check_no_aname(self):
        """Signature.cli_check() returns accountDoesNotExist error if aname is None"""
        self.assertEqual(
            (False, "urn:ietf:params:acme:error:accountDoesNotExist", None),
            self.signature.cli_check(None, "content"),
        )

    @patch("acme_srv.signature.Signature._jwk_loader")
    def test_025_cli_check_pubkey_none(self, mock_jwk):
        """Signature.cli_check() returns accountDoesNotExist error if pubkey is None"""
        mock_jwk.return_value = None
        self.assertEqual(
            (False, "urn:ietf:params:acme:error:accountDoesNotExist", None),
            self.signature.cli_check("foo", "content"),
        )

    @patch("acme_srv.signature.signature_check")
    @patch("acme_srv.signature.Signature._jwk_loader")
    def test_026_cli_check_success(self, mock_jwk, mock_sig):
        """Signature.cli_check() returns result from signature_check"""
        mock_jwk.return_value = {"foo": "bar"}
        mock_sig.return_value = (True, None)
        self.assertEqual((True, None, None), self.signature.cli_check("foo", "content"))

    def test_027_check_no_content(self):
        """Signature.check() returns malformed error if content is None"""
        self.assertEqual(
            (False, "urn:ietf:params:acme:error:malformed", None),
            self.signature.check("foo", None),
        )

    @patch("acme_srv.signature.Signature._jwk_loader")
    def test_028_check_pubkey_none(self, mock_jwk):
        """Signature.check() returns accountDoesNotExist error if pubkey is None"""
        mock_jwk.return_value = None
        self.assertEqual(
            (False, "urn:ietf:params:acme:error:accountDoesNotExist", None),
            self.signature.check("foo", "content"),
        )

    @patch("acme_srv.signature.signature_check")
    @patch("acme_srv.signature.Signature._jwk_loader")
    def test_029_check_success(self, mock_jwk, mock_sig):
        """Signature.check() returns result from signature_check"""
        mock_jwk.return_value = {"foo": "bar"}
        mock_sig.return_value = (True, None)
        self.assertEqual((True, None, None), self.signature.check("foo", "content"))

    def test_030_check_emb_key_no_protected(self):
        """Signature.check() returns accountDoesNotExist error if use_emb_key True but protected is None"""
        self.assertEqual(
            (False, "urn:ietf:params:acme:error:accountDoesNotExist", None),
            self.signature.check(None, "content", True, None),
        )

    def test_031_check_emb_key_no_jwk(self):
        """Signature.check() returns accountDoesNotExist error if use_emb_key True but protected lacks jwk"""
        protected = {"foo": "bar"}
        self.assertEqual(
            (False, "urn:ietf:params:acme:error:accountDoesNotExist", None),
            self.signature.check(None, "content", True, protected),
        )

    @patch("acme_srv.signature.signature_check")
    def test_032_check_emb_key_success(self, mock_sig):
        """Signature.check() returns result from signature_check with embedded jwk"""
        protected = {"jwk": {"foo": "bar"}}
        mock_sig.return_value = (True, None)
        self.assertEqual(
            (True, None, None), self.signature.check(None, "content", True, protected)
        )

    def test_033_check_no_aname_no_emb_key(self):
        """Signature.check() returns accountDoesNotExist error if no aname and use_emb_key False"""
        self.assertEqual(
            (False, "urn:ietf:params:acme:error:accountDoesNotExist", None),
            self.signature.check(None, "content", False),
        )

    def test_034_eab_check_no_content(self):
        """Signature.eab_check() returns malformed error if content is None"""
        self.assertEqual(
            (False, "urn:ietf:params:acme:error:malformed"),
            self.signature.eab_check(None, "mac_key"),
        )

    def test_035_eab_check_no_mac_key(self):
        """Signature.eab_check() returns malformed error if mac_key is None"""
        self.assertEqual(
            (False, "urn:ietf:params:acme:error:malformed"),
            self.signature.eab_check("content", None),
        )

    @patch("acme_srv.signature.signature_check")
    def test_036_eab_check_success(self, mock_sig):
        """Signature.eab_check() returns result from signature_check"""
        mock_sig.return_value = (True, None)
        self.assertEqual((True, None), self.signature.eab_check("content", "mac_key"))

    @patch("acme_srv.signature.signature_check")
    def test_037_eab_check_error(self, mock_sig):
        """Signature.eab_check() returns error from signature_check"""
        mock_sig.return_value = (False, "error")
        self.assertEqual(
            (False, "error"), self.signature.eab_check("content", "mac_key")
        )


if __name__ == "__main__":
    unittest.main()
