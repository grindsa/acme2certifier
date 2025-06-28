#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for acme2certifier"""
# pylint: disable= C0415, W0212
import unittest
import sys
import os
from OpenSSL import crypto
from unittest.mock import patch, Mock, MagicMock, mock_open
import requests
import configparser

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestACMEHandler(unittest.TestCase):
    """test class for cgi_handler"""

    def setUp(self):
        """setup unittest"""
        import logging

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        from examples.eab_handler.kid_profile_handler import EABhandler

        self.eabhandler = EABhandler(self.logger)
        self.dir_path = os.path.dirname(os.path.realpath(__file__))

    def test_001_default(self):
        """default test which always passes"""
        self.assertEqual("foo", "foo")

    @patch("examples.eab_handler.kid_profile_handler.EABhandler._config_load")
    def test_002__enter__(self, mock_cfg):
        """test enter  called"""
        mock_cfg.return_value = True
        self.eabhandler.__enter__()
        self.assertTrue(mock_cfg.called)

    @patch("examples.eab_handler.kid_profile_handler.load_config")
    def test_003_config_load(self, mock_load_cfg):
        """test _config_load - empty dictionary"""
        parser = configparser.ConfigParser()
        mock_load_cfg.return_value = parser
        self.eabhandler._config_load()
        self.assertFalse(self.eabhandler.key_file)

    @patch("examples.eab_handler.kid_profile_handler.load_config")
    def test_004_config_load(self, mock_load_cfg):
        """test _config_load - bogus values"""
        parser = configparser.ConfigParser()
        parser["foo"] = {"foo": "bar"}
        mock_load_cfg.return_value = parser
        self.eabhandler._config_load()
        self.assertFalse(self.eabhandler.key_file)

    @patch("examples.eab_handler.kid_profile_handler.load_config")
    def test_005_config_load(self, mock_load_cfg):
        """test _config_load - bogus values"""
        parser = configparser.ConfigParser()
        parser["EABhandler"] = {"foo": "bar"}
        mock_load_cfg.return_value = parser
        self.eabhandler._config_load()
        self.assertFalse(self.eabhandler.key_file)

    @patch("examples.eab_handler.kid_profile_handler.load_config")
    def test_006_config_load(self, mock_load_cfg):
        """test _config_load - bogus values"""
        parser = configparser.ConfigParser()
        parser["EABhandler"] = {"key_file": "key_file"}
        mock_load_cfg.return_value = parser
        self.eabhandler._config_load()
        self.assertEqual("key_file", self.eabhandler.key_file)

    def test_007_mac_key_get(self):
        """test mac_key_get without file specified"""
        self.assertFalse(self.eabhandler.mac_key_get(None))

    @patch("builtins.open", mock_open(read_data="foo"), create=True)
    def test_008_mac_key_get(self):
        """test mac_key_get with file but no kid"""
        self.eabhandler.key_file = "file"
        self.assertFalse(self.eabhandler.mac_key_get(None))

    @patch("examples.eab_handler.kid_profile_handler.EABhandler.keyfile_content_load")
    @patch("builtins.open", mock_open(read_data="foo"), create=True)
    def test_009_mac_key_get(self, mock_json):
        """test mac_key_get json reader return bogus values"""
        self.eabhandler.key_file = "file"
        mock_json.return_value = {"foo", "bar"}
        self.assertFalse(self.eabhandler.mac_key_get("kid"))

    @patch("examples.eab_handler.kid_profile_handler.EABhandler.keyfile_content_load")
    @patch("builtins.open", mock_open(read_data="foo"), create=True)
    def test_010_mac_key_get(self, mock_json):
        """test mac_key_get json match"""
        self.eabhandler.key_file = "file"
        mock_json.return_value = {"kid": {"hmac": "mac", "foo": "bar"}}
        self.assertEqual("mac", self.eabhandler.mac_key_get("kid"))

    @patch("examples.eab_handler.kid_profile_handler.EABhandler.keyfile_content_load")
    @patch("builtins.open", mock_open(read_data="foo"), create=True)
    def test_011_mac_key_get(self, mock_json):
        """test mac_key_get json no match"""
        self.eabhandler.key_file = "file"
        mock_json.return_value = {"kid1": "mac"}
        self.assertFalse(self.eabhandler.mac_key_get("kid"))

    @patch("examples.eab_handler.kid_profile_handler.EABhandler.keyfile_content_load")
    @patch("builtins.open", mock_open(read_data="foo"), create=True)
    def test_012_mac_key_get(self, mock_json):
        """test mac_key_get json load exception"""
        self.eabhandler.key_file = "file"
        mock_json.side_effect = Exception("ex_json_load")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(self.eabhandler.mac_key_get("kid"))
        self.assertIn(
            "ERROR:test_a2c:EABhandler.mac_key_get() error: ex_json_load", lcm.output
        )

    @patch("json.load")
    @patch("builtins.open", mock_open(read_data="foo"), create=True)
    def test_013_mac_key_get(self, mock_json):
        """test mac_key_get json match"""
        self.eabhandler.key_file = "file"
        mock_json.return_value = {"kid": {"foo": "bar"}}
        self.assertFalse(self.eabhandler.mac_key_get("kid"))

    def test_014_wllist_check(self):
        """CAhandler._wllist_check failed check as empty entry"""
        list_ = ["bar.foo$", "foo.bar$"]
        entry = None
        self.assertFalse(self.eabhandler._wllist_check(entry, list_))

    def test_015_wllist_check(self):
        """CAhandler._wllist_check check against empty list"""
        list_ = []
        entry = "host.bar.foo"
        self.assertTrue(self.eabhandler._wllist_check(entry, list_))

    def test_016_wllist_check(self):
        """CAhandler._wllist_check successful check against 1st element of a list"""
        list_ = ["bar.foo$", "foo.bar$"]
        entry = "host.bar.foo"
        self.assertTrue(self.eabhandler._wllist_check(entry, list_))

    def test_017_wllist_check(self):
        """CAhandler._wllist_check unsuccessful as endcheck failed"""
        list_ = ["bar.foo$", "foo.bar$"]
        entry = "host.bar.foo.bar_"
        self.assertFalse(self.eabhandler._wllist_check(entry, list_))

    def test_018_wllist_check(self):
        """CAhandler._wllist_check successful without $"""
        list_ = ["bar.foo", "foo.bar$"]
        entry = "host.bar.foo.bar_"
        self.assertTrue(self.eabhandler._wllist_check(entry, list_))

    def test_019_wllist_check(self):
        """CAhandler._wllist_check wildcard check"""
        list_ = ["bar.foo$", "foo.bar$"]
        entry = "*.bar.foo"
        self.assertTrue(self.eabhandler._wllist_check(entry, list_))

    def test_020_wllist_check(self):
        """CAhandler._wllist_check failed wildcard check"""
        list_ = ["bar.foo$", "foo.bar$"]
        entry = "*.bar.foo_"
        self.assertFalse(self.eabhandler._wllist_check(entry, list_))

    def test_021_wllist_check(self):
        """CAhandler._wllist_check not end check"""
        list_ = ["bar.foo$", "foo.bar$"]
        entry = "bar.foo gna"
        self.assertFalse(self.eabhandler._wllist_check(entry, list_))

    def test_022_wllist_check(self):
        """CAhandler._wllist_check $ at the end"""
        list_ = ["bar.foo$", "foo.bar$"]
        entry = "bar.foo$"
        self.assertFalse(self.eabhandler._wllist_check(entry, list_))

    def test_023_wllist_check(self):
        """CAhandler._wllist_check check against empty list flip"""
        list_ = []
        entry = "host.bar.foo"
        self.assertFalse(self.eabhandler._wllist_check(entry, list_, True))

    def test_024_wllist_check(self):
        """CAhandler._wllist_check flip successful check"""
        list_ = ["bar.foo$", "foo.bar$"]
        entry = "host.bar.foo"
        self.assertFalse(self.eabhandler._wllist_check(entry, list_, True))

    def test_025_wllist_check(self):
        """CAhandler._wllist_check flip unsuccessful check"""
        list_ = ["bar.foo$", "foo.bar$"]
        entry = "host.bar.foo"
        self.assertFalse(self.eabhandler._wllist_check(entry, list_, True))

    def test_026_wllist_check(self):
        """CAhandler._wllist_check unsuccessful whildcard check"""
        list_ = ["foo.bar$", r"\*.bar.foo"]
        entry = "host.bar.foo"
        self.assertFalse(self.eabhandler._wllist_check(entry, list_))

    def test_027_wllist_check(self):
        """CAhandler._wllist_check successful whildcard check"""
        list_ = ["foo.bar$", r"\*.bar.foo"]
        entry = "*.bar.foo"
        self.assertTrue(self.eabhandler._wllist_check(entry, list_))

    def test_028_wllist_check(self):
        """CAhandler._wllist_check successful whildcard in list but not in string"""
        list_ = ["foo.bar$", "*.bar.foo"]
        entry = "foo.bar.foo"
        self.assertTrue(self.eabhandler._wllist_check(entry, list_))

    @patch("examples.eab_handler.kid_profile_handler.csr_san_get")
    def test_029_chk_san_lists_get(self, mock_san):
        """CAhandler._chk_san_lists_get()"""
        csr = "csr"
        mock_san.return_value = ["dns:foo.bar", "dns:bar.foo"]
        self.assertEqual(
            (["foo.bar", "bar.foo"], []), self.eabhandler._chk_san_lists_get(csr)
        )

    @patch("examples.eab_handler.kid_profile_handler.csr_san_get")
    def test_030_chk_san_lists_get(self, mock_san):
        """CAhandler._chk_san_lists_get()"""
        csr = "csr"
        mock_san.return_value = ["dns:foo.bar", "bar.foo"]
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                (["foo.bar"], [False]), self.eabhandler._chk_san_lists_get(csr)
            )
        self.assertIn(
            "INFO:test_a2c:SAN list parsing failed at entry: bar.foo",
            lcm.output,
        )

    @patch("examples.eab_handler.kid_profile_handler.csr_san_get")
    def test_031_chk_san_lists_get(self, mock_san):
        """CAhandler._chk_san_lists_get()"""
        csr = "csr"
        mock_san.return_value = None
        self.assertEqual(([], []), self.eabhandler._chk_san_lists_get(csr))

    @patch("examples.eab_handler.kid_profile_handler.csr_cn_get")
    def test_032_cn_add(self, mock_cnget):
        """CAhandler._cn_add()"""
        csr = "csr"
        san_list = ["foo.bar", "bar.foo"]
        mock_cnget.return_value = "foobar.bar"
        self.assertEqual(
            ["foo.bar", "bar.foo", "foobar.bar"], self.eabhandler._cn_add(csr, san_list)
        )

    @patch("examples.eab_handler.kid_profile_handler.csr_cn_get")
    def test_033_cn_add(self, mock_cnget):
        """CAhandler._cn_add()"""
        csr = "csr"
        san_list = ["foo.bar", "bar.foo"]
        mock_cnget.return_value = "bar.foo"
        self.assertEqual(["foo.bar", "bar.foo"], self.eabhandler._cn_add(csr, san_list))

    @patch("builtins.open", mock_open(read_data='{"foo": "bar"}'), create=True)
    def test_034_key_file_load(self):
        """CAhandler._cn_add()"""
        self.eabhandler.key_file = "file"
        self.assertEqual({"foo": "bar"}, self.eabhandler.key_file_load())

    @patch("builtins.open", mock_open(read_data="foobar:\n  foo: foobar"), create=True)
    def test_035_key_file_load(self):
        """CAhandler._key_file_load()"""
        self.eabhandler.key_file = "file"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                {"foobar": {"foo": "foobar"}}, self.eabhandler.key_file_load()
            )
        self.assertIn(
            "ERROR:test_a2c:EABhandler.keyfile_content_load(): error: Expecting value: line 1 column 1 (char 0)",
            lcm.output,
        )

    @patch("builtins.open", mock_open(read_data='{"foo": "bar"}'), create=True)
    def test_036_key_file_load(self):
        """CAhandler._key_file_load()"""
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(self.eabhandler.key_file_load())
        self.assertIn(
            "ERROR:test_a2c:EABhandler.key_file_load() no key_file specified",
            lcm.output,
        )

    @patch("builtins.open", mock_open(read_data="foobar: ="), create=True)
    def test_037_key_file_load(self):
        """CAhandler._key_file_load()"""
        self.eabhandler.key_file = "file"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(self.eabhandler.key_file_load())
        self.assertIn(
            "ERROR:test_a2c:EABhandler.keyfile_content_load(): error: Expecting value: line 1 column 1 (char 0)",
            lcm.output,
        )
        self.assertIn(
            "ERROR:test_a2c:EABhandler.keyfile_content_load(): error: could not determine a constructor for the tag 'tag:yaml.org,2002:value'\n  in \"<unicode string>\", line 1, column 9:\n    foobar: =\n            ^",
            lcm.output,
        )

    @patch("examples.eab_handler.kid_profile_handler.EABhandler.keyfile_content_load")
    @patch("builtins.open", mock_open(read_data='{"foo": "bar"}'), create=True)
    def test_038_key_file_load(self, mock_load):
        """CAhandler._key_file_load()"""
        self.eabhandler.key_file = "file"
        mock_load.side_effect = Exception("ex_load")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(self.eabhandler.key_file_load())
        self.assertIn(
            "ERROR:test_a2c:EABhandler.key_file_load() error: ex_load", lcm.output
        )

    @patch("examples.eab_handler.kid_profile_handler.EABhandler._wllist_check")
    @patch("examples.eab_handler.kid_profile_handler.EABhandler._cn_add")
    @patch("examples.eab_handler.kid_profile_handler.EABhandler._chk_san_lists_get")
    def test_039_allowed_domains_check(self, mock_san, mock_cn, mock_wlc):
        """test EABhanlder._allowed_domains_check()"""
        mock_san.return_value = (["foo"], [])
        mock_cn.return_value = ["foo", "bar"]
        mock_wlc.side_effect = [True, True]
        self.assertFalse(
            self.eabhandler._allowed_domains_check("csr", ["domain", "list"])
        )

    @patch("examples.eab_handler.kid_profile_handler.EABhandler._wllist_check")
    @patch("examples.eab_handler.kid_profile_handler.EABhandler._cn_add")
    @patch("examples.eab_handler.kid_profile_handler.EABhandler._chk_san_lists_get")
    def test_040_allowed_domains_check(self, mock_san, mock_cn, mock_wlc):
        """test EABhanlder._allowed_domains_check()"""
        mock_san.return_value = (["foo"], [False])
        mock_cn.return_value = ["foo", "bar"]
        mock_wlc.side_effect = [True, True]
        self.assertEqual(
            "Either CN or SANs are not allowed by profile",
            self.eabhandler._allowed_domains_check("csr", ["domain", "list"]),
        )

    @patch("examples.eab_handler.kid_profile_handler.EABhandler._wllist_check")
    @patch("examples.eab_handler.kid_profile_handler.EABhandler._cn_add")
    @patch("examples.eab_handler.kid_profile_handler.EABhandler._chk_san_lists_get")
    def test_041_allowed_domains_check(self, mock_san, mock_cn, mock_wlc):
        """test EABhanlder._allowed_domains_check()"""
        mock_san.return_value = (["foo"], [])
        mock_cn.return_value = ["foo", "bar"]
        mock_wlc.side_effect = [False, True]
        self.assertEqual(
            "Either CN or SANs are not allowed by profile",
            self.eabhandler._allowed_domains_check("csr", ["domain", "list"]),
        )

    @patch("examples.eab_handler.kid_profile_handler.EABhandler.key_file_load")
    def test_042_eab_profile_get(self, mock_prof):
        """test EABhandler._eab_profile_get()"""
        mock_prof.return_value = {
            "eab_kid": {"cahandler": {"foo_parameter": "bar_parameter"}}
        }
        models_mock = MagicMock()
        models_mock.DBstore().certificate_lookup.return_value = {
            "foo": "bar",
            "order__account__eab_kid": "eab_kid",
        }
        modules = {"acme_srv.db_handler": models_mock}
        patch.dict("sys.modules", modules).start()
        self.assertEqual(
            {"foo_parameter": "bar_parameter"}, self.eabhandler.eab_profile_get("csr")
        )

    @patch("examples.eab_handler.kid_profile_handler.EABhandler.key_file_load")
    def test_043_eab_profile_get(self, mock_prof):
        """test EABhandler._eab_profile_get()"""
        mock_prof.return_value = {
            "eab_kid": {"cahandler1": {"foo_parameter": "bar_parameter"}}
        }
        models_mock = MagicMock()
        models_mock.DBstore().certificate_lookup.return_value = {
            "foo": "bar",
            "order__account__eab_kid": "eab_kid",
        }
        modules = {"acme_srv.db_handler": models_mock}
        patch.dict("sys.modules", modules).start()
        self.assertFalse(self.eabhandler.eab_profile_get("csr"))

    @patch("examples.eab_handler.kid_profile_handler.EABhandler.key_file_load")
    def test_044_eab_profile_get(self, mock_prof):
        """test EABhandler._eab_profile_get()"""
        mock_prof.return_value = {
            "eab_kid": {"cahandler": {"foo_parameter": "bar_parameter"}}
        }
        models_mock = MagicMock()
        models_mock.DBstore().certificate_lookup.return_value = {
            "foo": "bar",
            "1order__account__eab_kid": "eab_kid",
        }
        modules = {"acme_srv.db_handler": models_mock}
        patch.dict("sys.modules", modules).start()
        self.assertFalse(self.eabhandler.eab_profile_get("csr"))

    @patch("examples.eab_handler.kid_profile_handler.EABhandler.key_file_load")
    def test_045_eab_profile_get(self, mock_prof):
        """test EABhandler._eab_profile_get()"""
        mock_prof.return_value = {
            "eab_kid": {"cahandler": {"foo_parameter": "bar_parameter"}}
        }
        models_mock = MagicMock()
        models_mock.DBstore().certificate_lookup.return_value = {
            "foo": "bar",
            "order__account__eab_kid": "eab_kid1",
        }
        modules = {"acme_srv.db_handler": models_mock}
        patch.dict("sys.modules", modules).start()
        self.assertFalse(self.eabhandler.eab_profile_get("csr"))

    @patch("examples.eab_handler.kid_profile_handler.EABhandler.key_file_load")
    def test_046_eab_profile_get(self, mock_prof):
        """test EABhandler._eab_profile_get()"""
        mock_prof.return_value = {
            "eab_kid": {"cahandler": {"foo_parameter": "bar_parameter"}}
        }
        models_mock = MagicMock()
        models_mock.DBstore().certificate_lookup.side_effect = Exception("ex_db_lookup")
        modules = {"acme_srv.db_handler": models_mock}
        patch.dict("sys.modules", modules).start()
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(self.eabhandler.eab_profile_get("csr"))
        self.assertIn(
            "ERROR:test_a2c:EABhandler._eab_profile_get() database error: ex_db_lookup",
            lcm.output,
        )


if __name__ == "__main__":

    unittest.main()
