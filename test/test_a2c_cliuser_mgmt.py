#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for a2c_cliuser_mgmt.py"""

# pylint: disable=C0415, W0212
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch


class TestA2CCliuserMgmt(unittest.TestCase):
    """tests for a2c_cliuser_mgmt"""

    def setUp(self):
        """import module under test"""
        from acme2certifier.tools import a2c_cliuser_mgmt

        self.mod = a2c_cliuser_mgmt

    def test_001_validate_keyfile_path_empty(self):
        """validate_keyfile_path rejects empty path"""
        with self.assertRaises(ValueError) as cm:
            self.mod.validate_keyfile_path("")
        self.assertIn("keyfile path is empty", str(cm.exception))

    def test_002_validate_keyfile_path_outside(self):
        """validate_keyfile_path rejects path outside cwd"""
        with self.assertRaises(ValueError) as cm:
            self.mod.validate_keyfile_path("/tmp/nope.json")
        self.assertIn("Path must be within", str(cm.exception))

    def test_003_validate_keyfile_path_missing(self):
        """validate_keyfile_path rejects missing file"""
        with self.assertRaises(ValueError) as cm:
            self.mod.validate_keyfile_path("missing_cliuser_key.json")
        self.assertIn("does not exist", str(cm.exception))

    def test_004_validate_keyfile_path_ok(self):
        """validate_keyfile_path accepts file in cwd"""
        with tempfile.NamedTemporaryFile(
            mode="w", dir=".", suffix=".json", delete=False
        ) as handle:
            handle.write("{}")
            name = os.path.basename(handle.name)
        try:
            result = self.mod.validate_keyfile_path(name)
            self.assertTrue(os.path.isfile(result))
        finally:
            os.unlink(name)

    def test_005_file_load(self):
        """file_load reads file contents"""
        with tempfile.NamedTemporaryFile(
            mode="w", dir=".", suffix=".json", delete=False
        ) as handle:
            handle.write('{"kty":"RSA"}')
            name = os.path.basename(handle.name)
        try:
            self.assertEqual('{"kty":"RSA"}', self.mod.file_load(name))
        finally:
            os.unlink(name)

    def test_006_arg_parse_list(self):
        """arg_parse builds list config"""
        with patch(
            "sys.argv",
            ["a2c-cliuser-mgmt", "--list", "-d", "-c", "-r", "-u", "-e", "a@b.c"],
        ):
            debug, config_dic = self.mod.arg_parse()
        self.assertTrue(debug)
        self.assertTrue(config_dic["list"])
        self.assertTrue(config_dic["permissions"]["certificateadmin"])
        self.assertTrue(config_dic["permissions"]["reportadmin"])
        self.assertTrue(config_dic["permissions"]["cliadmin"])
        self.assertEqual("a@b.c", config_dic["email"])

    def test_007_arg_parse_delete_with_jwkname(self):
        """arg_parse builds delete config with jwkname"""
        with patch("sys.argv", ["prog", "--delete", "-n", "kid1"]):
            debug, config_dic = self.mod.arg_parse()
        self.assertFalse(debug)
        self.assertTrue(config_dic["delete"])
        self.assertEqual("kid1", config_dic["jwkname"])

    def test_008_arg_parse_keyfile_ok(self):
        """arg_parse loads jwk from keyfile"""
        with tempfile.NamedTemporaryFile(
            mode="w", dir=".", suffix=".json", delete=False
        ) as handle:
            json.dump({"kty": "RSA", "n": "x"}, handle)
            name = os.path.basename(handle.name)
        try:
            with patch("sys.argv", ["prog", "-k", name]):
                _debug, config_dic = self.mod.arg_parse()
            self.assertEqual({"kty": "RSA", "n": "x"}, config_dic["jwk"])
        finally:
            os.unlink(name)

    def test_009_arg_parse_keyfile_error(self):
        """arg_parse prints error for invalid keyfile"""
        with patch("sys.argv", ["prog", "-k", "/tmp/bad.json"]), patch(
            "builtins.print"
        ) as mock_print:
            _debug, config_dic = self.mod.arg_parse()
        self.assertNotIn("jwk", config_dic)
        mock_print.assert_called()
        self.assertIn("Error:", mock_print.call_args[0][0])

    def test_010_main_calls_cli_usermgr(self):
        """main() calls housekeeping.cli_usermgr"""
        mock_cm = MagicMock()
        mock_hk = MagicMock()
        mock_cm.__enter__.return_value = mock_hk
        mock_cm.__exit__.return_value = False
        with patch.object(
            self.mod, "arg_parse", return_value=(False, {"list": True})
        ), patch.object(
            self.mod, "logger_setup", return_value=MagicMock()
        ), patch.object(self.mod, "Housekeeping", return_value=mock_cm):
            self.mod.main()
        mock_hk.cli_usermgr.assert_called_once()
        cfg = mock_hk.cli_usermgr.call_args[0][0]
        self.assertFalse(cfg["silent"])
        self.assertTrue(cfg["list"])

    def test_011_module_main_entrypoint(self):
        """``__main__`` guard calls main()"""
        import runpy

        sys.modules.pop("acme2certifier.tools.a2c_cliuser_mgmt", None)
        mock_cm = MagicMock()
        mock_cm.__enter__.return_value = MagicMock()
        mock_cm.__exit__.return_value = False
        with patch("sys.argv", ["prog", "--list"]), patch(
            "acme2certifier.acme_srv.helper.logger_setup", return_value=MagicMock()
        ), patch(
            "acme2certifier.acme_srv.housekeeping.Housekeeping",
            return_value=mock_cm,
        ):
            runpy.run_module(
                "acme2certifier.tools.a2c_cliuser_mgmt",
                run_name="__main__",
                alter_sys=True,
            )


if __name__ == "__main__":
    unittest.main()
