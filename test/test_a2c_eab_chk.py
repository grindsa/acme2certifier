#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for a2c_eab_chk.py"""

# pylint: disable=C0415, W0212
import logging
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch


class TestA2CEABChk(unittest.TestCase):
    """tests for a2c_eab_chk"""

    def setUp(self):
        """import module and logger"""
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        from acme2certifier.tools import a2c_eab_chk

        self.mod = a2c_eab_chk

    def test_001_summary_print(self):
        """_summary_print prints entry count"""
        with patch("builtins.print") as mock_print:
            self.mod._summary_print(self.logger, {"a": 1, "b": 2})
        mock_print.assert_called_once_with("Summary: 2 entries in kid_file")

    def test_002_filter_eab_dic(self):
        """_filter_eab_dic keeps matching keyid"""
        result = self.mod._filter_eab_dic(
            self.logger, {"kid1": {"hmac": "x"}, "kid2": {"hmac": "y"}}, "kid1"
        )
        self.assertEqual({"kid1": {"hmac": "x"}}, result)

    def test_003_eab_dic_print_summary_only(self):
        """_eab_dic_print with summary flag"""
        with patch.object(self.mod, "_summary_print") as mock_sum, patch(
            "builtins.print"
        ) as mock_print:
            self.mod._eab_dic_print(
                self.logger,
                {"k": {"hmac": "h"}},
                {"summary": True, "verbose": False, "veryverbose": False},
            )
        mock_sum.assert_called_once()
        mock_print.assert_not_called()

    def test_004_eab_dic_print_verbose_hmac(self):
        """_eab_dic_print verbose prints hmac values"""
        with patch("builtins.print") as mock_print:
            self.mod._eab_dic_print(
                self.logger,
                {"kid": {"hmac": "secret"}},
                {"summary": False, "verbose": True, "veryverbose": False},
            )
        mock_print.assert_called_with("kid: secret")

    def test_005_eab_dic_print_verbose_no_hmac(self):
        """_eab_dic_print verbose prints raw value without hmac"""
        with patch("builtins.print") as mock_print:
            self.mod._eab_dic_print(
                self.logger,
                {"kid": "plain"},
                {"summary": False, "verbose": True, "veryverbose": False},
            )
        mock_print.assert_called_with("kid: plain")

    def test_006_eab_dic_print_veryverbose(self):
        """_eab_dic_print veryverbose dumps yaml"""
        with patch("builtins.print") as mock_print, patch(
            "acme2certifier.tools.a2c_eab_chk.yaml.dump", return_value="yaml-out"
        ):
            self.mod._eab_dic_print(
                self.logger,
                {"kid": {"hmac": "h"}},
                {"summary": False, "verbose": False, "veryverbose": True},
            )
        mock_print.assert_called_with("yaml-out")

    def test_007_arg_parse_defaults_to_summary(self):
        """arg_parse sets summary when neither keyid nor summary given"""
        with patch("sys.argv", ["prog", "-c", "acme_srv.cfg"]):
            debug, config_dic = self.mod.arg_parse()
        self.assertFalse(debug)
        self.assertTrue(config_dic["summary"])
        self.assertEqual("acme_srv.cfg", config_dic["configfile"])

    def test_008_arg_parse_keyid_and_verbose(self):
        """arg_parse accepts keyid and verbose flags"""
        with patch(
            "sys.argv", ["prog", "-c", "cfg", "-k", "kid1", "-v", "-d", "-vv"]
        ):
            debug, config_dic = self.mod.arg_parse()
        self.assertTrue(debug)
        self.assertEqual("kid1", config_dic["keyid"])
        self.assertTrue(config_dic["verbose"])
        self.assertTrue(config_dic["veryverbose"])
        self.assertFalse(config_dic["summary"])

    def test_009_eab_dic_load_with_profiling(self):
        """eab_dic_load uses profile module when profiling enabled"""
        mock_handler_cls = MagicMock()
        mock_cm = MagicMock()
        mock_handler = MagicMock()
        mock_handler.key_file_load.return_value = {"kid": {"hmac": "x"}}
        mock_cm.__enter__.return_value = mock_handler
        mock_cm.__exit__.return_value = False
        mock_handler_cls.return_value = mock_cm

        with patch.object(
            self.mod, "config_eab_profile_load", return_value=(True, mock_handler_cls)
        ), patch.object(self.mod, "eab_handler_load") as mock_load:
            result = self.mod.eab_dic_load(self.logger, {"EABhandler": {}})
        self.assertEqual({"kid": {"hmac": "x"}}, result)
        mock_load.assert_not_called()

    def test_010_eab_dic_load_without_profiling(self):
        """eab_dic_load falls back to eab_handler_load"""
        mock_module = MagicMock()
        mock_cm = MagicMock()
        mock_handler = MagicMock()
        mock_handler.key_file_load.return_value = {"a": 1}
        mock_cm.__enter__.return_value = mock_handler
        mock_cm.__exit__.return_value = False
        mock_module.EABhandler.return_value = mock_cm

        with patch.object(
            self.mod, "config_eab_profile_load", return_value=(False, None)
        ), patch.object(self.mod, "eab_handler_load", return_value=mock_module):
            result = self.mod.eab_dic_load(self.logger, {"EABhandler": {}})
        self.assertEqual({"a": 1}, result)

    def test_011_main_missing_configfile(self):
        """main() reports missing configfile"""
        missing = "/no/such/acme_srv.cfg"
        with patch.object(self.mod, "initialize"), patch.object(
            self.mod,
            "arg_parse",
            return_value=(
                False,
                {
                    "configfile": missing,
                    "keyid": None,
                    "summary": True,
                    "verbose": False,
                    "veryverbose": False,
                },
            ),
        ), patch.object(
            self.mod, "logger_setup", return_value=self.logger
        ), patch.object(self.mod, "print_debug") as mock_dbg:
            # Path does not exist; no need to mock os.path.exists
            # (module uses ``import os.path``, so exists is not a module attr).
            self.assertFalse(self.mod.os.path.exists(missing))
            self.mod.main()
        mock_dbg.assert_any_call(True, f"Configfile {missing} not found.")
        mock_dbg.assert_any_call(True, "No EABhandler section in configfile")

    def test_012_main_with_eab_and_keyid(self):
        """main() loads eab dic, filters by keyid, prints"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False) as handle:
            handle.write("[EABhandler]\n")
            cfg = handle.name
        try:
            with patch.object(self.mod, "initialize"), patch.object(
                self.mod,
                "arg_parse",
                return_value=(
                    True,
                    {
                        "configfile": cfg,
                        "keyid": "kid1",
                        "summary": False,
                        "verbose": True,
                        "veryverbose": False,
                    },
                ),
            ), patch.object(
                self.mod, "logger_setup", return_value=self.logger
            ), patch.object(
                self.mod, "load_config", return_value={"EABhandler": {"foo": "bar"}}
            ), patch.object(
                self.mod, "eab_dic_load", return_value={"kid1": {"hmac": "h"}, "kid2": {}}
            ), patch.object(self.mod, "_eab_dic_print") as mock_print:
                self.mod.main()
            mock_print.assert_called_once()
            printed = mock_print.call_args[0][1]
            self.assertEqual({"kid1": {"hmac": "h"}}, printed)
        finally:
            import os

            os.unlink(cfg)

    def test_013_main_empty_eab_skips_print(self):
        """main() skips print when filtered eab dic is empty"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False) as handle:
            handle.write("[EABhandler]\n")
            cfg = handle.name
        try:
            with patch.object(self.mod, "initialize"), patch.object(
                self.mod,
                "arg_parse",
                return_value=(
                    False,
                    {
                        "configfile": cfg,
                        "keyid": "missing",
                        "summary": False,
                        "verbose": False,
                        "veryverbose": False,
                    },
                ),
            ), patch.object(
                self.mod, "logger_setup", return_value=self.logger
            ), patch.object(
                self.mod, "load_config", return_value={"EABhandler": {}}
            ), patch.object(
                self.mod, "eab_dic_load", return_value={"kid1": {"hmac": "h"}}
            ), patch.object(self.mod, "_eab_dic_print") as mock_print:
                self.mod.main()
            mock_print.assert_not_called()
        finally:
            import os

            os.unlink(cfg)

    def test_014_module_main_entrypoint(self):
        """``__main__`` guard calls main()"""
        import importlib
        import runpy
        from pathlib import Path

        path = Path(self.mod.__file__)
        sys.modules.pop("acme2certifier.tools.a2c_eab_chk", None)

        # importlib binds submodules on the parent package; required for
        # unittest.mock.patch on Python 3.10 (``__import__`` alone does not).
        db_handler = importlib.import_module("acme2certifier.acme_srv.db_handler")
        helper = importlib.import_module("acme2certifier.acme_srv.helper")

        with patch("sys.argv", ["prog", "-c", "/no/such.cfg"]), patch.object(
            db_handler, "initialize"
        ), patch.object(helper, "logger_setup", return_value=self.logger), patch.object(
            helper, "print_debug"
        ):
            runpy.run_path(str(path), run_name="__main__")


if __name__ == "__main__":
    unittest.main()
