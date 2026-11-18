#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for a2c_mscepces_connection_test.py"""

# pylint: disable=C0415
import sys
import unittest
from unittest.mock import MagicMock, patch


class TestA2CMscepcesConnectionTest(unittest.TestCase):
    """tests for a2c_mscepces_connection_test"""

    def test_001_main_ok(self):
        """main() calls handler_check and prints OK when no error"""
        mock_cm = MagicMock()
        mock_handler = MagicMock()
        mock_handler.handler_check.return_value = None
        mock_cm.__enter__.return_value = mock_handler
        mock_cm.__exit__.return_value = False

        with (
            patch(
                "acme2certifier.tools.a2c_mscepces_connection_test.logger_setup",
                return_value=MagicMock(),
            ) as mock_log,
            patch(
                "acme2certifier.tools.a2c_mscepces_connection_test.CAhandler",
                return_value=mock_cm,
            ) as mock_cls,
            patch(
                "acme2certifier.tools.a2c_mscepces_connection_test.print"
            ) as mock_print,
        ):
            from acme2certifier.tools import a2c_mscepces_connection_test as mod

            mod.main()

        mock_log.assert_called_once_with(True)
        mock_cls.assert_called_once_with(True, mock_log.return_value)
        mock_handler.handler_check.assert_called_once_with()
        mock_print.assert_called_once_with("mscepces connection check OK")

    def test_002_main_raises_on_error(self):
        """main() exits with SystemExit when handler_check returns an error"""
        mock_cm = MagicMock()
        mock_handler = MagicMock()
        mock_handler.handler_check.return_value = "ces_url missing"
        mock_cm.__enter__.return_value = mock_handler
        mock_cm.__exit__.return_value = False

        with (
            patch(
                "acme2certifier.tools.a2c_mscepces_connection_test.logger_setup",
                return_value=MagicMock(),
            ),
            patch(
                "acme2certifier.tools.a2c_mscepces_connection_test.CAhandler",
                return_value=mock_cm,
            ),
        ):
            from acme2certifier.tools import a2c_mscepces_connection_test as mod

            with self.assertRaises(SystemExit) as ctx:
                mod.main()
        self.assertIn("ces_url missing", str(ctx.exception))

    def test_003_module_main_entrypoint(self):
        """``__main__`` guard calls main()"""
        import runpy
        from pathlib import Path

        from acme2certifier.tools import a2c_mscepces_connection_test as mod

        path = Path(mod.__file__)
        sys.modules.pop("acme2certifier.tools.a2c_mscepces_connection_test", None)
        mock_cm = MagicMock()
        mock_handler = MagicMock()
        mock_handler.handler_check.return_value = None
        mock_cm.__enter__.return_value = mock_handler
        mock_cm.__exit__.return_value = False
        with (
            patch(
                "acme2certifier.acme_srv.helper.logger_setup", return_value=MagicMock()
            ),
            patch(
                "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler",
                return_value=mock_cm,
            ),
            patch("builtins.print"),
        ):
            runpy.run_path(str(path), run_name="__main__")


if __name__ == "__main__":
    unittest.main()
