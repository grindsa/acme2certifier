#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for a2c_msicpr_connection_test.py"""

# pylint: disable=C0415
import sys
import unittest
from unittest.mock import MagicMock, patch


class TestA2CMsicprConnectionTest(unittest.TestCase):
    """tests for a2c_msicpr_connection_test"""

    def test_001_main_creates_request(self):
        """main() builds CAhandler and calls request_create()"""
        mock_cm = MagicMock()
        mock_handler = MagicMock()
        mock_cm.__enter__.return_value = mock_handler
        mock_cm.__exit__.return_value = False

        with (
            patch(
                "acme2certifier.tools.a2c_msicpr_connection_test.logger_setup",
                return_value=MagicMock(),
            ) as mock_log,
            patch(
                "acme2certifier.tools.a2c_msicpr_connection_test.CAhandler",
                return_value=mock_cm,
            ) as mock_cls,
        ):
            from acme2certifier.tools import a2c_msicpr_connection_test as mod

            mod.main()

        mock_log.assert_called_once_with(True)
        mock_cls.assert_called_once()
        mock_handler.request_create.assert_called_once()

    def test_002_module_main_entrypoint(self):
        """``__main__`` guard calls main()"""
        import runpy
        from pathlib import Path

        from acme2certifier.tools import a2c_msicpr_connection_test as mod

        path = Path(mod.__file__)
        sys.modules.pop("acme2certifier.tools.a2c_msicpr_connection_test", None)
        mock_cm = MagicMock()
        mock_cm.__enter__.return_value = MagicMock()
        mock_cm.__exit__.return_value = False
        with (
            patch(
                "acme2certifier.acme_srv.helper.logger_setup", return_value=MagicMock()
            ),
            patch(
                "acme2certifier.cahandlers.msicpr_ca_handler.CAhandler",
                return_value=mock_cm,
            ),
        ):
            runpy.run_path(str(path), run_name="__main__")


if __name__ == "__main__":
    unittest.main()
