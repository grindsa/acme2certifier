#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for a2c_db_update.py"""

# pylint: disable=C0415
import sys
import unittest
from unittest.mock import MagicMock, patch


class TestA2CDbUpdate(unittest.TestCase):
    """tests for a2c_db_update"""

    def test_001_main_calls_db_update(self):
        """main() sets up logger and runs db_update"""
        mock_db = MagicMock()
        with patch(
            "acme2certifier.tools.a2c_db_update.logger_setup",
            return_value=MagicMock(),
        ) as mock_log, patch(
            "acme2certifier.tools.a2c_db_update.DBstore", return_value=mock_db
        ) as mock_cls:
            from acme2certifier.tools import a2c_db_update

            a2c_db_update.main()

        mock_log.assert_called_once_with(True)
        mock_cls.assert_called_once()
        mock_db.db_update.assert_called_once()

    def test_002_module_main_entrypoint(self):
        """``__main__`` guard calls main()"""
        import runpy

        sys.modules.pop("acme2certifier.tools.a2c_db_update", None)
        with patch(
            "acme2certifier.acme_srv.helper.logger_setup", return_value=MagicMock()
        ), patch("acme2certifier.acme_srv.db_handler.DBstore") as mock_cls:
            mock_cls.return_value.db_update.return_value = None
            runpy.run_module(
                "acme2certifier.tools.a2c_db_update",
                run_name="__main__",
                alter_sys=True,
            )
            mock_cls.return_value.db_update.assert_called()


if __name__ == "__main__":
    unittest.main()
