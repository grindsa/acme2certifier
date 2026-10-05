#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for a2c_schema_update.py"""

# pylint: disable=C0415
import sys
import unittest
from unittest.mock import MagicMock, patch


class TestA2CSchemaUpdate(unittest.TestCase):
    """tests for a2c_schema_update dispatch"""

    MODULE = "acme2certifier.tools.a2c_schema_update"

    def setUp(self):
        """fresh module import"""
        sys.modules.pop(self.MODULE, None)
        import acme2certifier.tools as tools_pkg

        if hasattr(tools_pkg, "a2c_schema_update"):
            delattr(tools_pkg, "a2c_schema_update")

    def tearDown(self):
        """cleanup"""
        if self.MODULE in sys.modules:
            mod = sys.modules[self.MODULE]
            mod.django = None
            mod.call_command = None
            mod.Status = None
            mod.Housekeeping = None
            mod.__dbversion__ = None
        sys.modules.pop(self.MODULE, None)

    def test_001_resolve_mode_explicit(self):
        """explicit --mode wins"""
        from acme2certifier.tools.a2c_schema_update import resolve_mode

        self.assertEqual(resolve_mode("django"), "django")
        self.assertEqual(resolve_mode("wsgi"), "wsgi")

    def test_002_resolve_mode_from_cfg_or_env(self):
        """unset --mode uses explicit cfg/env selection only"""
        with patch(
            "acme2certifier.acme_srv.helpers.db_handler_select.resolve_db_handler",
            return_value=("acme2certifier.dbhandlers.django_handler", "cfg"),
        ):
            from acme2certifier.tools.a2c_schema_update import resolve_mode

            self.assertEqual(resolve_mode(None), "django")

    def test_002b_resolve_mode_default_is_none(self):
        """runtime default (no handler set) does not imply wsgi for schema update"""
        with patch(
            "acme2certifier.acme_srv.helpers.db_handler_select.resolve_db_handler",
            return_value=("acme2certifier.dbhandlers.wsgi_handler", "default"),
        ):
            from acme2certifier.tools.a2c_schema_update import resolve_mode

            self.assertIsNone(resolve_mode(None))

    @patch("acme2certifier.tools.a2c_schema_update.run_wsgi_schema_update")
    @patch("acme2certifier.tools.a2c_schema_update.run_django_schema_update")
    def test_003_main_mode_django(self, mock_django, mock_wsgi):
        """--mode django calls django path"""
        mock_django.return_value = 0
        from acme2certifier.tools import a2c_schema_update as mod

        self.assertEqual(mod.main(["--mode", "django"]), 0)
        mock_django.assert_called_once()
        mock_wsgi.assert_not_called()

    @patch("acme2certifier.tools.a2c_schema_update.run_wsgi_schema_update")
    @patch("acme2certifier.tools.a2c_schema_update.run_django_schema_update")
    def test_004_main_mode_wsgi(self, mock_django, mock_wsgi):
        """--mode wsgi calls wsgi path"""
        mock_wsgi.return_value = 0
        from acme2certifier.tools import a2c_schema_update as mod

        self.assertEqual(mod.main(["--mode", "wsgi"]), 0)
        mock_wsgi.assert_called_once()
        mock_django.assert_not_called()

    @patch("acme2certifier.tools.a2c_schema_update.run_wsgi_schema_update")
    @patch("acme2certifier.tools.a2c_schema_update.run_django_schema_update")
    @patch("acme2certifier.tools.a2c_schema_update.resolve_mode", return_value="django")
    def test_005_main_auto_django(self, _resolve, mock_django, mock_wsgi):
        """no --mode uses resolve_mode"""
        mock_django.return_value = 0
        from acme2certifier.tools import a2c_schema_update as mod

        self.assertEqual(mod.main([]), 0)
        mock_django.assert_called_once()
        mock_wsgi.assert_not_called()

    @patch("acme2certifier.tools.a2c_schema_update.run_wsgi_schema_update")
    @patch("acme2certifier.tools.a2c_schema_update.run_django_schema_update")
    @patch("acme2certifier.tools.a2c_schema_update.resolve_mode", return_value=None)
    @patch("builtins.print")
    def test_005b_main_skips_when_handler_unset(
        self, mock_print, _resolve, mock_django, mock_wsgi
    ):
        """unset handler warns and exits 0 without updating"""
        from acme2certifier.tools import a2c_schema_update as mod

        self.assertEqual(mod.main([]), 0)
        mock_django.assert_not_called()
        mock_wsgi.assert_not_called()
        printed = " ".join(str(c) for c in mock_print.call_args_list)
        self.assertIn("WARNING", printed)
        self.assertIn("Skipping schema update", printed)

    @patch("acme2certifier.tools.a2c_schema_update.run_wsgi_schema_update")
    @patch("acme2certifier.tools.a2c_schema_update.run_django_schema_update")
    @patch("acme2certifier.tools.a2c_schema_update.resolve_mode", return_value="wsgi")
    def test_005c_main_auto_wsgi(self, _resolve, mock_django, mock_wsgi):
        """explicit cfg/env wsgi runs wsgi path only"""
        mock_wsgi.return_value = 0
        from acme2certifier.tools import a2c_schema_update as mod

        self.assertEqual(mod.main([]), 0)
        mock_wsgi.assert_called_once()
        mock_django.assert_not_called()

    def test_006_run_wsgi_calls_wsgi_handler(self):
        """wsgi path uses dbhandlers.wsgi_handler.DBstore"""
        mock_db = MagicMock()
        with (
            patch(
                "acme2certifier.acme_srv.helper.logger_setup",
                return_value=MagicMock(),
            ),
            patch(
                "acme2certifier.dbhandlers.wsgi_handler.DBstore",
                return_value=mock_db,
            ) as mock_cls,
        ):
            from acme2certifier.tools import a2c_schema_update as mod

            self.assertEqual(mod.run_wsgi_schema_update(), 0)
        mock_cls.assert_called_once()
        mock_db.db_update.assert_called_once()

    @patch("builtins.print")
    def test_006b_run_wsgi_error(self, mock_print):
        """wsgi path returns 1 and prints when DBstore raises"""
        with (
            patch(
                "acme2certifier.acme_srv.helper.logger_setup",
                return_value=MagicMock(),
            ),
            patch(
                "acme2certifier.dbhandlers.wsgi_handler.DBstore",
                side_effect=RuntimeError("wsgi boom"),
            ),
        ):
            from acme2certifier.tools import a2c_schema_update as mod

            self.assertEqual(mod.run_wsgi_schema_update(), 1)
        printed = " ".join(str(c) for c in mock_print.call_args_list)
        self.assertIn("Error during WSGI database update", printed)
        self.assertIn("wsgi boom", printed)

    @patch("acme2certifier.tools.a2c_schema_update.update_db_version", return_value=True)
    @patch(
        "acme2certifier.tools.a2c_schema_update.update_status_fields", return_value=True
    )
    @patch("acme2certifier.tools.a2c_schema_update.run_migrations", return_value=True)
    @patch("acme2certifier.tools.a2c_schema_update.setup_django", return_value=True)
    def test_007_run_django_success(
        self, mock_setup, mock_mig, mock_status, mock_ver
    ):
        """django path orchestrates migrate/status/version"""
        from acme2certifier.tools import a2c_schema_update as mod

        self.assertEqual(mod.run_django_schema_update(), 0)
        mock_setup.assert_called_once()
        mock_mig.assert_called_once()
        mock_status.assert_called_once()
        mock_ver.assert_called_once()


if __name__ == "__main__":
    unittest.main()
