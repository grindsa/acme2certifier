#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for a2c_schema_update.py"""

# pylint: disable=C0302, C0415, R0913, R0914
import sys
import unittest
from unittest.mock import MagicMock, call, patch


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
        import acme2certifier.tools as tools_pkg

        if hasattr(tools_pkg, "a2c_schema_update"):
            delattr(tools_pkg, "a2c_schema_update")

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

    def test_008_status_list_defined(self):
        """STATUS_LIST contains expected ACME status values"""
        from acme2certifier.tools import a2c_schema_update as mod

        expected = [
            "invalid",
            "pending",
            "ready",
            "processing",
            "valid",
            "expired",
            "deactivated",
            "revoked",
        ]
        self.assertEqual(mod.STATUS_LIST, expected)
        self.assertEqual(len(mod.STATUS_LIST), 8)

    @patch("builtins.print")
    def test_009_setup_django_success(self, mock_print):
        """setup_django configures Django and sets module globals"""
        from acme2certifier.tools import a2c_schema_update as mod

        mock_django = MagicMock()
        mock_call_command = MagicMock()
        mock_status = MagicMock()
        mock_housekeeping = MagicMock()
        mock_dbversion = "1.0.0"

        with patch.dict(
            "sys.modules",
            {
                "django": mock_django,
                "django.core.management": MagicMock(call_command=mock_call_command),
                "acme2certifier.django_app.models": MagicMock(
                    Status=mock_status, Housekeeping=mock_housekeeping
                ),
                "acme2certifier.acme_srv.version": MagicMock(
                    __dbversion__=mock_dbversion
                ),
            },
        ):
            with patch("acme2certifier.tools.a2c_schema_update.django", mock_django):
                result = mod.setup_django()

        self.assertTrue(result)
        mock_django.setup.assert_called_once()

    @patch("builtins.print")
    def test_010_setup_django_import_error(self, mock_print):
        """setup_django returns False on ImportError"""
        from acme2certifier.tools import a2c_schema_update as mod

        with patch("builtins.__import__", side_effect=ImportError("Django not found")):
            result = mod.setup_django()

        self.assertFalse(result)
        printed = " ".join(str(c) for c in mock_print.call_args_list)
        self.assertIn("Error importing Django modules", printed)

    @patch("builtins.print")
    def test_011_setup_django_general_error(self, mock_print):
        """setup_django returns False when django.setup raises"""
        from acme2certifier.tools import a2c_schema_update as mod

        mock_django = MagicMock()
        mock_django.setup.side_effect = Exception("Setup failed")

        with patch.dict("sys.modules", {"django": mock_django}):
            with patch("acme2certifier.tools.a2c_schema_update.django", mock_django):
                result = mod.setup_django()

        self.assertFalse(result)
        printed = " ".join(str(c) for c in mock_print.call_args_list)
        self.assertIn("Error during Django setup", printed)

    @patch("builtins.print")
    def test_012_run_migrations_success(self, mock_print):
        """run_migrations calls makemigrations and migrate"""
        from acme2certifier.tools import a2c_schema_update as mod

        mock_call_command = MagicMock()
        mod.call_command = mock_call_command

        self.assertTrue(mod.run_migrations())
        mock_call_command.assert_has_calls(
            [
                call("makemigrations", interactive=False),
                call("migrate", interactive=False),
            ]
        )
        stdout = [c[0][0] for c in mock_print.call_args_list]
        self.assertIn("Running Django migrations...", stdout)
        self.assertIn("Migrations applied successfully.", stdout)

    @patch("builtins.print")
    def test_013_run_migrations_error(self, mock_print):
        """run_migrations returns False when call_command fails"""
        from acme2certifier.tools import a2c_schema_update as mod

        mock_call_command = MagicMock()
        mock_call_command.side_effect = Exception("Migration failed")
        mod.call_command = mock_call_command

        self.assertFalse(mod.run_migrations())
        printed = " ".join(str(c) for c in mock_print.call_args_list)
        self.assertIn("Error during Django operations", printed)

    @patch("builtins.print")
    def test_014_update_status_fields_success(self, mock_print):
        """update_status_fields seeds every STATUS_LIST entry"""
        from acme2certifier.tools import a2c_schema_update as mod

        mock_status = MagicMock()
        mock_status.objects.update_or_create.return_value = (MagicMock(), True)
        mod.Status = mock_status

        self.assertTrue(mod.update_status_fields())
        self.assertEqual(mock_status.objects.update_or_create.call_count, 8)

    @patch("builtins.print")
    def test_015_update_status_fields_partial_error(self, mock_print):
        """update_status_fields returns False when one status fails"""
        from acme2certifier.tools import a2c_schema_update as mod

        mock_status = MagicMock()
        mock_status.objects.update_or_create.side_effect = [
            (MagicMock(), True),
            (MagicMock(), True),
            Exception("Database error"),
            (MagicMock(), True),
            (MagicMock(), True),
            (MagicMock(), True),
            (MagicMock(), True),
            (MagicMock(), True),
        ]
        mod.Status = mock_status

        self.assertFalse(mod.update_status_fields())
        printed = " ".join(str(c) for c in mock_print.call_args_list)
        self.assertIn("Error updating status 'ready'", printed)

    @patch("builtins.print")
    def test_016_update_db_version_success(self, mock_print):
        """update_db_version writes housekeeping dbversion row"""
        from acme2certifier.tools import a2c_schema_update as mod

        mock_housekeeping = MagicMock()
        mock_housekeeping.objects.update_or_create.return_value = (MagicMock(), True)
        mod.Housekeeping = mock_housekeeping
        mod.__dbversion__ = "2.0.0"

        self.assertTrue(mod.update_db_version())
        mock_housekeeping.objects.update_or_create.assert_called_once_with(
            name="dbversion", defaults={"name": "dbversion", "value": "2.0.0"}
        )

    @patch("builtins.print")
    def test_017_update_db_version_error(self, mock_print):
        """update_db_version returns False on ORM error"""
        from acme2certifier.tools import a2c_schema_update as mod

        mock_housekeeping = MagicMock()
        mock_housekeeping.objects.update_or_create.side_effect = Exception("DB error")
        mod.Housekeeping = mock_housekeeping
        mod.__dbversion__ = "2.0.0"

        self.assertFalse(mod.update_db_version())
        printed = " ".join(str(c) for c in mock_print.call_args_list)
        self.assertIn("Error updating database version", printed)

    @patch("acme2certifier.tools.a2c_schema_update.update_db_version")
    @patch("acme2certifier.tools.a2c_schema_update.update_status_fields")
    @patch("acme2certifier.tools.a2c_schema_update.run_migrations")
    @patch("acme2certifier.tools.a2c_schema_update.setup_django")
    @patch("builtins.print")
    def test_018_run_django_setup_failure(
        self, mock_print, mock_setup, mock_migrations, mock_status, mock_ver
    ):
        """run_django_schema_update stops when setup_django fails"""
        from acme2certifier.tools import a2c_schema_update as mod

        mock_setup.return_value = False

        self.assertEqual(mod.run_django_schema_update(), 1)
        mock_setup.assert_called_once()
        mock_migrations.assert_not_called()
        mock_status.assert_not_called()
        mock_ver.assert_not_called()

    @patch("acme2certifier.tools.a2c_schema_update.update_db_version")
    @patch("acme2certifier.tools.a2c_schema_update.update_status_fields")
    @patch("acme2certifier.tools.a2c_schema_update.run_migrations")
    @patch("acme2certifier.tools.a2c_schema_update.setup_django")
    @patch("builtins.print")
    def test_019_run_django_partial_failures(
        self, mock_print, mock_setup, mock_migrations, mock_status, mock_ver
    ):
        """run_django_schema_update aggregates step failures"""
        from acme2certifier.tools import a2c_schema_update as mod

        mock_setup.return_value = True
        mock_migrations.return_value = False
        mock_status.return_value = True
        mock_ver.return_value = False

        self.assertEqual(mod.run_django_schema_update(), 1)
        stdout = [c[0][0] for c in mock_print.call_args_list]
        self.assertIn("Django database update completed with errors.", stdout)

    @patch("acme2certifier.tools.a2c_schema_update.update_db_version")
    @patch("acme2certifier.tools.a2c_schema_update.update_status_fields")
    @patch("acme2certifier.tools.a2c_schema_update.run_migrations")
    @patch("acme2certifier.tools.a2c_schema_update.setup_django")
    @patch("builtins.print")
    def test_020_run_django_status_fields_failure(
        self, mock_print, mock_setup, mock_migrations, mock_status, mock_ver
    ):
        """run_django_schema_update fails when status seed fails"""
        from acme2certifier.tools import a2c_schema_update as mod

        mock_setup.return_value = True
        mock_migrations.return_value = True
        mock_status.return_value = False
        mock_ver.return_value = True

        self.assertEqual(mod.run_django_schema_update(), 1)

    @patch("acme2certifier.tools.a2c_schema_update.main")
    @patch("acme2certifier.tools.a2c_schema_update.sys.exit")
    def test_021_main_entry_point_success(self, mock_exit, mock_main):
        """script entry point calls sys.exit(main())"""
        from acme2certifier.tools import a2c_schema_update as mod

        mock_main.return_value = 0
        mod.sys.exit(mod.main())
        mock_main.assert_called_once()
        mock_exit.assert_called_once_with(0)

    @patch("acme2certifier.tools.a2c_schema_update.main")
    @patch("acme2certifier.tools.a2c_schema_update.sys.exit")
    def test_022_main_entry_point_error(self, mock_exit, mock_main):
        """script entry point propagates non-zero exit code"""
        from acme2certifier.tools import a2c_schema_update as mod

        mock_main.return_value = 1
        mod.sys.exit(mod.main())
        mock_exit.assert_called_once_with(1)

    def test_023_global_variables_initialization(self):
        """module globals start unset before setup_django"""
        from acme2certifier.tools import a2c_schema_update as mod

        self.assertIsNone(mod.django)
        self.assertIsNone(mod.call_command)
        self.assertIsNone(mod.Status)
        self.assertIsNone(mod.Housekeeping)
        self.assertIsNone(mod.__dbversion__)

    @patch("builtins.print")
    def test_024_setup_django_sets_globals(self, mock_print):
        """setup_django assigns call_command, models, and dbversion globals"""
        from acme2certifier.tools import a2c_schema_update as mod

        mock_django = MagicMock()
        mock_call_command = MagicMock()
        mock_status = MagicMock()
        mock_housekeeping = MagicMock()
        mock_dbversion = "4.0.0"

        with patch.dict(
            "sys.modules",
            {
                "django": mock_django,
                "django.core.management": MagicMock(call_command=mock_call_command),
                "acme2certifier.django_app.models": MagicMock(
                    Status=mock_status, Housekeeping=mock_housekeeping
                ),
                "acme2certifier.acme_srv.version": MagicMock(
                    __dbversion__=mock_dbversion
                ),
            },
        ):
            self.assertTrue(mod.setup_django())

        self.assertEqual(mod.call_command, mock_call_command)
        self.assertEqual(mod.Status, mock_status)
        self.assertEqual(mod.Housekeeping, mock_housekeeping)
        self.assertEqual(mod.__dbversion__, mock_dbversion)

    @patch("builtins.print")
    def test_025_update_status_fields_print_message(self, mock_print):
        """update_status_fields logs start message"""
        from acme2certifier.tools import a2c_schema_update as mod

        mock_status = MagicMock()
        mock_status.objects.update_or_create.return_value = (MagicMock(), True)
        mod.Status = mock_status

        mod.update_status_fields()
        stdout = [c[0][0] for c in mock_print.call_args_list]
        self.assertIn("adding additional status fields to table...", stdout)

    @patch("builtins.print")
    def test_026_update_db_version_print_messages(self, mock_print):
        """update_db_version logs version bump messages"""
        from acme2certifier.tools import a2c_schema_update as mod

        mock_housekeeping = MagicMock()
        mock_housekeeping.objects.update_or_create.return_value = (MagicMock(), True)
        mod.Housekeeping = mock_housekeeping
        mod.__dbversion__ = "3.0.0"

        mod.update_db_version()
        stdout = [c[0][0] for c in mock_print.call_args_list]
        self.assertIn("update dbversion to 3.0.0...", stdout)
        self.assertIn("Database version updated successfully.", stdout)

    def test_027_module_main_entrypoint(self):
        """``python -m`` entry runs main and sys.exit"""
        import runpy

        sys.modules.pop(self.MODULE, None)
        with patch("sys.exit") as mock_exit:
            runpy.run_module(
                "acme2certifier.tools.a2c_schema_update",
                run_name="__main__",
                alter_sys=True,
            )
        mock_exit.assert_called()
        self.assertIn(mock_exit.call_args[0][0], (0, 1))


if __name__ == "__main__":
    unittest.main()
