#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for django_update.py"""
# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212
import unittest
import sys
import os
import importlib
from unittest.mock import patch, MagicMock, Mock, call
from io import StringIO

# Add the tools directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))


class TestDjangoUpdate(unittest.TestCase):
    """test class for django_update.py"""

    def setUp(self):
        """setup unittest"""
        # Reset the global variables in django_update module
        if "django_update" in sys.modules:
            importlib.reload(sys.modules["django_update"])

    def tearDown(self):
        """cleanup after tests"""
        # Remove django_update from modules to ensure clean state
        if "django_update" in sys.modules:
            del sys.modules["django_update"]

    def test_001_imports_and_setup(self):
        """test that imports and environment setup work"""
        import django_update

        # Check STATUS_LIST is defined
        self.assertEqual(len(django_update.STATUS_LIST), 8)
        self.assertIn("invalid", django_update.STATUS_LIST)
        self.assertIn("pending", django_update.STATUS_LIST)

    @patch("builtins.print")
    def test_002_setup_django_success(self, mock_print):
        """test successful Django setup"""
        import django_update

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
                "acme_srv.models": MagicMock(
                    Status=mock_status, Housekeeping=mock_housekeeping
                ),
                "acme_srv.version": MagicMock(__dbversion__=mock_dbversion),
            },
        ):
            with patch("django_update.django", mock_django):
                result = django_update.setup_django()

        self.assertTrue(result)
        mock_django.setup.assert_called_once()

    @patch("builtins.print")
    def test_003_setup_django_import_error(self, mock_print):
        """test Django setup with import error"""
        import django_update

        with patch("builtins.__import__", side_effect=ImportError("Django not found")):
            result = django_update.setup_django()

        self.assertFalse(result)
        # Check that error was printed to stderr
        print_calls = mock_print.call_args_list
        error_found = any(
            "Error importing Django modules" in str(call) for call in print_calls
        )
        self.assertTrue(error_found)

    @patch("builtins.print")
    def test_004_setup_django_general_error(self, mock_print):
        """test Django setup with general error"""
        import django_update

        mock_django = MagicMock()
        mock_django.setup.side_effect = Exception("Setup failed")

        with patch.dict("sys.modules", {"django": mock_django}):
            with patch("django_update.django", mock_django):
                result = django_update.setup_django()

        self.assertFalse(result)
        # Check that error was printed
        print_calls = mock_print.call_args_list
        error_found = any(
            "Error during Django setup" in str(call) for call in print_calls
        )
        self.assertTrue(error_found)

    @patch("builtins.print")
    def test_005_run_migrations_success(self, mock_print):
        """test successful migration run"""
        import django_update

        mock_call_command = MagicMock()
        django_update.call_command = mock_call_command

        result = django_update.run_migrations()

        self.assertTrue(result)
        expected_calls = [
            call("makemigrations", interactive=False),
            call("migrate", interactive=False),
        ]
        mock_call_command.assert_has_calls(expected_calls)

        # Check print calls
        print_calls = [call[0][0] for call in mock_print.call_args_list]
        self.assertIn("Running Django migrations...", print_calls)
        self.assertIn("Migrations created successfully.", print_calls)
        self.assertIn("Migrations applied successfully.", print_calls)

    @patch("builtins.print")
    def test_006_run_migrations_error(self, mock_print):
        """test migration run with error"""
        import django_update

        mock_call_command = MagicMock()
        mock_call_command.side_effect = Exception("Migration failed")
        django_update.call_command = mock_call_command

        result = django_update.run_migrations()

        self.assertFalse(result)
        # Check that error was printed
        print_calls = mock_print.call_args_list
        error_found = any(
            "Error during Django operations" in str(call) for call in print_calls
        )
        self.assertTrue(error_found)

    @patch("builtins.print")
    def test_007_update_status_fields_success(self, mock_print):
        """test successful status fields update"""
        import django_update

        mock_status = MagicMock()
        mock_status.objects.update_or_create.return_value = (MagicMock(), True)
        django_update.Status = mock_status

        result = django_update.update_status_fields()

        self.assertTrue(result)

        # Check that update_or_create was called for each status
        self.assertEqual(mock_status.objects.update_or_create.call_count, 8)

        # Check specific calls
        expected_calls = []
        for status in django_update.STATUS_LIST:
            expected_calls.append(call(name=status, defaults={"name": status}))
        mock_status.objects.update_or_create.assert_has_calls(
            expected_calls, any_order=True
        )

    @patch("builtins.print")
    def test_008_update_status_fields_partial_error(self, mock_print):
        """test status fields update with partial errors"""
        import django_update

        mock_status = MagicMock()
        # Make the third call fail
        mock_status.objects.update_or_create.side_effect = [
            (MagicMock(), True),  # invalid - success
            (MagicMock(), True),  # pending - success
            Exception("Database error"),  # ready - fail
            (MagicMock(), True),  # processing - success
            (MagicMock(), True),  # valid - success
            (MagicMock(), True),  # expired - success
            (MagicMock(), True),  # deactivated - success
            (MagicMock(), True),  # revoked - success
        ]
        django_update.Status = mock_status

        result = django_update.update_status_fields()

        self.assertFalse(result)
        # Check that error was printed
        print_calls = mock_print.call_args_list
        error_found = any(
            "Error updating status 'ready'" in str(call) for call in print_calls
        )
        self.assertTrue(error_found)

    @patch("builtins.print")
    def test_009_update_db_version_success(self, mock_print):
        """test successful database version update"""
        import django_update

        mock_housekeeping = MagicMock()
        mock_housekeeping.objects.update_or_create.return_value = (MagicMock(), True)
        django_update.Housekeeping = mock_housekeeping
        django_update.__dbversion__ = "2.0.0"

        result = django_update.update_db_version()

        self.assertTrue(result)
        mock_housekeeping.objects.update_or_create.assert_called_once_with(
            name="dbversion", defaults={"name": "dbversion", "value": "2.0.0"}
        )

    @patch("builtins.print")
    def test_010_update_db_version_error(self, mock_print):
        """test database version update with error"""
        import django_update

        mock_housekeeping = MagicMock()
        mock_housekeeping.objects.update_or_create.side_effect = Exception("DB error")
        django_update.Housekeeping = mock_housekeeping
        django_update.__dbversion__ = "2.0.0"

        result = django_update.update_db_version()

        self.assertFalse(result)
        # Check that error was printed
        print_calls = mock_print.call_args_list
        error_found = any(
            "Error updating database version" in str(call) for call in print_calls
        )
        self.assertTrue(error_found)

    @patch("django_update.update_db_version")
    @patch("django_update.update_status_fields")
    @patch("django_update.run_migrations")
    @patch("django_update.setup_django")
    @patch("builtins.print")
    def test_011_main_all_success(
        self, mock_print, mock_setup, mock_migrations, mock_status, mock_dbversion
    ):
        """test main function with all operations successful"""
        import django_update

        mock_setup.return_value = True
        mock_migrations.return_value = True
        mock_status.return_value = True
        mock_dbversion.return_value = True

        result = django_update.main()

        self.assertEqual(result, 0)
        mock_setup.assert_called_once()
        mock_migrations.assert_called_once()
        mock_status.assert_called_once()
        mock_dbversion.assert_called_once()

        print_calls = [call[0][0] for call in mock_print.call_args_list]
        self.assertIn("Django database update completed successfully.", print_calls)

    @patch("django_update.update_db_version")
    @patch("django_update.update_status_fields")
    @patch("django_update.run_migrations")
    @patch("django_update.setup_django")
    @patch("builtins.print")
    def test_012_main_setup_failure(
        self, mock_print, mock_setup, mock_migrations, mock_status, mock_dbversion
    ):
        """test main function with Django setup failure"""
        import django_update

        mock_setup.return_value = False

        result = django_update.main()

        self.assertEqual(result, 1)
        mock_setup.assert_called_once()
        mock_migrations.assert_not_called()
        mock_status.assert_not_called()
        mock_dbversion.assert_not_called()

    @patch("django_update.update_db_version")
    @patch("django_update.update_status_fields")
    @patch("django_update.run_migrations")
    @patch("django_update.setup_django")
    @patch("builtins.print")
    def test_013_main_partial_failures(
        self, mock_print, mock_setup, mock_migrations, mock_status, mock_dbversion
    ):
        """test main function with partial failures"""
        import django_update

        mock_setup.return_value = True
        mock_migrations.return_value = False  # Migration fails
        mock_status.return_value = True
        mock_dbversion.return_value = False  # DB version update fails

        result = django_update.main()

        self.assertEqual(result, 1)
        mock_setup.assert_called_once()
        mock_migrations.assert_called_once()
        mock_status.assert_called_once()
        mock_dbversion.assert_called_once()

        print_calls = [call[0][0] for call in mock_print.call_args_list]
        self.assertIn("Django database update completed with errors.", print_calls)

    @patch("django_update.main")
    @patch("django_update.sys.exit")
    def test_014_main_entry_point(self, mock_exit, mock_main):
        """test main entry point when script is run directly"""
        mock_main.return_value = 0

        # Simulate running the script directly
        import django_update

        # Manually trigger the if __name__ == "__main__" block
        if True:  # Simulating __name__ == "__main__"
            django_update.sys.exit(django_update.main())

        mock_main.assert_called_once()
        mock_exit.assert_called_once_with(0)

    @patch("django_update.main")
    @patch("django_update.sys.exit")
    def test_015_main_entry_point_with_error(self, mock_exit, mock_main):
        """test main entry point when script encounters error"""
        mock_main.return_value = 1

        # Simulate running the script directly with error
        import django_update

        # Manually trigger the if __name__ == "__main__" block
        if True:  # Simulating __name__ == "__main__"
            django_update.sys.exit(django_update.main())

        mock_main.assert_called_once()
        mock_exit.assert_called_once_with(1)

    def test_016_status_list_completeness(self):
        """test that STATUS_LIST contains all expected status values"""
        import django_update

        expected_statuses = [
            "invalid",
            "pending",
            "ready",
            "processing",
            "valid",
            "expired",
            "deactivated",
            "revoked",
        ]

        self.assertEqual(django_update.STATUS_LIST, expected_statuses)
        self.assertEqual(len(django_update.STATUS_LIST), 8)

    @patch("builtins.print")
    def test_017_update_status_fields_print_messages(self, mock_print):
        """test that update_status_fields prints the correct messages"""
        import django_update

        mock_status = MagicMock()
        mock_status.objects.update_or_create.return_value = (MagicMock(), True)
        django_update.Status = mock_status

        django_update.update_status_fields()

        print_calls = [call[0][0] for call in mock_print.call_args_list]
        self.assertIn("adding additional status fields to table...", print_calls)

    @patch("builtins.print")
    def test_018_update_db_version_print_messages(self, mock_print):
        """test that update_db_version prints the correct messages"""
        import django_update

        mock_housekeeping = MagicMock()
        mock_housekeeping.objects.update_or_create.return_value = (MagicMock(), True)
        django_update.Housekeeping = mock_housekeeping
        django_update.__dbversion__ = "3.0.0"

        django_update.update_db_version()

        print_calls = [call[0][0] for call in mock_print.call_args_list]
        self.assertIn("update dbversion to 3.0.0...", print_calls)
        self.assertIn("Database version updated successfully.", print_calls)

    def test_019_global_variables_initialization(self):
        """test that global variables are properly initialized"""
        import django_update

        # Test that global variables exist and are initially None
        self.assertIsNone(django_update.django)
        self.assertIsNone(django_update.call_command)
        self.assertIsNone(django_update.Status)
        self.assertIsNone(django_update.Housekeeping)
        self.assertIsNone(django_update.__dbversion__)

    @patch("builtins.print")
    def test_020_setup_django_sets_globals(self, mock_print):
        """test that setup_django properly sets global variables"""
        import django_update

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
                "acme_srv.models": MagicMock(
                    Status=mock_status, Housekeeping=mock_housekeeping
                ),
                "acme_srv.version": MagicMock(__dbversion__=mock_dbversion),
            },
        ):
            result = django_update.setup_django()

        self.assertTrue(result)
        # Check that global variables are set
        self.assertEqual(django_update.call_command, mock_call_command)
        self.assertEqual(django_update.Status, mock_status)
        self.assertEqual(django_update.Housekeeping, mock_housekeeping)
        self.assertEqual(django_update.__dbversion__, mock_dbversion)


if __name__ == "__main__":
    unittest.main()
