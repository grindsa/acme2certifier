#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for deprecated a2c_db_update / a2c_django_update wrappers"""

# pylint: disable=C0415
import sys
import unittest
from unittest.mock import patch


class TestA2CDbUpdateWrapper(unittest.TestCase):
    """tests for a2c_db_update deprecation wrapper"""

    def test_001_main_warns_and_delegates(self):
        """main prints deprecation and calls schema_update --mode wsgi"""
        with (
            patch("builtins.print") as mock_print,
            patch(
                "acme2certifier.tools.a2c_schema_update.main", return_value=0
            ) as mock_schema,
        ):
            from acme2certifier.tools import a2c_db_update

            self.assertEqual(a2c_db_update.main(), 0)

        mock_schema.assert_called_once_with(["--mode", "wsgi"])
        printed = " ".join(str(c) for c in mock_print.call_args_list)
        self.assertIn("deprecated", printed)
        self.assertIn("a2c-schema-update", printed)

    def test_002_module_main_entrypoint(self):
        """``__main__`` guard exits with main()'s return code"""
        import runpy

        sys.modules.pop("acme2certifier.tools.a2c_db_update", None)
        with (
            patch("acme2certifier.tools.a2c_schema_update.main", return_value=0),
            patch("sys.exit") as mock_exit,
        ):
            runpy.run_module(
                "acme2certifier.tools.a2c_db_update",
                run_name="__main__",
                alter_sys=True,
            )
        mock_exit.assert_called_once_with(0)


class TestA2CDjangoUpdateWrapper(unittest.TestCase):
    """tests for a2c_django_update deprecation wrapper"""

    def test_001_main_warns_and_delegates(self):
        """main prints deprecation and calls schema_update --mode django"""
        with (
            patch("builtins.print") as mock_print,
            patch(
                "acme2certifier.tools.a2c_schema_update.main", return_value=0
            ) as mock_schema,
        ):
            from acme2certifier.tools import a2c_django_update

            self.assertEqual(a2c_django_update.main(), 0)

        mock_schema.assert_called_once_with(["--mode", "django"])
        printed = " ".join(str(c) for c in mock_print.call_args_list)
        self.assertIn("deprecated", printed)
        self.assertIn("a2c-schema-update", printed)

    def test_002_module_main_entrypoint(self):
        """``__main__`` guard exits with main()'s return code"""
        import runpy

        sys.modules.pop("acme2certifier.tools.a2c_django_update", None)
        with (
            patch("acme2certifier.tools.a2c_schema_update.main", return_value=0),
            patch("sys.exit") as mock_exit,
        ):
            runpy.run_module(
                "acme2certifier.tools.a2c_django_update",
                run_name="__main__",
                alter_sys=True,
            )
        mock_exit.assert_called_once_with(0)


if __name__ == "__main__":
    unittest.main()
