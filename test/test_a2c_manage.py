#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for a2c_manage.py"""

# pylint: disable=C0415
import sys
import unittest
from unittest.mock import MagicMock, patch


class TestA2CManage(unittest.TestCase):
    """tests for a2c_manage"""

    def test_001_main_executes_django_command(self):
        """main() sets DJANGO_SETTINGS_MODULE and runs execute_from_command_line"""
        mock_exec = MagicMock()
        with patch.dict("os.environ", {}, clear=False), patch.dict(
            "sys.modules",
            {
                "django.core.management": MagicMock(
                    execute_from_command_line=mock_exec
                ),
            },
        ):
            # Ensure a fresh import path for execute_from_command_line
            with patch(
                "django.core.management.execute_from_command_line", mock_exec
            ):
                from acme2certifier.tools import a2c_manage
                import os

                # Clear then call
                os.environ.pop("DJANGO_SETTINGS_MODULE", None)
                a2c_manage.main()
                self.assertEqual(
                    os.environ.get("DJANGO_SETTINGS_MODULE"),
                    "acme2certifier.django_project.settings",
                )
                mock_exec.assert_called_once_with(sys.argv)

    def test_002_main_django_import_error(self):
        """main() raises helpful ImportError when Django is missing"""
        import builtins

        real_import = builtins.__import__

        def _import(name, *args, **kwargs):
            if name == "django.core.management" or name.startswith("django."):
                raise ImportError("No module named django")
            return real_import(name, *args, **kwargs)

        from acme2certifier.tools import a2c_manage

        with patch("builtins.__import__", side_effect=_import):
            with self.assertRaises(ImportError) as cm:
                a2c_manage.main()
        self.assertIn("acme2certifier[django]", str(cm.exception))

    def test_003_module_main_entrypoint(self):
        """``__main__`` guard calls main()"""
        import runpy

        sys.modules.pop("acme2certifier.tools.a2c_manage", None)
        with patch(
            "django.core.management.execute_from_command_line"
        ) as mock_exec:
            runpy.run_module(
                "acme2certifier.tools.a2c_manage",
                run_name="__main__",
                alter_sys=True,
            )
        mock_exec.assert_called_once()


if __name__ == "__main__":
    unittest.main()
