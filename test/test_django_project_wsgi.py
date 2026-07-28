#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for django_project.wsgi"""

# pylint: disable=C0415
import importlib
import logging
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch


_WSGI = "acme2certifier.django_project.wsgi"


class TestDjangoProjectWsgi(unittest.TestCase):
    """cover wsgi path insert + get_wsgi_application"""

    def setUp(self) -> None:
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        sys.modules.pop(_WSGI, None)

    def tearDown(self) -> None:
        sys.modules.pop(_WSGI, None)

    def test_001_inserts_project_home_when_dir_exists(self) -> None:
        """existing ACME2CERTIFIER_BASE_DIR is prepended to sys.path"""
        with tempfile.TemporaryDirectory() as tmp:
            saved_path = list(sys.path)
            mock_app = MagicMock(name="wsgi_app")
            try:
                if tmp in sys.path:
                    sys.path.remove(tmp)
                with patch.dict(
                    os.environ,
                    {
                        "ACME2CERTIFIER_BASE_DIR": tmp,
                        "DJANGO_SETTINGS_MODULE": "acme2certifier.django_project.settings",
                    },
                    clear=False,
                ), patch(
                    "django.core.wsgi.get_wsgi_application", return_value=mock_app
                ):
                    mod = importlib.import_module(_WSGI)
                self.assertIs(mock_app, mod.application)
                self.assertEqual(tmp, sys.path[0])
            finally:
                sys.path[:] = saved_path

    def test_002_skips_insert_when_dir_missing(self) -> None:
        """missing project home is not inserted into sys.path"""
        missing = "/nonexistent/a2c/project/home/xyz"
        saved_path = list(sys.path)
        mock_app = MagicMock(name="wsgi_app2")
        try:
            with patch.dict(
                os.environ,
                {
                    "ACME2CERTIFIER_BASE_DIR": missing,
                    "DJANGO_SETTINGS_MODULE": "acme2certifier.django_project.settings",
                },
                clear=False,
            ), patch(
                "django.core.wsgi.get_wsgi_application", return_value=mock_app
            ):
                mod = importlib.import_module(_WSGI)
            self.assertIs(mock_app, mod.application)
            self.assertNotIn(missing, sys.path)
        finally:
            sys.path[:] = saved_path

    def test_003_skips_insert_when_already_on_path(self) -> None:
        """existing path entry is not duplicated"""
        with tempfile.TemporaryDirectory() as tmp:
            saved_path = list(sys.path)
            mock_app = MagicMock(name="wsgi_app3")
            try:
                if tmp not in sys.path:
                    sys.path.insert(0, tmp)
                before = list(sys.path)
                with patch.dict(
                    os.environ,
                    {
                        "ACME2CERTIFIER_BASE_DIR": tmp,
                        "DJANGO_SETTINGS_MODULE": "acme2certifier.django_project.settings",
                    },
                    clear=False,
                ), patch(
                    "django.core.wsgi.get_wsgi_application", return_value=mock_app
                ):
                    mod = importlib.import_module(_WSGI)
                self.assertIs(mock_app, mod.application)
                self.assertEqual(1, before.count(tmp))
                self.assertEqual(1, sys.path.count(tmp))
            finally:
                sys.path[:] = saved_path


if __name__ == "__main__":
    unittest.main()
