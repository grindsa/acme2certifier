#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for django_project.settings"""

# pylint: disable=C0415
import importlib
import logging
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

_SETTINGS = "acme2certifier.django_project.settings"


class TestDjangoProjectSettings(unittest.TestCase):
    """reload settings under different env combinations"""

    def setUp(self) -> None:
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        sys.modules.pop(_SETTINGS, None)

    def tearDown(self) -> None:
        sys.modules.pop(_SETTINGS, None)

    def _reload(self):
        return importlib.import_module(_SETTINGS)

    def test_001_default_base_dir_fallback_to_cwd(self) -> None:
        """without ACME2CERTIFIER_BASE_DIR and missing default path → cwd"""
        env = dict(os.environ)
        for key in (
            "ACME2CERTIFIER_BASE_DIR",
            "ACME2CERTIFIER_SECRET_KEY",
            "ACME2CERTIFIER_DEBUG",
            "ACME2CERTIFIER_ALLOWED_HOSTS",
        ):
            env.pop(key, None)
        with (
            patch.dict(os.environ, env, clear=True),
            patch("os.path.isdir", return_value=False),
        ):
            mod = self._reload()
            self.assertEqual(os.getcwd(), mod.BASE_DIR)
            self.assertFalse(mod.DEBUG)
            self.assertIn("127.0.0.1", mod.ALLOWED_HOSTS)
            self.assertIn("*", mod.ALLOWED_HOSTS)

    def test_002_base_dir_from_env_and_debug_true(self) -> None:
        """ACME2CERTIFIER_BASE_DIR and DEBUG=true honored"""
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(
                os.environ,
                {
                    "ACME2CERTIFIER_BASE_DIR": tmp,
                    "ACME2CERTIFIER_SECRET_KEY": "sekrit",
                    "ACME2CERTIFIER_DEBUG": "true",
                    "ACME2CERTIFIER_ALLOWED_HOSTS": "example.com, ,localhost",
                },
                clear=False,
            ):
                mod = self._reload()
                self.assertEqual(tmp, mod.BASE_DIR)
                self.assertEqual("sekrit", mod.SECRET_KEY)
                self.assertTrue(mod.DEBUG)
                self.assertEqual(["example.com", "localhost"], mod.ALLOWED_HOSTS)

    def test_003_debug_one_and_default_base_exists(self) -> None:
        """DEBUG=1 and existing /var/www default path branch"""
        env = dict(os.environ)
        env.pop("ACME2CERTIFIER_BASE_DIR", None)
        env["ACME2CERTIFIER_DEBUG"] = "1"
        with (
            patch.dict(os.environ, env, clear=True),
            patch("os.path.isdir", return_value=True),
        ):
            mod = self._reload()
            self.assertEqual("/var/www/acme2certifier", mod.BASE_DIR)
            self.assertTrue(mod.DEBUG)

    def test_004_debug_True_capital(self) -> None:
        """DEBUG=True (capital T) is accepted"""
        with patch.dict(os.environ, {"ACME2CERTIFIER_DEBUG": "True"}, clear=False):
            mod = self._reload()
            self.assertTrue(mod.DEBUG)

    def test_005_admin_not_installed(self) -> None:
        """django.contrib.admin is not enabled (unused browser UI)"""
        with patch.dict(
            os.environ,
            {
                "ACME2CERTIFIER_SECRET_KEY": "sekrit",
                "ACME2CERTIFIER_DEBUG": "1",
            },
            clear=False,
        ):
            mod = self._reload()
            self.assertNotIn("django.contrib.admin", mod.INSTALLED_APPS)


if __name__ == "__main__":
    unittest.main()
