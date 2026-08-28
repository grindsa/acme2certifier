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
import warnings
from unittest.mock import patch

from django.core.exceptions import ImproperlyConfigured

_SETTINGS = "acme2certifier.django_project.settings"
_INSECURE = "django-insecure-change-me-run-a2c-django-secret-keygen"


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

    def test_001_default_without_secret_key_raises(self) -> None:
        """without SECRET_KEY and DEBUG off → ImproperlyConfigured"""
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
            with self.assertRaises(ImproperlyConfigured):
                self._reload()

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

    def test_003_debug_allows_insecure_secret_and_star_hosts(self) -> None:
        """DEBUG=1 allows insecure SECRET_KEY; default ALLOWED_HOSTS keeps *"""
        env = dict(os.environ)
        env.pop("ACME2CERTIFIER_BASE_DIR", None)
        env.pop("ACME2CERTIFIER_SECRET_KEY", None)
        env.pop("ACME2CERTIFIER_ALLOWED_HOSTS", None)
        env["ACME2CERTIFIER_DEBUG"] = "1"
        with (
            patch.dict(os.environ, env, clear=True),
            patch("os.path.isdir", return_value=True),
        ):
            mod = self._reload()
            self.assertEqual("/var/www/acme2certifier", mod.BASE_DIR)
            self.assertTrue(mod.DEBUG)
            self.assertEqual(_INSECURE, mod.SECRET_KEY)
            self.assertIn("127.0.0.1", mod.ALLOWED_HOSTS)
            self.assertIn("*", mod.ALLOWED_HOSTS)

    def test_004_debug_True_capital(self) -> None:
        """DEBUG=True (capital T) is accepted"""
        with patch.dict(
            os.environ,
            {
                "ACME2CERTIFIER_DEBUG": "True",
                "ACME2CERTIFIER_SECRET_KEY": "sekrit",
            },
            clear=False,
        ):
            mod = self._reload()
            self.assertTrue(mod.DEBUG)

    def test_005_production_default_hosts_without_star(self) -> None:
        """with SECRET_KEY set and DEBUG off → default hosts omit *"""
        env = dict(os.environ)
        env.pop("ACME2CERTIFIER_BASE_DIR", None)
        env.pop("ACME2CERTIFIER_DEBUG", None)
        env.pop("ACME2CERTIFIER_ALLOWED_HOSTS", None)
        env["ACME2CERTIFIER_SECRET_KEY"] = "sekrit"
        with (
            patch.dict(os.environ, env, clear=True),
            patch("os.path.isdir", return_value=False),
        ):
            mod = self._reload()
            self.assertEqual(os.getcwd(), mod.BASE_DIR)
            self.assertFalse(mod.DEBUG)
            self.assertEqual(["127.0.0.1", "localhost"], mod.ALLOWED_HOSTS)

    def test_006_star_hosts_warns_when_not_debug(self) -> None:
        """explicit * with DEBUG off → UserWarning"""
        with patch.dict(
            os.environ,
            {
                "ACME2CERTIFIER_SECRET_KEY": "sekrit",
                "ACME2CERTIFIER_DEBUG": "0",
                "ACME2CERTIFIER_ALLOWED_HOSTS": "127.0.0.1,*",
            },
            clear=False,
        ):
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                mod = self._reload()
                self.assertIn("*", mod.ALLOWED_HOSTS)
                self.assertTrue(
                    any("ALLOWED_HOSTS contains '*'" in str(w.message) for w in caught)
                )

    def test_007_star_hosts_no_warn_when_debug(self) -> None:
        """explicit * with DEBUG on → no warning"""
        with patch.dict(
            os.environ,
            {
                "ACME2CERTIFIER_SECRET_KEY": "sekrit",
                "ACME2CERTIFIER_DEBUG": "1",
                "ACME2CERTIFIER_ALLOWED_HOSTS": "*",
            },
            clear=False,
        ):
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                mod = self._reload()
                self.assertEqual(["*"], mod.ALLOWED_HOSTS)
                self.assertFalse(
                    any("ALLOWED_HOSTS contains '*'" in str(w.message) for w in caught)
                )

    def test_008_admin_not_installed(self) -> None:
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
