#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for django_project.settings"""

# pylint: disable=C0415
import configparser
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
_LOAD_CONFIG = "acme2certifier.acme_srv.helpers.config.load_config"


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

    @staticmethod
    def _cfg_server_name(server_name: str) -> configparser.ConfigParser:
        cfg = configparser.ConfigParser()
        cfg["DEFAULT"] = {"server_name": server_name}
        return cfg

    @staticmethod
    def _empty_cfg() -> configparser.ConfigParser:
        return configparser.ConfigParser()

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
                self.assertIn("example.com", mod.ALLOWED_HOSTS)
                self.assertIn("localhost", mod.ALLOWED_HOSTS)

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
            self.assertIn("127.0.0.1", mod.ALLOWED_HOSTS)
            self.assertIn("localhost", mod.ALLOWED_HOSTS)
            self.assertNotIn("*", mod.ALLOWED_HOSTS)

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
                self.assertIn("*", mod.ALLOWED_HOSTS)
                self.assertFalse(
                    any("ALLOWED_HOSTS contains '*'" in str(w.message) for w in caught)
                )

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

    def test_009_server_name_from_cfg_merged_into_allowed_hosts(self) -> None:
        """DEFAULT.server_name in acme_srv.cfg is added to ALLOWED_HOSTS"""
        env = dict(os.environ)
        env.pop("ACME2CERTIFIER_ALLOWED_HOSTS", None)
        env["ACME2CERTIFIER_SECRET_KEY"] = "sekrit"
        env["ACME2CERTIFIER_DEBUG"] = "0"
        with (
            patch.dict(os.environ, env, clear=True),
            patch("os.path.isdir", return_value=False),
            patch(_LOAD_CONFIG, return_value=self._cfg_server_name("acme.example.com")),
        ):
            mod = self._reload()
            self.assertIn("acme.example.com", mod.ALLOWED_HOSTS)
            self.assertIn("127.0.0.1", mod.ALLOWED_HOSTS)
            self.assertIn("localhost", mod.ALLOWED_HOSTS)

    def test_010_server_name_merged_alongside_env_allowed_hosts(self) -> None:
        """cfg server_name supplements ACME2CERTIFIER_ALLOWED_HOSTS"""
        with (
            patch.dict(
                os.environ,
                {
                    "ACME2CERTIFIER_SECRET_KEY": "sekrit",
                    "ACME2CERTIFIER_DEBUG": "0",
                    "ACME2CERTIFIER_ALLOWED_HOSTS": "other.example.com",
                },
                clear=False,
            ),
            patch(_LOAD_CONFIG, return_value=self._cfg_server_name("acme.example.com")),
        ):
            mod = self._reload()
            self.assertIn("other.example.com", mod.ALLOWED_HOSTS)
            self.assertIn("acme.example.com", mod.ALLOWED_HOSTS)

    def test_011_server_name_not_duplicated_when_already_in_env(self) -> None:
        """no duplicate when server_name already listed in env"""
        with (
            patch.dict(
                os.environ,
                {
                    "ACME2CERTIFIER_SECRET_KEY": "sekrit",
                    "ACME2CERTIFIER_DEBUG": "0",
                    "ACME2CERTIFIER_ALLOWED_HOSTS": "acme.example.com,127.0.0.1",
                },
                clear=False,
            ),
            patch(_LOAD_CONFIG, return_value=self._cfg_server_name("acme.example.com")),
        ):
            mod = self._reload()
            self.assertEqual(
                mod.ALLOWED_HOSTS.count("acme.example.com"),
                1,
            )

    def test_012_no_server_name_in_cfg_leaves_allowed_hosts_unchanged(self) -> None:
        """empty cfg does not alter default ALLOWED_HOSTS"""
        env = dict(os.environ)
        env.pop("ACME2CERTIFIER_ALLOWED_HOSTS", None)
        env["ACME2CERTIFIER_SECRET_KEY"] = "sekrit"
        env["ACME2CERTIFIER_DEBUG"] = "0"
        with (
            patch.dict(os.environ, env, clear=True),
            patch("os.path.isdir", return_value=False),
            patch(_LOAD_CONFIG, return_value=self._empty_cfg()),
        ):
            mod = self._reload()
            self.assertEqual(["127.0.0.1", "localhost"], mod.ALLOWED_HOSTS)

    def test_013_server_name_url_with_scheme_and_port_normalized(self) -> None:
        """URL-shaped server_name is normalized to host:port for ALLOWED_HOSTS"""
        with (
            patch.dict(
                os.environ,
                {
                    "ACME2CERTIFIER_SECRET_KEY": "sekrit",
                    "ACME2CERTIFIER_DEBUG": "0",
                    "ACME2CERTIFIER_ALLOWED_HOSTS": "127.0.0.1",
                },
                clear=False,
            ),
            patch(
                _LOAD_CONFIG,
                return_value=self._cfg_server_name("https://acme.example.com:8443"),
            ),
        ):
            mod = self._reload()
            self.assertIn("acme.example.com:8443", mod.ALLOWED_HOSTS)

    def test_014_sqlite_busy_timeout_default(self) -> None:
        """default SQLite busy_timeout is 30 seconds"""
        env = dict(os.environ)
        env.pop("ACME2CERTIFIER_SQLITE_TIMEOUT", None)
        env["ACME2CERTIFIER_SECRET_KEY"] = "sekrit"
        env["ACME2CERTIFIER_DEBUG"] = "1"
        with patch.dict(os.environ, env, clear=True):
            mod = self._reload()
            self.assertEqual(30, mod.DATABASES["default"]["OPTIONS"]["timeout"])

    def test_015_sqlite_busy_timeout_from_env(self) -> None:
        """ACME2CERTIFIER_SQLITE_TIMEOUT overrides busy_timeout"""
        with patch.dict(
            os.environ,
            {
                "ACME2CERTIFIER_SECRET_KEY": "sekrit",
                "ACME2CERTIFIER_DEBUG": "1",
                "ACME2CERTIFIER_SQLITE_TIMEOUT": "45",
            },
            clear=False,
        ):
            mod = self._reload()
            self.assertEqual(45, mod.DATABASES["default"]["OPTIONS"]["timeout"])

    def test_016_sqlite_transaction_mode_on_django_51_plus(self) -> None:
        """Django 5.1+ uses OPTIONS.transaction_mode IMMEDIATE for SQLite"""
        import django

        env = dict(os.environ)
        env.pop("ACME2CERTIFIER_SQLITE_TIMEOUT", None)
        env["ACME2CERTIFIER_SECRET_KEY"] = "sekrit"
        env["ACME2CERTIFIER_DEBUG"] = "1"
        with patch.dict(os.environ, env, clear=True):
            mod = self._reload()
            if django.VERSION >= (5, 1):
                self.assertEqual(
                    "IMMEDIATE",
                    mod.DATABASES["default"]["OPTIONS"]["transaction_mode"],
                )
            else:
                self.assertNotIn(
                    "transaction_mode", mod.DATABASES["default"]["OPTIONS"]
                )


if __name__ == "__main__":
    unittest.main()
