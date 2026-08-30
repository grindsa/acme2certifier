#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Tests for a2c_django_deploy_env."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from acme2certifier.tools.a2c_django_deploy_env import (
    _parse_apache_export,
    _read_uwsgi_env,
    _unquote_uwsgi_value,
    load_deploy_env,
)


class TestA2cDjangoDeployEnv(unittest.TestCase):
    """Parse deployment env files and load into os.environ."""

    def test_001_uwsgi_unquote_secret_with_plugin_like_chars(self) -> None:
        raw = '"&r-wg_iyo$$umoyn5@(lu9h)te%7r*&&8yr0sr1z$$h38df4g8j"'
        self.assertEqual(
            "&r-wg_iyo$umoyn5@(lu9h)te%7r*&&8yr0sr1z$h38df4g8j",
            _unquote_uwsgi_value(raw),
        )

    def test_002_read_uwsgi_env_from_ini(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ini = Path(tmp) / "acme2certifier.ini"
            ini.write_text(
                'env = ACME2CERTIFIER_SECRET_KEY="sek$$ret"\n'
                "env = ACME2CERTIFIER_ALLOWED_HOSTS=127.0.0.1,localhost,acme-srv\n",
                encoding="utf-8",
            )
            env = _read_uwsgi_env(ini)
            self.assertEqual("sek$ret", env["ACME2CERTIFIER_SECRET_KEY"])
            self.assertEqual(
                "127.0.0.1,localhost,acme-srv",
                env["ACME2CERTIFIER_ALLOWED_HOSTS"],
            )

    def test_003_parse_apache_export(self) -> None:
        parsed = _parse_apache_export("export ACME2CERTIFIER_SECRET_KEY='a$b(c)d'")
        self.assertEqual(
            ("ACME2CERTIFIER_SECRET_KEY", "a$b(c)d"),
            parsed,
        )

    def test_004_load_deploy_env_prefers_uwsgi_ini(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "acme2certifier.ini").write_text(
                'env = ACME2CERTIFIER_SECRET_KEY="from-ini"\n'
                "env = ACME2CERTIFIER_ALLOWED_HOSTS=127.0.0.1,localhost,acme-srv\n",
                encoding="utf-8",
            )
            env = dict(os.environ)
            for key in (
                "ACME2CERTIFIER_SECRET_KEY",
                "ACME2CERTIFIER_ALLOWED_HOSTS",
                "ACME2CERTIFIER_DEBUG",
            ):
                env.pop(key, None)
            with patch.dict(os.environ, env, clear=True):
                load_deploy_env(str(base))
                self.assertEqual("from-ini", os.environ["ACME2CERTIFIER_SECRET_KEY"])
                self.assertEqual(
                    "127.0.0.1,localhost,acme-srv",
                    os.environ["ACME2CERTIFIER_ALLOWED_HOSTS"],
                )

    def test_005_read_uwsgi_env_missing_file(self) -> None:
        """_read_uwsgi_env returns empty dict when ini is missing"""
        self.assertEqual({}, _read_uwsgi_env(Path("/no/such/acme2certifier.ini")))

    def test_006_unquote_uwsgi_value_unquoted(self) -> None:
        """_unquote_uwsgi_value leaves unquoted values unchanged"""
        self.assertEqual("plain", _unquote_uwsgi_value("plain"))

    def test_007_parse_apache_export_invalid_lines(self) -> None:
        """_parse_apache_export returns None for non-export and malformed lines"""
        self.assertIsNone(_parse_apache_export("ACME2CERTIFIER_DEBUG=1"))
        self.assertIsNone(_parse_apache_export('export ACME2CERTIFIER_DEBUG="unclosed'))
        self.assertIsNone(_parse_apache_export("export ACME2CERTIFIER_DEBUG"))
        self.assertIsNone(
            _parse_apache_export("export ACME2CERTIFIER_DEBUG extra=tokens")
        )
        with patch(
            "acme2certifier.tools.a2c_django_deploy_env.shlex.split",
            return_value=["export", "OTHER_KEY=1"],
        ):
            self.assertIsNone(_parse_apache_export("export ACME2CERTIFIER_DEBUG=1"))

    def test_008_read_apache_envvars(self) -> None:
        """_read_apache_envvars parses export lines and skips missing files"""
        from acme2certifier.tools.a2c_django_deploy_env import _read_apache_envvars

        self.assertEqual({}, _read_apache_envvars(Path("/no/such/envvars")))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "envvars"
            path.write_text(
                "export ACME2CERTIFIER_DEBUG=1\n"
                "# comment\n"
                "export OTHER_VAR=x\n"
                "export ACME2CERTIFIER_ALLOWED_HOSTS='a,b'\n",
                encoding="utf-8",
            )
            env = _read_apache_envvars(path)
            self.assertEqual("1", env["ACME2CERTIFIER_DEBUG"])
            self.assertEqual("a,b", env["ACME2CERTIFIER_ALLOWED_HOSTS"])
            self.assertNotIn("OTHER_VAR", env)

    def test_009_load_deploy_env_generates_secret_and_main(self) -> None:
        """load_deploy_env generates SECRET_KEY; main prints set keys"""
        from acme2certifier.tools.a2c_django_deploy_env import main

        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            for key in (
                "ACME2CERTIFIER_SECRET_KEY",
                "ACME2CERTIFIER_ALLOWED_HOSTS",
                "ACME2CERTIFIER_DEBUG",
                "ACME2CERTIFIER_BASE_DIR",
            ):
                env.pop(key, None)
            env["ACME2CERTIFIER_BASE_DIR"] = tmp
            with patch.dict(os.environ, env, clear=True):
                with patch(
                    "django.core.management.utils.get_random_secret_key",
                    return_value="generated-secret",
                ):
                    load_deploy_env()
                self.assertEqual(
                    "generated-secret", os.environ["ACME2CERTIFIER_SECRET_KEY"]
                )
                with patch("builtins.print") as mock_print:
                    main()
                printed = " ".join(str(c) for c in mock_print.call_args_list)
                self.assertIn("ACME2CERTIFIER_SECRET_KEY is set", printed)

    def test_010_module_main_guard(self) -> None:
        """Running the module as __main__ invokes main()"""
        import runpy
        from acme2certifier.tools.a2c_django_deploy_env import __file__ as mod_file

        env = dict(os.environ)
        env["ACME2CERTIFIER_SECRET_KEY"] = "already-set"
        with patch.dict(os.environ, env, clear=True):
            with patch("builtins.print"):
                runpy.run_path(mod_file, run_name="__main__")


if __name__ == "__main__":
    unittest.main()
