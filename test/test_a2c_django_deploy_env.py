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
                'env = ACME2CERTIFIER_SECRET_KEY="from-ini"\n',
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
                self.assertIn("127.0.0.1", os.environ["ACME2CERTIFIER_ALLOWED_HOSTS"])


if __name__ == "__main__":
    unittest.main()
