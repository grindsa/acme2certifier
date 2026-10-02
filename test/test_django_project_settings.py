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
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.core.exceptions import ImproperlyConfigured

_SETTINGS = "acme2certifier.django_project.settings"
_INSECURE = "django-insecure-change-me-run-a2c-django-secret-keygen"
_LOAD_CONFIG = "acme2certifier.acme_srv.helpers.config.load_config"
_SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), "..", ".github", "scripts")
_DB_CA = "/var/www/acme2certifier/volume/db-ca.pem"


def _load_github_script(name: str):
    """Import a helper from .github/scripts without installing it."""
    if _SCRIPTS_DIR not in sys.path:
        sys.path.insert(0, _SCRIPTS_DIR)
    return importlib.import_module(name)


class TestDjangoProjectSettings(unittest.TestCase):
    """reload settings under different env combinations"""

    def setUp(self) -> None:
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        sys.modules.pop(_SETTINGS, None)
        self._saved_db_url = os.environ.pop("ACME2CERTIFIER_DATABASE_URL", None)

    def tearDown(self) -> None:
        sys.modules.pop(_SETTINGS, None)
        if self._saved_db_url is not None:
            os.environ["ACME2CERTIFIER_DATABASE_URL"] = self._saved_db_url
        else:
            os.environ.pop("ACME2CERTIFIER_DATABASE_URL", None)

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

    def test_017_logger_setup_cfg_debug_false_overrides_env(self) -> None:
        """ACME2CERTIFIER_DEBUG=1 but cfg debug=False → ACME logger INFO"""
        cfg = self._cfg_server_name("acme.example.com")
        cfg.set("DEFAULT", "debug", "False")
        mock_logger = MagicMock()
        with (
            patch.dict(
                os.environ,
                {
                    "ACME2CERTIFIER_SECRET_KEY": "sekrit",
                    "ACME2CERTIFIER_DEBUG": "1",
                    "ACME2CERTIFIER_ALLOWED_HOSTS": "127.0.0.1",
                },
                clear=False,
            ),
            patch(_LOAD_CONFIG, return_value=cfg),
            patch(
                "acme2certifier.acme_srv.helpers.logging_utils.logger_setup",
                return_value=mock_logger,
            ) as mock_setup,
        ):
            mod = self._reload()
        self.assertTrue(mod.DEBUG)
        mock_setup.assert_called_with(False)
        mock_logger.info.assert_called()

    def test_018_logger_setup_env_when_cfg_debug_unset(self) -> None:
        """ACME2CERTIFIER_DEBUG=1 and cfg debug unset → ACME logger DEBUG"""
        cfg = self._cfg_server_name("acme.example.com")
        mock_logger = MagicMock()
        with (
            patch.dict(
                os.environ,
                {
                    "ACME2CERTIFIER_SECRET_KEY": "sekrit",
                    "ACME2CERTIFIER_DEBUG": "1",
                    "ACME2CERTIFIER_ALLOWED_HOSTS": "127.0.0.1",
                },
                clear=False,
            ),
            patch(_LOAD_CONFIG, return_value=cfg),
            patch(
                "acme2certifier.acme_srv.helpers.logging_utils.logger_setup",
                return_value=mock_logger,
            ) as mock_setup,
        ):
            mod = self._reload()
        self.assertTrue(mod.DEBUG)
        mock_setup.assert_called_with(True)
        mock_logger.info.assert_called()

    def test_019_logger_setup_cfg_debug_true_overrides_env_off(self) -> None:
        """ACME2CERTIFIER_DEBUG off and cfg debug=True → ACME logger DEBUG"""
        cfg = self._cfg_server_name("acme.example.com")
        cfg.set("DEFAULT", "debug", "True")
        mock_logger = MagicMock()
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
            patch(_LOAD_CONFIG, return_value=cfg),
            patch(
                "acme2certifier.acme_srv.helpers.logging_utils.logger_setup",
                return_value=mock_logger,
            ) as mock_setup,
        ):
            mod = self._reload()
        self.assertFalse(mod.DEBUG)
        mock_setup.assert_called_with(True)
        mock_logger.info.assert_called()

    def _write_django_env(self, path: Path, url: str) -> None:
        path.write_text(
            "ACME2CERTIFIER_SECRET_KEY=sekrit\n"
            "ACME2CERTIFIER_ALLOWED_HOSTS=127.0.0.1,*\n"
            f"ACME2CERTIFIER_DATABASE_URL={url}\n",
            encoding="utf-8",
        )

    def test_020_patch_mariadb_injects_ssl(self) -> None:
        """MariaDB DATABASE_URL gains ca= query pointing at the runtime CA path"""
        patch_file = _load_github_script("patch_django_db_ssl").patch_file
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "django.env"
            self._write_django_env(
                dest, "mysql://acme2certifier:pw@mariadbsrv.acme/acme2certifier"
            )
            patch_file(dest, "mariadb", _DB_CA, allowed_bases=[Path(tmp)])
            text = dest.read_text(encoding="utf-8")
            self.assertIn(f"ca={_DB_CA}", text)
            patch_file(dest, "mariadb", _DB_CA, allowed_bases=[Path(tmp)])
            self.assertEqual(text, dest.read_text(encoding="utf-8"))

    def test_021_patch_psql_injects_sslmode(self) -> None:
        """PostgreSQL DATABASE_URL gains sslmode/sslrootcert/sslcert/sslkey"""
        patch_file = _load_github_script("patch_django_db_ssl").patch_file
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "django.env"
            self._write_django_env(
                dest, "postgres://acme2certifier:pw@postgresdbsrv/acme2certifier"
            )
            patch_file(dest, "psql", _DB_CA, allowed_bases=[Path(tmp)])
            text = dest.read_text(encoding="utf-8")
            self.assertIn("ACME2CERTIFIER_DATABASE_URL='", text)
            self.assertIn("sslmode=verify-ca", text)
            self.assertIn("&", text)
            self.assertIn(f"sslrootcert={_DB_CA}", text)
            self.assertIn(
                "sslcert=/var/www/acme2certifier/volume/db-client-cert.pem",
                text,
            )
            self.assertIn(
                "sslkey=/var/www/acme2certifier/volume/db-client-key.pem",
                text,
            )
            patch_file(dest, "psql", _DB_CA, allowed_bases=[Path(tmp)])
            self.assertEqual(text, dest.read_text(encoding="utf-8"))

    def test_022_patch_rejects_unknown_engine(self) -> None:
        """unsupported DJANGO_DB values fail closed"""
        patch_file = _load_github_script("patch_django_db_ssl").patch_file
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "django.env"
            self._write_django_env(
                dest, "mssql://u:p@ms-sql.acme:1433/acme2certifier"
            )
            with self.assertRaises(SystemExit):
                patch_file(dest, "mssql", _DB_CA, allowed_bases=[Path(tmp)])

    def test_022b_patch_rejects_path_outside_allowed_bases(self) -> None:
        """env file paths outside allowed_bases are rejected (path traversal)"""
        mod = _load_github_script("patch_django_db_ssl")
        with tempfile.TemporaryDirectory() as tmp:
            allowed = Path(tmp) / "allowed"
            allowed.mkdir()
            outside = Path(tmp) / "outside" / "django.env"
            outside.parent.mkdir()
            self._write_django_env(
                outside, "mysql://acme2certifier:pw@mariadbsrv.acme/acme2certifier"
            )
            with self.assertRaises(SystemExit) as ctx:
                mod.patch_file(
                    outside, "mariadb", _DB_CA, allowed_bases=[allowed]
                )
            self.assertIn("outside allowed directories", str(ctx.exception))
            escape = allowed / ".." / "outside" / "django.env"
            with self.assertRaises(SystemExit) as ctx2:
                mod.patch_file(
                    escape, "mariadb", _DB_CA, allowed_bases=[allowed]
                )
            self.assertIn("outside allowed directories", str(ctx2.exception))

    def test_022c_patch_rejects_unsafe_ca_runtime_path(self) -> None:
        """ca-runtime-path must be absolute and free of injection characters"""
        patch_file = _load_github_script("patch_django_db_ssl").patch_file
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "django.env"
            self._write_django_env(
                dest, "mysql://acme2certifier:pw@mariadbsrv.acme/acme2certifier"
            )
            with self.assertRaises(SystemExit):
                patch_file(
                    dest, "mariadb", "rel/ca.pem", allowed_bases=[Path(tmp)]
                )
            with self.assertRaises(SystemExit):
                patch_file(
                    dest,
                    "mariadb",
                    '/var/www/acme2certifier/volume/db-ca.pem"',
                    allowed_bases=[Path(tmp)],
                )

    def _run_ssl_verify_with_connection(self, vendor: str, fetchone) -> int:
        verify = _load_github_script("django_db_ssl_verify")
        cursor = MagicMock()
        cursor.fetchone.return_value = fetchone
        ctx = MagicMock()
        ctx.__enter__.return_value = cursor
        ctx.__exit__.return_value = False
        connection = SimpleNamespace(vendor=vendor, cursor=lambda: ctx)
        django_mock = MagicMock()
        db_mod = SimpleNamespace(connection=connection)
        with (
            patch.dict("sys.modules", {"django": django_mock, "django.db": db_mod}),
            patch.object(django_mock, "setup"),
            patch.object(verify, "_prepare_runtime"),
        ):
            return verify.main()

    def test_023_mysql_cipher_ok(self) -> None:
        """non-empty Ssl_cipher is success"""
        self.assertEqual(
            0,
            self._run_ssl_verify_with_connection(
                "mysql", ("Ssl_cipher", "TLS_AES_256_GCM_SHA384")
            ),
        )

    def test_024_mysql_empty_cipher_fails(self) -> None:
        """empty Ssl_cipher fails the check"""
        self.assertEqual(
            1, self._run_ssl_verify_with_connection("mysql", ("Ssl_cipher", ""))
        )

    def test_025_postgresql_ssl_true(self) -> None:
        """pg_stat_ssl ssl=true is success"""
        self.assertEqual(
            0,
            self._run_ssl_verify_with_connection(
                "postgresql", (True, "TLSv1.3", "TLS_AES_256_GCM_SHA384")
            ),
        )

    def test_026_postgresql_ssl_false_fails(self) -> None:
        """pg_stat_ssl ssl=false fails the check"""
        self.assertEqual(
            1,
            self._run_ssl_verify_with_connection("postgresql", (False, None, None)),
        )

    def test_027_unsupported_vendor_fails(self) -> None:
        """unknown Django vendor fails closed"""
        self.assertEqual(1, self._run_ssl_verify_with_connection("sqlite", None))

    def test_028_prepare_runtime_adds_app_root(self) -> None:
        """RPM/DEB APP_ROOT is prepended so django_project can be imported"""
        verify = _load_github_script("django_db_ssl_verify")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "opt" / "acme2certifier"
            (root / "acme2certifier" / "django_project").mkdir(parents=True)
            env = dict(os.environ)
            env.pop("ACME2CERTIFIER_BASE_DIR", None)
            env.pop("DJANGO_SETTINGS_MODULE", None)
            inserted = False
            try:
                with (
                    patch.object(verify, "_APP_ROOTS", (str(root), "/no/such/root")),
                    patch.dict(os.environ, env, clear=True),
                ):
                    verify._prepare_runtime()
                    inserted = bool(sys.path and sys.path[0] == str(root))
                    self.assertEqual(str(root), sys.path[0])
                    self.assertEqual(str(root), os.environ["ACME2CERTIFIER_BASE_DIR"])
                    self.assertEqual(
                        "acme2certifier.django_project.settings",
                        os.environ["DJANGO_SETTINGS_MODULE"],
                    )
            finally:
                if inserted and sys.path and sys.path[0] == str(root):
                    sys.path.pop(0)

    def test_029_database_url_sqlite_merges_timeout(self) -> None:
        """sqlite URL sets NAME and keeps busy_timeout OPTIONS"""
        with tempfile.TemporaryDirectory() as tmp:
            dbfile = os.path.join(tmp, "ci.sqlite3")
            url = f"sqlite:///{dbfile}"
            with patch.dict(
                os.environ,
                {
                    "ACME2CERTIFIER_SECRET_KEY": "sekrit",
                    "ACME2CERTIFIER_DEBUG": "1",
                    "ACME2CERTIFIER_DATABASE_URL": url,
                },
                clear=False,
            ):
                mod = self._reload()
            self.assertTrue(mod.DATABASES["default"]["ENGINE"].endswith("sqlite3"))
            self.assertEqual(dbfile, mod.DATABASES["default"]["NAME"])
            self.assertEqual(30, mod.DATABASES["default"]["OPTIONS"]["timeout"])

    def test_030_database_url_mysql_merges_charset(self) -> None:
        """mysql URL keeps default charset/init_command OPTIONS"""
        with patch.dict(
            os.environ,
            {
                "ACME2CERTIFIER_SECRET_KEY": "sekrit",
                "ACME2CERTIFIER_DEBUG": "1",
                "ACME2CERTIFIER_DATABASE_URL": (
                    "mysql://acme2certifier:pass@mariadbsrv.acme/acme2certifier"
                ),
            },
            clear=False,
        ):
            mod = self._reload()
        db = mod.DATABASES["default"]
        self.assertIn("mysql", db["ENGINE"])
        self.assertEqual("acme2certifier", db["NAME"])
        self.assertEqual("mariadbsrv.acme", db["HOST"])
        self.assertEqual("utf8mb4", db["OPTIONS"]["charset"])
        self.assertIn("STRICT_TRANS_TABLES", db["OPTIONS"]["init_command"])

    def test_031_database_url_mysql_ca_nests_ssl(self) -> None:
        """mysql URL ?ca= becomes OPTIONS['ssl']['ca']"""
        with patch.dict(
            os.environ,
            {
                "ACME2CERTIFIER_SECRET_KEY": "sekrit",
                "ACME2CERTIFIER_DEBUG": "1",
                "ACME2CERTIFIER_DATABASE_URL": (
                    "mysql://acme2certifier:pass@db/acme2certifier"
                    f"?ca={_DB_CA}"
                ),
            },
            clear=False,
        ):
            mod = self._reload()
        ssl_opt = mod.DATABASES["default"]["OPTIONS"]["ssl"]
        self.assertEqual(_DB_CA, ssl_opt["ca"])
        self.assertNotIn("ca", mod.DATABASES["default"]["OPTIONS"])

    def test_032_database_url_postgres_ssl_query(self) -> None:
        """postgres URL sslmode/sslrootcert land in OPTIONS"""
        with patch.dict(
            os.environ,
            {
                "ACME2CERTIFIER_SECRET_KEY": "sekrit",
                "ACME2CERTIFIER_DEBUG": "1",
                "ACME2CERTIFIER_DATABASE_URL": (
                    "postgres://acme2certifier:pass@postgresdbsrv/acme2certifier"
                    f"?sslmode=verify-ca&sslrootcert={_DB_CA}"
                ),
            },
            clear=False,
        ):
            mod = self._reload()
        options = mod.DATABASES["default"]["OPTIONS"]
        self.assertEqual("verify-ca", options["sslmode"])
        self.assertEqual(_DB_CA, options["sslrootcert"])

    def test_033_database_url_mssql_engine_and_driver(self) -> None:
        """mssql URL uses ENGINE mssql and default ODBC driver"""
        with patch.dict(
            os.environ,
            {
                "ACME2CERTIFIER_SECRET_KEY": "sekrit",
                "ACME2CERTIFIER_DEBUG": "1",
                "ACME2CERTIFIER_DATABASE_URL": (
                    "mssql://acme2certifier_user:pass@ms-sql.acme:1433/acme2certifier"
                    "?extra_params=Encrypt%3Dno%3BTrustServerCertificate%3Dyes"
                ),
            },
            clear=False,
        ):
            mod = self._reload()
        db = mod.DATABASES["default"]
        self.assertEqual("mssql", db["ENGINE"])
        self.assertEqual("ODBC Driver 18 for SQL Server", db["OPTIONS"]["driver"])
        self.assertIn("Encrypt=no", db["OPTIONS"].get("extra_params", ""))

    def test_034_dotenv_in_base_dir_is_read(self) -> None:
        """BASE_DIR/.env supplies SECRET_KEY when process env is unset"""
        from acme2certifier.django_project import settings_env

        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".env").write_text(
                "ACME2CERTIFIER_SECRET_KEY=from-dotenv\n",
                encoding="utf-8",
            )
            env = dict(os.environ)
            env.pop("ACME2CERTIFIER_SECRET_KEY", None)
            env["ACME2CERTIFIER_BASE_DIR"] = tmp
            env["ACME2CERTIFIER_DEBUG"] = "1"
            with patch.dict(os.environ, env, clear=True):
                loaded = settings_env.load_settings_env()
            self.assertEqual("from-dotenv", loaded["SECRET_KEY"])

    def test_035_cwd_dotenv_is_ignored(self) -> None:
        """A .env in CWD is not read when BASE_DIR is elsewhere"""
        from acme2certifier.django_project import settings_env

        with tempfile.TemporaryDirectory() as base, tempfile.TemporaryDirectory() as cwd:
            (Path(cwd) / ".env").write_text(
                "ACME2CERTIFIER_SECRET_KEY=from-cwd\n", encoding="utf-8"
            )
            env = dict(os.environ)
            env.pop("ACME2CERTIFIER_SECRET_KEY", None)
            env["ACME2CERTIFIER_BASE_DIR"] = base
            env["ACME2CERTIFIER_DEBUG"] = "1"
            with (
                patch.dict(os.environ, env, clear=True),
                patch("os.getcwd", return_value=cwd),
            ):
                loaded = settings_env.load_settings_env()
            self.assertEqual(settings_env.INSECURE_SECRET_KEY, loaded["SECRET_KEY"])

    def test_036_missing_django_environ_raises(self) -> None:
        """ImportError for django-environ becomes ImproperlyConfigured"""
        from acme2certifier.django_project import settings_env

        with patch.object(settings_env, "environ", None):
            with self.assertRaises(ImproperlyConfigured):
                settings_env.load_settings_env()


if __name__ == "__main__":
    unittest.main()
