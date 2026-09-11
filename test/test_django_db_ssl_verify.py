# -*- coding: utf-8 -*-
"""tests for .github/scripts/django_db_ssl_verify.py"""

from __future__ import annotations

import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".github", "scripts"))

import django_db_ssl_verify  # noqa: E402


def _run_with_connection(vendor: str, fetchone) -> int:
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
        patch.object(django_db_ssl_verify, "_prepare_runtime"),
    ):
        return django_db_ssl_verify.main()


def test_mysql_cipher_ok() -> None:
    """Non-empty Ssl_cipher is success."""
    assert _run_with_connection("mysql", ("Ssl_cipher", "TLS_AES_256_GCM_SHA384")) == 0


def test_mysql_empty_cipher_fails() -> None:
    """Empty Ssl_cipher fails the check."""
    assert _run_with_connection("mysql", ("Ssl_cipher", "")) == 1


def test_postgresql_ssl_true() -> None:
    """pg_stat_ssl ssl=true is success."""
    assert (
        _run_with_connection("postgresql", (True, "TLSv1.3", "TLS_AES_256_GCM_SHA384"))
        == 0
    )


def test_postgresql_ssl_false_fails() -> None:
    """pg_stat_ssl ssl=false fails the check."""
    assert _run_with_connection("postgresql", (False, None, None)) == 1


def test_unsupported_vendor_fails() -> None:
    """Unknown Django vendor fails closed."""
    assert _run_with_connection("sqlite", None) == 1


def test_prepare_runtime_adds_app_root(tmp_path, monkeypatch) -> None:
    """RPM/DEB APP_ROOT is prepended so django_project can be imported."""
    root = tmp_path / "opt" / "acme2certifier"
    (root / "acme2certifier" / "django_project").mkdir(parents=True)
    monkeypatch.setattr(
        django_db_ssl_verify, "_APP_ROOTS", (str(root), "/no/such/root")
    )
    monkeypatch.delenv("ACME2CERTIFIER_BASE_DIR", raising=False)
    monkeypatch.delenv("DJANGO_SETTINGS_MODULE", raising=False)
    django_db_ssl_verify._prepare_runtime()
    assert sys.path[0] == str(root)
    assert os.environ["ACME2CERTIFIER_BASE_DIR"] == str(root)
    assert (
        os.environ["DJANGO_SETTINGS_MODULE"]
        == "acme2certifier.django_project.settings"
    )
