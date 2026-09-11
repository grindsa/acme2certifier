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
