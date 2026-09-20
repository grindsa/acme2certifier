# -*- coding: utf-8 -*-
"""tests for .github/scripts/patch_django_db_ssl.py"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".github", "scripts"))

from patch_django_db_ssl import patch_file  # noqa: E402

_CA = "/var/www/acme2certifier/volume/db-ca.pem"
_REPO = Path(__file__).resolve().parents[1]


def test_patch_mariadb_injects_ssl(tmp_path: Path) -> None:
    """MariaDB OPTIONS gain ssl.ca pointing at the runtime CA path."""
    src = _REPO / ".github" / "django_settings_mariadb.py"
    dest = tmp_path / "settings.py"
    dest.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    patch_file(dest, "mariadb", _CA)
    text = dest.read_text(encoding="utf-8")
    assert f'"ssl": {{"ca": "{_CA}"}}' in text
    patch_file(dest, "mariadb", _CA)
    assert text.count('"ssl"') == dest.read_text(encoding="utf-8").count('"ssl"')


def test_patch_psql_injects_sslmode(tmp_path: Path) -> None:
    """PostgreSQL DATABASES gain sslmode verify-ca and sslrootcert."""
    src = _REPO / ".github" / "django_settings_psql.py"
    dest = tmp_path / "settings.py"
    dest.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    patch_file(dest, "psql", _CA)
    text = dest.read_text(encoding="utf-8")
    assert '"sslmode": "verify-ca"' in text
    assert f'"sslrootcert": "{_CA}"' in text
    assert '"sslcert": "/var/www/acme2certifier/volume/db-client-cert.pem"' in text
    assert '"sslkey": "/var/www/acme2certifier/volume/db-client-key.pem"' in text
    assert "HOME" not in text
    patch_file(dest, "psql", _CA)
    twice = dest.read_text(encoding="utf-8")
    assert twice.count("sslrootcert") == text.count("sslrootcert")


def test_patch_rejects_unknown_engine(tmp_path: Path) -> None:
    """Unsupported DJANGO_DB values fail closed."""
    dest = tmp_path / "settings.py"
    dest.write_text("DATABASES = {}\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        patch_file(dest, "mssql", _CA)
