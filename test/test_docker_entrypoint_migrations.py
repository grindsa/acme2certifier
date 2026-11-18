# -*- coding: utf-8 -*-
"""Static checks: Docker entrypoints must not own Django migrations on the volume."""

from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_ENTRYPOINTS = (
    _REPO / "examples/Docker/apache2/docker-entrypoint.sh",
    _REPO / "examples/Docker/nginx/docker-entrypoint.sh",
)


@pytest.mark.parametrize("entrypoint", _ENTRYPOINTS, ids=("apache2", "nginx"))
def test_001_entrypoint_exists(entrypoint: Path) -> None:
    assert entrypoint.is_file()


@pytest.mark.parametrize("entrypoint", _ENTRYPOINTS, ids=("apache2", "nginx"))
def test_002_no_copy_migrations_to_volume(entrypoint: Path) -> None:
    text = entrypoint.read_text(encoding="utf-8")
    assert "copying django migrations to volume" not in text
    assert 'cp -R "$DJANGO_MIGRATIONS" /var/www/acme2certifier/volume/' not in text
    assert "cp -R $DJANGO_MIGRATIONS /var/www/acme2certifier/volume/" not in text


@pytest.mark.parametrize("entrypoint", _ENTRYPOINTS, ids=("apache2", "nginx"))
def test_003_no_symlink_package_migrations_to_volume(entrypoint: Path) -> None:
    text = entrypoint.read_text(encoding="utf-8")
    assert "ln -s /var/www/acme2certifier/volume/migrations" not in text
    assert "replace migration directory with volume symlink" not in text


@pytest.mark.parametrize("entrypoint", _ENTRYPOINTS, ids=("apache2", "nginx"))
def test_004_warns_and_ignores_volume_migrations(entrypoint: Path) -> None:
    text = entrypoint.read_text(encoding="utf-8")
    assert "volume/migrations is deprecated and ignored" in text
    assert "migrations.image" in text
    assert "a2c-schema-update --mode django" in text
