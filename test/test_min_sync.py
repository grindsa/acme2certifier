"""Unit tests for min_sync helpers (no git network)."""

from __future__ import annotations

from tools.min_sync import sync as min_sync


def test_is_min_owned_prefix() -> None:
    owned = [".github/workflows/main-push-rpm.yml", "examples/install_scripts/rpm/packages/"]
    assert min_sync._is_min_owned(".github/workflows/main-push-rpm.yml", owned)
    assert min_sync._is_min_owned(
        "examples/install_scripts/rpm/packages/acme2certifier-min-1.rpm", owned
    )
    assert not min_sync._is_min_owned("acme2certifier/acme_srv/order.py", owned)


def test_target_classification() -> None:
    manifest = {
        "min_targets": ["min-devel", "min"],
        "full_targets": ["master", "devel"],
    }
    assert min_sync._is_min_target("min-devel", manifest)
    assert min_sync._is_full_target("master", manifest)
    assert not min_sync._is_min_target("master", manifest)
