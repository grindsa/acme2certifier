"""Unit tests for min_sync helpers (no git network)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# `tools` is acme2certifier.tools once other tests put the inner package on
# sys.path (regular package wins over repo-root tools/ namespace).
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools" / "min_sync"))
import sync as min_sync  # noqa: E402


def test_001_is_min_owned_prefix() -> None:
    owned = [
        ".github/workflows/main-push-rpm.yml",
        "examples/install_scripts/rpm/packages/",
    ]
    assert min_sync._is_min_owned(".github/workflows/main-push-rpm.yml", owned)
    assert min_sync._is_min_owned(
        "examples/install_scripts/rpm/packages/acme2certifier-min-1.rpm", owned
    )
    assert not min_sync._is_min_owned("acme2certifier/acme_srv/order.py", owned)


def test_002_target_classification() -> None:
    manifest = {
        "min_targets": ["min-devel", "min"],
        "full_targets": ["master", "devel"],
    }
    assert min_sync._is_min_target("min-devel", manifest)
    assert min_sync._is_full_target("master", manifest)
    assert not min_sync._is_min_target("master", manifest)


def test_003_local_and_create_pr_are_exclusive() -> None:
    parser = min_sync.build_parser()
    try:
        parser.parse_args(["--local", "--create-pr"])
        raised = False
    except SystemExit:
        raised = True
    assert raised


def test_004_local_flag_parses() -> None:
    args = min_sync.build_parser().parse_args(["--local"])
    assert args.local is True
    assert args.create_pr is False


def test_005_strip_pyproject_scripts(tmp_path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        "[project.scripts]\n"
        'a2c-cli = "acme2certifier.tools.a2c_cli:main"\n'
        'a2c-wsgi2django = "acme2certifier.tools.a2c_wsgi2django:main"\n'
        "\n"
        "[tool.pytest.ini_options]\n"
        'testpaths = ["test"]\n',
        encoding="utf-8",
    )
    removed = min_sync._strip_pyproject_scripts(
        tmp_path, ["a2c-wsgi2django", "a2c-msicpr-connection-test"]
    )
    assert removed == ["pyproject.toml:[project.scripts].a2c-wsgi2django"]
    text = pyproject.read_text(encoding="utf-8")
    assert "a2c-cli" in text
    assert "a2c-wsgi2django" not in text
    assert "testpaths" in text


_POLICY = {
    "min_targets": ["min-devel", "min"],
    "full_targets": ["master", "devel"],
}


def test_006_confine_to_root_accepts_in_repo(tmp_path: Path) -> None:
    manifest = tmp_path / "tools" / "min_sync" / "manifest.yaml"
    manifest.parent.mkdir(parents=True)
    manifest.write_text("x: 1\n", encoding="utf-8")
    confined = min_sync._confine_to_root(manifest, tmp_path)
    assert confined == os.path.realpath(str(manifest))
    relative = min_sync._confine_to_root(Path("tools/min_sync/manifest.yaml"), tmp_path)
    assert relative == os.path.realpath(str(manifest))


def test_007_confine_to_root_rejects_escape(tmp_path: Path) -> None:
    outside = tmp_path.parent / "secret.yaml"
    with pytest.raises(min_sync.SyncError, match="outside repository root"):
        min_sync._confine_to_root(outside, tmp_path)
    with pytest.raises(min_sync.SyncError, match="outside repository root"):
        min_sync._confine_to_root(Path("..") / "secret.yaml", tmp_path)


def test_008_load_manifest_confines_path(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text("source_default: master\n", encoding="utf-8")
    data = min_sync._load_manifest(manifest, tmp_path)
    assert data["source_default"] == "master"
    with pytest.raises(min_sync.SyncError, match="outside repository root"):
        min_sync._load_manifest(tmp_path.parent / "manifest.yaml", tmp_path)


def test_009_validate_direction() -> None:
    assert min_sync._validate_direction("master", "min-devel", _POLICY) is True
    assert min_sync._validate_direction("min-devel", "master", _POLICY) is False
    with pytest.raises(min_sync.SyncError, match="Unknown source"):
        min_sync._validate_direction("other", "min-devel", _POLICY)
    with pytest.raises(min_sync.SyncError, match="must differ"):
        min_sync._validate_direction("master", "master", _POLICY)
    with pytest.raises(min_sync.SyncError, match="min->min"):
        min_sync._validate_direction("min-devel", "min", _POLICY)
    with pytest.raises(min_sync.SyncError, match="full->full"):
        min_sync._validate_direction("master", "devel", _POLICY)


def test_010_work_branch_and_mode_label() -> None:
    assert (
        min_sync._work_branch_name(
            local_mode=True,
            dry_run=False,
            branch_name="ignored",
            source="master",
            target="min-devel",
            stamp="20260817",
        )
        == "min-devel"
    )
    assert (
        min_sync._work_branch_name(
            local_mode=False,
            dry_run=True,
            branch_name=None,
            source="master",
            target="min-devel",
            stamp="20260817",
        )
        == "sync/master-to-min-devel-20260817"
    )
    assert min_sync._mode_label(True, False, False) == "dry-run"
    assert min_sync._mode_label(False, True, False) == "local (files only, no commit)"
    assert min_sync._mode_label(False, False, True) == "commit + PR"
    assert min_sync._mode_label(False, False, False) == "commit (sync branch)"
