"""Unit tests for min_sync helpers (no git network)."""

from __future__ import annotations

import sys
from pathlib import Path

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


def test_006_ensure_under_root_accepts_inside(tmp_path: Path) -> None:
    inside = tmp_path / "tools" / "min_sync" / "manifest.yaml"
    inside.parent.mkdir(parents=True)
    inside.write_text("min_targets: []\n", encoding="utf-8")
    resolved = min_sync._ensure_under_root(inside, tmp_path)
    assert resolved == inside.resolve()


def test_007_ensure_under_root_rejects_escape(tmp_path: Path) -> None:
    outside = tmp_path / ".." / "escape.yaml"
    try:
        min_sync._ensure_under_root(outside, tmp_path)
        raised = False
    except min_sync.SyncError:
        raised = True
    assert raised


def test_008_load_manifest_rejects_outside_root(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "evil.yaml"
    outside.write_text("min_targets: []\n", encoding="utf-8")
    try:
        min_sync._load_manifest(outside, root=root)
        raised = False
    except min_sync.SyncError:
        raised = True
    assert raised


def test_009_validate_sync_pair_into_min() -> None:
    manifest = {
        "min_targets": ["min-devel", "min"],
        "full_targets": ["master", "devel"],
    }
    assert min_sync._validate_sync_pair("master", "min-devel", manifest) is True
    assert min_sync._validate_sync_pair("min-devel", "master", manifest) is False


def test_010_validate_sync_pair_rejects_same_family() -> None:
    manifest = {
        "min_targets": ["min-devel", "min"],
        "full_targets": ["master", "devel"],
    }
    try:
        min_sync._validate_sync_pair("min-devel", "min", manifest)
        raised = False
    except min_sync.SyncError:
        raised = True
    assert raised
