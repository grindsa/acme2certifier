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
