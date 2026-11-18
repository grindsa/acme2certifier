"""Unit tests for min_sync helpers (no git network)."""

from __future__ import annotations

import datetime as dt
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


def test_011_run_reports_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: dict[str, object] = {}

    def fake_run(cmd, *, cwd, check, text, capture_output):
        seen["capture"] = capture_output
        seen["cwd"] = cwd
        return min_sync.subprocess.CompletedProcess(
            cmd,
            seen.get("code", 0),
            stdout=seen.get("stdout"),
            stderr=seen.get("stderr"),
        )

    monkeypatch.setattr(min_sync.subprocess, "run", fake_run)
    seen.update(code=0, stdout="ok\n", stderr="")
    result = min_sync._run(["git", "status"], cwd=tmp_path, capture=False)
    assert result.stdout == "ok\n"
    assert seen["capture"] is False
    assert seen["cwd"] == tmp_path

    seen.update(code=1, stderr="boom\n", stdout="ignored")
    with pytest.raises(min_sync.SyncError, match="boom") as exc:
        min_sync._run(["git", "status"], cwd=tmp_path)
    assert "git status" in str(exc.value)

    seen.update(code=2, stderr="   ", stdout="out-only\n")
    with pytest.raises(min_sync.SyncError, match="out-only"):
        min_sync._run(["git", "status"], cwd=tmp_path)

    seen.update(code=3, stderr=None, stdout=None)
    with pytest.raises(min_sync.SyncError, match="exit 3"):
        min_sync._run(["git", "status"], cwd=tmp_path)

    seen.update(code=4, stderr="nope")
    unchecked = min_sync._run(["git", "status"], cwd=tmp_path, check=False)
    assert unchecked.returncode == 4


def test_012_load_manifest_rejects_non_dict(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text("- not\n- a-dict\n", encoding="utf-8")
    with pytest.raises(min_sync.SyncError, match="Invalid manifest"):
        min_sync._load_manifest(manifest, tmp_path)


def test_013_clean_tree_branch_and_fetch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[tuple[list[str], bool]] = []
    state = {"status": " M dirty\n"}

    def fake_run(cmd, *, cwd, check=True, capture=True):
        calls.append((list(cmd), capture))
        if cmd == ["git", "status", "--porcelain"]:
            stdout = state["status"]
        elif cmd == ["git", "branch", "--show-current"]:
            stdout = "min-devel\n"
        else:
            stdout = ""
        return min_sync.subprocess.CompletedProcess(cmd, 0, stdout, "")

    monkeypatch.setattr(min_sync, "_run", fake_run)
    with pytest.raises(min_sync.SyncError, match="dirty"):
        min_sync._ensure_clean(tmp_path)
    state["status"] = "\n"
    min_sync._ensure_clean(tmp_path)
    assert min_sync._current_branch(tmp_path) == "min-devel"
    min_sync._fetch(tmp_path, "master", "min-devel")
    assert calls[-1] == (["git", "fetch", "origin", "master", "min-devel"], False)


def test_014_path_exists_and_list_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fake_run(cmd, *, cwd, check=True, capture=True):
        if cmd[:3] == ["git", "cat-file", "-e"]:
            rc = 0 if cmd[3].endswith("present") or cmd[3].endswith("docs") else 1
            return min_sync.subprocess.CompletedProcess(cmd, rc, "", "")
        if cmd[:3] == ["git", "cat-file", "-t"]:
            kind = "blob" if cmd[3].endswith("present") else "tree"
            return min_sync.subprocess.CompletedProcess(cmd, 0, kind + "\n", "")
        return min_sync.subprocess.CompletedProcess(
            cmd, 0, "docs/a.md\n\ndocs/b.md\n", ""
        )

    monkeypatch.setattr(min_sync, "_run", fake_run)
    assert min_sync._path_exists_at_ref(tmp_path, "HEAD", "present") is True
    assert min_sync._path_exists_at_ref(tmp_path, "HEAD", "missing") is False
    assert min_sync._list_files_at_ref(tmp_path, "HEAD", "missing") == []
    assert min_sync._list_files_at_ref(tmp_path, "HEAD", "present") == ["present"]
    assert min_sync._list_files_at_ref(tmp_path, "HEAD", "docs") == [
        "docs/a.md",
        "docs/b.md",
    ]


def test_015_checkout_paths_skips_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cmds: list[list[str]] = []

    def fake_run(cmd, *, cwd, check=True, capture=True):
        cmds.append(list(cmd))
        return min_sync.subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(min_sync, "_run", fake_run)
    monkeypatch.setattr(
        min_sync,
        "_path_exists_at_ref",
        lambda repo, ref, path: path != "missing",
    )
    checked = min_sync._checkout_paths(tmp_path, "origin/master", ["missing", "yes.py"])
    assert checked == ["yes.py"]
    assert cmds == [["git", "checkout", "origin/master", "--", "yes.py"]]


def test_016_rm_fs_file_dir_and_symlink(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    min_sync._rm_fs(missing)
    assert not missing.exists()

    directory = tmp_path / "dir"
    directory.mkdir()
    (directory / "child").write_text("x", encoding="utf-8")
    min_sync._rm_fs(directory)
    assert not directory.exists()

    file_path = tmp_path / "file"
    file_path.write_text("x", encoding="utf-8")
    min_sync._rm_fs(file_path)
    assert not file_path.exists()

    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target)
    min_sync._rm_fs(link)
    assert not link.exists()
    assert target.is_dir()

    dangling = tmp_path / "dangling"
    dangling.symlink_to(tmp_path / "absent")
    min_sync._rm_fs(dangling)
    assert not dangling.is_symlink()


def test_017_rm_paths_skips_absent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cmds: list[list[str]] = []

    def fake_run(cmd, *, cwd, check=True, capture=True):
        cmds.append(list(cmd))
        return min_sync.subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(min_sync, "_run", fake_run)
    (tmp_path / "gone").write_text("g", encoding="utf-8")
    dangling = tmp_path / "dangling"
    dangling.symlink_to(tmp_path / "absent")
    removed = min_sync._rm_paths(tmp_path, ["missing", "gone", "dangling"])
    assert removed == ["gone", "dangling"]
    assert not (tmp_path / "gone").exists()
    assert not dangling.is_symlink()
    assert cmds[0] == ["git", "rm", "-rf", "--ignore-unmatch", "--", "gone"]
    assert cmds[1][-1] == "dangling"


def test_018_strip_handlers(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    assert min_sync._strip_handlers(empty, ["__init__.py"]) == []

    def fake_run(cmd, *, cwd, check=True, capture=True):
        return min_sync.subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(min_sync, "_run", fake_run)
    root = tmp_path / min_sync.CAHANDLERS_DIR
    root.mkdir(parents=True)
    (root / "__init__.py").write_text("", encoding="utf-8")
    (root / "drop.py").write_text("x", encoding="utf-8")
    dropdir = root / "dropdir"
    dropdir.mkdir()
    (dropdir / "x").write_text("x", encoding="utf-8")
    removed = min_sync._strip_handlers(tmp_path, ["__init__.py/"])
    assert removed == [
        f"{min_sync.CAHANDLERS_DIR}/drop.py",
        f"{min_sync.CAHANDLERS_DIR}/dropdir",
    ]
    assert (root / "__init__.py").is_file()
    assert not (root / "drop.py").exists()
    assert not dropdir.exists()


def test_019_strip_pyproject_scripts_edges(tmp_path: Path) -> None:
    assert min_sync._strip_pyproject_scripts(tmp_path, []) == []
    assert min_sync._strip_pyproject_scripts(tmp_path, ["missing"]) == []
    pyproject = tmp_path / "pyproject.toml"
    original = (
        "[project.scripts]\n"
        "# comment\n"
        'stay = "pkg:mod"\n'
        "\n"
        "[tool.black]\n"
        "line-length = 88\n"
    )
    pyproject.write_text(original, encoding="utf-8")
    assert min_sync._strip_pyproject_scripts(tmp_path, ["other"]) == []
    assert pyproject.read_text(encoding="utf-8") == original


def test_020_restore_min_owned(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cmds: list[list[str]] = []

    def fake_run(cmd, *, cwd, check=True, capture=True):
        cmds.append(list(cmd))
        return min_sync.subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(min_sync, "_run", fake_run)
    monkeypatch.setattr(
        min_sync,
        "_path_exists_at_ref",
        lambda repo, ref, path: path == "keep",
    )
    monkeypatch.setattr(min_sync, "_rm_paths", lambda repo, paths: [f"rm:{paths[0]}"])
    restored = min_sync._restore_min_owned(
        tmp_path, "origin/min-devel", ["keep", "drop"]
    )
    assert restored == ["keep", "rm:drop"]
    assert cmds == [["git", "checkout", "origin/min-devel", "--", "keep"]]


def test_021_port_into_min(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def checkout(repo, ref, paths):
        assert ref == "origin/master"
        return [f"co:{path}" for path in paths]

    monkeypatch.setattr(min_sync, "_checkout_paths", checkout)
    monkeypatch.setattr(min_sync, "_strip_handlers", lambda repo, keep: ["handler"])
    monkeypatch.setattr(
        min_sync, "_rm_paths", lambda repo, paths: [f"rm:{path}" for path in paths]
    )
    monkeypatch.setattr(
        min_sync,
        "_strip_pyproject_scripts",
        lambda repo, names: [f"script:{name}" for name in names],
    )
    monkeypatch.setattr(
        min_sync, "_restore_min_owned", lambda repo, ref, owned: ["restored"]
    )
    ported, stripped = min_sync._port_into_min(
        tmp_path,
        "origin/master",
        "origin/min-devel",
        {
            "sync_paths": ["owned/x", "shared.py"],
            "min_owned": ["owned/x"],
            "keep_handlers": ["h.py"],
            "strip_into_min": ["gone"],
            "strip_pyproject_scripts_into_min": ["cli"],
        },
    )
    assert ported == ["co:shared.py"]
    assert stripped == ["handler", "rm:gone", "script:cli", "restored"]


def test_022_port_into_full(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    listed: list[str] = []
    checked: list[list[str]] = []

    def list_files(repo, ref, path):
        listed.append(path)
        if path == f"{min_sync.CAHANDLERS_DIR}/kept.py":
            return []
        if path == f"{min_sync.CAHANDLERS_DIR}/also.py":
            return [path]
        if path == "docs":
            return ["docs/a.md", "docs/install_rpm.md", "docs/b.md"]
        return []

    def checkout(repo, ref, paths):
        checked.append(list(paths))
        return list(paths)

    monkeypatch.setattr(min_sync, "_list_files_at_ref", list_files)
    monkeypatch.setattr(min_sync, "_checkout_paths", checkout)
    ported, stripped = min_sync._port_into_full(
        tmp_path,
        "origin/min-devel",
        {
            "sync_paths": [
                "docs/install_rpm.md",
                min_sync.CAHANDLERS_DIR + "/",
                "docs",
            ],
            "min_owned": ["docs/install_rpm.md"],
            "keep_handlers": ["kept.py/", "also.py"],
        },
    )
    assert stripped == []
    assert listed == [
        f"{min_sync.CAHANDLERS_DIR}/kept.py",
        f"{min_sync.CAHANDLERS_DIR}/also.py",
        "docs",
    ]
    assert checked == [
        [f"{min_sync.CAHANDLERS_DIR}/kept.py"],
        [f"{min_sync.CAHANDLERS_DIR}/also.py"],
        ["docs/a.md", "docs/b.md"],
    ]
    assert ported == [item for group in checked for item in group]


def test_023_branch_commit_and_push(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[tuple[list[str], bool, bool]] = []
    state = {"show_rc": 0, "names": "a.py\n"}

    def fake_run(cmd, *, cwd, check=True, capture=True):
        calls.append((list(cmd), capture, check))
        if cmd[:3] == ["git", "show-ref", "--verify"]:
            return min_sync.subprocess.CompletedProcess(cmd, state["show_rc"], "", "")
        if cmd == ["git", "diff", "--cached", "--stat"]:
            return min_sync.subprocess.CompletedProcess(cmd, 0, " a.py | 1 +\n", "")
        if cmd == ["git", "diff", "--cached", "--name-only"]:
            return min_sync.subprocess.CompletedProcess(cmd, 0, state["names"], "")
        return min_sync.subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(min_sync, "_run", fake_run)
    assert min_sync._diff_stat(tmp_path) == "a.py | 1 +"
    min_sync._create_branch(tmp_path, "sync/x", "origin/min-devel")
    min_sync._push(tmp_path, "sync/x")
    min_sync._commit(tmp_path, "ship it")
    assert (
        ["git", "checkout", "-B", "sync/x", "origin/min-devel"],
        False,
        True,
    ) in calls
    assert (["git", "push", "-u", "origin", "sync/x"], False, True) in calls
    assert (["git", "commit", "-m", "ship it"], False, True) in calls

    min_sync._checkout_local_target(tmp_path, "min-devel", "origin/min-devel")
    assert (
        ["git", "show-ref", "--verify", "--quiet", "refs/heads/min-devel"],
        True,
        False,
    ) in calls
    assert (["git", "checkout", "min-devel"], False, True) in calls

    state["show_rc"] = 1
    min_sync._checkout_local_target(tmp_path, "min", "origin/min")
    assert (["git", "checkout", "-b", "min", "origin/min"], False, True) in calls

    state["names"] = " \n"
    with pytest.raises(min_sync.SyncError, match="No changes to commit"):
        min_sync._commit(tmp_path, "empty")


def test_024_create_pr(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    state = {"rc": 0, "stdout": "https://example/pr/1\n", "stderr": ""}

    def fake_run(cmd, *, cwd, check=True, capture=True):
        assert cmd[:3] == ["gh", "pr", "create"]
        assert "--base" in cmd and "--head" in cmd
        return min_sync.subprocess.CompletedProcess(
            cmd, state["rc"], state["stdout"], state["stderr"]
        )

    monkeypatch.setattr(min_sync, "_run", fake_run)
    assert (
        min_sync._create_pr(tmp_path, "sync/x", "min-devel", "title", "body")
        == "https://example/pr/1"
    )

    state.update(rc=1, stdout="", stderr="gh boom\n")
    with pytest.raises(min_sync.SyncError, match="gh boom"):
        min_sync._create_pr(tmp_path, "sync/x", "min-devel", "title", "body")

    state.update(rc=1, stdout="from-stdout\n", stderr="")
    with pytest.raises(min_sync.SyncError, match="from-stdout"):
        min_sync._create_pr(tmp_path, "sync/x", "min-devel", "title", "body")

    state.update(rc=1, stdout=None, stderr=None)
    with pytest.raises(min_sync.SyncError, match="open PR manually"):
        min_sync._create_pr(tmp_path, "sync/x", "min-devel", "title", "body")


def test_025_branch_and_repo_resolution(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    assert (
        min_sync._configured_branch("explicit", {}, "source_default", "master")
        == "explicit"
    )
    assert (
        min_sync._configured_branch(
            None, {"source_default": "devel"}, "source_default", "master"
        )
        == "devel"
    )
    assert (
        min_sync._configured_branch(
            None, {"source_default": ""}, "source_default", "master"
        )
        == "master"
    )
    assert (
        min_sync._configured_branch(
            None, {"source_default": 1}, "source_default", "master"
        )
        == "master"
    )
    assert (
        min_sync._configured_branch(None, {}, "source_default", "min-devel")
        == "min-devel"
    )
    assert (
        min_sync._manifest_file(tmp_path, None)
        == tmp_path / "tools" / "min_sync" / "manifest.yaml"
    )
    explicit = tmp_path / "other.yaml"
    assert min_sync._manifest_file(tmp_path, explicit) == explicit
    assert min_sync._resolve_repo(tmp_path) == tmp_path.resolve()

    def fake_run(cmd, *, cwd, check=True, capture=True):
        assert cmd == ["git", "rev-parse", "--show-toplevel"]
        assert cwd == Path.cwd()
        return min_sync.subprocess.CompletedProcess(cmd, 0, f"{tmp_path}\n", "")

    monkeypatch.setattr(min_sync, "_run", fake_run)
    assert min_sync._resolve_repo(None) == tmp_path.resolve()


def test_026_unknown_target_and_branch_override() -> None:
    with pytest.raises(min_sync.SyncError, match="Unknown target"):
        min_sync._validate_direction("master", "nope", _POLICY)
    assert (
        min_sync._work_branch_name(
            local_mode=False,
            dry_run=False,
            branch_name="sync/custom",
            source="master",
            target="min-devel",
            stamp="20260817",
        )
        == "sync/custom"
    )
    assert (
        min_sync._work_branch_name(
            local_mode=True,
            dry_run=True,
            branch_name="sync/local-dry",
            source="master",
            target="min-devel",
            stamp="20260817",
        )
        == "sync/local-dry"
    )


def test_027_plan_worktree_and_port(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    min_sync._print_plan(
        tmp_path, "origin/master", "origin/min-devel", "sync/x", "dry-run"
    )
    out = capsys.readouterr().out
    assert f"Repo:    {tmp_path}" in out
    assert "From:    origin/master" in out
    assert "Into:    origin/min-devel" in out
    assert "Branch:  sync/x" in out
    assert "Mode:    dry-run" in out

    called: dict[str, tuple] = {}
    monkeypatch.setattr(
        min_sync,
        "_checkout_local_target",
        lambda *args: called.setdefault("local", args),
    )
    monkeypatch.setattr(
        min_sync, "_create_branch", lambda *args: called.setdefault("create", args)
    )
    assert (
        min_sync._prepare_worktree(
            tmp_path,
            local_mode=True,
            dry_run=False,
            target="min-devel",
            origin_target_ref="origin/min-devel",
            work_branch="min-devel",
        )
        == "HEAD"
    )
    assert called["local"][1:] == ("min-devel", "origin/min-devel")
    assert (
        min_sync._prepare_worktree(
            tmp_path,
            local_mode=True,
            dry_run=True,
            target="min-devel",
            origin_target_ref="origin/min-devel",
            work_branch="sync/x",
        )
        == "origin/min-devel"
    )
    assert called["create"][1:] == ("sync/x", "origin/min-devel")

    monkeypatch.setattr(min_sync, "_port_into_min", lambda *args: (["m"], ["s"]))
    monkeypatch.setattr(min_sync, "_port_into_full", lambda *args: (["f"], []))
    assert min_sync._port(tmp_path, "origin/a", "origin/b", {}, True) == (["m"], ["s"])
    assert min_sync._port(tmp_path, "origin/a", "origin/b", {}, False) == (["f"], [])


def test_028_stage_and_summarize(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    cmds: list[list[str]] = []

    def fake_run(cmd, *, cwd, check=True, capture=True):
        cmds.append(list(cmd))
        return min_sync.subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(min_sync, "_run", fake_run)
    monkeypatch.setattr(min_sync, "_diff_stat", lambda repo: "")
    with pytest.raises(min_sync.SyncError, match="Nothing to sync"):
        min_sync._stage_and_summarize(tmp_path, [])
    assert "No allowlisted differences" in capsys.readouterr().out

    monkeypatch.setattr(min_sync, "_diff_stat", lambda repo: " a.py | 1 +")
    min_sync._stage_and_summarize(tmp_path, ["gone.py"])
    out = capsys.readouterr().out
    assert "staged diff" in out
    assert "a.py | 1 +" in out
    assert "Stripped/restored:" in out
    assert "gone.py" in out
    assert cmds == [["git", "add", "-A"], ["git", "add", "-A"]]


def test_029_pr_title_body() -> None:
    title, body = min_sync._pr_title_body(
        "master", "min-devel", "20260817", ["a.py"], ["b.py"]
    )
    assert title == "[sync] master → min-devel (20260817)"
    assert "- `a.py`" in body
    assert "- `b.py`" in body
    assert "does **not** promote" in body
    assert "tools/min_sync/manifest.yaml" in body

    title, body = min_sync._pr_title_body("min-devel", "master", "20260817", [], [])
    assert title == "[sync] min-devel → master (20260817)"
    assert "- (none)" in body


def test_030_finish_modes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    cmds: list[tuple[list[str], bool]] = []

    def fake_run(cmd, *, cwd, check=True, capture=True):
        cmds.append((list(cmd), capture))
        return min_sync.subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(min_sync, "_run", fake_run)
    min_sync._finish_dry_run(tmp_path, "master", "sync/x", "min-devel")
    out = capsys.readouterr().out
    assert "Dry-run: discarding" in out
    assert "Done (dry-run)." in out
    assert (["git", "reset", "--hard"], True) in cmds
    assert (["git", "checkout", "master"], False) in cmds
    assert (["git", "branch", "-D", "sync/x"], True) in cmds

    cmds.clear()
    min_sync._finish_dry_run(tmp_path, "sync/x", "sync/x", "min-devel")
    min_sync._finish_dry_run(tmp_path, "master", "min-devel", "min-devel")
    assert not any(cmd[:2] == ["git", "branch"] for cmd, _capture in cmds)

    min_sync._finish_local("min-devel", "title")
    out = capsys.readouterr().out
    assert "not committed, not pushed" in out
    assert "git commit -m 'title'" in out

    commits: list[str] = []
    pushes: list[str] = []
    monkeypatch.setattr(
        min_sync, "_commit", lambda repo, message: commits.append(message)
    )
    monkeypatch.setattr(min_sync, "_push", lambda repo, branch: pushes.append(branch))
    monkeypatch.setattr(
        min_sync,
        "_create_pr",
        lambda repo, head, base, title, body: "https://example/pr/1",
    )
    min_sync._finish_commit(tmp_path, "sync/x", "min-devel", "title", "body", True)
    assert commits == ["title"]
    assert pushes == ["sync/x"]
    assert "PR: https://example/pr/1" in capsys.readouterr().out

    pushes.clear()
    min_sync._finish_commit(tmp_path, "sync/x", "min-devel", "title", "body", False)
    assert pushes == []
    out = capsys.readouterr().out
    assert "git push -u origin sync/x" in out
    assert "--base min-devel --head sync/x" in out


def test_031_cleanup_after_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cmds: list[tuple[list[str], bool]] = []

    def fake_run(cmd, *, cwd, check=True, capture=True):
        cmds.append((list(cmd), check))
        return min_sync.subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(min_sync, "_run", fake_run)
    min_sync._cleanup_after_failure(tmp_path, "master", "sync/x", "min-devel", False)
    assert (["git", "reset", "--hard"], True) in cmds
    assert (["git", "checkout", "master"], False) in cmds
    assert (["git", "branch", "-D", "sync/x"], False) in cmds

    cmds.clear()
    min_sync._cleanup_after_failure(tmp_path, "", "sync/x", "min-devel", False)
    assert not any(cmd[:2] == ["git", "checkout"] for cmd, _check in cmds)
    assert (["git", "branch", "-D", "sync/x"], False) in cmds

    cmds.clear()
    min_sync._cleanup_after_failure(tmp_path, "master", "sync/x", "min-devel", True)
    min_sync._cleanup_after_failure(tmp_path, "master", "master", "min-devel", False)
    assert not any(cmd[:2] == ["git", "branch"] for cmd, _check in cmds)

    def boom(cmd, *, cwd, check=True, capture=True):
        raise min_sync.SyncError("reset failed")

    monkeypatch.setattr(min_sync, "_run", boom)
    min_sync._cleanup_after_failure(tmp_path, "master", "sync/x", "min-devel", False)


def test_032_complete_sync_dispatches(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(min_sync, "_finish_dry_run", lambda *args: calls.append("dry"))
    monkeypatch.setattr(min_sync, "_finish_local", lambda *args: calls.append("local"))
    monkeypatch.setattr(
        min_sync, "_finish_commit", lambda *args: calls.append("commit")
    )
    common = dict(
        original="master",
        work_branch="sync/x",
        target="min-devel",
        title="t",
        body="b",
    )
    min_sync._complete_sync(
        tmp_path, dry_run=True, local_mode=True, create_pr=True, **common
    )
    min_sync._complete_sync(
        tmp_path, dry_run=False, local_mode=True, create_pr=False, **common
    )
    min_sync._complete_sync(
        tmp_path, dry_run=False, local_mode=False, create_pr=True, **common
    )
    assert calls == ["dry", "local", "commit"]


def _install_main_doubles(
    monkeypatch: pytest.MonkeyPatch, manifest: dict, *, fail_port: bool = False
) -> dict:
    rec: dict = {
        "ensure": 0,
        "fetch": None,
        "prepare": None,
        "port": None,
        "stage": None,
        "complete": None,
        "cleanup": None,
        "manifest_path": None,
    }

    def load(path: Path, root: Path) -> dict:
        rec["manifest_path"] = path
        return manifest

    def ensure(repo: Path) -> None:
        rec["ensure"] += 1

    def fetch(repo: Path, *refs: str) -> None:
        rec["fetch"] = refs

    def prepare(repo: Path, **kwargs: object) -> str:
        rec["prepare"] = kwargs
        if kwargs["local_mode"] and not kwargs["dry_run"]:
            return "HEAD"
        return str(kwargs["origin_target_ref"])

    def do_port(*args: object) -> tuple[list[str], list[str]]:
        rec["port"] = args
        if fail_port:
            raise RuntimeError("port failed")
        return (["ported.py"], ["stripped.py"])

    def stage(repo: Path, stripped: list[str]) -> None:
        rec["stage"] = list(stripped)

    def complete(repo: Path, **kwargs: object) -> None:
        rec["complete"] = kwargs

    def cleanup(*args: object) -> None:
        rec["cleanup"] = args

    monkeypatch.setattr(min_sync, "_load_manifest", load)
    monkeypatch.setattr(min_sync, "_ensure_clean", ensure)
    monkeypatch.setattr(min_sync, "_current_branch", lambda repo: "feature")
    monkeypatch.setattr(min_sync, "_fetch", fetch)
    monkeypatch.setattr(min_sync, "_prepare_worktree", prepare)
    monkeypatch.setattr(min_sync, "_port", do_port)
    monkeypatch.setattr(min_sync, "_stage_and_summarize", stage)
    monkeypatch.setattr(min_sync, "_complete_sync", complete)
    monkeypatch.setattr(min_sync, "_cleanup_after_failure", cleanup)

    class _FixedDateTime(dt.datetime):
        @classmethod
        def now(cls, tz: dt.tzinfo | None = None) -> "_FixedDateTime":
            return cls(2026, 8, 17, tzinfo=tz)

    monkeypatch.setattr(min_sync.dt, "datetime", _FixedDateTime)
    return rec


_MAIN_MANIFEST = {
    "source_default": "master",
    "target_default": "min-devel",
    **_POLICY,
}


def test_033_main_success_modes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    cases = [
        (["--dry-run", "--branch-name", "sync/custom"], "sync/custom", "dry-run", True),
        (["--local"], "min-devel", "local (files only, no commit)", True),
        (["--create-pr"], "sync/master-to-min-devel-20260817", "commit + PR", True),
        ([], "sync/master-to-min-devel-20260817", "commit (sync branch)", True),
    ]
    for extra, work_branch, mode, into_min in cases:
        rec = _install_main_doubles(monkeypatch, _MAIN_MANIFEST)
        min_sync.main(
            [
                "--from",
                "master",
                "--into",
                "min-devel",
                "--repo-root",
                str(tmp_path),
                *extra,
            ]
        )
        assert rec["ensure"] == 1
        assert rec["fetch"] == ("master", "min-devel")
        assert rec["cleanup"] is None
        assert rec["prepare"]["work_branch"] == work_branch
        assert rec["port"][1] == "origin/master"
        assert rec["port"][4] is into_min
        assert rec["stage"] == ["stripped.py"]
        assert rec["complete"]["title"] == "[sync] master → min-devel (20260817)"
        assert "stripped.py" in rec["complete"]["body"]
        assert mode in capsys.readouterr().out
        assert (
            rec["manifest_path"]
            == tmp_path.resolve() / "tools" / "min_sync" / "manifest.yaml"
        )

    rec = _install_main_doubles(monkeypatch, _MAIN_MANIFEST)
    min_sync.main(["--repo-root", str(tmp_path), "--dry-run"])
    assert rec["fetch"] == ("master", "min-devel")

    rec = _install_main_doubles(monkeypatch, _MAIN_MANIFEST)
    custom = tmp_path / "custom.yaml"
    min_sync.main(
        [
            "--from",
            "min-devel",
            "--into",
            "master",
            "--repo-root",
            str(tmp_path),
            "--manifest",
            str(custom),
        ]
    )
    assert rec["manifest_path"] == custom
    assert rec["port"][1] == "origin/min-devel"
    assert rec["port"][2] == "origin/master"
    assert rec["port"][4] is False
    assert rec["complete"]["create_pr"] is False
    assert rec["prepare"]["local_mode"] is False


def test_034_main_errors(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    rec = _install_main_doubles(monkeypatch, _MAIN_MANIFEST)
    with pytest.raises(
        min_sync.SyncError, match="--branch-name cannot be used with --local"
    ):
        min_sync.main(
            [
                "--local",
                "--branch-name",
                "sync/nope",
                "--from",
                "master",
                "--into",
                "min-devel",
                "--repo-root",
                str(tmp_path),
            ]
        )
    assert rec["ensure"] == 0
    assert rec["cleanup"] is None

    rec = _install_main_doubles(monkeypatch, _MAIN_MANIFEST, fail_port=True)
    with pytest.raises(RuntimeError, match="port failed"):
        min_sync.main(
            [
                "--from",
                "master",
                "--into",
                "min-devel",
                "--repo-root",
                str(tmp_path),
            ]
        )
    _repo, original, work_branch, target, local_mode = rec["cleanup"]
    assert original == "feature"
    assert work_branch == "sync/master-to-min-devel-20260817"
    assert target == "min-devel"
    assert local_mode is False
    assert rec["complete"] is None


def test_035_main_guard_reports_syncerror(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(argv: list[str] | None = None) -> None:
        raise min_sync.SyncError("boom")

    monkeypatch.setattr(min_sync, "main", fail)
    source_path = Path(min_sync.__file__)
    lines = source_path.read_text(encoding="utf-8").splitlines(keepends=True)
    start = next(
        index
        for index, line in enumerate(lines)
        if line.startswith('if __name__ == "__main__":')
    )
    padded = "\n" * start + "".join(lines[start:])
    code = compile(padded, str(source_path), "exec")
    globs = dict(min_sync.__dict__)
    globs["__name__"] = "__main__"
    with pytest.raises(SystemExit) as exc:
        exec(code, globs)  # noqa: S102
    assert exc.value.code == 1
    assert isinstance(exc.value.__cause__, min_sync.SyncError)
    assert "ERROR: boom" in capsys.readouterr().err
