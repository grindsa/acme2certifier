#!/usr/bin/env python3
"""Bidirectional allowlist sync between full (master/devel) and min branches.

Default: sync branch for review PR. --local applies files on the target
branch without committing. Never promotes min-devel -> min.
"""

from __future__ import annotations

import argparse
import datetime as dt
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Sequence

import yaml

MANIFEST_NAME = "manifest.yaml"
CAHANDLERS_DIR = "acme2certifier/cahandlers"


class SyncError(RuntimeError):
    """Fatal sync error."""


def _run(
    cmd: Sequence[str],
    *,
    cwd: Path,
    check: bool = True,
    capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        list(cmd),
        cwd=cwd,
        check=False,
        text=True,
        capture_output=capture,
    )
    if check and result.returncode != 0:
        stderr = (result.stderr or "").strip()
        stdout = (result.stdout or "").strip()
        detail = stderr or stdout or f"exit {result.returncode}"
        raise SyncError(f"$ {' '.join(cmd)}\n{detail}")
    return result


def _load_manifest(path: Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SyncError(f"Invalid manifest: {path}")
    return data


def _is_min_target(branch: str, manifest: dict) -> bool:
    return branch in set(manifest.get("min_targets") or [])


def _is_full_target(branch: str, manifest: dict) -> bool:
    return branch in set(manifest.get("full_targets") or [])


def _ensure_clean(repo: Path) -> None:
    status = _run(["git", "status", "--porcelain"], cwd=repo).stdout
    if status.strip():
        raise SyncError("Working tree is dirty; commit/stash first.")


def _current_branch(repo: Path) -> str:
    return _run(["git", "branch", "--show-current"], cwd=repo).stdout.strip()


def _fetch(repo: Path, *refs: str) -> None:
    _run(["git", "fetch", "origin", *refs], cwd=repo, capture=False)


def _path_exists_at_ref(repo: Path, ref: str, path: str) -> bool:
    result = _run(
        ["git", "cat-file", "-e", f"{ref}:{path}"],
        cwd=repo,
        check=False,
    )
    return result.returncode == 0


def _list_files_at_ref(repo: Path, ref: str, path: str) -> list[str]:
    if not _path_exists_at_ref(repo, ref, path):
        return []
    # File vs tree
    obj_type = _run(
        ["git", "cat-file", "-t", f"{ref}:{path}"],
        cwd=repo,
    ).stdout.strip()
    if obj_type == "blob":
        return [path]
    out = _run(
        ["git", "ls-tree", "-r", "--name-only", ref, "--", path],
        cwd=repo,
    ).stdout
    return [line for line in out.splitlines() if line]


def _is_min_owned(path: str, min_owned: Sequence[str]) -> bool:
    for owned in min_owned:
        owned_n = owned.rstrip("/")
        if path == owned_n or path.startswith(owned_n + "/"):
            return True
    return False


def _checkout_paths(repo: Path, source_ref: str, paths: Iterable[str]) -> list[str]:
    checked: list[str] = []
    for path in paths:
        if not _path_exists_at_ref(repo, source_ref, path):
            continue
        _run(["git", "checkout", source_ref, "--", path], cwd=repo)
        checked.append(path)
    return checked


def _rm_fs(path: Path) -> None:
    """Remove leftover files/dirs git rm leaves behind (empty directories)."""
    if not path.exists() and not path.is_symlink():
        return
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
        return
    path.unlink()


def _rm_paths(repo: Path, paths: Iterable[str]) -> list[str]:
    removed: list[str] = []
    for path in paths:
        p = repo / path
        if not p.exists() and not p.is_symlink():
            continue
        _run(["git", "rm", "-rf", "--ignore-unmatch", "--", path], cwd=repo)
        _rm_fs(p)
        removed.append(path)
    return removed


def _strip_handlers(repo: Path, keep_handlers: Sequence[str]) -> list[str]:
    root = repo / CAHANDLERS_DIR
    if not root.exists():
        return []
    keep = {h.rstrip("/") for h in keep_handlers}
    removed: list[str] = []
    for child in sorted(root.iterdir()):
        name = child.name
        if name in keep:
            continue
        rel = f"{CAHANDLERS_DIR}/{name}"
        removed.extend(_rm_paths(repo, [rel]))
    return removed


def _strip_pyproject_scripts(repo: Path, script_names: Sequence[str]) -> list[str]:
    """Remove full-only console scripts from pyproject.toml on min targets."""
    if not script_names:
        return []
    path = repo / "pyproject.toml"
    if not path.exists():
        return []
    remove = set(script_names)
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    in_scripts = False
    new_lines: list[str] = []
    removed: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped == "[project.scripts]":
            in_scripts = True
            new_lines.append(line)
            continue
        if in_scripts and stripped.startswith("[") and stripped.endswith("]"):
            in_scripts = False
        if in_scripts and stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in remove:
                removed.append(key)
                continue
        new_lines.append(line)
    if removed:
        path.write_text("".join(new_lines), encoding="utf-8")
    return [f"pyproject.toml:[project.scripts].{name}" for name in removed]


def _restore_min_owned(
    repo: Path, target_ref: str, min_owned: Sequence[str]
) -> list[str]:
    restored: list[str] = []
    for path in min_owned:
        if _path_exists_at_ref(repo, target_ref, path):
            _run(["git", "checkout", target_ref, "--", path], cwd=repo)
            restored.append(path)
        else:
            # Source may have introduced a forbidden path; drop it.
            removed = _rm_paths(repo, [path])
            restored.extend(removed)
    return restored


def _port_into_min(
    repo: Path,
    source_ref: str,
    target_ref: str,
    manifest: dict,
) -> tuple[list[str], list[str]]:
    sync_paths: list[str] = list(manifest["sync_paths"])
    min_owned: list[str] = list(manifest.get("min_owned") or [])
    keep_handlers: list[str] = list(manifest.get("keep_handlers") or [])
    strip_into_min: list[str] = list(manifest.get("strip_into_min") or [])
    strip_pyproject_scripts: list[str] = list(
        manifest.get("strip_pyproject_scripts_into_min") or []
    )

    ported: list[str] = []
    for path in sync_paths:
        if _is_min_owned(path, min_owned):
            continue
        ported.extend(_checkout_paths(repo, source_ref, [path]))

    stripped: list[str] = []
    stripped.extend(_strip_handlers(repo, keep_handlers))
    stripped.extend(_rm_paths(repo, strip_into_min))
    stripped.extend(_strip_pyproject_scripts(repo, strip_pyproject_scripts))
    stripped.extend(_restore_min_owned(repo, target_ref, min_owned))
    return ported, stripped


def _port_into_full(
    repo: Path,
    source_ref: str,
    manifest: dict,
) -> tuple[list[str], list[str]]:
    sync_paths: list[str] = list(manifest["sync_paths"])
    min_owned: list[str] = list(manifest.get("min_owned") or [])
    keep_handlers: list[str] = list(manifest.get("keep_handlers") or [])

    ported: list[str] = []
    for path in sync_paths:
        if _is_min_owned(path, min_owned):
            continue
        if path.rstrip("/") == CAHANDLERS_DIR:
            handler_paths = [f"{CAHANDLERS_DIR}/{h.rstrip('/')}" for h in keep_handlers]
            for hp in handler_paths:
                files = _list_files_at_ref(repo, source_ref, hp)
                ported.extend(_checkout_paths(repo, source_ref, files or [hp]))
            continue
        # Update/add files present on source; never delete target-only files.
        files = _list_files_at_ref(repo, source_ref, path)
        files = [f for f in files if not _is_min_owned(f, min_owned)]
        ported.extend(_checkout_paths(repo, source_ref, files))
    return ported, []


def _diff_stat(repo: Path) -> str:
    return _run(["git", "diff", "--cached", "--stat"], cwd=repo).stdout.strip()


def _create_branch(repo: Path, name: str, start_ref: str) -> None:
    _run(["git", "checkout", "-B", name, start_ref], cwd=repo, capture=False)


def _checkout_local_target(repo: Path, name: str, origin_ref: str) -> None:
    """Checkout an existing local target branch; create it from origin if missing.

    Does not reset a local branch that already exists.
    """
    exists = _run(
        ["git", "show-ref", "--verify", "--quiet", f"refs/heads/{name}"],
        cwd=repo,
        check=False,
    )
    if exists.returncode == 0:
        _run(["git", "checkout", name], cwd=repo, capture=False)
        return
    _run(["git", "checkout", "-b", name, origin_ref], cwd=repo, capture=False)


def _commit(repo: Path, message: str) -> None:
    _run(["git", "add", "-A"], cwd=repo)
    # Nothing to commit?
    cached = _run(["git", "diff", "--cached", "--name-only"], cwd=repo).stdout.strip()
    if not cached:
        raise SyncError("No changes to commit after sync.")
    _run(["git", "commit", "-m", message], cwd=repo, capture=False)


def _push(repo: Path, branch: str) -> None:
    _run(["git", "push", "-u", "origin", branch], cwd=repo, capture=False)


def _create_pr(repo: Path, head: str, base: str, title: str, body: str) -> str:
    result = _run(
        [
            "gh",
            "pr",
            "create",
            "--base",
            base,
            "--head",
            head,
            "--title",
            title,
            "--body",
            body,
        ],
        cwd=repo,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise SyncError(
            f"gh pr create failed (push branch and open PR manually).\n{detail}"
        )
    return (result.stdout or "").strip()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Allowlist sync between full and min branches. "
            "Default prepares a sync branch; --local applies files only "
            "(no commit, no PR). Does not promote min-devel -> min."
        )
    )
    parser.add_argument(
        "--from",
        dest="source",
        default=None,
        help="Source branch (default: manifest source_default)",
    )
    parser.add_argument(
        "--into",
        dest="target",
        default=None,
        help="Target branch (default: manifest target_default)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Apply sync on a temp branch, print diff, discard",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--create-pr",
        action="store_true",
        help="Push sync branch and create a GitHub PR via gh",
    )
    mode.add_argument(
        "--local",
        action="store_true",
        help="Apply allowlist sync on the local target branch (no commit, no PR)",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Repository root (default: auto-detect from git)",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=None,
        help="Path to manifest.yaml",
    )
    parser.add_argument(
        "--branch-name",
        default=None,
        help="Override sync branch name (ignored with --local)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    repo = args.repo_root
    if repo is None:
        top = _run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=Path.cwd(),
        ).stdout.strip()
        repo = Path(top)
    repo = repo.resolve()

    manifest_path = args.manifest or (repo / "tools" / "min_sync" / MANIFEST_NAME)
    manifest = _load_manifest(manifest_path)

    source = args.source or manifest.get("source_default") or "master"
    target = args.target or manifest.get("target_default") or "min-devel"

    if not (_is_min_target(source, manifest) or _is_full_target(source, manifest)):
        raise SyncError(f"Unknown source branch for sync policy: {source}")
    if not (_is_min_target(target, manifest) or _is_full_target(target, manifest)):
        raise SyncError(f"Unknown target branch for sync policy: {target}")
    if source == target:
        raise SyncError("Source and target must differ.")
    if _is_min_target(source, manifest) and _is_min_target(target, manifest):
        raise SyncError("Refuse min->min sync; merge min-devel -> min manually.")
    if _is_full_target(source, manifest) and _is_full_target(target, manifest):
        raise SyncError("Refuse full->full sync; use normal git merge/PR.")

    into_min = _is_min_target(target, manifest)
    if into_min and not _is_full_target(source, manifest):
        raise SyncError("Into min requires a full source (master/devel).")
    if not into_min and not _is_min_target(source, manifest):
        raise SyncError("Into full requires a min source (min-devel/min).")

    if args.local and args.branch_name:
        raise SyncError("--branch-name cannot be used with --local.")

    _ensure_clean(repo)
    original = _current_branch(repo)
    _fetch(repo, source, target)

    source_ref = f"origin/{source}"
    origin_target_ref = f"origin/{target}"
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d")
    local_mode = bool(args.local)
    # Temp branch for dry-run; sync/* for PR path; target itself for --local
    if local_mode and not args.dry_run:
        work_branch = target
    else:
        work_branch = args.branch_name or f"sync/{source}-to-{target}-{stamp}"

    if args.dry_run:
        mode = "dry-run"
    elif local_mode:
        mode = "local (files only, no commit)"
    elif args.create_pr:
        mode = "commit + PR"
    else:
        mode = "commit (sync branch)"

    print(f"Repo:    {repo}")
    print(f"From:    {source_ref}")
    print(f"Into:    {origin_target_ref}")
    print(f"Branch:  {work_branch}")
    print(f"Mode:    {mode}")

    if local_mode and not args.dry_run:
        _checkout_local_target(repo, target, origin_target_ref)
        target_ref = "HEAD"
    else:
        _create_branch(repo, work_branch, origin_target_ref)
        target_ref = origin_target_ref

    try:
        if into_min:
            ported, stripped = _port_into_min(repo, source_ref, target_ref, manifest)
        else:
            ported, stripped = _port_into_full(repo, source_ref, manifest)

        _run(["git", "add", "-A"], cwd=repo)
        stat = _diff_stat(repo)
        if not stat:
            print("No allowlisted differences to port.")
            raise SyncError("Nothing to sync.")

        print("\n--- staged diff ---\n")
        print(stat)
        if stripped:
            print("\nStripped/restored:")
            for p in stripped:
                print(f"  - {p}")

        title = f"[sync] {source} → {target} ({stamp})"
        body = "\n".join(
            [
                f"Automated allowlist sync from `{source}` into `{target}`.",
                "",
                "Review carefully. This does **not** promote `min-devel` → `min`.",
                "",
                "### Ported paths",
                *[f"- `{p}`" for p in ported],
                "",
                "### Strip / restore",
                *([f"- `{p}`" for p in stripped] if stripped else ["- (none)"]),
                "",
                f"Manifest: `tools/min_sync/{MANIFEST_NAME}`",
            ]
        )

        if args.dry_run:
            print("\nDry-run: discarding branch changes.")
            _run(["git", "reset", "--hard"], cwd=repo)
            _run(["git", "checkout", original], cwd=repo, capture=False)
            if work_branch != original and work_branch != target:
                _run(["git", "branch", "-D", work_branch], cwd=repo)
            print("Done (dry-run).")
            return 0

        if local_mode:
            print(
                f"\nSynced files onto `{target}` (not committed, not pushed). "
                f"Review, then commit when ready:"
            )
            print(f"  git commit -m '{title}'")
            return 0

        _commit(repo, title)
        if args.create_pr:
            _push(repo, work_branch)
            url = _create_pr(repo, work_branch, target, title, body)
            print(f"\nPR: {url}")
        else:
            print(
                f"\nCommitted on `{work_branch}`. "
                f"Push and open PR into `{target}` when ready:"
            )
            print(f"  git push -u origin {work_branch}")
            print(
                f"  gh pr create --base {target} --head {work_branch} "
                f"--title '{title}'"
            )
        return 0
    except Exception:
        # Best-effort cleanup back to original branch
        try:
            _run(["git", "reset", "--hard"], cwd=repo)
            if original:
                _run(["git", "checkout", original], cwd=repo, check=False)
            if not local_mode and work_branch != original and work_branch != target:
                _run(
                    ["git", "branch", "-D", work_branch],
                    cwd=repo,
                    check=False,
                )
        except SyncError:
            pass
        raise


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SyncError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
