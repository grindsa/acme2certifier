#!/usr/bin/env python3
"""Rewrite relative Markdown links/images in README.md for PyPI rendering.

PyPI does not resolve repository-relative paths. Convert them to absolute
GitHub URLs pinned to a release tag (or commit SHA).
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from urllib.parse import urlparse

# Markdown link or image: ![alt](url) or [text](url)
# Use [^\]]* (not .*?) to avoid super-linear backtracking (python:S8786).
_MD_LINK = re.compile(
    r"""
    (?P<prefix>!?\[[^\]]*\]\()       # ![alt]( or [text](
    (?P<url>[^)\s]+)             # destination (no spaces / closing paren)
    (?P<suffix>\))               # closing paren
    """,
    re.VERBOSE,
)


def _is_absolute(url: str) -> bool:
    if url.startswith(("#", "//")):
        return True
    return bool(urlparse(url).scheme)


def _github_url(repo: str, ref: str, path: str, fragment: str) -> str:
    """Build a GitHub blob/tree URL for a relative path."""
    clean = path.lstrip("./")
    kind = "tree" if clean.endswith("/") else "blob"
    clean = clean.rstrip("/")
    base = f"https://github.com/{repo}/{kind}/{ref}/{clean}"
    return f"{base}#{fragment}" if fragment else base


def rewrite_url(url: str, repo: str, ref: str) -> str:
    """Return an absolute GitHub URL when *url* is repository-relative."""
    if _is_absolute(url):
        return url

    path, fragment = url, ""
    if "#" in url:
        path, fragment = url.split("#", 1)

    if not path:
        # Pure fragment (#section) — leave unchanged
        return url

    return _github_url(repo, ref, path, fragment)


def rewrite_readme(text: str, repo: str, ref: str) -> str:
    """Replace relative Markdown destinations with absolute GitHub URLs."""

    def _sub(match: re.Match[str]) -> str:
        return f"{match.group('prefix')}{rewrite_url(match.group('url'), repo, ref)}{match.group('suffix')}"

    return _MD_LINK.sub(_sub, text)


def _resolve_within_cwd(path: Path) -> Path:
    """Resolve *path* and reject values that escape the working directory."""
    base = Path.cwd().resolve()
    resolved = path.resolve()
    if not resolved.is_relative_to(base):
        raise SystemExit(f"Refusing path outside working directory: {path}")
    return resolved


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "readme",
        type=Path,
        nargs="?",
        default=Path("README.md"),
        help="Path to README.md (default: README.md)",
    )
    parser.add_argument(
        "--repo",
        required=True,
        help="GitHub repository as owner/name (e.g. grindsa/acme2certifier)",
    )
    parser.add_argument(
        "--ref",
        required=True,
        help="Git ref to pin links to (release tag or commit SHA)",
    )
    args = parser.parse_args()

    readme = _resolve_within_cwd(args.readme)
    original = readme.read_text(encoding="utf-8")
    rewritten = rewrite_readme(original, args.repo, args.ref)
    if rewritten == original:
        raise SystemExit(f"No relative links rewritten in {readme}")
    readme.write_text(rewritten, encoding="utf-8")
    print(f"Rewrote relative links in {readme} → github.com/{args.repo}/…/{args.ref}/…")


if __name__ == "__main__":
    main()
