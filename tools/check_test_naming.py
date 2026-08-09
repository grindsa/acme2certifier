#!/usr/bin/env python3
"""Validate unittest naming in test files.

Required format:
- test_<number>_<description>
- numbers must be strictly increasing within each class or module scope
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

CLASS_RE = re.compile(r"^(\s*)class\s+([A-Za-z_][A-Za-z0-9_]*)\b")
TEST_DEF_RE = re.compile(r"^(\s*)def\s+(test_[A-Za-z0-9_]+)\s*\(")
TEST_NAME_RE = re.compile(r"^test_(\d+)_([A-Za-z0-9_]+)$")


def _indent_len(prefix: str) -> int:
    return len(prefix.replace("\t", "    "))


def _normalize_paths(input_paths: Sequence[str]) -> List[Path]:
    if not input_paths:
        return sorted(Path("test").glob("test*.py"))

    result: List[Path] = []
    for raw in input_paths:
        path = Path(raw)
        if not path.exists() or path.suffix != ".py":
            continue

        rel = path
        try:
            rel = path.resolve().relative_to(Path.cwd().resolve())
        except ValueError:
            pass

        rel_str = rel.as_posix()
        if rel_str.startswith("test/") and rel.name.startswith("test"):
            result.append(rel)

    seen = set()
    deduped: List[Path] = []
    for p in result:
        if p not in seen:
            seen.add(p)
            deduped.append(p)
    return deduped


def check_file(file_path: Path) -> List[str]:
    errors: List[str] = []
    lines = file_path.read_text(encoding="utf-8").splitlines()

    class_stack: List[Tuple[int, str, int]] = []
    class_instance_counter: Dict[str, int] = {}
    prev_num_by_scope: Dict[Tuple[str, int], int] = {}
    seen_name_by_scope: Dict[Tuple[str, int], set] = {}

    for line_no, line in enumerate(lines, start=1):
        class_match = CLASS_RE.match(line)
        if class_match:
            class_indent = _indent_len(class_match.group(1))
            while class_stack and class_stack[-1][0] >= class_indent:
                class_stack.pop()
            class_name = class_match.group(2)
            class_idx = class_instance_counter.get(class_name, 0) + 1
            class_instance_counter[class_name] = class_idx
            class_stack.append((class_indent, class_name, class_idx))
            continue

        def_match = TEST_DEF_RE.match(line)
        if not def_match:
            continue

        def_indent = _indent_len(def_match.group(1))
        while class_stack and class_stack[-1][0] >= def_indent:
            class_stack.pop()

        test_name = def_match.group(2)
        if class_stack:
            scope = (class_stack[-1][1], class_stack[-1][2])
            scope_label = f"{scope[0]}[{scope[1]}]"
        else:
            scope = ("__module__", 1)
            scope_label = "module"

        if scope not in seen_name_by_scope:
            seen_name_by_scope[scope] = set()
        if test_name in seen_name_by_scope[scope]:
            errors.append(
                f"{file_path}:{line_no}: duplicate test name '{test_name}' in scope {scope_label}"
            )
        seen_name_by_scope[scope].add(test_name)

        name_match = TEST_NAME_RE.match(test_name)
        if not name_match:
            errors.append(
                f"{file_path}:{line_no}: invalid name '{test_name}' (expected test_<number>_<description>)"
            )
            continue

        num = int(name_match.group(1))
        prev = prev_num_by_scope.get(scope)
        if prev is not None and num <= prev:
            errors.append(
                f"{file_path}:{line_no}: non-increasing test number {num:03d} after {prev:03d} in scope {scope_label}"
            )
        prev_num_by_scope[scope] = num

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate test naming convention")
    parser.add_argument("paths", nargs="*", help="Optional file paths from pre-commit")
    args = parser.parse_args()

    test_files = _normalize_paths(args.paths)
    if not test_files:
        return 0

    issues: List[str] = []
    for file_path in test_files:
        issues.extend(check_file(file_path))

    if issues:
        print("Test naming validation failed:")
        for issue in issues:
            print(issue)
        return 1

    print(f"Test naming validation passed for {len(test_files)} file(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
