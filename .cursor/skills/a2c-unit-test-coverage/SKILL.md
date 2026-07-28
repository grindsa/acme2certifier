---
name: a2c-unit-test-coverage
description: >-
  Raises unit-test line coverage for acme2certifier modules to 100% using
  existing test/ conventions (test_NNN_ numbering, unittest.TestCase,
  assertLogs on test_a2c). Use when closing coverage gaps, adding missing
  unit tests, or when the user asks for 100% coverage of a module.
disable-model-invocation: true
---

# a2c unit-test coverage

## Goal

Bring **line coverage** of targeted modules under `acme2certifier/` to **100%**, one module at a time, without breaking existing suites.

## Scope

**Include:** Python under `acme2certifier/` (package code).

**Exclude unless the user asks:**

- `**/migrations/**`
- `**/skeletons/**`
- `examples/`
- empty/`__init__.py` that only re-export
- generated / fixture-only paths

**Tests location:** `test/test_<name>.py` only. Never put unit tests under `acme2certifier/`.

## Conventions (mandatory)

1. Scan neighboring files in `test/` before writing anything.
2. Method names: `test_NNN_<descriptive_snake_case>` with zero-padded numbers (`test_001_…`).
3. Continue numbering from the **highest existing** number in that file. **Never renumber** old tests.
4. Match the style of the suite you edit. Most suites use `unittest.TestCase` + `unittest.mock`. Do **not** convert unittest suites to pytest.
5. Logger name in tests: `"test_a2c"`. Assert INFO and higher with `self.assertLogs("test_a2c", level="INFO")` (or `WARNING`/`ERROR` when that is the expected severity). Prefer asserting message strings via `self.assertIn(..., lcm.output)`.
6. Do not assert DEBUG unless needed solely to cover an otherwise unreachable branch.
7. Run/measure with pytest + pytest-cov; writing style follows the file under edit.
8. Prefer behavior and edge cases over pure line-hitting. Prefer mocks over production refactors. Ask before changing production code.

See [examples.md](examples.md) for naming, `assertLogs`, and setup patterns.

## Workflow

Copy and track:

```
Coverage progress:
- [ ] Inventory module → test file mapping
- [ ] Measure line coverage (term-missing)
- [ ] Skip if already 100%
- [ ] Add tests for missing lines + INFO+ logs / edge cases
- [ ] Re-measure until 100% or documented omission
- [ ] Report table
```

### 1. Inventory

Map `acme2certifier/.../<module>.py` → `test/test_<…>.py`.

If no suite exists, create `test/test_<module>.py` modeled on a similar neighbor (same package area: `acme_srv`, `cahandlers`, `eabhandlers`, `tools`, etc.).

### 2. Measure

```bash
pytest test/test_<name>.py \
  --cov=acme2certifier.<dotted.module> \
  --cov-report=term-missing -q
```

If the user named a specific module, start there. Otherwise:

1. Suites that exist but are under 100%
2. Modules with no suite

Process **one module at a time**.

### 3. Fill gaps

- Use `term-missing` line numbers as the checklist.
- Cover branches that emit INFO / WARNING / ERROR / CRITICAL.
- Justified omissions only (e.g. unreachable defensive branches after exhaustive mocks). Document them in the final report; do not silently leave gaps.

### 4. Verify

Re-run the same pytest/cov command until the module is at 100% line coverage or omissions are listed.

Do **not** commit unless asked.

## Done report

```markdown
| module | test file | before % | after % | notes |
|--------|-----------|----------|---------|-------|
| …      | …         | …        | …       | …     |
```

## Anti-patterns

- Rewriting a unittest suite to pytest “for consistency”
- Renumbering or renaming existing `test_NNN_` methods
- Putting tests outside `test/`
- Broad production refactors to make testing easier without asking
- Asserting DEBUG logs by default
- Repo-wide sweep in one go when the user named a single target
