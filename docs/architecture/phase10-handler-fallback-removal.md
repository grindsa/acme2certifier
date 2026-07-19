<!-- markdownlint-disable MD013 MD029 -->

<!-- wiki-title Phase 10 — handler fallback removal -->

# Phase 10: Remove handler loading fallbacks

Agent brief for completing the package-layout migration in **acme2certifier 1.0**: remove deprecated `*_file` config keys and the default `acme_srv.ca_handler` fallback.

Related: [Package layout migration](../migration_package_layout.md).

## Role

You are an expert Python backend engineer working on **acme2certifier** (ACME server, RFC 8555). Follow `.cursorrules`: type hints, pytest only, Black/Ruff style, brief output, minimal diffs. Do **not** commit unless asked.

## Goal

Complete Phase 10 of the package-layout migration by **removing deprecated handler loading fallbacks** planned for **acme2certifier 1.0**.

Import shims (`acme_srv.*`, `examples.*`, `tools/*.py`) are **already removed**. Phase 10 is only:

1. Remove config keys: `handler_file`, `eab_handler_file`, `hooks_file`
2. Remove default fallback: `importlib.import_module("acme_srv.ca_handler")` when no CA handler is configured
3. Remove related deprecation helpers in `acme2certifier/compat.py` (or delete the module if unused)
4. Update tests, CI, Docker entrypoints, and docs

## Current architecture (do not undo)

| Area | Location |
| --- | --- |
| ACME core | `acme2certifier/acme_srv/` |
| CA / EAB / hooks | `acme2certifier/{cahandlers,eabhandlers,hookhandlers}/` |
| Tools | `acme2certifier/tools/` → `python3 -m acme2certifier.tools.<name>` |
| Django app | top-level `acme_srv/` (`models`, `views`, `urls`, `admin` only) |
| Skeletons / EAB data | `examples/{ca_handler,eab_handler,hooks}/` |

Preferred config keys (**keep**):

- `handler_module`
- `eab_handler_module`
- `hooks_module`

## Primary code to change

### `acme2certifier/acme_srv/helpers/plugin_loader.py`

Today:

- Loads via `*_module`, else `*_file` (with deprecation warning), else for CA only falls back to `acme_srv.ca_handler`
- If both `*_module` and `*_file` are set, module wins

After Phase 10:

- **Only** `*_module` paths
- If CA/EAB/Hooks section exists but required `*_module` key is missing → clear error / return `None` (match existing logging style; fail loudly, no silent default CA handler)
- Remove `_load_from_file` if unused
- Remove “both set / ignoring file” branches
- Remove imports of `warn_*` from compat

### `acme2certifier/compat.py`

- Remove `warn_file_config_deprecated`, `warn_default_ca_handler`, and likely the whole module if nothing else remains
- Update `setup.py` if it still packages `compat.py`
- Delete or rewrite `test/test_compat.py`

### Custom handlers (breaking change — document clearly)

Out-of-tree handlers must use:

```ini
handler_module: mypkg.my_ca_handler
```

Not:

```ini
handler_file: /path/to/handler.py
```

Custom code must be importable (installed package, or on `PYTHONPATH`). Skeleton templates stay under `examples/*/skeleton_*.py`.

## Tests to update

Search for `handler_file`, `eab_handler_file`, `hooks_file`, `warn_file_config`, `warn_default_ca`, `acme_srv.ca_handler`:

- `test/test_helper.py` (plugin loader / deprecation cases)
- `test/test_compat.py`
- `test/test_trigger.py`, `test/test_renewalinfo.py`, `test/test_account.py`, `test/test_directory.py`, `test/test_message.py` (any `*_file` fixtures)

Replace with `*_module` tests. Add/keep tests that missing `handler_module` does **not** import `acme_srv.ca_handler`.

Run:

```bash
python3 -m pytest test/ -q
```

## CI / Docker / examples

Update anything that still relies on `handler_file` or default `acme_srv/ca_handler.py`:

- `.github/workflows/cahandler-legacy.yml` — intentionally uses `handler_file`; **retire, rewrite for `handler_module`, or rename** (do not leave broken 1.0 assumptions)
- `.github/workflows/feature-enrollment-timeout.yml` — sed swaps `handler_module` → `handler_file`; switch to module-only
- `examples/Docker/*/docker-entrypoint.sh` — still checks `handler_file` / copies skeleton to `volume/ca_handler.py`; align with `handler_module` (or document volume + `PYTHONPATH` / installable module)
- Sample cfgs: `examples/acme_srv.cfg`, `acme_srv/acme_srv.cfg` — ensure examples use `handler_module` only

## Docs to update

- `docs/migration_package_layout.md` — Phase 10 complete; remove “still supported” for `*_file` / default fallback; migration = `*_module` only
- `docs/acme_srv.md`, `docs/ca_handler.md`, `docs/eab.md`, `docs/hooks.md`, `docs/upgrading.md`
- Per-handler docs that still list `handler_file` as deprecated
- Install guides that say `handler_file` / copy-to-`acme_srv/ca_handler.py` remain supported
- This document — mark Phase 10 done or move to historical notes when finished

## Acceptance criteria

1. No runtime support for `handler_file` / `eab_handler_file` / `hooks_file`
2. No import of `acme_srv.ca_handler` as default
3. No deprecation helpers for those paths (or empty/removed `compat.py`)
4. Tests + docs consistent; pytest green
5. CI workflows that encoded the old path are fixed or intentionally retired
6. Do not reintroduce import shims under `acme_srv/`, `examples/`, or `tools/`

## Suggested work order

1. Read `plugin_loader.py` + `compat.py` + `docs/migration_package_layout.md`
2. Change loader to module-only; remove fallback
3. Fix unit tests
4. Fix CI / Docker entrypoints
5. Update docs
6. Full `pytest`
7. Summarize breaking changes for release notes / `docs/upgrading.md`

## Constraints

- First-party Cursor models only if the user asks for model choice
- Minimal diffs; no drive-by refactors
- Keep Django app under top-level `acme_srv/`
- Keep skeleton templates and EAB sample data under `examples/`
- Do not commit unless explicitly asked

## Optional decision (ask user if unclear)

Should Phase 10 also remove **legacy cfg path discovery** for `acme_srv/acme_srv.cfg` (if still present in `helpers/config.py`), or only handler loading?

**Default scope:** handler loading only.

## One-liner starter message

```text
Execute Phase 10 of the acme2certifier package-layout migration: remove *_file
handler config keys and the default acme_srv.ca_handler fallback from
plugin_loader.py, clean up compat.py/tests/CI/docs, keep *_module only.
Follow docs/architecture/phase10-handler-fallback-removal.md; do not commit
unless I ask.
```
