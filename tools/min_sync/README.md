# min_sync — bidirectional allowlist sync

Sync shared product code between **full** branches (`master`, `devel`) and
**min** branches (`min-devel`, `min`) using `manifest.yaml`.

## Rules

- Always prepare a **review PR** into the target branch (no direct merge).
- **Never** promote `min-devel` → `min` (manual merge when you want an RPM).
- `main-push-rpm.yml` stays min-owned; push-to-`min` RPM workflow is untouched.
- Either side can be upstream for a given change.

## Usage

```bash
# Preview master → min-devel
python3 tools/min_sync/sync.py --from master --into min-devel --dry-run

# Create sync branch + commit (push/PR yourself)
python3 tools/min_sync/sync.py --from master --into min-devel

# Also push and open PR (requires gh auth)
python3 tools/min_sync/sync.py --from master --into min-devel --create-pr

# Min-first fix → master
python3 tools/min_sync/sync.py --from min-devel --into master --dry-run
```

Working tree must be clean. Script fetches `origin/<from>` and `origin/<into>`.

## Direction behaviour

| Direction | Behaviour |
| --- | --- |
| full → min | Checkout `sync_paths` from source; keep only `keep_handlers`; apply `strip_into_min`; restore `min_owned` from target |
| min → full | Checkout files that exist on source under `sync_paths`; only kept handlers under `cahandlers/`; **do not** delete full-only handlers/tests/workflows |

## Manifest knobs

- `sync_paths` — shared paths to consider
- `keep_handlers` — CA handlers retained on min
- `min_owned` — never overwritten / never pushed to full
- `strip_into_min` — extra paths removed after a port into min

Edit the manifest when the min surface area changes; do not special-case in the script.
