<!-- markdownlint-disable MD013 MD029 -->

<!-- wiki-title WSGI→Django dump spec (v1) -->

# WSGI → Django dump spec (v1)

Frozen handoff format for `a2c-wsgi2django` (Phase 0). Source of truth for export/import/check.

**Sources:** `dbhandlers/wsgi_handler.py` (`_db_create`), `django_app/models.py`, `django_app/fixture/status.yaml`, `acme_srv/version.py` (`__dbversion__ = "0.41"`).

## Dump JSON schema (v1)

```json
{
  "meta": {
    "schema_version": 1,
    "tool_version": "<a2c-wsgi2django version>",
    "a2c_version": "<__version__>",
    "dbversion": "<housekeeping.dbversion from source>",
    "source": "wsgi-sqlite",
    "source_path": "<optional absolute path>",
    "created_at": "<ISO-8601 UTC>",
    "include_nonces": false
  },
  "tables": {
    "status": [],
    "account": [],
    "orders": [],
    "authorization": [],
    "challenge": [],
    "certificate": [],
    "cliaccount": [],
    "cahandler": [],
    "housekeeping": [],
    "nonce": []
  }
}
```

Rules:

- Dump keys use **WSGI table names** (`orders`, not `order`).
- Row dicts use **WSGI column names**, including `*_id` FKs.
- Every row includes integer `id` (preserved PK).
- **`status` is verify-only** — export may include it for audit/`check`; **import never writes Status**; Django owns rows via fixture (`django_app/fixture/status.yaml` / `a2c-django-update`).
- `nonce` is omitted or empty unless `meta.include_nonces` is true.
- Timestamps are ISO-8601 strings (or SQLite `TIMESTAMP` strings as stored); importer parses to aware datetimes when `USE_TZ=True`.
- Booleans may appear as `0`/`1` in the dump; importer coerces to `bool`.

## Entity list

| Dump key | WSGI table | Django model | Django table | Default migrate? |
| --- | --- | --- | --- | --- |
| `status` | `status` | `Status` | `acme_srv_status` | **no** — verify only (Django fixture) |
| `account` | `account` | `Account` | `acme_srv_account` | yes |
| `orders` | `orders` | `Order` | `acme_srv_order` | yes |
| `authorization` | `authorization` | `Authorization` | `acme_srv_authorization` | yes |
| `challenge` | `challenge` | `Challenge` | `acme_srv_challenge` | yes |
| `certificate` | `certificate` | `Certificate` | `acme_srv_certificate` | yes |
| `cliaccount` | `cliaccount` | `Cliaccount` | `acme_srv_cliaccount` | yes |
| `cahandler` | `cahandler` | `Cahandler` | `acme_srv_cahandler` | yes |
| `housekeeping` | `housekeeping` | `Housekeeping` | `acme_srv_housekeeping` | merge (see below) |
| `nonce` | `nonce` | `Nonce` | `acme_srv_nonce` | no (optional) |

**Import order (FK-safe):** Assert Status fixture → Account → Order ← `orders` → Authorization → Challenge → Certificate → Cliaccount → Cahandler → Housekeeping → (optional Nonce).

**Wipe order:** Challenge → Authorization → Certificate → Order → Account → Cliaccount → Cahandler → Nonce → Housekeeping (non-`dbversion` or all then re-seed). **Never delete Status**; if wiped by mistake, re-`loaddata status` before import.

## Status (verify-only; not migrated)

Django loads Status during install (`fixture/status.yaml` / `a2c-django-update`). WSGI seeds the same eight names in the same order. Migrating status rows is redundant and unsafe.

| Step | Behavior |
| --- | --- |
| **export** | Include `tables.status` for audit / `check` (optional but recommended) |
| **import** | **No Status writes** — assert Django PKs 1–8 match names below; refuse on drift |
| **wipe** | Leave Status untouched |
| **check** | Dump status (if present) and/or expected 1–8 vs Django ORM |

Required PK ↔ name map:

| PK | name |
| --- | --- |
| 1 | invalid |
| 2 | pending |
| 3 | ready |
| 4 | processing |
| 5 | valid |
| 6 | expired |
| 7 | deactivated |
| 8 | revoked |

## Field transforms

### Shared

| Transform | Policy |
| --- | --- |
| Preserve `id` | Explicit `pk=` on ORM create |
| FK `*_id` → ORM FK | Pass id into `status_id` / `account_id` / … or related object by pk |
| `TIMESTAMP` → `DateTimeField` | Parse; make aware if `USE_TZ` |
| `NULL` int → Django `IntegerField` | `NULL` → `0` (`expires`, etc.) |
| `NULL` string → blankable Char/Text | `NULL` → `""` when `blank=True` |
| INT / `bolean` → `BooleanField` | `0`/`1`/`NULL` → `False`/`True`/`False` |
| Char/Text length checks | Prefer live `django_app.models` `max_length`; fallback constants if Django unavailable |

### Per-entity columns (dump → Django)

**status** — `id`, `name` (varchar/CharField 15). Export/check only; **never import or update**.

**account** — `id`, `name`(15), `alg`(10), `jwk`(TEXT), `contact`(TEXT→CharField **255**), `eab_kid`(TEXT→TextField max **255**), `status_id`, `created_at`.

**orders** → Order — `id`, `name`(15), `notbefore`, `notafter`, `identifiers`, `account_id`, `profile`, `status_id`, `expires`, `created_at`.

**authorization** — `id`, `name`(15), `order_id`, `type`(5), `value`, `expires`, `token`(64), `status_id`, `created_at`. Note: WSGI default status=2, Django model default=1 — migrate **stored** `status_id` only.

**challenge** — `id`, `name`(15), `token`(64; NULL→`""`), `authorization_id`, `expires`, `type`(15), `keyauthorization`(128), `source`(128), `status_id`, `validated`, `validation_error`, `created_at`.

**certificate** — `id`, `name`(15), `cert`, `cert_raw`, `error`, `order_id`, `csr`, `poll_identifier`, `header_info`, `created_at`, `renewal_info`, `aki`, `serial`, `issue_uts`, `expire_uts`, `replaced`(0/1→bool).

**cliaccount** — `id`, `name`(15), `jwk`, `contact`(TEXT→**255**), `cliadmin`/`reportadmin`/`certificateadmin`(INT→bool), `created_at`. Import via model (Django handler has no `cliaccount_add`).

**cahandler** — `id`, `name`(WSGI 15 → Django 50), `value1`/`value2`(TEXT→CharField **250**), `created_at`.

**housekeeping** — `id`, `name`(30), `value`(TEXT→Django `Housekeeping.value` **max_length from model**), `modified_at`. For `name=dbversion`: keep Django post-migrate / `a2c-django-update` value unless dump equals target `__dbversion__`; never downgrade silently.

**nonce** (optional) — `id`, `nonce`(WSGI 30 → Django 50), `created_at`.

## Failure modes

| Condition | Exit | Behavior |
| --- | --- | --- |
| Dump `schema_version` ≠ 1 | fail | Refuse import/check |
| Source `dbversion` ≠ tool `__dbversion__` | fail (warn-only flag later) | Refuse export/import by default |
| Django Status PK missing or name mismatch (1–8) | fail | Refuse import (no Status writes) |
| Dump `status` present but PK/name ≠ expected map | fail | Refuse import/`check` |
| String field exceeds Django model `max_length` | fail | No truncate. Export reads limits from `django_app.models` when Django is importable; else uses frozen fallbacks in `a2c_wsgi2django.FALLBACK_LENGTH_LIMITS`. Unlimited `TextField` (no `max_length`) is not length-checked. |
| Dangling / NULL FK (`account_id`, `order_id`, …) | warn | Export skips orphan rows (and dependent children) with a stderr warning; does not fail |
| Target ACME tables non-empty without `--wipe` | fail | Refuse import |
| `--wipe` without `--yes` (CLI wipe subcommand) | fail | Require confirmation |
| Duplicate `name` / PK collision after wipe skip | fail | Abort transaction |
| Missing required WSGI NOT NULL with empty dump value (`account.jwk`, etc.) | fail | Refuse row |
| `Challenge.token` NULL | warn→`""` | Django field not blank/null; empty string allowed |
| Concurrent writers during export | operator error | Docs: stop ACME first (not auto-detected) |

## Operator procedure (agreed)

1. Quiesce + backup (`acme_srv.db`, cfg, CA/volume).
1. `a2c-wsgi2django export --db … --out dump.json`.
1. Switch flavor to Django **same a2c version**; migrate / `a2c-django-update`.
1. Optional `wipe`; then `import`; then `check`.
1. Restart; renew with migrated account keys.

Rollback: restore WSGI image/cfg/db from backup; do not delete the dump.
