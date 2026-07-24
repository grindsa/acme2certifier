<!-- markdownlint-disable MD013 MD029 -->

<!-- wiki-title Package layout migration -->

# Package layout migration

This guide describes the restructuring of `acme2certifier` into a proper Python package namespace, how to migrate configuration and imports, and which options remain for backwards compatibility.

## Phase status

| Phase | Status |
| --- | --- |
| 1–6 Package layout, dual loader, handler/tool moves, import updates | Complete |
| 7 Tests and CI | Complete |
| 8 Documentation | Complete |
| 9 Deprecation warnings (runtime) | Complete |
| 10 Remove shims / deprecated keys | **Partial** — import shims removed; `*_file` keys and default `acme_srv.ca_handler` fallback remain until **1.0** |

## Summary

| Area | Legacy location | Current location |
| --- | --- | --- |
| ACME server core | `acme_srv/` | `acme2certifier/acme_srv/` |
| CA handlers | `examples/ca_handler/` | `acme2certifier/cahandlers/` (+ skeletons in `acme2certifier/share/skeletons/ca_handler/`) |
| EAB handlers | `examples/eab_handler/` | `acme2certifier/eabhandlers/` (+ skeletons in `acme2certifier/share/skeletons/eab_handler/`) |
| Hook handlers | `examples/hooks/` | `acme2certifier/hookhandlers/` (+ skeletons in `acme2certifier/share/skeletons/hooks/`) |
| Django app | `examples/django/acme_srv/` | `acme2certifier/django_app/` |
| Django project | `examples/django/acme2certifier/` | `acme2certifier/django_project/` |
| Django settings template | `examples/django/acme2certifier/settings.py` | `examples/django/settings.py` |

## Current status

- Core modules live under `acme2certifier.acme_srv`. Import `acme2certifier.acme_srv.*` (legacy `acme_srv.*` import shims are **removed**).
- CA / EAB / hook **implementations** live under `acme2certifier.cahandlers`, `acme2certifier.eabhandlers`, and `acme2certifier.hookhandlers`.
- Skeleton templates (and EAB sample data files) live under `acme2certifier/share/skeletons/{ca_handler,eab_handler,hooks}/`.
- Tools live under `acme2certifier.tools`. Invoke with `python3 -m acme2certifier.tools.<name>` (top-level `tools/*.py` wrappers are removed; see `tools/README.md`).
- Handler loading supports both file paths (`*_file`, **deprecated**) and dotted module names (`*_module`, **preferred**).
- The Django app lives under `acme2certifier.django_app`; the Django project shell under `acme2certifier.django_project`. Install with `pip install 'acme2certifier[django]'` and use `a2c-manage`. `examples/django/settings.py` is an optional MySQL settings template for Docker/external DB installs.

## Backwards compatibility

Still supported:

1. **Config keys** `handler_file`, `eab_handler_file`, and `hooks_file` (file-based loading of out-of-tree handlers).
1. Default fallback to `acme_srv.ca_handler` when no CA handler key is set (deprecated).

No longer supported:

- Importing ACME core via top-level `acme_srv.account` (etc.) — use `acme2certifier.acme_srv.account`.
- Importing built-in handlers via `examples.ca_handler.*` / `examples.eab_handler.*` / `examples.hooks.*` shims.
- Running `python tools/<name>.py` wrappers — use `python3 -m acme2certifier.tools.<name>`.

Preferred config keys:

- `handler_module`
- `eab_handler_module`
- `hooks_module`

If both a `*_module` and a `*_file` key are set for the same section, **`*_module` wins** and `*_file` is ignored (with a warning).

## Deprecation warnings

Runtime guidance is centralized in `acme2certifier.compat` and emitted when:

| Trigger | What you see |
| --- | --- |
| Config key `handler_file` / `eab_handler_file` / `hooks_file` | Prefer the matching `*_module` key |
| Fallback load of `acme_srv.ca_handler` | Set `handler_module` explicitly |

Each warning is emitted as:

- a Python `DeprecationWarning`, and
- a `logger.warning(...)` when a logger is available (plugin loader).

Config-key warnings (`*_file`) are emitted on each load. The default CA-handler fallback warning is once per process.

Example message:

```text
handler_file is deprecated; use handler_module (e.g. acme2certifier.cahandlers.openssl_ca_handler). File-based handler loading will be removed in acme2certifier 1.0.
```

Notes:

- `DeprecationWarning` from library code is often filtered by default Python warning filters. Rely on application logs at `WARNING` (or lower) to see the message during normal operation.
- To also show `DeprecationWarning` on stderr: run with `PYTHONWARNINGS=default` or `python -W default`.

### Deprecation timeline

| When | What |
| --- | --- |
| **Now** | Import shims removed. Warnings remain for `*_file` keys and default `acme_srv.ca_handler` fallback. |
| **acme2certifier 1.0** | Planned removal of `*_file` config keys and the default `acme_srv.ca_handler` fallback. |

## Config migration (recommended)

### CA handler

Legacy (deprecated):

```ini
[CAhandler]
handler_file: /path/to/custom_ca_handler.py
```

Preferred (module-based):

```ini
[CAhandler]
handler_module: acme2certifier.cahandlers.openssl_ca_handler
```

### EAB handler

Legacy (deprecated):

```ini
[EABhandler]
eab_handler_file: /path/to/custom_eab_handler.py
```

Preferred:

```ini
[EABhandler]
eab_handler_module: acme2certifier.eabhandlers.file_handler
```

### Hook

Legacy (deprecated):

```ini
[Hooks]
hooks_file: acme2certifier/share/skeletons/hooks/skeleton_hooks.py
```

Preferred:

```ini
[Hooks]
hooks_module: acme2certifier.hookhandlers.skeleton_hooks
```

## Django migration

Existing Django deployments must point `settings.py` at the packaged app. The app label stays **`acme_srv`** (`AcmeSrvConfig.label`), so existing tables and migration history remain valid once `INSTALLED_APPS` is updated.

Legacy (in-tree layout under `examples/django/`):

```python
INSTALLED_APPS = [
    ...
    "acme_srv",  # or legacy "acme" before v0.17
    ...
]
```

Current:

```python
INSTALLED_APPS = [
    ...
    "acme2certifier.django_app.apps.AcmeSrvConfig",
    ...
]
```

If your project still references the old Django project package, also update:

```python
ROOT_URLCONF = "acme2certifier.django_project.urls"
WSGI_APPLICATION = "acme2certifier.django_project.wsgi.application"
```

After editing `settings.py`, run `a2c-django-update` (or `a2c-manage migrate`) and verify the ACME directory endpoint.

## Old path → new module mapping

### Core (`acme_srv` → `acme2certifier.acme_srv`)

| Legacy import (removed) | New import |
| --- | --- |
| `acme_srv.account` | `acme2certifier.acme_srv.account` |
| `acme_srv.order` | `acme2certifier.acme_srv.order` |
| `acme_srv.certificate` | `acme2certifier.acme_srv.certificate` |
| `acme_srv.challenge` | `acme2certifier.acme_srv.challenge` |
| `acme_srv.helper` | `acme2certifier.acme_srv.helper` |
| `acme_srv.helpers.*` | `acme2certifier.acme_srv.helpers.*` |
| `acme_srv.challenge_validators.*` | `acme2certifier.acme_srv.challenge_validators.*` |
| `acme_srv.version` | `acme2certifier.acme_srv.version` |

`load_config()` looks for `acme_srv.cfg` next to the package first, then falls back to the legacy path `<repo>/acme_srv/acme_srv.cfg`. You can also set `ACME_SRV_CONFIGFILE`.

### Database handlers

Implementations live under `acme2certifier.dbhandlers`. Selection (cfg wins over env):

1. `[DBhandler] handler_module` or `handler` in `acme_srv.cfg`
2. `ACME_SRV_DB_HANDLER` (`wsgi`, `django`, or a dotted module)
3. default `wsgi`

| Preferred module |
| --- |
| `acme2certifier.dbhandlers.wsgi_handler` |
| `acme2certifier.dbhandlers.django_handler` |

`acme2certifier.acme_srv.db_handler` is a thin loader that re-exports `DBstore` from the selected backend. Do not copy handler files into the install tree for pip installs.

### CA handlers

| Preferred module |
| --- |
| `acme2certifier.cahandlers.openssl_ca_handler` |
| `acme2certifier.cahandlers.skeleton_ca_handler` |
| `acme2certifier.cahandlers.acme_ca_handler` |
| `acme2certifier.cahandlers.asa_ca_handler` |
| `acme2certifier.cahandlers.certifier_ca_handler` |
| `acme2certifier.cahandlers.cmp_ca_handler` |
| `acme2certifier.cahandlers.digicert_ca_handler` |
| `acme2certifier.cahandlers.dogtag_ca_handler` |
| `acme2certifier.cahandlers.ejbca_ca_handler` |
| `acme2certifier.cahandlers.entrust_ca_handler` |
| `acme2certifier.cahandlers.est_ca_handler` |
| `acme2certifier.cahandlers.freeipa_ca_handler` |
| `acme2certifier.cahandlers.mscertsrv_ca_handler` |
| `acme2certifier.cahandlers.mswcce_ca_handler` |
| `acme2certifier.cahandlers.nclm_ca_handler` |
| `acme2certifier.cahandlers.openxpki_ca_handler` |
| `acme2certifier.cahandlers.pkcs7_soap_ca_handler` |
| `acme2certifier.cahandlers.vault_ca_handler` |
| `acme2certifier.cahandlers.xca_ca_handler` |

Related helpers: `acme2certifier.cahandlers.certsrv`, `acme2certifier.cahandlers.ms_wcce.*`.

Skeleton templates for custom handlers remain under `acme2certifier/share/skeletons/*/skeleton_*.py` (also available as package modules).

### EAB handlers

| Preferred module |
| --- |
| `acme2certifier.eabhandlers.file_handler` |
| `acme2certifier.eabhandlers.json_handler` |
| `acme2certifier.eabhandlers.kid_profile_handler` |
| `acme2certifier.eabhandlers.sql_handler` |
| `acme2certifier.eabhandlers.skeleton_eab_handler` |

Sample key/profile data files remain under `acme2certifier/share/skeletons/eab_handler/`.

### Hooks

| Preferred module |
| --- |
| `acme2certifier.hookhandlers.skeleton_hooks` |
| `acme2certifier.hookhandlers.email_hooks` |
| `acme2certifier.hookhandlers.cn_dump_hooks` |
| `acme2certifier.hookhandlers.exception_test_hooks` |

### Tools

| Preferred invocation |
| --- |
| `python3 -m acme2certifier.tools.a2c_cli` |
| `python3 -m acme2certifier.tools.a2c_cert_poll` |
| `python3 -m acme2certifier.tools.a2c_db_update` |
| `python3 -m acme2certifier.tools.…` |

## Custom handlers

If you maintain a custom handler outside this repository:

1. Keep using `handler_file: /path/to/your_handler.py` during the transition (deprecated, still supported).
1. Or install/import it as a normal Python module and set `handler_module: your_package.your_handler`.
1. The loaded module must still expose the expected class (`CAhandler`, `EABhandler`, or `Hooks`).

## Migration checklist

1. Switch `acme_srv.cfg` to `*_module` keys (`acme2certifier.cahandlers.*` / `eabhandlers.*` / `hookhandlers.*`).
1. **Django:** set `INSTALLED_APPS` to `acme2certifier.django_app.apps.AcmeSrvConfig` (replace `acme_srv` / `acme`); update `ROOT_URLCONF` / `WSGI_APPLICATION` if still on the old project path.
1. Update application code and Django views to import `acme2certifier.acme_srv.*`.
1. Prefer `python3 -m acme2certifier.tools.<name>` for maintenance tools.
1. Watch logs for deprecation warnings related to `*_file` or the default CA-handler fallback.

## Related documentation

- [Phase 10 agent brief — handler fallback removal](architecture/phase10-handler-fallback-removal.md)
- [How to create your own CA handler](ca_handler.md)
- [EAB](eab.md)
- [Hooks](hooks.md)
- [Upgrading acme2certifier](upgrading.md)
- [acme_srv.cfg options](acme_srv.md)
