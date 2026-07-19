<!-- markdownlint-disable MD013 MD029 -->

<!-- wiki-title Package layout migration -->

# Package layout migration

This guide describes the restructuring of `acme2certifier` into a proper Python package namespace, how to migrate configuration and imports, and which options remain for backwards compatibility.

## Phase status

| Phase | Status |
| --- | --- |
| 1–6 Package layout, shims, dual loader, handler/tool moves, import updates | Complete |
| 7 Tests and CI | Complete |
| 8 Documentation | Complete |
| 9 Deprecation warnings (runtime) | Mostly complete (`*_file` warns today) |
| 10 Remove shims / deprecated keys | Future release |

## Summary

| Area | Legacy location | Current location |
| --- | --- | --- |
| ACME server core | `acme_srv/` | `acme2certifier/acme_srv/` |
| CA handlers | `examples/ca_handler/` | `acme2certifier/cahandlers/` |
| EAB handlers | `examples/eab_handler/` | `acme2certifier/eabhandlers/` |
| Hook handlers | `examples/hooks/` | `acme2certifier/hookhandlers/` |
| Tools / CLI | `tools/` | `acme2certifier/tools/` |

**Current status**

- Core modules live under `acme2certifier.acme_srv`. Legacy imports `acme_srv.*` continue to work via temporary compatibility shims.
- CA / EAB / hook **implementations** live under `acme2certifier.cahandlers`, `acme2certifier.eabhandlers`, and `acme2certifier.hookhandlers`.
- Paths under `examples/ca_handler/`, `examples/eab_handler/`, and `examples/hooks/` are compatibility shims (except **skeleton** templates, which remain full example sources for custom handlers).
- Tools live under `acme2certifier.tools`; `tools/*.py` are compatibility wrappers (`python tools/…` still works; prefer `python3 -m acme2certifier.tools.<name>`).
- Handler loading supports both file paths (`*_file`, **deprecated**) and dotted module names (`*_module`, **preferred**).
- The Django app (`models`, `views`, `urls`) remains under top-level `acme_srv/` for now.

## Backwards compatibility

The following continue to work:

1. **Python imports** such as `from acme_srv.account import Account` (shim → `acme2certifier.acme_srv.account`).
1. **Config keys** `handler_file`, `eab_handler_file`, and `hooks_file` (file-based loading).
1. Existing deployments that only use legacy paths do not need an immediate config change.

Preferred (non-deprecated) config keys:

- `handler_module`
- `eab_handler_module`
- `hooks_module`

If both a `*_module` and a `*_file` key are set for the same section, **`*_module` wins** and `*_file` is ignored (with a warning).

## Deprecation warnings

When file-based loading is used, `acme2certifier.acme_srv.helpers.plugin_loader` emits:

- a Python `DeprecationWarning`, and
- a `logger.warning(...)` with the same message.

Example message:

```text
handler_file is deprecated; use handler_module (e.g. acme2certifier.cahandlers.openssl_ca_handler)
```

Notes:

- `DeprecationWarning` from library code is often filtered by default Python warning filters. Rely on application logs at `WARNING` (or lower) to see the message during normal operation.
- To also show `DeprecationWarning` on stderr: run with `PYTHONWARNINGS=default` or `python -W default`.

There is **no** hard removal of `*_file` in this release. Removal is planned for a future major cleanup (Phase 10) once migrations are complete.

## Config migration (recommended)

### CA handler

Legacy (deprecated):

```ini
[CAhandler]
handler_file: examples/ca_handler/openssl_ca_handler.py
```

Preferred (module-based):

```ini
[CAhandler]
handler_module: acme2certifier.cahandlers.openssl_ca_handler
```

Legacy module path (still works via shim):

```ini
[CAhandler]
handler_module: examples.ca_handler.openssl_ca_handler
```

### EAB handler

Legacy (deprecated):

```ini
[EABhandler]
eab_handler_file: examples/eab_handler/file_handler.py
```

Preferred:

```ini
[EABhandler]
eab_handler_module: acme2certifier.eabhandlers.file_handler
```

### Hooks

Legacy (deprecated):

```ini
[Hooks]
hooks_file: examples/hooks/skeleton_hooks.py
```

Preferred:

```ini
[Hooks]
hooks_module: acme2certifier.hookhandlers.skeleton_hooks
```

## Old path → new module mapping

### Core (`acme_srv` → `acme2certifier.acme_srv`)

| Legacy import | New import |
| --- | --- |
| `acme_srv` | `acme2certifier.acme_srv` |
| `acme_srv.account` | `acme2certifier.acme_srv.account` |
| `acme_srv.order` | `acme2certifier.acme_srv.order` |
| `acme_srv.certificate` | `acme2certifier.acme_srv.certificate` |
| `acme_srv.challenge` | `acme2certifier.acme_srv.challenge` |
| `acme_srv.helper` | `acme2certifier.acme_srv.helper` |
| `acme_srv.helpers.*` | `acme2certifier.acme_srv.helpers.*` |
| `acme_srv.challenge_validators.*` | `acme2certifier.acme_srv.challenge_validators.*` |
| `acme_srv.version` | `acme2certifier.acme_srv.version` |

Shims under the top-level `acme_srv/` package re-export the new modules. Prefer updating application and test code to the new namespace when convenient; shims are temporary.

`load_config()` looks for `acme_srv.cfg` next to the new package first, then falls back to the legacy path `<repo>/acme_srv/acme_srv.cfg`. You can also set `ACME_SRV_CONFIGFILE`.

### CA handlers (`examples/ca_handler` → `acme2certifier.cahandlers`)

| Legacy file | Import via shim | Preferred module |
| --- | --- | --- |
| `examples/ca_handler/openssl_ca_handler.py` | `examples.ca_handler.openssl_ca_handler` | `acme2certifier.cahandlers.openssl_ca_handler` |
| `examples/ca_handler/skeleton_ca_handler.py` | `examples.ca_handler.skeleton_ca_handler` | `acme2certifier.cahandlers.skeleton_ca_handler` |
| `examples/ca_handler/acme_ca_handler.py` | `examples.ca_handler.acme_ca_handler` | `acme2certifier.cahandlers.acme_ca_handler` |
| `examples/ca_handler/asa_ca_handler.py` | `examples.ca_handler.asa_ca_handler` | `acme2certifier.cahandlers.asa_ca_handler` |
| `examples/ca_handler/certifier_ca_handler.py` | `examples.ca_handler.certifier_ca_handler` | `acme2certifier.cahandlers.certifier_ca_handler` |
| `examples/ca_handler/cmp_ca_handler.py` | `examples.ca_handler.cmp_ca_handler` | `acme2certifier.cahandlers.cmp_ca_handler` |
| `examples/ca_handler/digicert_ca_handler.py` | `examples.ca_handler.digicert_ca_handler` | `acme2certifier.cahandlers.digicert_ca_handler` |
| `examples/ca_handler/dogtag_ca_handler.py` | `examples.ca_handler.dogtag_ca_handler` | `acme2certifier.cahandlers.dogtag_ca_handler` |
| `examples/ca_handler/ejbca_ca_handler.py` | `examples.ca_handler.ejbca_ca_handler` | `acme2certifier.cahandlers.ejbca_ca_handler` |
| `examples/ca_handler/entrust_ca_handler.py` | `examples.ca_handler.entrust_ca_handler` | `acme2certifier.cahandlers.entrust_ca_handler` |
| `examples/ca_handler/est_ca_handler.py` | `examples.ca_handler.est_ca_handler` | `acme2certifier.cahandlers.est_ca_handler` |
| `examples/ca_handler/freeipa_ca_handler.py` | `examples.ca_handler.freeipa_ca_handler` | `acme2certifier.cahandlers.freeipa_ca_handler` |
| `examples/ca_handler/mscertsrv_ca_handler.py` | `examples.ca_handler.mscertsrv_ca_handler` | `acme2certifier.cahandlers.mscertsrv_ca_handler` |
| `examples/ca_handler/mswcce_ca_handler.py` | `examples.ca_handler.mswcce_ca_handler` | `acme2certifier.cahandlers.mswcce_ca_handler` |
| `examples/ca_handler/nclm_ca_handler.py` | `examples.ca_handler.nclm_ca_handler` | `acme2certifier.cahandlers.nclm_ca_handler` |
| `examples/ca_handler/openxpki_ca_handler.py` | `examples.ca_handler.openxpki_ca_handler` | `acme2certifier.cahandlers.openxpki_ca_handler` |
| `examples/ca_handler/pkcs7_soap_ca_handler.py` | `examples.ca_handler.pkcs7_soap_ca_handler` | `acme2certifier.cahandlers.pkcs7_soap_ca_handler` |
| `examples/ca_handler/vault_ca_handler.py` | `examples.ca_handler.vault_ca_handler` | `acme2certifier.cahandlers.vault_ca_handler` |
| `examples/ca_handler/xca_ca_handler.py` | `examples.ca_handler.xca_ca_handler` | `acme2certifier.cahandlers.xca_ca_handler` |

Related helper modules (same pattern): `certsrv`, `ms_wcce.*`.

**Note:** `examples/*/skeleton_*.py` remain full template sources for custom handlers. Built-in handler files under `examples/` are shims that re-export the package modules.

### EAB handlers

| Legacy file | Import via shim | Preferred module |
| --- | --- | --- |
| `examples/eab_handler/file_handler.py` | `examples.eab_handler.file_handler` | `acme2certifier.eabhandlers.file_handler` |
| `examples/eab_handler/json_handler.py` | `examples.eab_handler.json_handler` | `acme2certifier.eabhandlers.json_handler` |
| `examples/eab_handler/kid_profile_handler.py` | `examples.eab_handler.kid_profile_handler` | `acme2certifier.eabhandlers.kid_profile_handler` |
| `examples/eab_handler/sql_handler.py` | `examples.eab_handler.sql_handler` | `acme2certifier.eabhandlers.sql_handler` |
| `examples/eab_handler/skeleton_eab_handler.py` | `examples.eab_handler.skeleton_eab_handler` | `acme2certifier.eabhandlers.skeleton_eab_handler` |

### Hooks

| Legacy file | Import via shim | Preferred module |
| --- | --- | --- |
| `examples/hooks/skeleton_hooks.py` | `examples.hooks.skeleton_hooks` | `acme2certifier.hookhandlers.skeleton_hooks` |
| `examples/hooks/email_hooks.py` | `examples.hooks.email_hooks` | `acme2certifier.hookhandlers.email_hooks` |
| `examples/hooks/cn_dump_hooks.py` | `examples.hooks.cn_dump_hooks` | `acme2certifier.hookhandlers.cn_dump_hooks` |
| `examples/hooks/exception_test_hooks.py` | `examples.hooks.exception_test_hooks` | `acme2certifier.hookhandlers.exception_test_hooks` |

### Tools

| Legacy path | Preferred invocation |
| --- | --- |
| `tools/a2c_cli.py` | `python3 -m acme2certifier.tools.a2c_cli` |
| `tools/cert_poll.py` | `python3 -m acme2certifier.tools.cert_poll` |
| `tools/db_update.py` | `python3 -m acme2certifier.tools.db_update` |
| `tools/…` | `python3 -m acme2certifier.tools.…` |

## Custom handlers

If you maintain a custom handler outside this repository:

1. Keep using `handler_file: /path/to/your_handler.py` during the transition (deprecated, still supported).
1. Or install/import it as a normal Python module and set `handler_module: your_package.your_handler`.
1. The loaded module must still expose the expected class (`CAhandler`, `EABhandler`, or `Hooks`).

## Migration checklist

1. Confirm the server starts with your existing `*_file` configuration (no change required).
1. Switch `acme_srv.cfg` to `*_module` keys (prefer `acme2certifier.cahandlers.*` / `eabhandlers.*` / `hookhandlers.*`).
1. Watch logs for deprecation warnings related to `*_file`.
1. Update in-house scripts and tests from `acme_srv.*` to `acme2certifier.acme_srv.*` (shims keep old imports working until Phase 10).
1. Prefer `python3 -m acme2certifier.tools.<name>` over `python tools/<name>.py`.

## Related documentation

- [How to create your own CA handler](ca_handler.md)
- [EAB](eab.md)
- [Hooks](hooks.md)
- [Upgrading acme2certifier](upgrading.md)
- [acme_srv.cfg options](acme_srv.md)
