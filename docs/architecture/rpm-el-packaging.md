<!-- markdownlint-disable MD013 MD014 MD029 -->

# Design: EL8/EL9 RPM Packaging with Python Flavor Metapackages

## 1. Purpose

Provide **one noarch application RPM** for EL8 and EL9 that:

- Installs the application under `/opt/acme2certifier` (interpreter-agnostic payload)
- Does **not** use pip, a wheelhouse, or a shipped/created venv for dependencies
- Selects the Python runtime via **flavor metapackages** that `Require:` matching `pythonX-*` module RPMs
- Defaults to **Python 3.9 on both EL8 and EL9** (same app runtime across majors)
- Keeps **EL8 system Python 3.6** as an explicit **legacy/fallback** flavor for hosts that cannot install a parallel Python
- Remains operable under **nginx + uWSGI** with SELinux enforcing
- Stays air-gap friendly via **RPM repositories** (AppStream, EPEL, and/or project-provided module RPMs)

This document replaces the earlier venv / offline-wheelhouse / arch-specific RPM brief.

---

## 2. Goals and Non-Goals

### Goals

| ID | Goal |
|---|---|
| G1 | One **noarch** content RPM for EL8 and EL9 |
| G2 | User-selectable Python via installable flavor packages |
| G3 | Dependencies only from RPMs (OS, EPEL, or project-built) |
| G4 | **Default app runtime = Python 3.9** on EL8 and EL9 |
| G5 | EL8 Python **3.6** remains supported as **legacy/fallback** (system `python3-*`) |
| G6 | Clear install / upgrade / flavor-switch / uninstall lifecycle |
| G7 | Default process model: nginx + uWSGI (where the flavor’s interpreter allows) |

### Non-Goals

- Shipping or creating a virtualenv for the application
- Bundling a pip wheelhouse inside the RPM
- Making the application RPM arch-specific because of binary wheels
- Dropping EL8 system Python 3.6 as a supported (non-default) runtime
- Replacing the DEB or container install paths in this design
- Claiming that every parallel AppStream Python ships a complete a2c dependency set without project RPMs

---

## 3. Current State (baseline)

Today ([`examples/install_scripts/rpm/acme2certifier.spec`](../../examples/install_scripts/rpm/acme2certifier.spec)):

- Payload under `/opt/acme2certifier`
- Hard `Requires:` on many `python3-*` packages on the **main** package
- systemd unit runs system `uwsgi` with `plugins = python3`
- EL8 often needs backport RPMs for cryptography / dnspython / jwcrypto ([`docs/install_rpm.md`](../install_rpm.md))
- `BuildArch: noarch`

Pain: module deps are bound to system Python on the main package, so “install once, pick another interpreter later” is not modeled. Flavor metapackages separate **payload** from **Python stack**.

---

## 4. Target Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│  acme2certifier (noarch)                                    │
│   /opt/acme2certifier/     application code + examples      │
│   systemd unit, nginx examples, SELinux helpers, a2c-*      │
│   NO Requires on python3-* / python39-* / python3.11-*      │
└─────────────────────────────────────────────────────────────┘
                            ▲
                            │ Requires: acme2certifier = NVR
┌─────────────────────────────────────────────────────────────┐
│  acme2certifier-pythonX (metapackage, noarch)               │
│   Requires: interpreter + matching pythonX-* modules        │
│   %config(noreplace) /etc/acme2certifier/python.conf        │
│   Conflicts: other acme2certifier-python* flavors           │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  pythonX-* RPMs (AppStream / EPEL / project-provided)       │
│  sitelib for the selected interpreter                       │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────┐      uwsgi protocol       ┌──────────────────┐
│    nginx     │ ─────────────────────────▶│ uwsgi (systemd)  │
│              │                           │ python-path=/opt │
└──────────────┘                           └──────────────────┘
```

### Design decisions (locked)

1. **App RPM stays noarch** — code under `/opt`; no embedded wheels or venv.
2. **Deps are RPM-only** — AppStream/EPEL where available; otherwise **project-provided** EL8/EL9 module RPMs for the chosen flavor.
3. **No pip at install or runtime** for core application dependencies.
4. **Default runtime version is Python 3.9** on both EL8 and EL9 (unified app Python across majors).
5. **EL8 3.6** remains supported via legacy flavor `acme2certifier-python3` → system `python3-*` (upgrade holdouts / no parallel Python allowed).
6. **Flavor metapackages** select the stack; see §5.3.
7. **Process model** remains nginx + uWSGI where the flavor matches system uWSGI Python; non-system flavors need a matching plugin or documented alternative.
8. **Flavor contents** = Requires + Conflicts + `python.conf` only. No second copy of application code.

---

## 5. Package Split

### 5.1 Main package: `acme2certifier`

Owns the payload:

| Path / artifact | Role |
|---|---|
| `/opt/acme2certifier/` | Application tree, examples, WSGI entrypoints |
| systemd unit | Starts uWSGI with `python-path` / `PYTHONPATH` pointing at `/opt` |
| nginx examples | Unchanged role (uwsgi upstream) |
| `a2c-*` wrappers | Admin/CLI helpers |
| SELinux scriptlets | Existing nginx ↔ socket policy flow |

**Does not** `Require:` `python3-cryptography`, `python39-jwcrypto`, `python3.11-jwcrypto`, etc. Soft OS deps that are not Python-module-specific (e.g. `tar`, SELinux helpers) may remain on the main package or move with the web stack as today.

### 5.2 Flavor packages: `acme2certifier-python*`

**Metapackages** — almost no application files. They bind one Python stack to the install.

| What | Example |
|---|---|
| `Requires:` main package | `acme2certifier = %{version}-%{release}` |
| `Requires:` interpreter | `python3`, `python39` / `python3.9`, or `python3.11` |
| `Requires:` module RPMs | Matching `python3-*`, `python39-*`, or `python3.11-*` set |
| Config | `/etc/acme2certifier/python.conf` (`%config(noreplace)`) with absolute `python_interpreter=` |
| `Conflicts:` | Other `acme2certifier-python*` flavors (one stack at a time) |

They do **not** store another copy of acme2certifier under a versioned directory.

### 5.3 Flavor set (locked for v1)

**Policy:** default **app** Python is **3.9** on both majors. Package *names* differ because on EL9 3.9 is system `python3`, while on EL8 3.9 is a parallel stack.

| Flavor RPM | EL8 | EL9 | Module prefix | Role |
|---|---|---|---|---|
| `acme2certifier-python39` | **Default** — parallel Python 3.9 | — (not used; 3.9 is system) | `python39-*` / `python3.9-*` (use OS-real names) | Unified 3.9 default on EL8 |
| `acme2certifier-python3` | **Legacy** — system Python **3.6** | **Default** — system Python **3.9** | `python3-*` | EL9 default; EL8 fallback |
| `acme2certifier-python3.11` | Optional modern | Optional modern | `python3.11-*` | Parallel 3.11 on both |

Installer / `a2c-rpm.sh` default selection:

```text
if EL8: install acme2certifier-python39
if EL9: install acme2certifier-python3
# both → app runs on Python 3.9
```

Explicit legacy on EL8:

```bash
dnf install acme2certifier acme2certifier-python3   # EL8 only: stay on 3.6
```

Additional flavors (e.g. `python3.12`) are added only after the full module set exists for that prefix (OS or project RPMs).

---

## 6. Requires Model

### 6.1 Versioned package prefixes

RHEL/Alma/Rocky bind libraries to an interpreter via the RPM name prefix:

- System Python 3: `python3-<module>` (EL8 → 3.6, EL9 → 3.9)
- EL8 parallel 3.9: `python39-<module>` and/or `python3.9-<module>` (flavor SPEC must match what the target OS ships)
- Parallel 3.11: `python3.11-<module>`

A single main RPM must not hard-`Require:` every prefix. Each flavor lists the **complete** a2c dependency set for **one** prefix.

### 6.2 Dependency source policy

For each `(EL major, Python flavor)`:

1. Prefer AppStream / BaseOS packages.
2. Else EPEL.
3. Else **project-provided** RPMs for that EL major and prefix (same operational model as today’s EL8 cryptography/dns/jwcrypto backports, extended per flavor as needed).

Assumption for this design: the project **will** ship any missing module RPMs required for supported flavors on EL8 and EL9.

### 6.3 Core module set (illustrative)

Aligned with today’s SPEC (exact NVR/version pins live in flavor SPECs):

- cryptography, pyOpenSSL, jwcrypto, josepy, acme
- dnspython (`pythonX-dns`), requests, requests-pkcs12, pysocks
- dateutil, pytz, setuptools, pyyaml
- xmltodict, pyasn1, pyasn1-modules
- Optional / Recommends: dataclasses (EL8 3.6 path), krb5 libs for gssapi handlers, Django stack for `--mode django`

### 6.4 Removed from main package

Once flavors exist, move the long `python3-*` list off [`acme2certifier.spec`](../../examples/install_scripts/rpm/acme2certifier.spec) onto the appropriate flavors (`acme2certifier-python3`, `acme2certifier-python39`, …) with the correct prefix on each.

---

## 7. Interpreter Binding and Process Model

### 7.1 `python.conf`

Examples by flavor:

```ini
# acme2certifier-python39 (EL8 default)
python_interpreter=/usr/bin/python3.9
```

```ini
# acme2certifier-python3 (EL9 default / EL8 legacy)
python_interpreter=/usr/bin/python3
```

```ini
# acme2certifier-python3.11
python_interpreter=/usr/bin/python3.11
```

Wrappers and service Environment files read this path. `%config(noreplace)` preserves local edits across upgrades.

### 7.2 uWSGI + `/opt`

- Application import path: `PYTHONPATH` / uWSGI `python-path` = `/opt/acme2certifier` (deploy root), unchanged in spirit from the Phase 3 `/opt` layout.
- Modules come from the selected interpreter’s system sitelib (provided by the flavor’s `pythonX-*` RPMs).

### 7.3 uWSGI plugin constraint

Distro package `uwsgi-plugin-python3` is built for **system** Python:

- **EL9 default** (`acme2certifier-python3` / 3.9): matches system plugin — `plugins = python3`.
- **EL8 legacy** (`acme2certifier-python3` / 3.6): matches system plugin — `plugins = python3`.
- **EL8 default** (`acme2certifier-python39` / 3.9): requires project-provided **`uwsgi-plugin-python39`** — `plugins = python39`.
- **python3.11** flavors: same pattern once a matching plugin RPM exists (or use httpd/`python3.11-mod_wsgi`).

`acme2certifier-python39` **Recommends:** `uwsgi-plugin-python39`. Flavor `%post` and `a2c-rpm.sh` set `plugins = python39` in `acme2certifier.ini`. Build the plugin from EPEL `uwsgi` sources via `--build-plugin "plugins/python python39"` against AppStream `python39`.

httpd + `python39-mod_wsgi` remains a documented alternate for sites that prefer Apache.

### 7.4 Default for new installs

| OS | Default packages | App Python |
|---|---|---|
| EL8 | `acme2certifier` + `acme2certifier-python39` | 3.9 |
| EL9 | `acme2certifier` + `acme2certifier-python3` | 3.9 |

Optional: `acme2certifier-python3.11` on either OS.
EL8 fallback: `acme2certifier-python3` (3.6) when parallel 3.9 cannot be installed.

---

## 8. Install, Upgrade, Switch, Uninstall

### 8.1 Install

```bash
# Default — app on Python 3.9 both majors
# EL8:
sudo dnf install acme2certifier acme2certifier-python39
# EL9:
sudo dnf install acme2certifier acme2certifier-python3

# EL8 legacy fallback — system Python 3.6
sudo dnf install acme2certifier acme2certifier-python3

# Optional modern stack
sudo dnf install acme2certifier acme2certifier-python3.11
```

`a2c-rpm.sh` selects the default flavor from OS major (`python39` on EL8, `python3` on EL9) and accepts `--python` / flavor overrides (`3.6` / `python3` on EL8 for legacy, `3.11`, etc.).

### 8.2 Upgrade

- Upgrading `acme2certifier` refreshes `/opt` payload.
- Upgrading a flavor refreshes module `Requires` and may replace `python.conf` only if not noreplace-modified.
- Module ABI/security updates come from the usual `dnf update` of `pythonX-*` packages.
- Existing EL8 hosts on `acme2certifier-python3` (3.6) stay there until an admin swaps to `acme2certifier-python39`.

### 8.3 Switch flavor

```bash
# EL8: legacy 3.6 → default 3.9
sudo dnf swap acme2certifier-python3 acme2certifier-python39

# Either OS: 3.9 path → 3.11
sudo dnf swap acme2certifier-python39 acme2certifier-python3.11   # EL8
sudo dnf swap acme2certifier-python3 acme2certifier-python3.11    # EL9

sudo systemctl restart acme2certifier
```

Verify nginx/uWSGI (or alternate) config still matches the flavor’s process-manager rules.

### 8.4 Uninstall

- Removing a flavor removes its `Requires` pull and its `python.conf` per RPM config policy.
- Removing `acme2certifier` removes `/opt` payload; leave operator data/volume paths per existing packaging practice.

---

## 9. EL8 Backports and Newer Flavors

| Path | Behavior |
|---|---|
| `acme2certifier-python3` on EL8 (3.6 legacy) | May still need project backports for cryptography / dns / jwcrypto — same class as [`docs/install_rpm.md`](../install_rpm.md) |
| `acme2certifier-python39` on EL8 (default) | Prefer AppStream/EPEL `python39-*`; fill gaps with project RPMs |
| `acme2certifier-python3` on EL9 (default 3.9) | Prefer distro `python3-*`; project RPMs only for gaps |
| `acme2certifier-python3.11` | Prefer AppStream `python3.11-*`; project RPMs for gaps |

Backports remain **RPMs in a repo**, not pip installs on the target host.

---

## 10. Testing Matrix (CI)

| OS | Flavor | Expectation |
|---|---|---|
| Alma/Rocky 8 | `acme2certifier-python39` (**default**) | Parallel 3.9; process manager per §7.3 |
| Alma/Rocky 8 | `acme2certifier-python3` (legacy) | System 3.6 + uWSGI plugin; backports as needed |
| Alma/Rocky 9 | `acme2certifier-python3` (**default**) | System 3.9 + uWSGI plugin |
| Alma/Rocky 8/9 | `acme2certifier-python3.11` | Once full module set + process manager are ready |

Assertions:

- Default install path yields **Python 3.9** on both EL8 and EL9.
- Main RPM alone does not pull app module RPMs (flavor required).
- `Conflicts` prevent two flavors simultaneously.
- Offline install works when only configured RPM repos are reachable (no PyPI).
- `/directory` responds after `a2c-rpm.sh` (or equivalent) with the selected flavor.
- EL8 legacy 3.6 path remains installable and tested.

---

## 11. Implementation Phases

### Phase A — Design and SPEC split (docs + packaging layout)

1. Keep this document as the source of truth.
2. Split SPECs: main payload + `acme2certifier-python3` + `acme2certifier-python39`.
3. Move module `Requires` off the main SPEC onto flavors; add `python.conf` per flavor.
4. Update `a2c-rpm.sh` / install docs: OS-aware **3.9 default**; `--python` for EL8 legacy 3.6 and optional 3.11.

### Phase B — Additional flavors

1. Add `acme2certifier-python3.11` when the module list and process manager are ready.
2. Publish any missing `python39-*` / `python3.11-*` RPMs for EL8/EL9 via the project repo.
3. Document per-flavor web-stack requirements (uWSGI plugin vs alternative).
   EL8 default 3.9 uses project `uwsgi-plugin-python39` (`plugins = python39`).

### Phase C — CI and deprecation polish

1. Matrix jobs: EL8 default 3.9, EL8 legacy 3.6, EL9 default 3.9, optional 3.11.
2. Ensure EL8 backport repo usage is emphasized for the **3.6 legacy** flavor.
3. Remove obsolete “pip on the RPM host” guidance if any remains.

---

## 12. How This Addresses Prior Concerns

| Concern | Resolution |
|---|---|
| Same Python across EL8/EL9 | **Default app runtime = 3.9** (`python39` on EL8, `python3` on EL9) |
| EL8 3.6 still needed | Legacy flavor `acme2certifier-python3` on EL8 |
| No arch-specific app RPM | Payload stays noarch; no wheelhouse |
| No pip-installed modules | All deps are RPM `Requires` on flavors |
| Selectable Python | Flavor metapackages + `python.conf` |
| Missing distro modules | Project provides EL8/EL9 RPMs for supported flavors |
| Air-gapped CA sites | dnf/yum from configured repos only |
| uWSGI vs alternate Python | EL8 `python39`: project `uwsgi-plugin-python39`; system flavors use `uwsgi-plugin-python3` |

---

## 13. Summary

Ship a **noarch** `acme2certifier` RPM with application code under `/opt` and **no** Python module `Requires`. Pair it with **flavor metapackages** that pull the matching interpreter and `pythonX-*` RPMs, install `/etc/acme2certifier/python.conf`, and conflict with each other.

**Default:** Python **3.9** on both majors — `acme2certifier-python39` on EL8, `acme2certifier-python3` on EL9.
**Legacy:** `acme2certifier-python3` on EL8 keeps system **3.6** for hosts that cannot take a parallel Python.
**Optional:** `acme2certifier-python3.11` on both.

Do not use pip, wheelhouses, or venvs for this RPM path.
