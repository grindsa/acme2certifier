<!-- markdownlint-disable MD013 MD014 MD029 -->

# Design: EL8/EL9 RPM Packaging with Isolated Python Runtime

## 1. Purpose

Replace the current “install into system Python via `python3-*` RPM deps + uWSGI Python plugin” model with an **interpreter-selectable, venv-isolated** runtime that:

- Ships **one application payload** usable on EL8 and EL9
- Does **not** modify or replace system Python (`/usr/bin/python3`)
- Works **offline / air-gapped** (typical near CA deployments)
- Supports multiple AppStream / parallel Python interpreters without repackaging application code
- Remains operable under nginx + systemd with SELinux enforcing

This document is the concrete design that addresses the gaps in the earlier “single RPM + pip-at-install” brief.

---

## 2. Goals and Non-Goals

### Goals

| ID | Goal |
|---|---|
| G1 | One *content* RPM for EL8 and EL9 (same versioned artifact family) |
| G2 | User-selectable Python ≥ 3.9 from parallel interpreters |
| G3 | Dedicated venv; zero use of system `site-packages` for app deps |
| G4 | Offline install: no PyPI access at `%post` or first start |
| G5 | Deterministic dependency set (pinned + hashed where practical) |
| G6 | Clear upgrade / uninstall / interpreter-switch lifecycle |
| G7 | Service process runs **inside** the venv (not via system uWSGI Python plugin) |

### Non-Goals

- Replacing container or DEB install paths in this design
- Supporting EL8 system Python 3.6 as an application runtime
- True RPM `--relocate` of an already-created venv
- Claiming Fedora/RHEL “pure library packaging” compliance (this is a **/opt vendor application** with a managed venv)

---

## 3. Current State (baseline)

Today ([`examples/install_scripts/rpm/acme2certifier.spec`](../../examples/install_scripts/rpm/acme2certifier.spec)):

- Payload under `/opt/acme2certifier`
- Hard `Requires:` on many `python3-*` packages + `uwsgi-plugin-python3`
- systemd unit runs system `uwsgi` with `plugins = python3`
- EL8 needs backport RPMs for cryptography / dnspython / jwcrypto ([`docs/install_rpm.md`](../install_rpm.md))
- `BuildArch: noarch`

Pain: system Python coupling, EL8 dependency skew, and uWSGI plugin binding prevent “pick any Python” without risk.

---

## 4. Target Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│  RPM (arch-specific):                                       │
│   /opt/acme2certifier/          application code + examples │
│   /opt/acme2certifier/wheelhouse/  bundled wheels (offline) │
│   /usr/lib/systemd/system/acme2certifier.service            │
│   /usr/libexec/acme2certifier/{select-python,setup-venv}    │
│   /etc/acme2certifier/python.conf   (noreplace)             │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼  acme2certifier-setup (posttrans / admin)
┌─────────────────────────────────────────────────────────────┐
│  State (not in RPM payload as a prebuilt venv):             │
│   /var/lib/acme2certifier/venv/                             │
│   /var/lib/acme2certifier/venv.stamp   (hash of pins+py)    │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────┐     unix socket / HTTP      ┌────────────────┐
│    nginx     │ ───────────────────────────▶│ gunicorn/uvicorn│
│  (RPM dep)   │                             │  (inside venv)  │
└──────────────┘                             └────────────────┘
```

### Design decisions (locked)

1. **Runtime server:** systemd starts **gunicorn** from the venv (WSGI). Django and classic WSGI entrypoints both work. This **drops** `uwsgi-plugin-python3` from the supported venv path.
2. **Legacy path:** optional `acme2certifier-legacy` mode (or separate doc/profile) keeps today’s system-Python + uWSGI model for existing sites; new installs default to venv mode.
3. **Venv location:** `/var/lib/acme2certifier/venv` (state). Code stays in `/opt/acme2certifier`.
4. **Minimum Python:** **3.9**. Supported matrix: EL8 `python39` / `python3.11`; EL9 `python3` / `python3.11` / `python3.12`.
5. **No silent fallback to 3.6/3.8.** Missing interpreter → setup fails with an actionable error.
6. **Offline deps:** ship a **wheelhouse** inside the RPM; `pip install --no-index --find-links=...`.
7. **Arch:** RPM becomes **arch-specific** (`x86_64`, `aarch64`) because binary wheels are arch-bound. Abandon `BuildArch: noarch` for the venv-mode package.

---

## 5. Package Contents

### 5.1 Files owned by the RPM

| Path | Role |
|---|---|
| `/opt/acme2certifier/` | Application tree (`acme_srv`, tools, examples, WSGI modules) |
| `/opt/acme2certifier/wheelhouse/` | Pre-downloaded wheels for all Python deps (incl. gunicorn) |
| `/opt/acme2certifier/requirements.locked.txt` | Pinned requirements used for venv create |
| `/usr/libexec/acme2certifier/select-python` | Resolves interpreter per policy |
| `/usr/libexec/acme2certifier/setup-venv` | Creates/updates venv from wheelhouse |
| `/usr/sbin/acme2certifier-setup` | Admin entrypoint (thin wrapper) |
| `/etc/acme2certifier/python.conf` | `%config(noreplace)` interpreter preference |
| `/usr/lib/systemd/system/acme2certifier.service` | Runs venv gunicorn |
| nginx example configs | Unchanged role; socket/upstream updated for gunicorn |

### 5.2 Explicitly **not** in the RPM

- A prebuilt `venv/` directory
- A Python interpreter
- Unpinned `pip install` from the network

### 5.3 RPM `Requires` / `Recommends`

**Hard Requires (OS / non-PyPI):**

- `nginx`
- `policycoreutils-python-utils` (SELinux tooling used in scriptlets)
- Kerberos runtime libs used by `gssapi` (`krb5-libs`, and build-time only if sdists remain — prefer wheels)
- `/usr/bin/python3` **not** required as the app runtime

**Weak / documented prerequisites (not a single fixed Python RPM name):**

Because EL8/EL9 package names differ (`python39` vs `python3.11` vs module streams), do **not** encode one `Requires: python3.11`. Instead:

- Document supported packages per OS
- `acme2certifier-setup` checks for a usable interpreter and prints the exact `dnf install` line if missing
- Optional: ship tiny metapackages later (`acme2certifier-python311`) that only `Require:` the right AppStream package — out of scope for v1

**Removed from default Requires (venv mode):**

- All `python3-jwcrypto`, `python3-cryptography`, … module RPMs
- `uwsgi-plugin-python3`, `python3-uwsgidecorators`

---

## 6. Interpreter Selection

### 6.1 Configuration

`/etc/acme2certifier/python.conf` (`%config(noreplace)`):

```ini
# Absolute path preferred. Empty = auto (newest supported).
python_interpreter=

# Minimum accepted version (major.minor)
python_min=3.9
```

Overrides (highest wins):

1. CLI: `acme2certifier-setup --python /usr/bin/python3.11`
2. Env: `ACME2CERTIFIER_PYTHON=/usr/bin/python3.11`
3. Config file `python_interpreter=`
4. Auto: scan known binaries, pick **newest** that is ≥ `python_min`

### 6.2 Auto-discovery candidates (ordered newest-first)

```text
python3.12, python3.11, python3.10, python3.9
```

Resolve via `command -v` / well-known paths (`/usr/bin/python3.11`, …).  
Validate with:

```bash
"$py" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)'
"$py" -m venv -h >/dev/null
```

### 6.3 Failure mode

If no candidate works: **exit non-zero**, print:

- Detected OS
- Tried paths
- Example: `dnf install python3.11` (EL9) / `dnf install python3.11` or `python39` (EL8)

Never select `/usr/bin/python3` on EL8 when it is 3.6.

---

## 7. Virtual Environment Lifecycle

### 7.1 Creation (`setup-venv`)

Idempotent algorithm:

1. Resolve interpreter (`select-python`).
2. Compute stamp = hash(`interpreter realpath + version` + `requirements.locked.txt` + wheelhouse index).
3. If `/var/lib/acme2certifier/venv` exists and stamp matches → no-op (success).
4. Else:
   - Move old venv aside (`venv.prev`) or remove after successful create
   - `"$PYTHON" -m venv /var/lib/acme2certifier/venv`
   - `/var/lib/acme2certifier/venv/bin/pip install --upgrade pip setuptools wheel` from wheelhouse only
   - `pip install --no-index --find-links=/opt/acme2certifier/wheelhouse -r requirements.locked.txt`
   - Write stamp file; fix ownership for service user
5. `systemctl try-restart acme2certifier.service` when invoked from upgrade path

### 7.2 When setup runs

| Event | Behavior |
|---|---|
| `%posttrans` (install/upgrade) | Call `acme2certifier-setup --noninteractive`; **must not** hit network |
| Admin | `acme2certifier-setup [--python PATH] [--force]` |
| First HTTP request | **Not** used (avoids race with systemd/`nginx` user) |

If `%posttrans` fails (no Python yet), RPM install still succeeds (payload on disk); service stays inactive until admin installs a Python and re-runs setup. Scriptlet prints a clear WARN — do not soft-fail silently.

### 7.3 Ownership and permissions

- Service user: `nginx` (keep current convention) or dedicated `acme2certifier` user (preferred long-term; v1 may keep `nginx` for less nginx.conf churn).
- Venv owned `root:root`, mode `755`; app-writable data (DB, accounts) remains under paths already used today with correct ownership.
- Do not run `pip` as `nginx`.

### 7.4 Uninstall (`%postun` when `$1 = 0`)

- `systemctl disable --now acme2certifier.service` (best effort)
- Remove `/var/lib/acme2certifier/venv` and stamp
- Leave `/etc/acme2certifier/python.conf` and admin-edited `acme_srv.cfg` alone on erase only if marked `%config(noreplace)` — follow normal RPM config policy; delete venv state always

### 7.5 Interpreter switch

```bash
acme2certifier-setup --python /usr/bin/python3.12 --force
systemctl restart acme2certifier.service
```

`--force` ignores stamp match and recreates the venv.

---

## 8. Offline Wheelhouse

### 8.1 Build-time generation (CI)

On the RPM build host (per arch):

```bash
python3.11 -m pip download \
  -r requirements.locked.txt \
  -d wheelhouse/ \
  --platform manylinux_2_28_x86_64 \
  --python-version 39 --python-version 311 --python-version 312 \
  --only-binary=:all:
```

Practical approach for v1:

- Lock deps with `pip-compile` (or uv lock) → `requirements.locked.txt`
- Download wheels for each supported major.minor on the target arch
- Fail the release build if any dependency lacks a binary wheel for a supported Python (forces an explicit decision to vendor an sdist + document compiler `BuildRequires` on the **build** host only — not on customers)

### 8.2 Install-time pip flags (mandatory)

```bash
pip install --no-index --find-links=/opt/acme2certifier/wheelhouse \
  -- compulsory-hashes  # when hash-pinning is enabled \
  -r /opt/acme2certifier/requirements.locked.txt
```

No PyPI fallback. Air-gap safe.

### 8.3 Optional extras (CA handlers)

Heavy/optional deps (e.g. impacket for MS-WCCE) go into:

- `requirements.optional-mswcce.txt` + wheels in the same house, or
- a second RPM `acme2certifier-extras-mswcce`

v1: keep optional handler wheels in the main house if size is acceptable; otherwise split.

### 8.4 Native library packages

Python wheels that link to system libs still need OS packages, e.g.:

- `krb5-libs` for `gssapi`
- OpenSSL (always present on EL)

These remain normal RPM `Requires`.

---

## 9. Process Model (replacing uWSGI plugin coupling)

### 9.1 systemd unit (venv mode)

```ini
[Unit]
Description=acme2certifier (gunicorn)
After=network.target

[Service]
Type=notify
User=nginx
Group=nginx
WorkingDirectory=/opt/acme2certifier
RuntimeDirectory=acme2certifier
ExecStart=/var/lib/acme2certifier/venv/bin/gunicorn \
  --workers 5 \
  --bind unix:/run/acme2certifier/acme.sock \
  --umask 007 \
  acme2certifier_wsgi:application
Restart=always

[Install]
WantedBy=multi-user.target
```

Django mode: same unit, module `acme2certifier.wsgi:application` (or a small generator in `setup-venv` that writes an environment file selecting the entrypoint).

### 9.2 nginx

Point `uwsgi_pass` / upstream to the gunicorn unix socket (switch example configs from uWSGI protocol to `proxy_pass http://unix:...` unless gunicorn is run with a uWSGI-compatible setup — **prefer HTTP proxy_pass to gunicorn** for simplicity).

### 9.3 Why not keep system uWSGI?

`uwsgi-plugin-python3` loads **system** Python. Pointing uWSGI at a venv is fragile and still couples to distro plugin builds. Gunicorn installed *inside* the venv tracks the selected interpreter automatically.

### 9.4 Legacy uWSGI profile

Retain current unit + `python3-*` Requires behind:

- Package flag / subpackage `acme2certifier-uwsgi-legacy`, **or**
- Documented manual path using existing spec behavior until sites migrate

Default for new releases: venv + gunicorn.

---

## 10. Scriptlets (sketch)

```text
%posttrans
/usr/sbin/acme2certifier-setup --noninteractive || \
  echo "WARN: venv not created; install a supported Python and run acme2certifier-setup"

%postun
if [ "$1" -eq 0 ]; then
  rm -rf /var/lib/acme2certifier/venv /var/lib/acme2certifier/venv.stamp
fi
```

SELinux policy compilation (existing `%post` module for nginx ↔ socket) is retained and updated for the new socket path (`/run/acme2certifier/acme.sock`).

---

## 11. Upgrade Behavior

| From → To | Action |
|---|---|
| Old system-Python RPM → venv RPM | Conflict/Obsoletes old layout carefully; run setup; admin switches nginx config to gunicorn upstream |
| venv RPM N → N+1 | `%posttrans` rebuilds venv if lock/wheelhouse/interpreter stamp changed |
| Python security update (OS) | If interpreter path unchanged and ABI compatible, stamp may still match; `--force` after major AppStream switch |

Provide `Obsoletes:` / migration notes in release docs for socket path and removal of uWSGI dependency.

---

## 12. Testing Matrix (CI)

Reuse existing EL8/EL9 RPM consumer workflows; extend:

| OS | Python | Mode |
|---|---|---|
| Alma/Rocky 8 | 3.9, 3.11 | venv + gunicorn |
| Alma/Rocky 9 | 3.9, 3.11, 3.12 | venv + gunicorn |
| Alma 8/9 | system Python only | legacy uWSGI (smoke only, while retained) |

Assertions:

- Install with network blocked after RPM fetch → setup succeeds
- `/usr/bin/python3 --version` on EL8 remains 3.6; app does not use it
- `systemctl start acme2certifier` + `curl /directory` succeeds
- `acme2certifier-setup --python … --force` switches interpreters cleanly

---

## 13. How This Addresses Prior Concerns

| Concern | Resolution |
|---|---|
| One RPM myth | One **arch-specific** app+wheelhouse RPM works on EL8/EL9; Python itself is an OS prerequisite discovered at setup, not a single `Requires` name |
| RHEL guideline overclaim | Positioned as **/opt vendor app** with offline venv; not “pure” Fedora Python packaging |
| `%post` pip from PyPI | Forbidden; wheelhouse + `--no-index` |
| Silent 3.6 fallback | Minimum 3.9; fail hard |
| uWSGI ↔ venv mismatch | Gunicorn inside venv; legacy uWSGI optional |
| Relocatable venv contradiction | Code relocatable in principle; venv is fixed under `/var/lib` and recreated |
| First-run races | Setup in `%posttrans` / admin CLI only |
| EL8 backport RPMs | Eliminated for app deps (wheels ship cryptography, etc.) |
| Upgrade/uninstall | Stamp-based recreate; `%postun` removes venv state |

---

## 14. Implementation Phases

### Phase A — Foundations (docs + scripts, no cutover)

1. Add `requirements.locked.txt` generation to CI
2. Implement `select-python` / `setup-venv` / `acme2certifier-setup`
3. Add gunicorn to locked requirements
4. Draft new systemd unit + nginx examples (`proxy_pass` to unix socket)

### Phase B — RPM cutover

1. Update SPEC: arch-specific, wheelhouse payload, drop `python3-*` / uWSGI Requires
2. Wire `%posttrans` / `%postun`
3. SELinux policy path update
4. Publish migration notes in `docs/install_rpm.md`

### Phase C — CI & release

1. EL8/EL9 matrix with network-restricted setup test
2. Keep legacy profile documented until deprecation window closes
3. Remove EL8 backport instructions once venv mode is the only supported RPM path

---

## 15. Open Items Deferred (non-blocking for v1)

- Dedicated `acme2certifier` system user instead of `nginx`
- Split `acme2certifier-extras-*` RPMs for niche handlers
- Hash-pinned `requirements.locked.txt` (`pip-compile --generate-hashes`)
- Metapackages that `Require:` specific AppStream Pythons
- DEB parity with the same wheelhouse approach

---

## 16. Summary

Ship an **arch-specific** RPM containing application code and an **offline wheelhouse**. At install or admin setup time, create `/var/lib/acme2certifier/venv` with a **user-selected or newest ≥3.9** interpreter, install deps with **`pip --no-index`**, and run **gunicorn from that venv** behind nginx. System Python stays untouched; EL8 backport RPMs go away; uWSGI’s system Python plugin is no longer on the critical path.
