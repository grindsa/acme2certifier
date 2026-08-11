<!-- markdownlint-disable MD013 MD014 MD029 -->

<!-- wiki-title RPM Installation on AlmaLinux / RHEL / Rocky -->

# RPM Installation on AlmaLinux / Red Hat EL / Rocky / CentOS Stream

One **noarch** payload RPM (`acme2certifier`) installs on **EL8 and EL9** under `/opt/acme2certifier` (`PYTHONPATH=/opt/acme2certifier`). Python modules come from a **flavor metapackage**:

| Flavor | Role |
| --- | --- |
| `acme2certifier-python39` | **EL8 default** — parallel Python 3.9 |
| `acme2certifier-python3` | **EL9 default** (system 3.9) / **EL8 legacy** (system 3.6) |

Default **app** Python is **3.9** on both majors.

> **PyPI / pip installs** (e.g. [`a2c-rel-nginx.sh`](../examples/install_scripts/a2c-rel-nginx.sh)) require Python ≥ 3.7 and are **EL9-only**. Use this RPM path for EL8.

## Automated install script

[`examples/install_scripts/a2c-rpm.sh`](../examples/install_scripts/a2c-rpm.sh) installs the main `.rpm` **plus** the matching flavor from the same directory, configures Nginx + uWSGI, and sets `--mode` (either wsgi or django):

```bash
chmod a+rx examples/install_scripts/a2c-rpm.sh
./examples/install_scripts/a2c-rpm.sh --rpm ./acme2certifier-0.45.dev1-1.0.noarch.rpm
./examples/install_scripts/a2c-rpm.sh -r ../acme2certifier-*.rpm -m django
./examples/install_scripts/a2c-rpm.sh -m wsgi --no-ssl
# EL8 legacy system Python 3.6
./examples/install_scripts/a2c-rpm.sh --rpm ./acme2certifier-*.rpm --python 3.6
# Sync volume/cfg and restart nginx + acme2certifier (no reinstall)
./examples/install_scripts/a2c-rpm.sh restart --volume-dir /path/to/volume
# Copy volume/acme_ca only (no restart)
./examples/install_scripts/a2c-rpm.sh --update --volume-dir /path/to/volume
```

| Option | Meaning |
| --- | --- |
| `-r, --rpm PATH` | path to **main** `acme2certifier-<ver>*.rpm` (flavors auto-found beside it) |
| `-m, --mode wsgi\|django` | DB handler + matching uWSGI module (default: `wsgi`) |
| `--python VER` | flavor: `3.9` / `python39` (EL8 default), `3.6` / `python3` (EL9 default / EL8 legacy) |
| `--restart` / `restart` | sync volume/cfg and restart services (no reinstall) |
| `--update` / `update` | sync `volume/acme_ca` only (no restart) |
| `--volume-dir DIR` | sync source (default: `/tmp/acme2certifier/volume` when present) |
| `--no-ssl` | skip SSL nginx vhost / self-signed cert generation |

Works with `dnf` or `yum` on EL8 and EL9. The remainder of this guide is the manual equivalent.

## Layout

| Path | Purpose |
| --- | --- |
| `/opt/acme2certifier/acme2certifier/` | Importable Python package |
| `/opt/acme2certifier/acme_srv.cfg` | Main config (`noreplace`) |
| `/opt/acme2certifier/acme2certifier_wsgi.py` | WSGI entry |
| `/opt/acme2certifier/acme2certifier.ini` | uWSGI (includes `python-path`) |
| `/opt/acme2certifier/share/{nginx,apache2,skeletons}/` | Example web configs |
| `/etc/acme2certifier/python.conf` | Active flavor interpreter (`python_interpreter=`) |
| `/usr/bin/a2c-*` | CLI wrappers (`PYTHONPATH` + interpreter from `python.conf`) |

## 1. Download the Latest RPM Packages

Download the latest [RPM packages](https://github.com/grindsa/acme2certifier/releases):

- `acme2certifier-<version>-1.0.noarch.rpm` (payload)
- `acme2certifier-python3-<version>-1.0.noarch.rpm` and/or `acme2certifier-python39-<version>-1.0.noarch.rpm`

## 2. Install "Extra Packages for Enterprise Linux (EPEL)"

```bash
sudo yum install -y epel-release
sudo yum update -y
```

## 3. Install the RPM Packages

**EL9 (default — system Python 3.9):**

```bash
sudo yum -y localinstall \
  /tmp/acme2certifier/acme2certifier-<version>-1.0.noarch.rpm \
  /tmp/acme2certifier/acme2certifier-python3-<version>-1.0.noarch.rpm
```

**EL8 (default — parallel Python 3.9):**

```bash
sudo yum -y install python39   # AppStream / module as required by your OS
sudo yum -y localinstall \
  /tmp/acme2certifier/acme2certifier-<version>-1.0.noarch.rpm \
  /tmp/acme2certifier/acme2certifier-python39-<version>-1.0.noarch.rpm
```

**EL8 legacy (system Python 3.6):**

```bash
sudo yum -y localinstall \
  /tmp/acme2certifier/acme2certifier-<version>-1.0.noarch.rpm \
  /tmp/acme2certifier/acme2certifier-python3-<version>-1.0.noarch.rpm
```

Nginx and uWSGI are **Recommends**, not hard Requires. Matching Python plugin comes from the flavor:

```bash
# EL9 / EL8 legacy (system Python) — stock EPEL plugin
sudo yum -y install nginx uwsgi uwsgi-plugin-python3 python3-uwsgidecorators

# EL8 default (python39) — project-provided plugin + AppStream python39
sudo yum -y install nginx uwsgi
sudo yum -y localinstall /tmp/acme2certifier/uwsgi-plugin-python39-*.rpm
```

Set `plugins = python3` or `plugins = python39` in `/opt/acme2certifier/acme2certifier.ini` to match the flavor (flavor `%post` and `a2c-rpm.sh` do this). See [rpm-el-packaging.md](architecture/rpm-el-packaging.md) §7.3.

### Project RPM repository (SBOM)

Companion / backport RPMs live under [grindsa/sbom `rpm-repo/RPMs`](https://github.com/grindsa/sbom/tree/main/rpm-repo/RPMs), split by **EL major** and **Python stack**:

| OS | a2c flavor | Directory |
| --- | --- | --- |
| EL8 | `acme2certifier-python39` (default) | [`RPMs/rhel8/python39/`](https://github.com/grindsa/sbom/tree/main/rpm-repo/RPMs/rhel8/python39) |
| EL8 | `acme2certifier-python3` (legacy 3.6) | [`RPMs/rhel8/python36/`](https://github.com/grindsa/sbom/tree/main/rpm-repo/RPMs/rhel8/python36) |
| EL9 | `acme2certifier-python3` (default) | [`RPMs/rhel9/python3/`](https://github.com/grindsa/sbom/tree/main/rpm-repo/RPMs/rhel9/python3) |

Install matching `noarch` / host-arch RPMs only (do not mix `python3-*` and `python39-*` leaves).

### Red Hat 8.x: Upgrade Required Packages (legacy python3 / 3.6)

If using **`acme2certifier-python3` on EL8**, upgrade (from [`rhel8/python36`](https://github.com/grindsa/sbom/tree/main/rpm-repo/RPMs/rhel8/python36)):

- [python3-cryptography](https://cryptography.io/en/latest/) to version 36.0.1 or higher.
- [python3-dns](https://www.dnspython.org/) to version 2.1 or higher.
- [python3-jwcrypto](https://jwcrypto.readthedocs.io/en/latest/) to version 0.8 or higher.

Examples (grindsa rebuilds):

- [python3-cryptography-36.0.1-4grindsa.el8.x86_64.rpm](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8/python36/python3-cryptography-36.0.1-4grindsa.el8.x86_64.rpm)
- [python3-dns-2.2.1-2grindsa.el8.noarch.rpm](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8/python36/python3-dns-2.2.1-2grindsa.el8.noarch.rpm)
- [python3-jwcrypto-1.5.1-1grindsa.el8.noarch.rpm](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8/python36/python3-jwcrypto-1.5.1-1grindsa.el8.noarch.rpm)

### Additional Modules for Specific CA Handlers

Depending on your CA handler, you may need these additional modules (prefix must match the flavor: `python3-*` or `python39-*`). Examples for **EL8 legacy** (`python36/`):

- [python3-impacket-0.11.0-2grindsa](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8/python36/python3-impacket-0.11.0-2grindsa.el8.noarch.rpm) for [MS WCCE handler](mswcce.md).
- [python3-ntlm-auth-1.5.0-2grindsa](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8/python36/python3-ntlm-auth-1.5.0-2grindsa.el8.noarch.rpm) for [MS WSE handler](mscertsrv.md).
- [python3-requests_ntlm-1.1.0-14grindsa](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8/python36/python3-requests_ntlm-1.1.0-14grindsa.el8.noarch.rpm) for [MS WSE handler](mscertsrv.md).
- [python3-requests-pkcs12-1.16-1grindsa](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8/python36/python3-requests-pkcs12-1.16-1grindsa.el8.noarch.rpm) for [EST](est.md) or [EJBCA](ejbca.md) handler.

For **EL8 default** (`python39/`), matching grindsa NVRs:

- [python39-impacket-0.11.0-2grindsa](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8/python39/python39-impacket-0.11.0-2grindsa.el8.noarch.rpm) for [MS WCCE handler](mswcce.md).
- [python39-ntlm-auth-1.5.0-1grindsa](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8/python39/python39-ntlm-auth-1.5.0-1grindsa.el8.noarch.rpm) for [MS WSE handler](mscertsrv.md).
- [python39-requests_ntlm-1.1.0-1grindsa](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8/python39/python39-requests_ntlm-1.1.0-1grindsa.el8.noarch.rpm) for [MS WSE handler](mscertsrv.md).
- [python39-requests-pkcs12-1.7-1grindsa](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8/python39/python39-requests-pkcs12-1.7-1grindsa.el8.noarch.rpm) for [EST](est.md) or [EJBCA](ejbca.md) handler.
- [python39-requests-gssapi-1.4.0-1grindsa](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8/python39/python39-requests-gssapi-1.4.0-1grindsa.el8.noarch.rpm) / [python39-gssapi-1.6.9-1grindsa](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8/python39/python39-gssapi-1.6.9-1grindsa.el8.x86_64.rpm) for Kerberos / GSSAPI handlers.

## 4. Copy the Nginx Configuration File

```bash
sudo cp /opt/acme2certifier/share/nginx/nginx_acme_srv.conf /etc/nginx/conf.d/
```

## 5. Copy the Nginx SSL Configuration File (Optional)

```bash
sudo cp /opt/acme2certifier/share/nginx/nginx_acme_srv_ssl.conf /etc/nginx/conf.d/
```

Apache examples (optional) are under `/opt/acme2certifier/share/apache2/`.

## 6. Configure `acme_srv.cfg`

The package ships `/opt/acme2certifier/acme_srv.cfg` (`%config(noreplace)`). Edit it in place, or replace it with your own.

Default SQLite path: `/opt/acme2certifier/acme_srv.db`.

Modify options per [acme_srv.cfg](acme_srv.md).

## 7. Configure the CA Handler

Set up the CA handler via `handler_module` in `acme_srv.cfg` (preferred). [Example for Insta Certifier](certifier.md). See [Upgrading](upgrading.md).

## 8. Enable and Start the Acme2Certifier Service

```bash
sudo systemctl enable acme2certifier.service
sudo systemctl start acme2certifier.service
```

## 9. Enable and Start the Nginx Service

```bash
sudo systemctl enable nginx.service
sudo systemctl start nginx.service
```

## 10. Verify the Server

Smoke-check the import path (use the flavor interpreter from `/etc/acme2certifier/python.conf` when set):

```bash
PYTHONPATH=/opt/acme2certifier python3 -c "import acme2certifier.acme_srv; print('ok')"
# or: a2c-cli --help
```

Test the directory resource:

```bash
curl http://<your-server-name>/directory
```

Expected output:

```json
{
  "newAccount": "http://127.0.0.1:8000/acme_srv/newaccount",
  "fa8b347d3849421ebc4b234205418805": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417",
  "keyChange": "http://127.0.0.1:8000/acme_srv/key-change",
  "newNonce": "http://127.0.0.1:8000/acme_srv/newnonce",
  "meta": {
    "home": "https://github.com/grindsa/acme2certifier",
    "author": "grindsa <grindelsack@gmail.com>"
  },
  "newOrder": "http://127.0.0.1:8000/acme_srv/neworders",
  "revokeCert": "http://127.0.0.1:8000/acme_srv/revokecert"
}
```

## 11. Enroll a Certificate

Use your preferred ACME client to enroll a certificate. If an issue occurs, enable debugging in `/opt/acme2certifier/acme_srv.cfg` and check `/var/log/messages` for errors.
