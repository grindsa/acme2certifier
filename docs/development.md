<!-- markdownlint-disable MD013 MD029 -->

<!-- wiki-title How to setup a development environment -->

# How to setup a development environment

Local checkout of **acme2certifier** with an editable install and Django’s `runserver`. This is not a production deploy. Production installs: [Apache2 Ubuntu](install_apache2_ubuntu.md), [Nginx Ubuntu](install_nginx_ubuntu.md), [DEB](install_deb.md), [RPM](install_rpm.md), [Docker](install_docker.md).

[Package layout](architecture/package-layout.md).

## 1. Clone and virtualenv

```bash
git clone https://github.com/grindsa/acme2certifier.git -b <branch_name>
cd acme2certifier

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python3 -m pip install -U pip
pip install -e ".[test]"
```

`[test]` pulls Django, pytest, and coverage. Add `[gssapi]` or `[ntlm]` if you work on those CA handlers.

The editable install (`-e`) puts `a2c-manage` and the other [CLI tools](../tools/README.md) on `PATH` and picks up source edits without reinstalling.

## 2. Adjust environment (optional)

```bash
export ACME2CERTIFIER_BASE_DIR="$PWD"
export ACME_SRV_CONFIGFILE="$PWD/acme_srv.cfg"
export ACME2CERTIFIER_DEBUG=1
```

| Variable                  | Role                                                           |
| ------------------------- | -------------------------------------------------------------- |
| `ACME2CERTIFIER_BASE_DIR` | Deploy root: Django `db.sqlite3`, relative `dbfile` / CA paths |
| `ACME_SRV_CONFIGFILE`     | Absolute path to cfg (beats `/var/www/...` and `/opt/...`)     |
| `ACME2CERTIFIER_DEBUG`    | Django `DEBUG` (`1` / `true`)                                  |

## 3. Config and a local OpenSSL CA

`acme_srv.cfg` at the repo root is gitignored.

```bash
cp acme2certifier/share/acme_srv.cfg acme_srv.cfg
mkdir -p acme_srv/ca/certs
cp test/ca/sub-ca-key.pem test/ca/sub-ca-cert.pem \
   test/ca/sub-ca-crl.pem test/ca/root-ca-cert.pem \
   acme_srv/ca/
```

Edit `acme_srv.cfg`:

```ini
[DEFAULT]
debug: True

[CAhandler]
handler_module: acme2certifier.cahandlers.openssl_ca_handler
issuing_ca_key: acme_srv/ca/sub-ca-key.pem
issuing_ca_key_passphrase: Test1234
issuing_ca_cert: acme_srv/ca/sub-ca-cert.pem
issuing_ca_crl: acme_srv/ca/sub-ca-crl.pem
ca_cert_chain_list: ["acme_srv/ca/root-ca-cert.pem"]
cert_validity_days: 30
cert_save_path: acme_srv/ca/certs

[DBhandler]
handler: django

[Challenge]
# local-only: skip HTTP-01 / DNS-01 (do not use in production)
challenge_validation_disable: True
```

- CA options: [OpenSSL handler](openssl.md), [acme_srv.cfg](acme_srv.md).
- `test/ca/` is the same lab CA used in CI (`Test1234`). Replace it with your own CA when needed.
- `handler: django` selects `acme2certifier.dbhandlers.django_handler`. No `db_handler.py` symlink.
- Leave `challenge_validation_disable` at `False` if you want real HTTP-01 (then bind port 80, below).

## 4. Django database and runserver

```bash
a2c-manage migrate
a2c-manage loaddata status
a2c-manage runserver 0.0.0.0:80
```

Equivalent: `python3 -m acme2certifier.tools.a2c_manage …`. One-shot migrate + status seed: `a2c-django-update`.

SQLite file: `$ACME2CERTIFIER_BASE_DIR/db.sqlite3` (gitignored).

```bash
curl -sS http://127.0.0.1/directory
```

Port **80** needs privileges (`sudo -E a2c-manage runserver 0.0.0.0:80`). Use it for HTTP-01 from ACME clients; with `challenge_validation_disable: True`, 8000 is enough.

Client examples: [acme-clients](acme-clients.md). Point `--server` at `http://127.0.0.1:8000/directory`.

## 5. HTTPS with `runserver_plus`

Django’s `runserver` has no TLS. Use `[runserver_plus](https://django-extensions.readthedocs.io/en/latest/runserver_plus.html)` from `django-extensions` (Werkzeug and pyOpenSSL are already package dependencies).

```bash
pip install django-extensions
```

### `local_settings.py`

Do not edit packaged `acme2certifier/django_project/settings.py`. Copy it to a gitignored file at the repo root and enable `django_extensions`:

```bash
cp acme2certifier/django_project/settings.py local_settings.py
```

In `local_settings.py`, add `"django_extensions"` to `INSTALLED_APPS` and set `DEBUG = True`:

```python
DEBUG = True

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "acme2certifier.django_app.apps.AcmeSrvConfig",
    "django_extensions",
]
```

Leave the rest of the copied file unchanged. `a2c-manage` does not put the checkout on `sys.path`, so point Django at the copy:

```bash
export PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}"
export DJANGO_SETTINGS_MODULE=local_settings
```

### Server certificate

Issue a TLS server cert from the lab sub-CA in `test/ca/` (key passphrase `Test1234`). `acme_srv/ssl/` is gitignored.

```bash
mkdir -p acme_srv/ssl

openssl genrsa -out acme_srv/ssl/cert.key 2048

openssl req -new -key acme_srv/ssl/cert.key -out acme_srv/ssl/cert.csr \
  -subj "/CN=localhost"

cat > acme_srv/ssl/cert.ext << 'EOF'
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1
EOF

openssl x509 -req -in acme_srv/ssl/cert.csr \
  -CA test/ca/sub-ca-cert.pem \
  -CAkey test/ca/sub-ca-key.pem \
  -passin pass:Test1234 \
  -CAserial acme_srv/ssl/cert.srl -CAcreateserial \
  -out acme_srv/ssl/cert.crt \
  -days 365 -sha256 \
  -extfile acme_srv/ssl/cert.ext
```

Add further `DNS:` / `IP:` names to `subjectAltName` if you connect by hostname. Trust the issuing CA (`test/ca/sub-ca-cert.pem`) or the root (`test/ca/root-ca-cert.pem`) in the client; the leaf alone is not a trust anchor.

### Start TLS

```bash
a2c-manage runserver_plus 0.0.0.0:443 \
  --cert-file acme_srv/ssl/cert.crt \
  --key-file acme_srv/ssl/cert.key
```

Port **443** needs privileges (`sudo -E` so the env vars survive).

```bash
curl --cacert test/ca/sub-ca-cert.pem -sS https://127.0.0.1:8443/directory
```

ACME clients: `--server https://127.0.0.1:8443/directory` and trust the lab CA (or use their insecure/debug flags). See [acme-clients](acme-clients.md).

## 6. WSGI / SQLite instead of Django

Skip Django if you only need the WSGI stack:

```ini
[DBhandler]
handler: wsgi
dbfile: acme_srv.db
```

The WSGI handler creates the SQLite schema on first use. Bind address is hardcoded to `0.0.0.0:80`:

```bash
python3 acme2certifier/share/acme2certifier_wsgi.py
```

For a production-like WSGI/Django install (Apache/Nginx + venv), use the pip guides rather than `runserver`.

## 7. Tests

From the repo root, with the venv active:

```bash
pytest
```

`pyproject.toml` collects `test/` only. Coverage is enabled by default (`--cov=acme2certifier`).

### CSR-to-order binding

Unit coverage: `pytest test/test_hardening.py::TestCsrBinding`.

Live container coverage is the composite action `.github/actions/wf_specific/error_tests/csr_binding_checks`, invoked from [quality-error.yml](../.github/workflows/quality-error.yml):

- Strict (default): missing order identifier → `badCSR`; extra CSR SAN → `badCSR`
- `csr_binding_strict: False`: subset CSR still enrolls
- Email SAN smuggling is covered by unit tests (needs `email_identifier_support` plus mailbox config)

## Related

- [Package layout](architecture/package-layout.md)
- [acme_srv.cfg](acme_srv.md)
- [Upgrading](upgrading.md)
- [OpenSSL CA handler](openssl.md)
- [External databases](external_database_support.md) (MySQL template: `examples/django/settings.py`)
- [Contributing](CONTRIBUTING.md)
