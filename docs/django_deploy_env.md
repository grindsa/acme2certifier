<!-- markdownlint-disable MD013 MD014 MD029 -->

<!-- wiki-title: Django deployment environment variables -->
<!-- wiki-category: Installation -->

# Django deployment environment variables

When `[DBhandler] handler: django`, Django uses `acme2certifier.django_project.settings`, which reads **`ACME2CERTIFIER_*`** environment variables at worker startup.

## Variables

| Variable | Required | Notes |
| --- | --- | --- |
| `ACME2CERTIFIER_SECRET_KEY` | yes (production) | Install scripts generate one via `a2c-django-secret-keygen` when unset and persist it. |
| `ACME2CERTIFIER_ALLOWED_HOSTS` | recommended | Comma-separated hostnames/IPs Django accepts in the `Host` header. Default without override: `127.0.0.1,localhost`. When `[DEFAULT] server_name` is set in `acme_srv.cfg`, that hostname is merged into `ALLOWED_HOSTS` at worker startup (see below). |
| `ACME2CERTIFIER_BASE_DIR` | no | Application root (default `/var/www/acme2certifier` or `/opt/acme2certifier`). |
| `ACME2CERTIFIER_DEBUG` | no | Set to `1` for local development only. |

MySQL / external DB templates: [`examples/django/settings.py`](../examples/django/settings.py).

### `server_name` from `acme_srv.cfg`

When `[DEFAULT] server_name` is configured in `acme_srv.cfg` (or YAML equivalent), Django merges that hostname into `ALLOWED_HOSTS` at worker startup. This uses the same config file resolution as the ACME stack (`ACME_SRV_CONFIGFILE` or default search paths). Use `ACME2CERTIFIER_ALLOWED_HOSTS` for additional hosts such as `127.0.0.1` for local health checks; both sources are combined without duplicates.

## Set at install time (recommended)

Export hostnames **before** running an install script. The script writes them into the web-server config and restarts services:

```bash
export ACME2CERTIFIER_ALLOWED_HOSTS="acme.example.com,127.0.0.1"
./examples/install_scripts/a2c-ubuntu-apache2.sh --mode django
# or: a2c-ubuntu-nginx.sh, a2c-rel-nginx.sh, a2c-deb.sh, a2c-rpm.sh
```

`ACME2CERTIFIER_SECRET_KEY` is generated automatically when not already set.

## Where values are persisted (by web server)

| Web server | File | Format | Restart after edit |
| --- | --- | --- | --- |
| **Apache2** (mod_wsgi) | `/etc/apache2/envvars` | `export ACME2CERTIFIER_ALLOWED_HOSTS=…` | `sudo systemctl restart apache2` |
| **Nginx** (uWSGI) | `${APP_ROOT}/acme2certifier.ini` | `env = ACME2CERTIFIER_ALLOWED_HOSTS="…"` | `sudo systemctl restart acme2certifier` |

`${APP_ROOT}` is `/var/www/acme2certifier` (Debian/Ubuntu pip/DEB) or `/opt/acme2certifier` (Alma/RHEL pip/RPM).

Install scripts that persist Django env vars when set at install time:

| Script | Apache2 → envvars | Nginx → uWSGI ini |
| --- | --- | --- |
| [`a2c-ubuntu-apache2.sh`](../examples/install_scripts/a2c-ubuntu-apache2.sh) | yes | — |
| [`a2c-ubuntu-nginx.sh`](../examples/install_scripts/a2c-ubuntu-nginx.sh) | — | yes |
| [`a2c-rel-nginx.sh`](../examples/install_scripts/a2c-rel-nginx.sh) | — | yes |
| [`a2c-deb.sh`](../examples/install_scripts/a2c-deb.sh) | yes (`--webserver apache2`) | yes (`--webserver nginx`) |
| [`a2c-rpm.sh`](../examples/install_scripts/a2c-rpm.sh) | — | yes |

## Post-install / manual changes

Do **not** rely on editing `settings.py` in the venv for production hostnames — change the persisted file for your web server and restart.

### Apache2

Append or update lines in `/etc/apache2/envvars` (Ubuntu’s mod_wsgi does not support `WSGIDaemonProcess environ=`):

```bash
export ACME2CERTIFIER_SECRET_KEY='…'
export ACME2CERTIFIER_ALLOWED_HOSTS=acme.example.com,127.0.0.1
sudo systemctl restart apache2
```

### Nginx + uWSGI

Add or update `env =` lines in `${APP_ROOT}/acme2certifier.ini`:

```ini
env = ACME2CERTIFIER_SECRET_KEY="…"
env = ACME2CERTIFIER_ALLOWED_HOSTS="acme.example.com,127.0.0.1"
```

Then:

```bash
sudo systemctl restart acme2certifier
```

## CLI and migration tools

- **`a2c-manage`** (one-off shell): export `ACME2CERTIFIER_SECRET_KEY` and `ACME2CERTIFIER_ALLOWED_HOSTS` in the same shell, or use **`a2c-django-update`** instead of separate migrate + loaddata.
- **`a2c-wsgi2django`** `import` / `check` and **`a2c-django-update`**: load `ACME2CERTIFIER_*` from uWSGI ini or Apache envvars when unset in the environment.

## Related

- [Migrate WSGI to Django](migrate_wsgi_to_django.md)
- [PyPI + Apache2 (Ubuntu)](install_apache2_ubuntu.md)
- [PyPI + Nginx (Ubuntu)](install_nginx_ubuntu.md)
- [PyPI + Nginx (Alma / RHEL)](install_nginx_alma.md)
- [DEB package](install_deb.md)
- [RPM package](install_rpm.md)
- [Support for External Databases](external_database_support.md)
