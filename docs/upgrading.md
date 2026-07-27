<!-- markdownlint-disable MD013 MD029 -->

<!-- wiki-title Upgrading acme2certifier -->

# Upgrading acme2certifier

Step-by-step upgrade from **acme2certifier v0.44** to the package-first layout (`acme2certifier.*`).

Target architecture: [Package layout](architecture/package-layout.md).
Install guides: [pip/Apache](install_apache2_ubuntu.md) · [pip/Nginx Ubuntu](install_nginx_ubuntu.md) · [pip/Nginx Alma](install_nginx_alma.md) · [DEB](install_deb.md) · [RPM](install_rpm.md) · [Docker](install_docker.md).

## What changed

| Area | v0.44 | Now |
| --- | --- | --- |
| ACME core | top-level `acme_srv/` | `acme2certifier.acme_srv` |
| CA / EAB / hooks | `examples/{ca_handler,eab_handler,hooks}/` | `acme2certifier.{cahandlers,eabhandlers,hookhandlers}` |
| Django app | `examples/django/acme_srv/` | `acme2certifier.django_app` |
| Tools | `python tools/<name>.py` | `python3 -m acme2certifier.tools.<name>` |
| Plugin config | `*_file` paths | `*_module` (preferred); `*_file` until **1.0** |

There are no compatibility shims between old and new structure. You need to switch config and Django settings before or **immediately** after upgrade.

## Config (all install types)

Edit `acme_srv.cfg`:

```ini
[CAhandler]
handler_module: acme2certifier.cahandlers.openssl_ca_handler
# remove: handler_file: ...

[EABhandler]
eab_handler_module: acme2certifier.eabhandlers.file_handler
# remove: eab_handler_file: ...

[Hooks]
hooks_module: acme2certifier.hookhandlers.email_hooks
# remove: hooks_file: ...

[DBhandler]
handler: wsgi   # or django
```

Built-in module names: [mapping below](#module-mapping). Custom handlers: keep `handler_file: /path/to/handler.py` until **1.0**, or package as a module and set `handler_module` (see [How to create your own CA handler](ca_handler.md#packaging-a-custom-handler-as-a-module) — howto TBD).

### Custom handler imports

Update helper imports inside custom handler files:

```python
# old
from acme_srv.helper import ...
# new
from acme2certifier.acme_srv.helper import ...
```

## Django settings (Django installs only)

App label stays `acme_srv` (tables unchanged). `INSTALLED_APPS` must use the new AppConfig path; the label is set in `AcmeSrvConfig.label`, not by the import string.

```python
INSTALLED_APPS = [
    ...
    "acme2certifier.django_app.apps.AcmeSrvConfig",
]

ROOT_URLCONF = "acme2certifier.django_project.urls"
WSGI_APPLICATION = "acme2certifier.django_project.wsgi.application"
```

Then migrate / load fixtures as shown per channel below.

---

## Docker (WSGI)

1. Backup the volume (`data/` or your compose mount → `/var/www/acme2certifier/volume`).
2. Pull the matching image tag (`*-wsgi`, apache2 or nginx). Keep the same webserver variant.
3. On the volume, edit `acme_srv.cfg` → set `handler_module` / `eab_handler_module` / `hooks_module` as above. Set `[DBhandler] handler: wsgi` (or omit; image default is wsgi).
4. If you use `volume/ca_handler.py` as custom code: fix imports (`acme2certifier.acme_srv.helper`) and either keep the file (entrypoint may symlink it) or switch to `handler_module`.
5. Pull the new image and replace the running container (volume mount stays; no `docker compose down` needed — avoid `down -v`, which can delete data):

```bash
docker compose pull
docker compose up -d --force-recreate
curl -sS http://127.0.0.1:<host-port>/directory
```

6. Check container logs for `*_file` deprecation warnings; clear them before 1.0.

## Docker (Django)

Same as WSGI, but:

1. Use a `*-django` image tag (do not switch WSGI↔Django via cfg alone). Keep the volume, including `migrations/` (entrypoint symlinks the package migrations dir to the volume).
2. Edit `volume/settings.py`:

```python
INSTALLED_APPS = [
    ...
    "acme2certifier.django_app.apps.AcmeSrvConfig",
]
ROOT_URLCONF = "acme2certifier.django_project.urls"
WSGI_APPLICATION = "acme2certifier.django_project.wsgi.application"
```

3. Set `[DBhandler] handler: django` in `volume/acme_srv.cfg`.
4. After start, ensure migrations ran (entrypoint usually does this). If needed:

```bash
docker compose exec <service> a2c-manage migrate
docker compose exec <service> a2c-manage loaddata status
```

5. Verify: `curl -sS http://127.0.0.1:<host-port>/directory`

---

## DEB (WSGI)

Paths: `/var/www/acme2certifier`, config `/var/www/acme2certifier/acme_srv.cfg`.

1. Backup cfg, DB (`acme_srv.db`), and any custom handlers.
2. Install the new package:

```bash
sudo apt-get install -y ./acme2certifier_<version>-1_all.deb
# or: sudo ./examples/install_scripts/a2c-deb.sh --deb ./acme2certifier_<version>-1_all.deb --mode wsgi
```

3. Edit `/var/www/acme2certifier/acme_srv.cfg` → `*_module` keys; `[DBhandler] handler: wsgi`.
4. Refresh webserver config from share if needed (Apache example):

```bash
sudo cp /var/www/acme2certifier/share/apache2/apache_wsgi.conf \
  /etc/apache2/sites-available/acme2certifier.conf
sudo systemctl restart apache2
```

Nginx/uWSGI: re-copy `share/nginx/*` and `acme2certifier.ini` if entrypoints changed; `module` stays the WSGI script.

5. Verify:

```bash
curl -sS http://127.0.0.1/directory
```

## DEB (Django)

1. Backup cfg, DB (includes `django_migrations` history), and `settings.py` (if customized). Migration *files* ship in the package — no separate migrations directory to preserve (unlike Docker).
2. Install with Django mode:

```bash
sudo ./examples/install_scripts/a2c-deb.sh \
  --deb ./acme2certifier_<version>-1_all.deb \
  --mode django \
  --webserver apache2   # or nginx
```

Or manual: install `.deb`, deploy `share/apache2/apache_django.conf` (or nginx + uWSGI with `module = acme2certifier.django_project.wsgi:application`).

3. Update Django settings (`INSTALLED_APPS` / `ROOT_URLCONF` / `WSGI_APPLICATION` as above). Packaged default settings already use the new paths; customize only if you keep an old settings file.
4. Set `[DBhandler] handler: django` in `acme_srv.cfg`; set `*_module` for CA/EAB/hooks.
5. Apply schema:

```bash
export ACME_SRV_CONFIGFILE=/var/www/acme2certifier/acme_srv.cfg
sudo -E a2c-manage migrate
sudo -E a2c-manage loaddata status
```

6. Restart apache2 or `acme2certifier` (uWSGI) + nginx; verify `/directory`.

---

## RPM (WSGI)

Paths: `/opt/acme2certifier`, config `/opt/acme2certifier/acme_srv.cfg` (`%config(noreplace)`).

1. Backup cfg, DB, custom handlers.
2. Install:

```bash
sudo yum -y localinstall ./acme2certifier-<version>-1.0.noarch.rpm
# or: sudo ./examples/install_scripts/a2c-rpm.sh --rpm ./acme2certifier-*.rpm --mode wsgi
```

3. Edit `/opt/acme2certifier/acme_srv.cfg` → `*_module`; `[DBhandler] handler: wsgi`.
4. Refresh nginx/uWSGI from share if needed:

```bash
sudo cp /opt/acme2certifier/share/nginx/nginx_acme_srv.conf /etc/nginx/conf.d/
sudo systemctl restart nginx acme2certifier
```

5. Verify: `curl -sS http://127.0.0.1/directory`

## RPM (Django)

1. Backup as above (DB includes `django_migrations` history; migration files ship in the RPM).
2. Install with Django mode:

```bash
sudo ./examples/install_scripts/a2c-rpm.sh \
  --rpm ./acme2certifier-<version>-1.0.noarch.rpm \
  --mode django
```

3. Ensure uWSGI uses `module = acme2certifier.django_project.wsgi:application`.
4. Update settings if you ship a custom `settings.py` (see Django section).
5. Set `[DBhandler] handler: django` and `*_module` in `/opt/acme2certifier/acme_srv.cfg`.
6. Migrate:

```bash
export ACME_SRV_CONFIGFILE=/opt/acme2certifier/acme_srv.cfg
export PYTHONPATH=/opt/acme2certifier
sudo -E a2c-manage migrate
sudo -E a2c-manage loaddata status
```

7. `sudo systemctl restart nginx acme2certifier`; verify `/directory`.

---

## pip / venv (WSGI or Django)

Typical root: `/var/www/acme2certifier` + venv.

1. Backup cfg, DB, venv (optional), custom handlers.
2. Upgrade:

```bash
sudo /var/www/acme2certifier/venv/bin/pip install -U 'acme2certifier'
# Django:
sudo /var/www/acme2certifier/venv/bin/pip install -U 'acme2certifier[django]'
```

3. Re-link package and refresh entrypoints from share (see [Apache Ubuntu](install_apache2_ubuntu.md) / [Nginx Ubuntu](install_nginx_ubuntu.md)):

```bash
A2C=$(/var/www/acme2certifier/venv/bin/python -c \
  "import acme2certifier, pathlib; print(pathlib.Path(acme2certifier.__file__).parent)")
sudo ln -sfn "$A2C" /var/www/acme2certifier/acme2certifier
```

4. Edit `acme_srv.cfg` → `*_module`; set `[DBhandler] handler: wsgi` or `django`.
5. **Django:** update settings; then:

```bash
export ACME_SRV_CONFIGFILE=/var/www/acme2certifier/acme_srv.cfg
sudo -E /var/www/acme2certifier/venv/bin/a2c-manage migrate
sudo -E /var/www/acme2certifier/venv/bin/a2c-manage loaddata status
```

6. Restart apache2 or nginx + uWSGI; verify `/directory`.

---

## Module mapping

| Role | Example `*_module` |
| --- | --- |
| OpenSSL CA | `acme2certifier.cahandlers.openssl_ca_handler` |
| Skeleton CA | `acme2certifier.cahandlers.skeleton_ca_handler` |
| ACME proxy CA | `acme2certifier.cahandlers.acme_ca_handler` |
| EAB file | `acme2certifier.eabhandlers.file_handler` |
| EAB JSON | `acme2certifier.eabhandlers.json_handler` |
| EAB SQL | `acme2certifier.eabhandlers.sql_handler` |
| Email hooks | `acme2certifier.hookhandlers.email_hooks` |
| DB WSGI | `acme2certifier.dbhandlers.wsgi_handler` (or `handler: wsgi`) |
| DB Django | `acme2certifier.dbhandlers.django_handler` (or `handler: django`) |

Full CA list and import renames: see git history of this file or `acme2certifier/cahandlers/`. Common core rename: `acme_srv.X` → `acme2certifier.acme_srv.X`.

## Checklist

1. Backup cfg + DB (+ volume / settings).
2. Install new package / image / wheel.
3. Switch `acme_srv.cfg` to `*_module`.
4. Django: update `INSTALLED_APPS` / URLconf / WSGI; run `a2c-manage migrate`.
5. Fix custom handler imports.
6. Restart services; hit `/directory`.
7. Clear deprecation warnings before **1.0** (`*_file` and default `acme_srv.ca_handler` fall away).

## Related

- [Package layout](architecture/package-layout.md)
- [Phase 10 — remove `*_file` fallbacks](architecture/phase10-handler-fallback-removal.md)
