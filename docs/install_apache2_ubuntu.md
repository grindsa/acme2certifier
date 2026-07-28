<!-- markdownlint-disable MD013 MD014 MD029 -->

<!-- wiki-title Installation from PyPI on Apache2 (Ubuntu) -->

# Installation from PyPI on Apache2 (Ubuntu)

Install `acme2certifier` from PyPI into a virtualenv under `/var/www/acme2certifier` and serve it with Apache2 + `mod_wsgi`.

Tested on Ubuntu 24.04. Adapt package names as needed for other releases.

**Other install guides:** [Nginx on Ubuntu](install_nginx_ubuntu.md) · [Nginx on Alma / RHEL](install_nginx_alma.md)

## Automated install script

A ready-made script mirrors the steps below (WSGI or Django, HTTP + SSL):

[`examples/install_scripts/a2c-ubuntu-apache2.sh`](../examples/install_scripts/a2c-ubuntu-apache2.sh)

```bash
# from a checkout (install into the venv from the local tree):
chmod a+rx examples/install_scripts/a2c-ubuntu-apache2.sh
./examples/install_scripts/a2c-ubuntu-apache2.sh --mode wsgi --from-source

# from PyPI:
./examples/install_scripts/a2c-ubuntu-apache2.sh --mode wsgi
./examples/install_scripts/a2c-ubuntu-apache2.sh --mode django --version 0.45.dev1
./examples/install_scripts/a2c-ubuntu-apache2.sh --mode django --pre
```

| Option | Meaning |
| --- | --- |
| `--mode wsgi\|django` | DB backend + matching Apache vhosts (default: `wsgi`) |
| `--version VERSION` | `pip` pin (e.g. `0.45.dev1`) |
| `--pre` | allow pre-releases |
| `--from-source` | `pip install .` from the current checkout (into the venv) |

> **Devel / pre-release builds:** packages published as `X.Y.devN` are **not** installed by a plain `pip install acme2certifier`. Use an exact version or `--pre`.

The remainder of this guide is the manual equivalent of that script.

## 1. Install system packages

```bash
sudo apt-get update
sudo apt-get install -y \
  apache2 libapache2-mod-wsgi-py3 apache2-data \
  python3-venv python3-pip curl openssl \
  krb5-user libgssapi-krb5-2 libkrb5-3 python3-gssapi
```

Enable and confirm modules:

```bash
sudo a2enmod wsgi
sudo a2enmod ssl
sudo apache2ctl -M | grep -iE 'wsgi|ssl'
```

## 2. Create the application directory and venv

```bash
sudo mkdir -p /var/www/acme2certifier/volume
sudo python3 -m venv /var/www/acme2certifier/venv
sudo /var/www/acme2certifier/venv/bin/pip install -U pip
```

## 3. Install acme2certifier from PyPI

```bash
# WSGI / SQLite (default)
sudo /var/www/acme2certifier/venv/bin/pip install acme2certifier

# Django / external DB
sudo /var/www/acme2certifier/venv/bin/pip install 'acme2certifier[django]'

# pre-release example
sudo /var/www/acme2certifier/venv/bin/pip install 'acme2certifier==0.45.dev1'
# or: sudo /var/www/acme2certifier/venv/bin/pip install --pre acme2certifier
```

## 4. Deploy share files and Apache vhosts

```bash
SHARE=$(/var/www/acme2certifier/venv/bin/python -c \
  "import acme2certifier.share as s, pathlib; print(pathlib.Path(s.__file__).parent)")
A2C=$(/var/www/acme2certifier/venv/bin/python -c \
  "import acme2certifier, pathlib; print(pathlib.Path(acme2certifier.__file__).parent)")

sudo cp "$SHARE/acme_srv.cfg" /var/www/acme2certifier/acme_srv.cfg
sudo mkdir -p /var/www/acme2certifier/acme_srv
sudo ln -sfn /var/www/acme2certifier/acme_srv.cfg \
  /var/www/acme2certifier/acme_srv/acme_srv.cfg
```

**WSGI mode:**

```bash
sudo cp "$SHARE/acme2certifier_wsgi.py" /var/www/acme2certifier/
sudo cp "$SHARE/apache2/apache_wsgi.conf" \
  /etc/apache2/sites-available/acme2certifier.conf
sudo cp "$SHARE/apache2/apache_wsgi_ssl.conf" \
  /etc/apache2/sites-available/acme2certifier_ssl.conf
```

**Django mode:**

```bash
sudo ln -sfn "$A2C" /var/www/acme2certifier/acme2certifier
sudo cp "$SHARE/apache2/apache_django.conf" \
  /etc/apache2/sites-available/acme2certifier.conf
sudo cp "$SHARE/apache2/apache_django_ssl.conf" \
  /etc/apache2/sites-available/acme2certifier_ssl.conf
```

After package upgrades, re-copy `$SHARE/acme2certifier_wsgi.py` (WSGI mode) if the entrypoint changed.

## 5. Configure `acme_srv.cfg`

Edit `/var/www/acme2certifier/acme_srv.cfg`. Minimum useful settings:

```ini
[DEFAULT]
debug: False

[CAhandler]
handler_module: acme2certifier.cahandlers.openssl_ca_handler
# plus CA-specific options for your handler

[DBhandler]
handler: wsgi
# handler: django
dbfile: /var/www/acme2certifier/acme_srv.db
```

- CA handlers: [acme_srv.cfg](acme_srv.md), [Upgrading](upgrading.md).
- Prefer `handler:` in cfg (cfg wins over `ACME_SRV_DB_HANDLER`). Do not put the DB handler in `/etc/apache2/envvars`.

## 6. Point Apache at the venv and config

Packaged vhosts use `python-home=/var/www/acme2certifier/venv`. Ubuntu’s `mod_wsgi` does **not** support `WSGIDaemonProcess environ=`; set the config path in `/etc/apache2/envvars`:

```bash
echo 'export ACME_SRV_CONFIGFILE=/var/www/acme2certifier/acme_srv.cfg' | sudo tee -a /etc/apache2/envvars
echo 'export ACME2CERTIFIER_BASE_DIR=/var/www/acme2certifier' | sudo tee -a /etc/apache2/envvars
```

Example HTTP vhost (WSGI mode; also shipped as `share/apache2/apache_wsgi.conf`):

```apache
<VirtualHost *:80>
        DocumentRoot /var/www/acme2certifier/
        WSGIDaemonProcess acme_srv \
          python-home=/var/www/acme2certifier/venv \
          python-path=/var/www/acme2certifier
        WSGIProcessGroup acme_srv
        WSGIApplicationGroup %{GLOBAL}
        WSGIScriptAlias / /var/www/acme2certifier/acme2certifier_wsgi.py
        <Directory /var/www/acme2certifier>
        Require all granted
        </Directory>
</VirtualHost>
```

## 7. TLS certificate for the SSL vhost

The SSL vhost expects a PEM bundle at `/var/www/acme2certifier/volume/acme2certifier.pem` (key + leaf + intermediates):

```bash
# place your production PEM, or generate a lab self-signed bundle:
sudo openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout /var/www/acme2certifier/volume/acme2certifier-key.pem \
  -out /var/www/acme2certifier/volume/acme2certifier-cert.pem \
  -days 365 -subj "/CN=localhost"
sudo sh -c 'cat /var/www/acme2certifier/volume/acme2certifier-cert.pem \
  /var/www/acme2certifier/volume/acme2certifier-key.pem \
  > /var/www/acme2certifier/volume/acme2certifier.pem'
```

## 8. Django mode extras

If `handler: django`:

1. Configure `acme2certifier.django_project.settings` (or env `ACME2CERTIFIER_SECRET_KEY` / `ACME2CERTIFIER_ALLOWED_HOSTS`). MySQL template: `examples/django/settings.py`.
1. Apply schema and fixtures:

```bash
export ACME_SRV_CONFIGFILE=/var/www/acme2certifier/acme_srv.cfg
export ACME2CERTIFIER_BASE_DIR=/var/www/acme2certifier
export ACME2CERTIFIER_SECRET_KEY="$(/var/www/acme2certifier/venv/bin/a2c-django-secret-keygen)"
sudo -E /var/www/acme2certifier/venv/bin/a2c-manage migrate
sudo -E /var/www/acme2certifier/venv/bin/a2c-manage loaddata status
```

Full MariaDB/PostgreSQL/SQL Server details: [Support for External Databases](external_database_support.md).

## 9. Permissions and enable sites

```bash
sudo chown -R www-data:www-data /var/www/acme2certifier
sudo a2dissite 000-default.conf || true
sudo a2dissite default-ssl.conf || true
sudo a2ensite acme2certifier.conf
sudo a2ensite acme2certifier_ssl.conf
sudo apache2ctl configtest
sudo systemctl restart apache2
```

On startup, the error log should include:

```text
Using DB handler 'wsgi' (acme2certifier.dbhandlers.wsgi_handler) selected via cfg ...
```

```bash
sudo tail -n 50 /var/log/apache2/error.log
curl -sS http://127.0.0.1/directory
```

## Upgrading

```bash
sudo /var/www/acme2certifier/venv/bin/pip install -U acme2certifier
# or pin: ... install 'acme2certifier==0.45.dev2'

SHARE=$(/var/www/acme2certifier/venv/bin/python -c \
  "import acme2certifier.share as s, pathlib; print(pathlib.Path(s.__file__).parent)")
sudo cp "$SHARE/acme2certifier_wsgi.py" /var/www/acme2certifier/   # WSGI mode
sudo systemctl restart apache2
```

## Related

- Install script: [`a2c-ubuntu-apache2.sh`](../examples/install_scripts/a2c-ubuntu-apache2.sh)
- [Nginx + uWSGI (Ubuntu)](install_nginx_ubuntu.md)
- [Nginx + uWSGI (Alma / RHEL)](install_nginx_alma.md)
- [acme_srv.cfg options](acme_srv.md)
- [Upgrading](upgrading.md)
- [Support for External Databases (Django)](external_database_support.md)
- [DEB installation](install_deb.md)
