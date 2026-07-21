



# Installation from PyPI on Apache2 (Ubuntu)

Install `acme2certifier` from PyPI into a virtualenv and serve it with Apache2 + `mod_wsgi`.

Tested on Ubuntu 24.04. Adapt package names as needed for other releases.

> **Devel / pre-release builds:** packages published as `X.Y.devN` are **not** installed by a plain `pip install acme2certifier`. Use an exact version or `--pre` (see step 3).

## 1. Install system packages

```bash
sudo apt-get update
sudo apt-get install -y \
  apache2 libapache2-mod-wsgi-py3 apache2-data \
  python3-venv python3-pip curl \
  krb5-user libgssapi-krb5-2 libkrb5-3 python3-gssapi
```

Confirm `mod_wsgi` is loaded:

```bash
sudo apache2ctl -M | grep -i wsgi
# wsgi_module (shared)
```



## 2. Create the application directory and venv

```bash
sudo mkdir -p /var/www/acme2certifier
sudo python3 -m venv /var/www/acme2certifier/venv
sudo /var/www/acme2certifier/venv/bin/pip install -U pip
```



## 3. Install acme2certifier from PyPI

Stable release (when published):

```bash
sudo /var/www/acme2certifier/venv/bin/pip install acme2certifier
```

Optional extras:

```bash
sudo /var/www/acme2certifier/venv/bin/pip install 'acme2certifier[django]'
# or: 'acme2certifier[gssapi]' / 'acme2certifier[full]'
```

Devel / pre-release (example):

```bash
sudo /var/www/acme2certifier/venv/bin/pip install 'acme2certifier==0.45.dev0'
# or: sudo /var/www/acme2certifier/venv/bin/pip install --pre acme2certifier
```



## 4. Deploy share files (WSGI entry + example config)

```bash
SHARE=$(/var/www/acme2certifier/venv/bin/python -c \
  "import acme2certifier.share as s, pathlib; print(pathlib.Path(s.__file__).parent)")

sudo cp "$SHARE/acme2certifier_wsgi.py" /var/www/acme2certifier/
sudo cp "$SHARE/acme_srv.cfg" /var/www/acme2certifier/acme_srv.cfg
sudo cp "$SHARE/apache2/apache_wsgi.conf" /etc/apache2/sites-available/acme2certifier.conf
```

After package upgrades, re-copy `$SHARE/acme2certifier_wsgi.py` if the entrypoint changed.

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
dbfile: /var/www/acme2certifier/acme_srv.db
```

- CA handlers: see [acme_srv.cfg](acme_srv.md) and [Package layout migration](migration_package_layout.md).
- DB handler: default is `wsgi` (SQLite). For MariaDB/PostgreSQL/SQL Server or concurrent writes, use `handler: django` — see [Django / external databases](#django--external-databases) below.



## 6. Point Apache at the venv and config

The packaged vhost must use the venv (`python-home`) and must **not** rely on unsupported `WSGIDaemonProcess environ=` on Ubuntu’s `mod_wsgi`.

`/etc/apache2/sites-available/acme2certifier.conf`:

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

Set the config path in `/etc/apache2/envvars` (read at process start via `os.environ`):

```bash
echo 'export ACME_SRV_CONFIGFILE=/var/www/acme2certifier/acme_srv.cfg' | sudo tee -a /etc/apache2/envvars
```



## 7. Enable TLS (optional)

Enable the Apache SSL module if it is not already loaded:

```bash
sudo a2enmod ssl
```

Validate that `ssl_module` is active:

```bash
sudo apache2ctl -M | grep -i ssl
# ssl_module (shared)
```

If the module does not appear, enable it with `sudo a2enmod ssl` and restart Apache (`sudo systemctl restart apache2`), then check again.

Deploy and adjust the SSL vhost:

```bash
SHARE=$(/var/www/acme2certifier/venv/bin/python -c \
  "import acme2certifier.share as s, pathlib; print(pathlib.Path(s.__file__).parent)")

sudo cp "$SHARE/apache2/apache_wsgi_ssl.conf" /etc/apache2/sites-available/acme2certifier_ssl.conf
```

`/etc/apache2/sites-available/acme2certifier_ssl.conf` must use the same venv settings as the HTTP vhost:

```apache
<IfModule mod_ssl.c>
<VirtualHost *:443>
        DocumentRoot /var/www/acme2certifier/
        WSGIDaemonProcess acme_srv_ssl \
          python-home=/var/www/acme2certifier/venv \
          python-path=/var/www/acme2certifier
        WSGIProcessGroup acme_srv_ssl
        WSGIApplicationGroup %{GLOBAL}
        WSGIScriptAlias / /var/www/acme2certifier/acme2certifier_wsgi.py
        <Directory /var/www/acme2certifier>
        Require all granted
        </Directory>
        SSLEngine on
        SSLCertificateFile /var/www/acme2certifier/volume/acme2certifier.pem
</VirtualHost>
</IfModule>
```

Point `SSLCertificateFile` at your PEM bundle (private key + leaf certificate + intermediates, leaf to root, excluding the root CA).

## 8. Permissions

```bash
sudo chown -R www-data:www-data /var/www/acme2certifier
```

Keep the venv readable/executable by `www-data`; do not expose `/venv` via Apache aliases.

## 9. Enable the site and restart Apache

```bash
sudo a2dissite 000-default.conf || true
sudo a2ensite acme2certifier.conf
# sudo a2ensite acme2certifier_ssl.conf   # if TLS was configured
sudo apache2ctl configtest
sudo systemctl restart apache2
```

On startup, the error log should include a line like:

```text
Using DB handler 'wsgi' (acme2certifier.dbhandlers.wsgi_handler) selected via cfg ...
```

```bash
sudo tail -n 50 /var/log/apache2/error.log
```



## 10. Verify

```bash
curl http://127.0.0.1/directory
```

Expected JSON includes `newAccount`, `newNonce`, `newOrder`, etc.

## 11. Enroll a certificate

Use your preferred ACME client against this directory URL. If enrollment fails, check the CA handler section in `acme_srv.cfg`, Apache/error logs, and [debug mode](acme_srv.md).

## Django / external databases

The steps above use the default **WSGI + SQLite** backend. For an external database (MariaDB, PostgreSQL, …), install the Django extra and switch the DB handler:

```bash
sudo /var/www/acme2certifier/venv/bin/pip install 'acme2certifier[django]'
# plus DB driver, e.g. mysqlclient / psycopg2 — see external DB guide
```

```ini
[DBhandler]
handler: django
```

Then:

1. Configure `acme2certifier.django_project.settings` (DB credentials, `SECRET_KEY`, `ALLOWED_HOSTS`). Start from `examples/django/settings.py` for MySQL if useful.
2. Point Apache at the Django WSGI entry instead of `acme2certifier_wsgi.py`. Use the packaged vhost as a starting point:

```bash
SHARE=$(/var/www/acme2certifier/venv/bin/python -c \
  "import acme2certifier.share as s, pathlib; print(pathlib.Path(s.__file__).parent)")
sudo cp "$SHARE/apache2/apache_django.conf" /etc/apache2/sites-available/acme2certifier.conf
```

Ensure `python-home=/var/www/acme2certifier/venv` (and `ACME_SRV_CONFIGFILE` in `envvars`) match the WSGI setup above. The alias targets `.../acme2certifier/django_project/wsgi.py` when the package lives under DocumentRoot; for a pure venv install, point `WSGIScriptAlias` at the `django_project/wsgi.py` inside the venv’s `site-packages`.

3. Apply schema and fixtures:

```bash
sudo -u www-data env ACME_SRV_CONFIGFILE=/var/www/acme2certifier/acme_srv.cfg \
  /var/www/acme2certifier/venv/bin/a2c-manage migrate
sudo -u www-data env ACME_SRV_CONFIGFILE=/var/www/acme2certifier/acme_srv.cfg \
  /var/www/acme2certifier/venv/bin/a2c-manage loaddata status
```

Full MariaDB/PostgreSQL/SQL Server setup, Docker notes, and sample `DATABASES` blocks: [Support for External Databases](external_database_support.md).

## Upgrading

```bash
sudo /var/www/acme2certifier/venv/bin/pip install -U acme2certifier
# or pin: ... install 'acme2certifier==0.45.dev1'

SHARE=$(/var/www/acme2certifier/venv/bin/python -c \
  "import acme2certifier.share as s, pathlib; print(pathlib.Path(s.__file__).parent)")
sudo cp "$SHARE/acme2certifier_wsgi.py" /var/www/acme2certifier/
sudo systemctl restart apache2
```



## Related

- [acme_srv.cfg options](acme_srv.md)
- [Package layout migration](migration_package_layout.md)
- [Support for External Databases (Django)](external_database_support.md)
- [DEB installation](install_deb.md) (apt package alternative)
- [Nginx + uWSGI (Ubuntu)](install_nginx_wsgi_ub24.md)

