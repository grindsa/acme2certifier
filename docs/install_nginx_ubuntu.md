<!-- markdownlint-disable MD013 MD014 MD029 -->

<!-- wiki-title Installation on Nginx Running on Ubuntu 24.04 -->

# Installation on Nginx Running on Ubuntu 24.04

Install `acme2certifier` from PyPI into a virtualenv under `/var/www/acme2certifier` and serve it with Nginx + uWSGI.

**Other install guides:** [Apache2 on Ubuntu](install_apache2_ubuntu.md) · [Nginx on Alma / RHEL](install_nginx_alma.md)

## Automated install script

[`examples/install_scripts/a2c-ubuntu-nginx.sh`](../examples/install_scripts/a2c-ubuntu-nginx.sh)

```bash
chmod a+rx examples/install_scripts/a2c-ubuntu-nginx.sh
./examples/install_scripts/a2c-ubuntu-nginx.sh --mode wsgi --from-source
./examples/install_scripts/a2c-ubuntu-nginx.sh --mode wsgi
./examples/install_scripts/a2c-ubuntu-nginx.sh --mode django --version 0.45.dev1
```

| Option | Meaning |
| --- | --- |
| `--mode wsgi\|django` | DB backend + matching uWSGI `module` (default: `wsgi`) |
| `--version VERSION` | `pip` pin |
| `--pre` | allow pre-releases |
| `--from-source` | `pip install .` from the current checkout (into the venv) |

The remainder of this guide is the manual equivalent of that script.

## 1. Install system packages

```bash
sudo apt-get update
sudo apt-get install -y \
  nginx uwsgi uwsgi-plugin-python3 \
  python3-venv python3-pip curl openssl \
  krb5-user libgssapi-krb5-2 libkrb5-3 python3-gssapi
```

## 2. Create app root and venv

```bash
sudo mkdir -p /var/www/acme2certifier/volume
sudo python3 -m venv /var/www/acme2certifier/venv
sudo /var/www/acme2certifier/venv/bin/pip install -U pip
```

## 3. Install acme2certifier

```bash
sudo /var/www/acme2certifier/venv/bin/pip install acme2certifier
# Django: sudo ... pip install 'acme2certifier[django]'
# pre-release: sudo ... pip install 'acme2certifier==0.45.dev1'
```

## 4. Deploy config and WSGI entry

```bash
SHARE=$(/var/www/acme2certifier/venv/bin/python -c \
  "import acme2certifier.share as s, pathlib; print(pathlib.Path(s.__file__).parent)")
A2C=$(/var/www/acme2certifier/venv/bin/python -c \
  "import acme2certifier, pathlib; print(pathlib.Path(acme2certifier.__file__).parent)")

sudo cp "$SHARE/acme_srv.cfg" /var/www/acme2certifier/acme_srv.cfg
sudo mkdir -p /var/www/acme2certifier/acme_srv
sudo ln -sfn /var/www/acme2certifier/acme_srv.cfg \
  /var/www/acme2certifier/acme_srv/acme_srv.cfg

# set handler: wsgi  or  handler: django  under [DBhandler]
```

**WSGI mode:**

```bash
sudo cp "$SHARE/acme2certifier_wsgi.py" /var/www/acme2certifier/
# uWSGI module = acme2certifier_wsgi:application
```

**Django mode:**

```bash
sudo ln -sfn "$A2C" /var/www/acme2certifier/acme2certifier
# uWSGI module = acme2certifier.django_project.wsgi:application
sudo /var/www/acme2certifier/venv/bin/a2c-manage migrate
sudo /var/www/acme2certifier/venv/bin/a2c-manage loaddata status
```

Set `handler_module` for your CA in `acme_srv.cfg` (see [acme_srv.cfg](acme_srv.md)).

## 5. uWSGI ini

Create `/var/www/acme2certifier/acme2certifier.ini` (socket under DocumentRoot, user `www-data`, venv via `virtualenv`):

```ini
[uwsgi]
plugins = python3
virtualenv = /var/www/acme2certifier/venv
chdir = /var/www/acme2certifier
module = acme2certifier_wsgi:application
# django: module = acme2certifier.django_project.wsgi:application
master = true
processes = 5
uid = www-data
gid = www-data
socket = /var/www/acme2certifier/acme.sock
chown-socket = www-data
chmod-socket = 660
vacuum = true
die-on-term = true
disable-logging = true
enable-threads = true
env = ACME_SRV_CONFIGFILE=/var/www/acme2certifier/acme_srv.cfg
env = ACME2CERTIFIER_BASE_DIR=/var/www/acme2certifier
```

## 6. Nginx HTTP + SSL sites

Copy packaged configs and point the upstream socket at DocumentRoot:

```bash
sudo cp "$SHARE/nginx/nginx_acme_srv.conf" /etc/nginx/sites-available/acme_srv.conf
sudo cp "$SHARE/nginx/nginx_acme_srv_ssl.conf" /etc/nginx/sites-available/acme_srv_ssl.conf
sudo sed -i 's|/run/uwsgi/acme.sock|/var/www/acme2certifier/acme.sock|g' \
  /etc/nginx/sites-available/acme_srv.conf \
  /etc/nginx/sites-available/acme_srv_ssl.conf

sudo rm -f /etc/nginx/sites-enabled/default
sudo ln -sfn /etc/nginx/sites-available/acme_srv.conf /etc/nginx/sites-enabled/acme_srv.conf
sudo ln -sfn /etc/nginx/sites-available/acme_srv_ssl.conf /etc/nginx/sites-enabled/acme_srv_ssl.conf
```

TLS files expected by the SSL server block:

- `/var/www/acme2certifier/volume/acme2certifier_cert.pem`
- `/var/www/acme2certifier/volume/acme2certifier_key.pem`

## 7. systemd unit for uWSGI

```bash
sudo tee /etc/systemd/system/acme2certifier.service >/dev/null <<'EOF'
[Unit]
Description=uWSGI instance to serve acme2certifier
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/acme2certifier
Environment=PATH=/var/www/acme2certifier/venv/bin:/usr/bin
Environment=ACME_SRV_CONFIGFILE=/var/www/acme2certifier/acme_srv.cfg
Environment=ACME2CERTIFIER_BASE_DIR=/var/www/acme2certifier
ExecStart=/usr/bin/uwsgi --ini /var/www/acme2certifier/acme2certifier.ini
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
```

## 8. Permissions and start

```bash
sudo chown -R www-data:www-data /var/www/acme2certifier
sudo nginx -t
sudo systemctl daemon-reload
sudo systemctl enable --now acme2certifier nginx
sudo systemctl restart acme2certifier nginx
curl -sS http://127.0.0.1/directory
```

## Related

- Install script: [`a2c-ubuntu-nginx.sh`](../examples/install_scripts/a2c-ubuntu-nginx.sh)
- [Apache2 + mod_wsgi (Ubuntu / PyPI)](install_apache2_ubuntu.md)
- [Nginx on Alma / RHEL](install_nginx_alma.md)
- [Support for External Databases (Django)](external_database_support.md)
- [acme_srv.cfg options](acme_srv.md)
- [Upgrading](upgrading.md)
