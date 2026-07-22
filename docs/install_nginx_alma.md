<!-- markdownlint-disable MD013 MD014 MD029 -->

<!-- wiki-title: Installation on NGINX Running on Alma Linux 9 -->

# Installation on NGINX Running on Alma Linux 9

Install `acme2certifier` from PyPI into a virtualenv under **`/opt/acme2certifier`** and serve it with Nginx + uWSGI. The same flow applies to RHEL 9 / Rocky / CentOS Stream with EPEL.

> **Not supported on EL8:** AlmaLinux / RHEL / Rocky 8 ship Python 3.6 as `python3`. The PyPI package requires **Python ≥ 3.7** (and a modern `setuptools` build). Use **EL9** for this install path, or the [RPM packages](install_rpm.md) where EL8 is still covered separately.

uWSGI serves the application; Nginx is the reverse proxy.

**Other install guides:** [Apache2 on Ubuntu](install_apache2_ubuntu.md) · [Nginx on Ubuntu](install_nginx_ubuntu.md)

## Automated install script

[`examples/install_scripts/a2c-rel-nginx.sh`](../examples/install_scripts/a2c-rel-nginx.sh)

```bash
chmod a+rx examples/install_scripts/a2c-rel-nginx.sh
./examples/install_scripts/a2c-rel-nginx.sh --mode wsgi --from-source
./examples/install_scripts/a2c-rel-nginx.sh --mode wsgi
./examples/install_scripts/a2c-rel-nginx.sh --mode django --version 0.45.dev1
```

| Option | Meaning |
| --- | --- |
| `--mode wsgi\|django` | DB backend + matching uWSGI `module` (default: `wsgi`) |
| `--version VERSION` | `pip` pin |
| `--pre` | allow pre-releases |
| `--from-source` | `pip install .` from the current checkout (into the venv) |

App root is always `/opt/acme2certifier`. The remainder of this guide is the manual equivalent of that script.

## 1. Install system packages

```bash
sudo dnf install -y epel-release   # or: yum install -y epel-release
sudo dnf install -y \
  nginx uwsgi uwsgi-plugin-python3 \
  python3 python3-pip python3-devel gcc tar curl openssl \
  policycoreutils-python-utils checkpolicy \
  krb5-workstation krb5-libs krb5-devel procps-ng
```

## 2. Create app root and venv

```bash
sudo mkdir -p /opt/acme2certifier/volume /run/uwsgi
sudo python3 -m venv /opt/acme2certifier/venv
sudo /opt/acme2certifier/venv/bin/pip install -U pip
```

## 3. Install acme2certifier

```bash
sudo /opt/acme2certifier/venv/bin/pip install acme2certifier
# Django: sudo ... pip install 'acme2certifier[django]'
# pre-release: sudo ... pip install 'acme2certifier==0.45.dev1'
```

## 4. Deploy config and WSGI entry

```bash
SHARE=$(/opt/acme2certifier/venv/bin/python -c \
  "import acme2certifier.share as s, pathlib; print(pathlib.Path(s.__file__).parent)")
A2C=$(/opt/acme2certifier/venv/bin/python -c \
  "import acme2certifier, pathlib; print(pathlib.Path(acme2certifier.__file__).parent)")

sudo cp "$SHARE/acme_srv.cfg" /opt/acme2certifier/acme_srv.cfg
sudo mkdir -p /opt/acme2certifier/acme_srv
sudo ln -sfn /opt/acme2certifier/acme_srv.cfg /opt/acme2certifier/acme_srv/acme_srv.cfg
```

Edit `/opt/acme2certifier/acme_srv.cfg`:

```ini
[DBhandler]
handler: wsgi
# handler: django
dbfile: /opt/acme2certifier/acme_srv.db

[CAhandler]
handler_module: acme2certifier.cahandlers.openssl_ca_handler
# plus CA-specific options — see acme_srv.md
```

**WSGI mode:**

```bash
sudo cp "$SHARE/acme2certifier_wsgi.py" /opt/acme2certifier/
# uWSGI module = acme2certifier_wsgi:application
```

**Django mode:**

```bash
sudo ln -sfn "$A2C" /opt/acme2certifier/acme2certifier
# uWSGI module = acme2certifier.django_project.wsgi:application
export ACME_SRV_CONFIGFILE=/opt/acme2certifier/acme_srv.cfg
export ACME2CERTIFIER_BASE_DIR=/opt/acme2certifier
sudo -E /opt/acme2certifier/venv/bin/a2c-manage migrate
sudo -E /opt/acme2certifier/venv/bin/a2c-manage loaddata status
```

## 5. uWSGI ini

Create `/opt/acme2certifier/acme2certifier.ini` (socket under `/run/uwsgi`, user `nginx`):

```ini
[uwsgi]
plugins = python3
virtualenv = /opt/acme2certifier/venv
chdir = /opt/acme2certifier
module = acme2certifier_wsgi:application
# django: module = acme2certifier.django_project.wsgi:application
master = true
processes = 5
uid = nginx
gid = nginx
socket = /run/uwsgi/acme.sock
chown-socket = nginx
chmod-socket = 660
vacuum = true
die-on-term = true
disable-logging = true
enable-threads = true
env = ACME_SRV_CONFIGFILE=/opt/acme2certifier/acme_srv.cfg
env = ACME2CERTIFIER_BASE_DIR=/opt/acme2certifier
```

## 6. Nginx configs (`/etc/nginx/conf.d/`)

```bash
sudo cp "$SHARE/nginx/nginx_acme_srv.conf" /etc/nginx/conf.d/nginx_acme_srv.conf
sudo cp "$SHARE/nginx/nginx_acme_srv_ssl.conf" /etc/nginx/conf.d/nginx_acme_srv_ssl.conf
# rewrite TLS paths from the Ubuntu-oriented defaults to /opt
sudo sed -i 's|/var/www/acme2certifier|/opt/acme2certifier|g' \
  /etc/nginx/conf.d/nginx_acme_srv.conf \
  /etc/nginx/conf.d/nginx_acme_srv_ssl.conf
sudo rm -f /etc/nginx/conf.d/default.conf
```

TLS files:

- `/opt/acme2certifier/volume/acme2certifier_cert.pem`
- `/opt/acme2certifier/volume/acme2certifier_key.pem`

## 7. systemd unit for uWSGI

```bash
sudo tee /etc/systemd/system/acme2certifier.service >/dev/null <<'EOF'
[Unit]
Description=uWSGI instance to serve acme2certifier
After=network.target

[Service]
RuntimeDirectory=uwsgi
User=nginx
Group=nginx
WorkingDirectory=/opt/acme2certifier
Environment=PATH=/opt/acme2certifier/venv/bin:/usr/bin
Environment=ACME_SRV_CONFIGFILE=/opt/acme2certifier/acme_srv.cfg
Environment=ACME2CERTIFIER_BASE_DIR=/opt/acme2certifier
ExecStart=/usr/sbin/uwsgi --ini /opt/acme2certifier/acme2certifier.ini
Restart=on-failure
Type=notify
NotifyAccess=all

[Install]
WantedBy=multi-user.target
EOF
# if uwsgi is only at /usr/bin/uwsgi, adjust ExecStart accordingly
```

## 8. SELinux (Nginx ↔ uWSGI socket)

```bash
sudo cp "$SHARE/nginx/acme2certifier.te" ./acme2certifier.te
sudo checkmodule -M -m -o acme2certifier.mod acme2certifier.te
sudo semodule_package -o acme2certifier.pp -m acme2certifier.mod
sudo semodule -i acme2certifier.pp
```

## 9. Permissions and start

```bash
sudo chown -R nginx:nginx /opt/acme2certifier
sudo chmod a+x /opt/acme2certifier/acme_srv
sudo nginx -t
sudo systemctl daemon-reload
sudo systemctl enable --now acme2certifier nginx
sudo systemctl restart acme2certifier nginx
curl -sS http://127.0.0.1/directory
```

## Related

- Install script: [`a2c-rel-nginx.sh`](../examples/install_scripts/a2c-rel-nginx.sh)
- [Apache2 + mod_wsgi (Ubuntu / PyPI)](install_apache2_ubuntu.md)
- [Nginx + uWSGI (Ubuntu)](install_nginx_ubuntu.md)
- [Support for External Databases (Django)](external_database_support.md)
- [acme_srv.cfg options](acme_srv.md)
- [Package layout migration](migration_package_layout.md)
- Example CA: [Insta Certifier](certifier.md)
