<!-- markdownlint-disable MD013 MD014 MD029 -->

<!-- wiki-title: DEB Installation on Ubuntu / Debian -->

# DEB Installation on Ubuntu / Debian

The Debian package is webserver-agnostic and supports **WSGI** or **Django** with **Apache2** or **Nginx**.

## Recommended: install script

Use [`examples/install_scripts/a2c-deb.sh`](../examples/install_scripts/a2c-deb.sh) after you have a `.deb` (from a [release](https://github.com/grindsa/acme2certifier/releases) or a local `dpkg-buildpackage`).

```bash
# Apache2 + WSGI (default)
sudo ./examples/install_scripts/a2c-deb.sh --deb ../acme2certifier_<version>-1_all.deb

# Apache2 + Django
sudo ./examples/install_scripts/a2c-deb.sh \
  --deb ../acme2certifier_<version>-1_all.deb \
  --mode django \
  --webserver apache2

# Nginx + uWSGI + Django
sudo ./examples/install_scripts/a2c-deb.sh \
  --deb ../acme2certifier_<version>-1_all.deb \
  --mode django \
  --webserver nginx

# After changing volume/cfg in place (lab/CI): sync and restart
sudo ./examples/install_scripts/a2c-deb.sh restart nginx \
  --volume-dir /path/to/volume
```

| Switch | Values | Default |
| --- | --- | --- |
| `-d` / `--deb` | path to `.deb` | auto: `./` / `../` / data-dir |
| `-m` / `--mode` | `wsgi` | `django` | `wsgi` |
| `-w` / `--webserver` | `apache2` | `nginx` | `apache2` |
| `--restart` / `restart` | — | sync volume/cfg and restart services (no reinstall) |
| `--volume-dir DIR` | path | `/tmp/acme2certifier/volume` when present |
| `--no-ssl` | — | SSL vhosts enabled |
| `--skip-pkcs12` | — | installs `requests-pkcs12` via pip |

The script installs web-server packages, installs the `.deb`, deploys configs from `/var/www/acme2certifier/share/`, sets `[DBhandler] handler:` to the chosen mode, optionally generates a lab TLS cert, runs Django migrations when `--mode django`, and starts the services.

Config file: `/var/www/acme2certifier/acme_srv.cfg`. Then configure your CA handler ([acme_srv.cfg](acme_srv.md), [certifier](certifier.md)).

Smoke test:

```bash
curl -sS http://127.0.0.1/directory
```

For **pip/venv** installs (no `.deb`), use [`a2c-ubuntu-apache2.sh`](../examples/install_scripts/a2c-ubuntu-apache2.sh) or [`a2c-ubuntu-nginx.sh`](../examples/install_scripts/a2c-ubuntu-nginx.sh) instead.

______________________________________________________________________

## Manual installation with Apache2

1. Download the latest [DEB package](https://github.com/grindsa/acme2certifier/releases).
2. Install `acme2certifier` and Apache2 packages:

   ```bash
   sudo apt-get install -y apache2 apache2-data libapache2-mod-wsgi-py3
   sudo apt-get install -y ../acme2certifier_<version>-1_all.deb
   ```

3. Copy and activate the Apache2 configuration (WSGI example):

   ```bash
   sudo cp /var/www/acme2certifier/share/apache2/apache_wsgi.conf /etc/apache2/sites-available/acme2certifier.conf
   sudo a2ensite acme2certifier
   ```

   For Django, use `share/apache2/apache_django.conf` (and the `_ssl` variants as needed). Ensure `/var/www/acme2certifier/acme2certifier` links to the installed package (the package `postinst` creates this symlink).

4. Copy and activate the Apache2 SSL configuration file (optional):

   ```bash
   sudo cp /var/www/acme2certifier/share/apache2/apache_wsgi_ssl.conf /etc/apache2/sites-available/acme2certifier_ssl.conf
   sudo a2ensite acme2certifier_ssl
   ```

5. Create or edit `/var/www/acme2certifier/acme_srv.cfg` (sample is shipped with the package).
6. Modify the [configuration file](acme_srv.md) according to your needs.
7. Configure the CA handler as needed. [Example for Insta Certifier](certifier.md).
8. Enable and start the Apache2 service:

   ```bash
   sudo systemctl enable apache2.service
   sudo systemctl start apache2.service
   ```

9. Test the server by accessing the directory resource:

   ```bash
   curl http://<your-server-name>/directory
   ```

   Expected response:

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

10. Try enrolling a certificate using your favorite ACME client. If something does not work, enable debugging in `/var/www/acme2certifier/acme_srv.cfg` and check `/var/log/apache2/error.log` for errors.

## Manual installation with Nginx

1. Download the latest [DEB package](https://github.com/grindsa/acme2certifier/releases).
2. Install `acme2certifier` and Nginx packages:

   ```bash
   sudo apt-get install -y nginx uwsgi uwsgi-plugin-python3
   sudo apt-get install -y ../acme2certifier_<version>-1_all.deb
   ```

3. Activate the Nginx configuration (uWSGI socket is `/run/uwsgi/acme.sock`):

   ```bash
   sudo cp /var/www/acme2certifier/share/nginx/nginx_acme_srv.conf /etc/nginx/sites-available/acme_srv.conf
   sudo rm /etc/nginx/sites-enabled/default
   sudo ln -s /etc/nginx/sites-available/acme_srv.conf /etc/nginx/sites-enabled/acme_srv.conf
   ```

4. Copy the uWSGI configuration:

   ```bash
   sudo cp /var/www/acme2certifier/share/nginx/acme2certifier.ini /var/www/acme2certifier
   ```

   For Django, set `module = acme2certifier.django_project.wsgi:application` in that ini (the install script does this when `--mode django`).

5. Install the systemd unit shipped with the package (or create one). The unit uses `RuntimeDirectory=uwsgi` so `/run/uwsgi` exists for the socket:

   ```bash
   sudo cp /var/www/acme2certifier/share/nginx/acme2certifier.service /etc/systemd/system/acme2certifier.service
   ```

   Alternatively, create the service file manually:

   ```bash
   sudo cat <<EOT > /etc/systemd/system/acme2certifier.service
   [Unit]
   Description=uWSGI instance to serve acme2certifier
   After=network.target

   [Service]
   User=www-data
   Group=www-data
   WorkingDirectory=/var/www/acme2certifier
   RuntimeDirectory=uwsgi
   Environment="PYTHONPATH=/var/www/acme2certifier"
   Environment="PATH=/var/www/acme2certifier:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
   Environment="ACME_SRV_CONFIGFILE=/var/www/acme2certifier/acme_srv.cfg"
   ExecStart=uwsgi --ini /var/www/acme2certifier/acme2certifier.ini

   [Install]
   WantedBy=multi-user.target
   EOT
   ```

6. Enable and start the `acme2certifier` service:

   ```bash
   sudo systemctl start acme2certifier
   sudo systemctl enable acme2certifier
   ```

7. Enable and start Nginx:

   ```bash
   sudo systemctl start nginx
   sudo systemctl enable nginx
   ```

8. Test the server by accessing the directory resource:

   ```bash
   curl http://<your-server-name>/directory
   ```

   Expected response:

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

9. Try enrolling a certificate using your favorite ACME client. If something does not work, enable debugging in `/var/www/acme2certifier/acme_srv.cfg` and check `/var/log/nginx/error.log` for errors.
