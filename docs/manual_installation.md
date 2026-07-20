<!-- markdownlint-disable MD013 MD014 MD029 -->

<!-- wiki-title Manual Installation Guide for acme2certifier -->

# Manual Installation Guide for acme2certifier

This guide provides step-by-step instructions for manually installing and configuring **acme2certifier** from source. These steps assume you have downloaded and extracted the source code to `/tmp/acme2certifier`.

> **Prefer PyPI?** For Apache2 on Ubuntu, use [Installation from PyPI on Apache2](install_apache2_wsgi.md).

> **Note:** These instructions are based on an installation on Ubuntu 24.04. Adapting them to other Linux distributions should be straightforward, though package names and service management commands may vary slightly.

______________________________________________________________________

## 1. System Preparation

Update your package lists and install required dependencies:

```sh
apt-get update  # && apt-get upgrade
apt-get install -y python3-pip nginx uwsgi uwsgi-plugin-python3 curl krb5-user libkrb5-3 python3-gssapi
```

______________________________________________________________________

## 2. Install acme2certifier

Navigate to the source directory and install Python dependencies:

```sh
cd /tmp/acme2certifier
pip3 install Cython --break-system-packages
python3 setup.py install
```

## 3. Post-Installation File Setup (nginx in this example)

Copy and link required files for the application and web server:

```sh
cp /var/lib/acme2certifier/acme2certifier/share/acme2certifier_wsgi.py /var/lib/acme2certifier/
ln -s /var/lib/acme2certifier/volume/acme_srv.cfg /var/lib/acme2certifier/acme_srv/

cp /var/lib/acme2certifier/examples/nginx/nginx_acme_srv.conf /etc/nginx/sites-available/acme_srv.conf
cp /var/lib/acme2certifier/examples/nginx/nginx_acme_srv_ssl.conf /etc/nginx/sites-available/acme_srv_ssl.conf
rm /etc/nginx/sites-enabled/default
ln -s /etc/nginx/sites-available/acme_srv.conf /etc/nginx/sites-enabled/acme_srv.conf
ln -s /etc/nginx/sites-available/acme_srv_ssl.conf /etc/nginx/sites-enabled/acme_srv_ssl.conf

cp /var/lib/acme2certifier/examples/nginx/acme2certifier.ini /var/lib/acme2certifier

chown -R www-data:www-data /var/lib/acme2certifier/
```

______________________________________________________________________

## 4. Configure the database handler

Select the packaged handler in `acme_srv.cfg`:

```ini
[DBhandler]
handler: wsgi
# handler: django
```

When using the django handler configure install and configure the django environment.

```sh
apt-get install -y python3-django python3-mysqldb python3-pymysql python3-yaml
cp -R /var/lib/acme2certifier/examples/django/* /var/lib/acme2certifier/
sed -i "s/acme2certifier_wsgi/acme2certifier.wsgi/g" /var/lib/acme2certifier/acme2certifier.ini
```

Modify the `settings.py` according to your needs, create the database tables and load the fixtures.

```sh
cd /var/lib/acme2certifier
python3 manage.py makemigrations
python3 manage.py migrate
python3 manage.py loaddata acme_srv/fixture/status.yaml
chown -R www-data:www-data /var/lib/acme2certifier/
```

______________________________________________________________________

## 5. Configure the CA handler

In `acme_srv.cfg`, set `handler_module` to a built-in handler (preferred), for example:

```ini
[CAhandler]
handler_module: acme2certifier.cahandlers.openssl_ca_handler
```

See [acme_srv.cfg options](acme_srv.md) and [Package layout migration](migration_package_layout.md). Handler-specific settings are documented per CA (for example [OpenSSL](openssl.md)).

______________________________________________________________________

## 6. Create systemd Service

Create the following systemd service file at `/etc/systemd/system/acme2certifier.service`:

```ini
[Unit]
Description=uWSGI instance to serve acme2certifier
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/lib/acme2certifier
Environment="PATH=/var/lib/acme2certifier"
ExecStart=uwsgi --ini acme2certifier.ini

[Install]
WantedBy=multi-user.target
```

______________________________________________________________________

## 7. Start and Enable Services

Start and enable the acme2certifier service and restart nginx:

```sh
systemctl start acme2certifier
systemctl enable acme2certifier
systemctl restart nginx
```

To restart or stop the services later, use:

```sh
systemctl restart acme2certifier
systemctl restart nginx

systemctl stop acme2certifier
systemctl stop nginx

systemctl start acme2certifier
systemctl start nginx
```

______________________________________________________________________

## 8. Test with lego Client

You can test your ACME server using the lego client:

```sh
docker run -i -v /home/joern/data/lego:/.lego/ --network acme --rm --name lego goacme/lego run \
  -s http://acme-srv.acme -a --email "lego@example.com" \
  -d lego.acme --key-type rsa2048 --tls-skip-verify --http
```

______________________________________________________________________

**acme2certifier** should now be installed and running. For further configuration, refer to the project documentation.
