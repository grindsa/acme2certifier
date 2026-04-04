<!-- markdownlint-disable MD013 MD014 MD029 -->

<!-- wiki-title Manual Installation Guide for acme2certifier -->

# Manual Installation Guide for acme2certifier

This guide provides step-by-step instructions for manually installing and configuring **acme2certifier** from source. These steps assume you have downloaded and extracted the source code to `/tmp/acme2certifier`.

---

## 1. System Preparation

Update your package lists and install required dependencies:

```sh
apt-get update  # && apt-get upgrade
apt-get install -y python3-pip nginx uwsgi uwsgi-plugin-python3 curl krb5-user libkrb5-3 python3-gssapi
```

---

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
cp /var/lib/acme2certifier/examples/acme2certifier_wsgi.py /var/lib/acme2certifier
ln -s /var/lib/acme2certifier/volume/acme_srv.cfg /var/lib/acme2certifier/acme_srv/
ln -s /var/lib/acme2certifier/examples/db_handler/wsgi_handler.py /var/lib/acme2certifier/acme_srv/db_handler.py

cp /var/lib/acme2certifier/examples/nginx/nginx_acme_srv.conf /etc/nginx/sites-available/acme_srv.conf
cp /var/lib/acme2certifier/examples/nginx/nginx_acme_srv_ssl.conf /etc/nginx/sites-available/acme_srv_ssl.conf
rm /etc/nginx/sites-enabled/default
ln -s /etc/nginx/sites-available/acme_srv.conf /etc/nginx/sites-enabled/acme_srv.conf
ln -s /etc/nginx/sites-available/acme_srv_ssl.conf /etc/nginx/sites-enabled/acme_srv_ssl.conf

cp /var/lib/acme2certifier/examples/nginx/acme2certifier.ini /var/lib/acme2certifier

chown -R www-data:www-data /var/lib/acme2certifier/
# chmod a+x /var/lib/acme2certifier/acme_srv
```

---

## 4. Create systemd Service

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

---

## 5. Start and Enable Services

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

---

## 6. Test with lego Client

You can test your ACME server using the lego client:

```sh
docker run -i -v /home/joern/data/lego:/.lego/ --network acme --rm --name lego goacme/lego \
  -s http://acme-srv.acme -a --email "lego@example.com" \
  -d lego.acme --key-type rsa2048 --tls-skip-verify --http run
```

---

**acme2certifier** should now be installed and running. For further configuration, refer to the project documentation.
