<!-- markdownlint-disable  MD013 MD014 MD029 -->
<!-- wiki-title DEB installation on Ubuntu 22.04-->
# DEB installation on Ubuntu 22.04

The debian package is generic and supports running acme2certifier with either apache2 and nginx

## Installation with apache2

1. Download the latest [DEB package](https://github.com/grindsa/acme2certifier/releases).
2. Install acme2certifier and apache2 packages

```bash
$ sudo apt-get install -y apache2  apache2-data  libapache2-mod-wsgi-py3
$ sudo apt-get install -y ../acme2certifier_<version>-1_all.deb
```

3. Copy and activete apache2 configuration file

```bash
$ sudo cp /var/www/acme2certifier/examples/apache2/apache_wsgi.conf /etc/apache2/sites-available acme2certifier.conf
$ sudo a2ensite acme2certifier
```

4. Copy and activate apache2 ssl configuration file (optional)

```bash
$ sudo cp /var/www/acme2certifier/examples/apache2/apache_wsgi_ssl.conf /etc/apache2/sites-available acme2certifier_ssl.conf
$ sudo a2ensite acme2certifier_ssl
```

5. Create a configuration file `acme_srv.cfg` in `/var/www/acme2certifier/acme_srv/` or use the example stored in the examples directory
6. Modify the [configuration file](acme_srv.md) according to you needs
7. Configure the CA handler according to your needs. [Example for Insta Certifier](certifier.md)

8. Enable and start the apache2 service

```bash
$ systemctl enable apache2.service
$ systemctl start apache2.service
```

9. Test the server by accessing the directory resource

```bash
$ curl http://<your server name>/directory
{"newAccount": "http://127.0.0.1:8000/acme_srv/newaccount", "fa8b347d3849421ebc4b234205418805": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417", "keyChange": "http://127.0.0.1:8000/acme_srv/key-change", "newNonce": "http://127.0.0.1:8000/acme_srv/newnonce", "meta": {"home": "https://github.com/grindsa/acme2certifier", "author": "grindsa <grindelsack@gmail.com>"}, "newOrder": "http://127.0.0.1:8000/acme_srv/neworders", "revokeCert": "http://127.0.0.1:8000/acme_srv/revokecert"}
```

10. Try to enroll a certificate by using your favourite acme-client. If something does not work enable debugging in `/var/www/acme2certifier/acme_srv/acme_srv.cfg` and check `/var/log/apache2/error.log` for errors.

## Installation with nginx

1. Download the latest [DEB package](https://github.com/grindsa/acme2certifier/releases).
2. Install acme2certifier and nginx packages

```bash
$ sudo apt-get install -y python3-pip nginx uwsgi uwsgi-plugin-python3
$ sudo apt-get install -y ../acme2certifier_<version>-1_all.deb
```

3. Adapt the nginx configuration file to Ubuntu 22.04 and activate the configuration

```bash
$ sed -i "s/run\/uwsgi\/acme.sock/var\/www\/acme2certifier\/acme.sock/g" examples/nginx/nginx_acme_srv.conf
$ sudo cp examples/nginx/nginx_acme_srv.conf /etc/nginx/sites-available/acme_srv.conf
$ sudo rm /etc/nginx/sites-enabled/default
$ sudo ln -s /etc/nginx/sites-available/acme_srv.conf /etc/nginx/sites-enabled/acme_srv.conf
```

4. Adapt and copy uwsgi configuration files

```bash
$ sed -i "s/\/run\/uwsgi\/acme.sock/acme.sock/g" examples/nginx/acme2certifier.ini
$ sed -i "s/nginx/www-data/g" examples/nginx/acme2certifier.ini
$ echo "plugins=python3" >> examples/nginx/acme2certifier.ini
$ sudo cp examples/nginx/acme2certifier.ini /var/www/acme2certifier
```

5. Create acme2certifier systemd service file

```bash
cat <<EOT > acme2certifier.service
[Unit]
Description=uWSGI instance to serve acme2certifier
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/acme2certifier
Environment="PATH=/var/www/acme2certifier"
ExecStart=uwsgi --ini acme2certifier.ini

[Install]
WantedBy=multi-user.target
EOT
```

6. Copy systemd service file

```bash
$ sudo mv acme2certifier.service /etc/systemd/system/acme2certifier.service
```

7. Enable and start acme2certifier service

```bash
$ sudo systemctl start acme2certifier
$ sudo systemctl enable acme2certifier
```

8. Enable and start nginx

```bash
$ sudo systemctl start nginx
$ sudo systemctl enable nginx
```

9. Test the server by accessing the directory resource

```bash
$ curl http://<your server name>/directory
{"newAccount": "http://127.0.0.1:8000/acme_srv/newaccount", "fa8b347d3849421ebc4b234205418805": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417", "keyChange": "http://127.0.0.1:8000/acme_srv/key-change", "newNonce": "http://127.0.0.1:8000/acme_srv/newnonce", "meta": {"home": "https://github.com/grindsa/acme2certifier", "author": "grindsa <grindelsack@gmail.com>"}, "newOrder": "http://127.0.0.1:8000/acme_srv/neworders", "revokeCert": "http://127.0.0.1:8000/acme_srv/revokecert"}
```

10. Try to enroll a certificate by using your favourite acme-client. If something does not work enable debugging in `/var/www/acme2certifier/acme_srv/acme_srv.cfg` and check `/var/log/nginx/error.log` for errors.
