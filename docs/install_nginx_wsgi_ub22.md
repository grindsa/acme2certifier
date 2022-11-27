<!-- markdownlint-disable  MD013 MD014 MD029 -->
<!-- wiki-title Installation on nginx running on Ubuntu 22.04 -->
# Installation on nginx running on Ubuntu 22.04

A [readymade shell script](../examples/install_scripts/a2c-ubuntu22-nginx.sh) performing the below tasks will can be found in `examples/install_scripts` directory.

1. Install nginx and the corresponding wsgi module

```bash
$ sudo apt-get install -y python3-pip nginx uwsgi uwsgi-plugin-python3 curl
```

2. download the acme2certifier from [Github](https://github.com/grindsa/acme2certifier/archive/refs/heads/master.tar.gz) and unpack it.

3. install the missing python modules via pip

```bash
$ sudo pip3 install -r requirements.txt
```

4. Copy files and directories you need to run acme2certifier

```bash
$ sudo cp examples/acme2certifier_wsgi.py /var/www/acme2certifier/acme2certifier_wsgi.py
$ sudo cp -R examples/ca_handler/ /var/www/acme2certifier/examples/ca_handler
$ sudo cp -R examples/eab_handler/ /var/www/acme2certifier/examples/eab_handler
$ sudo cp -R examples/hooks/ /var/www/acme2certifier/examples/hooks
$ sudo cp -R examples/nginx/ /var/www/acme2certifier/examples/nginx
$ sudo cp examples/acme_srv.cfg /var/www/acme2certifier/examples/
$ sudo cp -R acme_srv/ /var/www/acme2certifier/acme_srv
$ sudo cp -R tools/ /var/www/acme2certifier/tools
$ sudo cp examples/db_handler/wsgi_handler.py /var/www/acme2certifier/acme_srv/db_handler.py
```

5. Adapt the nginx configuration file (uwsgi socket file is located in `/var/www/acme2certifier`) and activate the configuration

```bash
$ sed -i "s/run\/uwsgi\/acme.sock/var\/www\/acme2certifier\/acme.sock/g" examples/nginx/nginx_acme_srv.conf
$ sudo cp examples/nginx/nginx_acme_srv.conf /etc/nginx/sites-available/acme_srv.conf
$ sudo ln -s /etc/nginx/sites-available/acme_srv.conf /etc/nginx/sites-enabled/acme_srv.conf
```

6. A adapt the uwsgi configuration file in place it in `/var/www/acme2certifier`:
    - uwsgi socket file will be located in `/var/www/acme2certifer`
    - uwsgi daemon will be run under `www-data` user
    - uwsgi plugin for python3 must be activated

```bash
$ sed -i "s/\/run\/uwsgi\/acme.sock/acme.sock/g" examples/nginx/acme2certifier.ini
$ sed -i "s/nginx/www-data/g" examples/nginx/acme2certifier.ini
$ echo "plugins=python3" >> examples/nginx/acme2certifier.ini
$ sudo cp examples/nginx/acme2certifier.ini /var/www/acme2certifier
```

7. Pick the correct ca handler from `the examples/ca_handler` directory and copy it to `/var/www/acme2certifier/acme_srv/ca_handler.py`
8. configure the the ca_handler in `acme_srv.cfg`. [Example for Insta Certifier](certifier.md)

9. ensure that the all files and directories under /var/www/acme2certifier are owned by the user running the webserver (www-data is just an example!)

```bash
$ sudo chown -R www-data.www-data /var/www/acme2certifier/
```

10. set correct permissions to acme subdirectory

```bash
$ sudo chmod a+x /var/www/acme2certifier/acme_srv
```

11. Create acme2certifier uwsgi service and place it under `/etc/systemd/system/`

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

$ sudo cp  acme2certifier.service /etc/systemd/system/acme2certifier.service
```

12. Start and activate the acme2certifier service

```bash
$ sudo systemctl start acme2certifier
$ sudo systemctl enable acme2certifier
```

13. Restart nginx

```bash
$ sudo systemctl restart nginx
```

14. Check access to the directory resource to verify that nginx and uwsgi services are up and running

```bash
$ curl http://127.0.0.1/directory
{"newAccount": "http://127.0.0.1/acme_srv/newaccount", "fa8b347d3849421ebc4b234205418805": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417", "keyChange": "http://127.0.0.1/acme_srv/key-change", "newNonce": "http://127.0.0.1/acme_srv/newnonce", "meta": {"home": "https://github.com/grindsa/acme2certifier", "author": "grindsa <grindelsack@gmail.com>"}, "newOrder": "http://127.0.0.1/acme_srv/neworders", "revokeCert": "http://127.0.0.1/acme_srv/revokecert"}
```

Try to enroll a certificate by using your favorite acme-client. If it fails check the configuration of your ca_handler, logs and enable [debug mode](acme_srv.md) in acme2certifier for further investigation.
