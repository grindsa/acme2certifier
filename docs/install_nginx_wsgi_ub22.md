<!-- markdownlint-disable MD013 MD014 MD029 -->

<!-- wiki-title Installation on Nginx Running on Ubuntu 22.04 -->

# Installation on Nginx Running on Ubuntu 22.04

A [ready-made shell script](../examples/install_scripts/a2c-ubuntu22-nginx.sh) performing the tasks below can be found in the `examples/install_scripts` directory.

## Steps

### 1. Install Nginx and the Corresponding WSGI Module

```bash
sudo apt-get install -y python3-pip nginx uwsgi uwsgi-plugin-python3 curl krb5-user libgssapi-krb5-2 libkrb5-3 python3-gssapi
```

### 2. Download Acme2Certifier from [GitHub](https://github.com/grindsa/acme2certifier/archive/refs/heads/master.tar.gz) and Unpack It

### 3. Install the Missing Python Modules via Pip

```bash
sudo pip3 install -r requirements.txt
```

### 4. Copy the Required Files and Directories

```bash
sudo cp examples/acme2certifier_wsgi.py /var/www/acme2certifier/acme2certifier_wsgi.py
sudo cp -R examples/ca_handler/ /var/www/acme2certifier/examples/ca_handler
sudo cp -R examples/eab_handler/ /var/www/acme2certifier/examples/eab_handler
sudo cp -R examples/hooks/ /var/www/acme2certifier/examples/hooks
sudo cp -R examples/nginx/ /var/www/acme2certifier/examples/nginx
sudo cp examples/acme_srv.cfg /var/www/acme2certifier/examples/
sudo cp -R acme_srv/ /var/www/acme2certifier/acme_srv
sudo cp -R tools/ /var/www/acme2certifier/tools
sudo cp examples/db_handler/wsgi_handler.py /var/www/acme2certifier/acme_srv/db_handler.py
```

### 5. Adapt and Activate the Nginx Configuration File

```bash
sudo sed -i "s/run\/uwsgi\/acme.sock/var\/www\/acme2certifier\/acme.sock/g" examples/nginx/nginx_acme_srv.conf
sudo cp examples/nginx/nginx_acme_srv.conf /etc/nginx/sites-available/acme_srv.conf
sudo ln -s /etc/nginx/sites-available/acme_srv.conf /etc/nginx/sites-enabled/acme_srv.conf
```

### 6. Adapt and Place the uWSGI Configuration File

- The uWSGI socket file will be located in `/var/www/acme2certifier`.
- The uWSGI daemon will run under the `www-data` user.
- The uWSGI plugin for Python 3 must be activated.

```bash
sudo sed -i "s/\/run\/uwsgi\/acme.sock/acme.sock/g" examples/nginx/acme2certifier.ini
sudo sed -i "s/nginx/www-data/g" examples/nginx/acme2certifier.ini
sudo echo "plugins=python3" >> examples/nginx/acme2certifier.ini
sudo cp examples/nginx/acme2certifier.ini /var/www/acme2certifier
```

### 7. Pick the Correct CA Handler and Copy It

Select the appropriate CA handler from the `examples/ca_handler` directory and copy it to:

```bash
sudo cp examples/ca_handler/<your_ca_handler>.py /var/www/acme2certifier/acme_srv/ca_handler.py
```

### 8. Configure the CA Handler in `acme_srv.cfg`

Refer to the [Example for Insta Certifier](certifier.md).

### 9. Ensure Correct Ownership of Files and Directories

```bash
sudo chown -R www-data:www-data /var/www/acme2certifier/
```

### 10. Set Correct Permissions for the `acme_srv` Subdirectory

```bash
sudo chmod a+x /var/www/acme2certifier/acme_srv
```

### 11. Create and Install the uWSGI Service for Acme2Certifier

```bash
cat <<EOT > acme2certifier.service
[Unit]
Description=uWSGI instance to serve Acme2Certifier
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

sudo cp acme2certifier.service /etc/systemd/system/acme2certifier.service
```

### 12. Start and Enable the Acme2Certifier Service

```bash
sudo systemctl start acme2certifier
sudo systemctl enable acme2certifier
```

### 13. Restart Nginx

```bash
sudo systemctl restart nginx
```

### 14. Verify the Services

Check if Nginx and uWSGI are up and running:

```bash
curl http://127.0.0.1/directory
```

Expected output:

```json
{
  "newAccount": "http://127.0.0.1/acme_srv/newaccount",
  "fa8b347d3849421ebc4b234205418805": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417",
  "keyChange": "http://127.0.0.1/acme_srv/key-change",
  "newNonce": "http://127.0.0.1/acme_srv/newnonce",
  "meta": {
    "home": "https://github.com/grindsa/acme2certifier",
    "author": "grindsa <grindelsack@gmail.com>"
  },
  "newOrder": "http://127.0.0.1/acme_srv/neworders",
  "revokeCert": "http://127.0.0.1/acme_srv/revokecert"
}
```

### 15. Enroll a Certificate

Use your preferred ACME client to enroll a certificate. If it fails, check the CA handler configuration, logs, and enable [debug mode](acme_srv.md) in Acme2Certifier for troubleshooting.
