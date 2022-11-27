#!/bin/bash
# acme2certifier script installing a2c on CentOS with NGINX as webserver
# usage:
#   - download acme2certifer and unpack it into a directory
#   - enter the directory
#   - execute this script with "sh ./examples/install_scripts/a2c-ubuntu22-apache2.sh"

# 1 install needed packages
echo "## Install missing packages"
sudo apt-get update
sudo apt-get install -y python3-pip nginx uwsgi uwsgi-plugin-python3 curl

# 3 install needed python modules
echo "## Install missing pythom modules"
sudo pip3 install -r requirements.txt

# 8 create data directory
echo "## Create directory structure required by acme2certifier"
sudo mkdir -p /var/www/acme2certifier/examples

sudo cp examples/acme2certifier_wsgi.py /var/www/acme2certifier/acme2certifier_wsgi.py
sudo cp -R examples/ca_handler/ /var/www/acme2certifier/examples/ca_handler
sudo cp -R examples/eab_handler/ /var/www/acme2certifier/examples/eab_handler
sudo cp -R examples/hooks/ /var/www/acme2certifier/examples/hooks
sudo cp -R examples/nginx/ /var/www/acme2certifier/examples/nginx
sudo cp examples/acme_srv.cfg /var/www/acme2certifier/examples/
sudo cp -R acme_srv/ /var/www/acme2certifier/acme_srv
sudo cp -R tools/ /var/www/acme2certifier/tools
sudo cp examples/db_handler/wsgi_handler.py /var/www/acme2certifier/acme_srv/db_handler.py

echo "## Modify nginx configuration file"
sed -i "s/run\/uwsgi\/acme.sock/var\/www\/acme2certifier\/acme.sock/g" examples/nginx/nginx_acme_srv.conf
sudo cp examples/nginx/nginx_acme_srv.conf /etc/nginx/sites-available/acme_srv.conf
sudo  rm /etc/nginx/sites-enabled/default
sudo ln -s /etc/nginx/sites-available/acme_srv.conf /etc/nginx/sites-enabled/acme_srv.conf

echo "## Modify uwsgi configuration file"
sed -i "s/\/run\/uwsgi\/acme.sock/acme.sock/g" examples/nginx/acme2certifier.ini
sed -i "s/nginx/www-data/g" examples/nginx/acme2certifier.ini
echo "plugins=python3" >> examples/nginx/acme2certifier.ini
sudo cp examples/nginx/acme2certifier.ini /var/www/acme2certifier

# 14 configure a2c with openssl handler - to be modified!!!!
echo "## Configure openssl ca handler"
sudo cp .github/openssl_ca_handler.py_acme_srv_choosen_handler.cfg /var/www/acme2certifier/acme_srv/acme_srv.cfg
sudo mkdir -p /var/www/acme2certifier/volume/acme_ca/certs
sudo cp test/ca/sub-ca-key.pem test/ca/sub-ca-crl.pem test/ca/sub-ca-cert.pem test/ca/root-ca-cert.pem /var/www/acme2certifier/volume/acme_ca/

# 18 set correct ownership
echo "## Set ownership and permissions"
sudo chown -R www-data.www-data /var/www/acme2certifier/
# 19 set permssions
sudo chmod a+x /var/www/acme2certifier/acme_srv

echo "## Create acme2certifier service"

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

sudo cp  acme2certifier.service /etc/systemd/system/acme2certifier.service

echo "## Restart acme2certifier"
sudo systemctl start acme2certifier
sudo systemctl enable acme2certifier

echo "## Restart nginx"
sudo systemctl restart nginx