#!/bin/bash
# acme2certifier script installing a2c on CentOS with NGINX as webserver
# usage:
#   - download acme2certifer and unpack it into a directory
#   - enter the directory
#   - execute this script with "sh ./examples/install_scripts/a2c-ubuntu22-apache2.sh"

# 1 install needed packages
sudo apt-get install -y apache2 libapache2-mod-wsgi-py3 python3-pip apache2-data

# 2 check if mod wsgi got activated
apache2ctl -M | grep -i wsgi

# 4 install needed python modules
sudo pip3 install -r requirements.txt

# 5 configure apache2
sudo cp examples/apache_wsgi.conf /etc/apache2/sites-available/acme2certifier.conf

# 7 activate a2c
sudo a2ensite acme2certifier.conf

# 8 create data directory
sudo mkdir /var/www/acme2certifier

# 9 copy main wsgi file
sudo cp examples/acme2certifier_wsgi.py /var/www/acme2certifier

# 10 copy components needed by a2c
sudo mkdir /var/www/acme2certifier/examples
sudo cp -R examples/ca_handler/ /var/www/acme2certifier/examples/ca_handler
sudo cp -R examples/eab_handler/ /var/www/acme2certifier/examples/eab_handler
sudo cp -R examples/hooks/ /var/www/acme2certifier/examples/hooks
sudo cp -R examples/acme_srv.cfg /var/www/acme2certifier/examples/
sudo cp -R tools/ /var/www/acme2certifier/tools

# 11 create directory for server files
sudo mkdir /var/www/acme2certifier/acme_srv

# 12 copy files
sudo cp -R acme_srv /var/www/acme2certifier/

# 13 use default configuration file
sudo cp examples/acme_srv.cfg /var/www/acme2certifier/acme_srv/

# 14 configure a2c with openssl handler - to be modified!!!!
sudo cp .github/openssl_ca_handler.py_acme_srv_choosen_handler.cfg /var/www/acme2certifier/acme_srv/acme_srv.cfg
sudo mkdir -p /var/www/acme2certifier/volume/acme_ca/certs
sudo cp test/ca/sub-ca-key.pem test/ca/sub-ca-crl.pem test/ca/sub-ca-cert.pem test/ca/root-ca-cert.pem /var/www/acme2certifier/volume/acme_ca/

# 17 copy database handler
sudo cp examples/db_handler/wsgi_handler.py /var/www/acme2certifier/acme_srv/db_handler.py

# 18 set correct ownership
sudo chown -R www-data.www-data /var/www/acme2certifier/

# 19 set permssions
sudo chmod a+x /var/www/acme2certifier/acme_srv

# 20 delete default apache configuration and restart apache2 server
sudo rm /etc/apache2/sites-enabled/000-default.conf
sudo systemctl start apache2
