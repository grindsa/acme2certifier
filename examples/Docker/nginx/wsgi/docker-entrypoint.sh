#!/bin/bash

# create acme-srv.cfg if not existing
if [ ! -f /var/www/acme2certifier/volume/acme_srv.cfg ]
then
    cp /var/www/acme2certifier/examples/acme_srv.cfg /var/www/acme2certifier/volume/
fi

# enable ssl if acme2certifier_cert.pem and acme2certifier_key.pem exist on volume
if [ -f /var/www/acme2certifier/volume/acme2certifier_cert.pem ] && [ -f /var/www/acme2certifier/volume/acme2certifier_key.pem ]
then
   if [ ! -f /etc/nginx/sites-available/acme_ssl.conf ]
   then
     cp  /var/www/acme2certifier/examples/nginx/nginx_acme_ssl.conf /etc/nginx/sites-available/acme_ssl.conf
     ln -s /etc/nginx/sites-available/acme_ssl.conf /etc/nginx/sites-enabled/acme_ssl.conf
   fi
fi

# create ca_handler if not existing
if [ ! -f /var/www/acme2certifier/volume/ca_handler.py ]
then
    cp /var/www/acme2certifier/examples/ca_handler/skeleton_ca_handler.py /var/www/acme2certifier/volume/ca_handler.py
fi

# create symlink for the acme_srv.cfg
if [ ! -L /var/www/acme2certifier/acme/acme_srv.cfg ]
then
    ln -s /var/www/acme2certifier/volume/acme_srv.cfg /var/www/acme2certifier/acme/acme_srv.cfg
    chown www-data.www-data /var/www/acme2certifier/volume/acme_srv.cfg
fi

# create symlink for the acme_srv.db
if [ ! -L /var/www/acme2certifier/acme/acme_srv.db ]
then
    ln -s /var/www/acme2certifier/volume/acme_srv.db /var/www/acme2certifier/acme/acme_srv.db
fi

# apply database updates (if needed)
python3 /var/www/acme2certifier/tools/db_update.py

# create symlink for the ca_handler
if [ ! -L /var/www/acme2certifier/acme/ca_handler.py ]
then
    ln -s /var/www/acme2certifier/volume/ca_handler.py /var/www/acme2certifier/acme/ca_handler.py
fi

chown -R www-data.www-data /var/www/acme2certifier/volume
chmod u+s /var/www/acme2certifier/volume/
exec "$@"
