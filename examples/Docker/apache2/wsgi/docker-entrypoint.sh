#!/bin/bash

# create acme-srv.cfg if not existing
if [ ! -f /var/www/acme2certifier/volume/acme_srv.cfg ]
then
    echo "no acme_srv.cfg found! creating acme_srv.cfg" >> /proc/1/fd/1
    cp /var/www/acme2certifier/examples/acme_srv.cfg /var/www/acme2certifier/volume/
fi

# enable tls if acme2certifier.pm exists on volume
if [ -f /var/www/acme2certifier/volume/acme2certifier.pem ]
then
    echo "found acme2certifier.pem! enable TLS" >> /proc/1/fd/1
   cp  /var/www/acme2certifier/examples/apache_wsgi_ssl.conf /etc/apache2/sites-enabled/acme2certifier_ssl.conf
fi

# create ca_handler if:
# - ca_handler.py does not exists in volume AND
# - no entry handler_file: exists in acme_srv.cfg
# - define ca_handler defined under handler_file does not exists
if ( [ ! -f /var/www/acme2certifier/volume/ca_handler.py ] && \
     ! ( grep -E '^handler_file:' /var/www/acme2certifier/volume/acme_srv.cfg &> /dev/null && \
         [ -f $(grep -E '^handler_file:' /var/www/acme2certifier/volume/acme_srv.cfg | awk -F":" '{print $2}') ] \
        ))
then
    echo "no ca_handler.py found! creating from skeleton_ca_handler.py" >> /proc/1/fd/1
    cp /var/www/acme2certifier/examples/ca_handler/skeleton_ca_handler.py /var/www/acme2certifier/volume/ca_handler.py
else
    if [ -f /var/www/acme2certifier/volume/ca_handler.py ]
    then
        sed -i "s/from acme.helper import/from acme_srv.helper import/g" /var/www/acme2certifier/volume/ca_handler.py
    fi
fi

# create symlink for the acme_srv.cfg
if [ ! -L /var/www/acme2certifier/acme_srv/acme_srv.cfg ]
then
    ln -s /var/www/acme2certifier/volume/acme_srv.cfg /var/www/acme2certifier/acme_srv/acme_srv.cfg
    chown www-data.www-data /var/www/acme2certifier/volume/acme_srv.cfg
fi

# create symlink for the acme_srv.db
if [ ! -L /var/www/acme2certifier/acme_srv/acme_srv.db ]
then
    ln -s /var/www/acme2certifier/volume/acme_srv.db /var/www/acme2certifier/acme_srv/acme_srv.db
fi

# apply database updates (if needed)
python3 /var/www/acme2certifier/tools/db_update.py

# create symlink for the ca_handler
if [ ! -L /var/www/acme2certifier/acme_srv/ca_handler.py ]
then
    ln -s /var/www/acme2certifier/volume/ca_handler.py /var/www/acme2certifier/acme_srv/ca_handler.py
fi

chown -R www-data /var/www/acme2certifier/volume
chmod u+s /var/www/acme2certifier/volume/
exec "$@"
