#!/bin/bash

# create acme-srv.cfg if not existing
if [ ! -f /var/www/acme2certifier/volume/acme_srv.cfg ] 
then 
    cp /var/www/acme2certifier/examples/acme_srv.cfg /var/www/acme2certifier/volume/
fi

# enable ssl if acme2certifier.pem exists on volume
if [ -f /var/www/acme2certifier/volume/acme2certifier.pem ]
then
   cp  /var/www/acme2certifier/examples/apache_django_ssl.conf /etc/apache2/sites-enabled/acme2certifier_ssl.conf
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

# create symlink for the ca_handler
if [ ! -L /var/www/acme2certifier/acme/ca_handler.py ]
then
    ln -s /var/www/acme2certifier/volume/ca_handler.py /var/www/acme2certifier/acme/ca_handler.py
fi

# create settings.py if not existing
if [ ! -f /var/www/acme2certifier/volume/settings.py ] 
then	
    cp /var/www/acme2certifier/examples/django/acme2certifier/settings.py /var/www/acme2certifier/volume/settings.py
fi

# apply migration or create a symlink for settings.py
if [ -L /var/www/acme2certifier/acme2certifier/settings.py ]
then
    # apply migrations
    python3 manage.py makemigrations
    python3 manage.py migrate
    python3 manage.py loaddata acme/fixture/status.yaml

else
    ln -s /var/www/acme2certifier/volume/settings.py /var/www/acme2certifier/acme2certifier/settings.py
fi



exec "$@"
