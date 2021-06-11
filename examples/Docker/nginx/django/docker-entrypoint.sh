#!/bin/bash

# create acme-srv.cfg if not existing
if [ ! -f /var/www/acme2certifier/volume/acme_srv.cfg ]
then
    echo "no acme_srv.cfg found! creating acme_srv.cfg"
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
    echo "no ca_handler.py found! creating from skeleton_ca_handler.py"
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
    echo "no settings.py found! copy settings.py"
    egrep -v '(# SECURITY WARNING: keep the secret key used in production secret!|^SECRET_KEY)' /var/www/acme2certifier/examples/django/acme2certifier/settings.py > /var/www/acme2certifier/volume/settings.py
    ## generate SECRET_KEY
    echo "generating SECRET_KEY"
    DJANGO_SECRET_KEY=`python3 tools/django_secret_keygen.py`
    cat >>/var/www/acme2certifier/volume/settings.py <<EOF
# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '${DJANGO_SECRET_KEY}'
EOF
    echo "adding '*' wildcard hosts in settings.py"
    sed -i "s/ALLOWED_HOSTS = \['127.0.0.1'\]/ALLOWED_HOSTS = \['127.0.0.1','*'\]/g" /var/www/acme2certifier/volume/settings.py
fi

# apply migration or create a symlink for settings.py
if [ -L /var/www/acme2certifier/acme2certifier/settings.py ]
then
    # apply migrations
    python3 /var/www/acme2certifier/tools/django_update.py
    python3 manage.py loaddata acme/fixture/status.yaml
else
    ln -s /var/www/acme2certifier/volume/settings.py /var/www/acme2certifier/acme2certifier/settings.py
fi

chown -R www-data /var/www/acme2certifier/volume
chmod u+s /var/www/acme2certifier/volume/

exec "$@"
