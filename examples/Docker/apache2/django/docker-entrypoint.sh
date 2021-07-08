#!/bin/bash

# create acme-srv.cfg if not existing
if [ ! -f /var/www/acme2certifier/volume/acme_srv.cfg ]
then
    echo "no acme_srv.cfg found! creating acme_srv.cfg" >> /proc/1/fd/1
    cp /var/www/acme2certifier/examples/acme_srv.cfg /var/www/acme2certifier/volume/
fi

# enable tls if acme2certifier.pem exists on volume
if [ -f /var/www/acme2certifier/volume/acme2certifier.pem ]
then
    echo "found acme2certifier.pem! enable TLS" >> /proc/1/fd/1
    cp  /var/www/acme2certifier/examples/apache_django_ssl.conf /etc/apache2/sites-enabled/acme2certifier_ssl.conf
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

# create symlink for the ca_handler
if [ ! -L /var/www/acme2certifier/acme_srv/ca_handler.py ]
then
    ln -s /var/www/acme2certifier/volume/ca_handler.py /var/www/acme2certifier/acme_srv/ca_handler.py
fi

# create settings.py if not existing
if [ ! -f /var/www/acme2certifier/volume/settings.py ]
then
    echo "no settings.py found! copy settings.py"  >> /proc/1/fd/1
    egrep -v '(# SECURITY WARNING: keep the secret key used in production secret!|^SECRET_KEY)' /var/www/acme2certifier/examples/django/acme2certifier/settings.py > /var/www/acme2certifier/volume/settings.py
    ## generate SECRET_KEY
    echo "generating SECRET_KEY" >> /proc/1/fd/1
    DJANGO_SECRET_KEY=`python3 tools/django_secret_keygen.py`
    cat >>/var/www/acme2certifier/volume/settings.py <<EOF
# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '${DJANGO_SECRET_KEY}'
EOF
    echo "adding '*' wildcard hosts in settings.py"  >> /proc/1/fd/1
    sed -i "s/ALLOWED_HOSTS = \['127.0.0.1'\]/ALLOWED_HOSTS = \['127.0.0.1','*'\]/g" /var/www/acme2certifier/volume/settings.py
fi

# create migrations if not existing
if [ ! -d /var/www/acme2certifier/volume/migrations ]
then
    echo "no acme_srv.cfg found! creating acme_srv.cfg" >> /proc/1/fd/1
    cp  -R /var/www/acme2certifier/examples/django/acme_srv/migrations /var/www/acme2certifier/volume/
    # mkdir -p /var/www/acme2certifier/volume/migrations
fi

# create a symlink for migrations
if [ ! -L /var/www/acme2certifier/acme_srv/migrations ]
then
    if [ -d /var/www/acme2certifier/volume/migrations ]
    then
        echo "delete migration directory" >> /proc/1/fd/1
        rm -rf /var/www/acme2certifier/acme_srv/migrations
    fi

    echo "create symlink for migration directory" >> /proc/1/fd/1
    ln -s /var/www/acme2certifier/volume/migrations /var/www/acme2certifier/acme_srv/
fi

# apply migrations or create a symlink for settings.py
if [ ! -L /var/www/acme2certifier/acme2certifier/settings.py ]
then
    ln -s /var/www/acme2certifier/volume/settings.py /var/www/acme2certifier/acme2certifier/settings.py
fi

# check if we need to rename the app
if !( grep "    'acme_srv'" /var/www/acme2certifier/volume/settings.py &> /dev/null)
then
    echo "rename django application" >> /proc/1/fd/1
    sed -i "s/    'acme'/    'django_rename_app',\n    'acme_srv'/g" /var/www/acme2certifier/volume/settings.py
    rm -rf /var/www/acme2certifier/volume/migrations/*
    cp  -R /var/www/acme2certifier/examples/django/acme_srv/migrations /var/www/acme2certifier/volume/
    python3 manage.py rename_app acme acme_srv
fi

echo "apply migrations"  >> /proc/1/fd/1
python3 /var/www/acme2certifier/tools/django_update.py
python3 manage.py loaddata acme_srv/fixture/status.yaml

chown -R www-data /var/www/acme2certifier/volume
chmod u+s /var/www/acme2certifier/volume/

exec "$@"
