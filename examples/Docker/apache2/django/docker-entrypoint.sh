#!/bin/bash

# shellcheck source=/resolve_db_handler.sh
. /resolve_db_handler.sh

# create acme-srv.cfg if not existing
if [[ ! -f /var/www/acme2certifier/volume/acme_srv.cfg ]]
then
    echo "no acme_srv.cfg found! creating acme_srv.cfg" >> /proc/1/fd/1
    cp /var/www/acme2certifier/examples/acme_srv.cfg /var/www/acme2certifier/volume/
fi

# enable tls if acme2certifier.pm exists on volume
if [[ -f /var/www/acme2certifier/volume/acme2certifier.pem ]]
then
    echo "found acme2certifier.pem! enable TLS" >> /proc/1/fd/1
    cp  /var/www/acme2certifier/share/apache2/apache_django_ssl.conf /etc/apache2/sites-enabled/acme2certifier_ssl.conf
fi

# create ca_handler if:
# - ca_handler.py does not exists in volume AND
# - no entry handler_file: exists in acme_srv.cfg
# - define ca_handler defined under handler_file does not exists
if ( [[ ! -f /var/www/acme2certifier/volume/ca_handler.py ]] && \
     ! ( grep -E '^handler_file:' /var/www/acme2certifier/volume/acme_srv.cfg &> /dev/null && \
         [[ -f $(grep -E '^handler_file:' /var/www/acme2certifier/volume/acme_srv.cfg | awk -F":" '{print $2}') ]] \
        ))
then
    echo "no ca_handler.py found! creating from skeleton_ca_handler.py" >> /proc/1/fd/1
    cp /var/www/acme2certifier/share/skeletons/ca_handler/skeleton_ca_handler.py /var/www/acme2certifier/volume/ca_handler.py
else
    if [[ -f /var/www/acme2certifier/volume/ca_handler.py ]]
    then
        sed -i "s/from acme\.helper import/from acme2certifier.acme_srv.helper import/g; s/from acme_srv\.helper import/from acme2certifier.acme_srv.helper import/g" /var/www/acme2certifier/volume/ca_handler.py
    fi
fi

# create symlink for the acme_srv.cfg
if [[ ! -L /var/www/acme2certifier/acme_srv.cfg ]]
then
    ln -s /var/www/acme2certifier/volume/acme_srv.cfg /var/www/acme2certifier/acme_srv.cfg
    chown www-data.www-data /var/www/acme2certifier/volume/acme_srv.cfg
fi

# create symlink for the ca_handler
if [[ ! -L /var/www/acme2certifier/acme_srv/ca_handler.py ]]
then
    mkdir -p /var/www/acme2certifier/acme_srv
    ln -s /var/www/acme2certifier/volume/ca_handler.py /var/www/acme2certifier/acme_srv/ca_handler.py
fi

DB_HANDLER=$(a2c_resolve_db_handler)
echo "resolved DB handler: ${DB_HANDLER} (cfg > ACME_SRV_DB_HANDLER=${ACME_SRV_DB_HANDLER:-} > wsgi)" >> /proc/1/fd/1

if [[ "$DB_HANDLER" == "django" ]]; then
    DJANGO_SETTINGS=/usr/lib/python3/dist-packages/acme2certifier/django_project/settings.py
    DJANGO_MIGRATIONS=/usr/lib/python3/dist-packages/acme2certifier/django_app/migrations

    # create settings.py if not existing
    if [[ ! -f /var/www/acme2certifier/volume/settings.py ]]
    then
        echo "no settings.py found! copy settings.py"  >> /proc/1/fd/1
        egrep -v '(# SECURITY WARNING: keep the secret key used in production secret!|^SECRET_KEY)' /var/www/acme2certifier/examples/django/settings.py > /var/www/acme2certifier/volume/settings.py
        ## generate SECRET_KEY
        echo "generating SECRET_KEY" >> /proc/1/fd/1
        DJANGO_SECRET_KEY=$(a2c-django-secret-keygen)
        cat >>/var/www/acme2certifier/volume/settings.py <<EOF
# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '${DJANGO_SECRET_KEY}'
EOF
        echo "adding '*' wildcard hosts in settings.py"  >> /proc/1/fd/1
        sed -i "s/ALLOWED_HOSTS = \['127.0.0.1'\]/ALLOWED_HOSTS = \['127.0.0.1','*'\]/g" /var/www/acme2certifier/volume/settings.py
    fi

    # create migrations if not existing
    if [[ ! -d /var/www/acme2certifier/volume/migrations ]]
    then
        echo "copying django migrations to volume" >> /proc/1/fd/1
        cp -R "$DJANGO_MIGRATIONS" /var/www/acme2certifier/volume/
    fi

    # create a symlink for migrations
    if [[ ! -L "$DJANGO_MIGRATIONS" ]]
    then
        if [[ -d /var/www/acme2certifier/volume/migrations ]]
        then
            echo "replace migration directory with volume symlink" >> /proc/1/fd/1
            rm -rf "$DJANGO_MIGRATIONS"
            ln -s /var/www/acme2certifier/volume/migrations "$DJANGO_MIGRATIONS"
        fi
    fi

    # create a symlink for settings.py
    if [[ ! -L "$DJANGO_SETTINGS" ]]
    then
        rm -f "$DJANGO_SETTINGS"
        ln -s /var/www/acme2certifier/volume/settings.py "$DJANGO_SETTINGS"
    fi

    # check if we need to remove django_rename app
    if ( grep "    'django_rename_app'," /var/www/acme2certifier/volume/settings.py &> /dev/null)
    then
        echo "remove django_rename application" >> /proc/1/fd/1
        sed -i "/    'django_rename_app',/d" /var/www/acme2certifier/volume/settings.py
    fi

    echo "apply migrations"  >> /proc/1/fd/1
    touch /var/www/acme2certifier/volume/migrations/__init__.py
    a2c-django-update
    a2c-manage loaddata status
else
    echo "DB handler is wsgi; skipping Django settings/migrations bootstrap" >> /proc/1/fd/1
    a2c-db-update
fi

chown -R www-data /var/www/acme2certifier/volume
chmod u+s /var/www/acme2certifier/volume/

exec "$@"
