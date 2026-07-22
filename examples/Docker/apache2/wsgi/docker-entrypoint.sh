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
   cp  /var/www/acme2certifier/share/apache2/apache_wsgi_ssl.conf /etc/apache2/sites-enabled/acme2certifier_ssl.conf
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

# create symlink for the acme_srv.db
if [[ ! -L /var/www/acme2certifier/acme_srv/acme_srv.db ]]
then
    ln -s /var/www/acme2certifier/volume/acme_srv.db /var/www/acme2certifier/acme_srv/acme_srv.db
fi

DB_HANDLER=$(a2c_resolve_db_handler)
echo "resolved DB handler: ${DB_HANDLER} (cfg > ACME_SRV_DB_HANDLER=${ACME_SRV_DB_HANDLER:-} > wsgi)" >> /proc/1/fd/1
if [[ "$DB_HANDLER" == "django" ]]; then
    echo "WARNING: handler resolves to django but this is a WSGI image; Apache/mod_wsgi entry and packages stay WSGI. Selection only — use a django image for a full Django stack." >> /proc/1/fd/1
fi

# apply database updates (if needed)
a2c-db-update

# create symlink for the ca_handler
if [[ ! -L /var/www/acme2certifier/acme_srv/ca_handler.py ]]
then
    ln -s /var/www/acme2certifier/volume/ca_handler.py /var/www/acme2certifier/acme_srv/ca_handler.py
fi

chown -R www-data /var/www/acme2certifier/volume
chmod u+s /var/www/acme2certifier/volume/
exec "$@"
