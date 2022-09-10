#!/bin/bash

# chown -R www-data /etc/www/acme2certifier/volume
chmod u+s /usr/local/soap-srv/mock_soap_srv.py
exec "$@"
