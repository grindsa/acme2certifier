#!/bin/bash

case "$1" in

  "restart")
    echo "update configuration and restart service"
    yes | cp /tmp/acme2certifier/acme_srv.cfg /opt/acme2certifier/acme_srv
    yes | cp -R /tmp/acme2certifier/acme_ca/* /opt/acme2certifier/volume/acme_ca/
    systemctl restart acme2certifier.service
    systemctl restart nginx.service
    ;;

  *)
    echo "install missing packages"
    yum install -y procps rsyslog

    systemctl start rsyslog.service

    yum -y install epel-release
    yum -y localinstall /tmp/acme2certifier/*.rpm
    yum -y install python3-PyMySQL python3-psycopg2 python3-pyyaml python3-mysqlclient

    yes | cp /opt/acme2certifier/examples/db_handler/django_handler.py /opt/acme2certifier/acme_srv/db_handler.py
    yes | cp -R /opt/acme2certifier/examples/django/* /opt/acme2certifier/

    cp /opt/acme2certifier/examples/nginx/nginx_acme_srv.conf /etc/nginx/conf.d
    cp /opt/acme2certifier/examples/nginx/nginx_acme_srv_ssl.conf /etc/nginx/conf.d
    mkdir -p /opt/acme2certifier/volume/

    yes | cp /tmp/acme2certifier/volume/acme_srv.cfg /opt/acme2certifier/acme_srv
    if [ -d /tmp/acme2certifier/volume ]
      then
      mkdir -p /opt/acme2certifier/volume
      yes | cp -R /tmp/acme2certifier/volume/* /opt/acme2certifier/volume/
    fi
    if [ -d /tmp/acme2certifier/acme2certifier ]
      then
      mkdir -p /opt/acme2certifier/acme2certifier
      yes | cp -R /tmp/acme2certifier/acme2certifier/* /opt/acme2certifier/acme2certifier/
    fi
    if [ -d /tmp/acme2certifier/nginx ]
      then
      yes | cp -R /tmp/acme2certifier/nginx/* /etc/nginx/
    fi

    cd /opt/acme2certifier
    python3 manage.py makemigrations
    python3 manage.py migrate
    python3 /opt/acme2certifier/tools/django_update.py
    python3 manage.py loaddata acme_srv/fixture/status.yaml

    chown -R nginx.nginx /opt/acme2certifier/acme2certifier/
    chown -R nginx.nginx /opt/acme2certifier/volume/

    systemctl enable acme2certifier.service
    systemctl start acme2certifier.service

    systemctl enable nginx.service
    systemctl start nginx.service
    ;;
esac
