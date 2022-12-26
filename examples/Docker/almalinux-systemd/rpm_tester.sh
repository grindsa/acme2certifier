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
    cp /opt/acme2certifier/examples/nginx/nginx_acme_srv.conf /etc/nginx/conf.d
    mkdir -p /opt/acme2certifier/volume/

    yes | cp /tmp/acme2certifier/acme_srv.cfg /opt/acme2certifier/acme_srv
    if [ -d /tmp/acme2certifier/acme_ca ]
      then
      mkdir -p /opt/acme2certifier/volume/acme_ca/certs
      cp -R /tmp/acme2certifier/acme_ca/* /opt/acme2certifier/volume/acme_ca/
    fi

    chown -R nginx.nginx /opt/acme2certifier/volume/
    ls -la /opt/acme2certifier/
    ls -la /opt/acme2certifier/volume

    systemctl enable acme2certifier.service
    systemctl start acme2certifier.service

    systemctl enable nginx.service
    systemctl start nginx.service
    ;;
esac
