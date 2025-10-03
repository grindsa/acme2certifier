#!/bin/bash

case "$1" in

  "update")
    echo "update configuration only"
    # yes | cp /tmp/acme2certifier/acme_srv.cfg /opt/acme2certifier/acme_srv
    yes | cp -R /tmp/acme2certifier/acme_ca/* /opt/acme2certifier/volume/acme_ca/
    ;;

  "restart")
    echo "update configuration and restart service"
    yes | cp /tmp/acme2certifier/acme_srv.cfg /opt/acme2certifier/acme_srv
    yes | cp -R /tmp/acme2certifier/acme_ca/* /opt/acme2certifier/volume/acme_ca/
    systemctl restart acme2certifier.service
    systemctl restart nginx.service
    ;;

  *)
    echo "install missing packages"
    yum -y install epel-release
    yum install -y procps syslog-ng
    systemctl start syslog-ng.service

    yum -y localinstall /tmp/acme2certifier/*.rpm
    cp /opt/acme2certifier/examples/nginx/nginx_acme_srv.conf /etc/nginx/conf.d
    cp /opt/acme2certifier/examples/nginx/nginx_acme_srv_ssl.conf /etc/nginx/conf.d
    mkdir -p /opt/acme2certifier/volume/

    yes | cp /tmp/acme2certifier/acme_srv.cfg /opt/acme2certifier/acme_srv
    if [[ -d /tmp/acme2certifier/acme_ca ]]
      then
      mkdir -p /opt/acme2certifier/volume/acme_ca/certs
      cp -R /tmp/acme2certifier/acme_ca/* /opt/acme2certifier/volume/acme_ca/
    fi

    if [[ -d /tmp/acme2certifier/nginx ]]
      then
      mkdir -p /etc/nginx
      yes | cp -R /tmp/acme2certifier/nginx/* /etc/nginx/
    fi

    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.orig
    head -n 37 /etc/nginx/nginx.conf.orig > /etc/nginx/nginx.conf
    echo "}" >> /etc/nginx/nginx.conf

    chown -R nginx.nginx /opt/acme2certifier/volume/
    ls -la /opt/acme2certifier/
    ls -la /opt/acme2certifier/volume

    systemctl enable acme2certifier.service
    systemctl start acme2certifier.service

    systemctl enable nginx.service
    systemctl start nginx.service
    ;;
esac
