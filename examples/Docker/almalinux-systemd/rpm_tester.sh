#!/bin/bash

echo "install missing packages"
yum install -y procps rsyslog

systemctl start rsyslog.service

yum -y install epel-release
yum -y localinstall /tmp/acme2certifier/acme2certifier-0.23.1-1.0.noarch.rpm
cp /opt/acme2certifier/examples/nginx/nginx_acme_srv.conf /etc/nginx/conf.d

yes | cp /tmp/acme2certifier/acme_srv.cfg /opt/acme2certifier/acme_srv
mkdir -p /opt/acme2certifier/volume/acme_ca/certs
cp -R /tmp/acme2certifier/acme_ca/* /opt/acme2certifier/volume/acme_ca/
chown -R nginx.nginx /opt/acme2certifier/volume/
ls -la /opt/acme2certifier/
ls -la /opt/acme2certifier/volume
ls -la /opt/acme2certifier/volume/acme_ca/

systemctl enable acme2certifier.service
systemctl start acme2certifier.service

systemctl enable nginx.service
systemctl start nginx.service