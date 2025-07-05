#!/bin/bash

echo "install missing packages"
yum -y install epel-release
yum install -y sudo checkpolicy python3-pip procps syslog-ng
systemctl start syslog-ng

cd /tmp/acme2certifier

echo "execute install script"
sh examples/install_scripts/a2c-centos9-nginx.sh


echo "configure handler"
mkdir -p /opt/acme2certifier/volume/acme_ca/certs/
cp test/ca/sub-ca-key.pem test/ca/sub-ca-crl.pem test/ca/sub-ca-cert.pem test/ca/root-ca-cert.pem /opt/acme2certifier/volume/acme_ca/

echo "fix ownership"
chown -R nginx /opt/acme2certifier/volume
