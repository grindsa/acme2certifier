#!/bin/bash

echo "install missing packages"
yum install -y sudo checkpolicy python3-pip procps rsyslog
systemctl start rsyslog

cd /tmp/acme2certifier

echo "execute install script"
sh examples/install_scripts/a2c-centos9-nginx.sh


echo "configure handler"
sudo mkdir -p /opt/acme2certifier/volume/acme_ca/certs/
sudo cp test/ca/sub-ca-key.pem test/ca/sub-ca-crl.pem test/ca/sub-ca-cert.pem test/ca/root-ca-cert.pem /opt/acme2certifier/volume/acme_ca/

echo "fix ownership"
sudo chown -R nginx /opt/acme2certifier/volume