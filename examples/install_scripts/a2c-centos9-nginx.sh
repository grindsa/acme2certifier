#!/bin/bash
# acme2certifier script installing a2c on CentOS with NGINX as webserver
# usage:
#   - download acme2certifer and unpack it into a directory
#   - enter the directory
#   - execute this script with "sh ./examples/install_scripts/a2c-centos9-nginx.sh"

# 1. install neded packages
echo "## Installing missing packages"
yum install -y epel-release
yum update -y

yum install -y python-pip nginx python3-uwsgidecorators.x86_64 tar uwsgi-plugin-python3 policycoreutils-python-utils krb5-workstation krb5-libs krb5-devel gcc python3-devel procps syslog-ng

# 2. create directory
mkdir /opt/acme2certifier

echo "## Download software from github"
# 3. download archive
cd /tmp
# curl https://codeload.github.com/grindsa/acme2certifier/tar.gz/refs/heads/master -o a2c-master.tgz
# tar xvfz a2c-master.tgz
cd /tmp/acme2certifier

# 4 install modules
echo "## Install missing python modules"
pip install -r requirements.txt

# copy data
echo "## Copy needed data to /opt/acme2certifier"
cp -R * /opt/acme2certifier/

# 5 copy acme-srv.cfg
cp .github/openssl_ca_handler.py_acme_srv_choosen_handler.cfg /opt/acme2certifier/acme_srv/acme_srv.cfg

# 9 copy db handler
cp /opt/acme2certifier/examples/db_handler/wsgi_handler.py /opt/acme2certifier/acme_srv/db_handler.py

# 10 copy wsgi file
cp /opt/acme2certifier/examples/acme2certifier_wsgi.py /opt/acme2certifier/

# 16 add uswgi plugin
echo "## Modify acme2certifier.ini for Redhat/Centos and deviations"
echo "plugins = python3" >> examples/nginx/acme2certifier.ini
cp examples/nginx/acme2certifier.ini /opt/acme2certifier

# 11-12 fix ownwership and permissions
echo "## Set correct ownership"
chmod a+x /opt/acme2certifier/acme_srv
chown -R nginx /opt/acme2certifier/acme_srv

# 15 - 18 configure and enable uWSGI
echo "## Configure and enable uWSGI services"
cp examples/nginx/uwsgi.service /etc/systemd/system/
systemctl enable uwsgi.service
systemctl start uwsgi

# 19 - 20 configure nginxinsta
echo "## Configure and enable nginx services"
cp examples/nginx/nginx_acme_srv.conf /etc/nginx/conf.d/nginx_acme_srv.conf
cp examples/nginx/nginx_acme_srv_ssl.conf /etc/nginx/conf.d/nginx_acme_srv_ssl.conf
echo "## Add keyfile and certificate"
mkdir -p /var/www/acme2certifier/volume/
cp .github/acme2certifier_cert.pem /var/www/acme2certifier/volume/
cp .github/acme2certifier_key.pem /var/www/acme2certifier/volume/

systemctl enable nginx.service
systemctl restart nginx
systemctl status nginx.service

echo "## Add missing SELinux rules"

cat <<EOT > acme2certifier.te
module acme2certifier 1.0;

require {
	type var_run_t;
	type initrc_t;
	type httpd_t;
	class sock_file write;
	class unix_stream_socket connectto;
}

#============= httpd_t ==============
allow httpd_t initrc_t:unix_stream_socket connectto;
allow httpd_t var_run_t:sock_file write;
EOT

checkmodule -M -m -o acme2certifier.mod acme2certifier.te
semodule_package -o acme2certifier.pp -m acme2certifier.mod
semodule -i acme2certifier.pp
exit 0
