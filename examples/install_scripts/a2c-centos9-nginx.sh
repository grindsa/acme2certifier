
#!/bin/bash
# acme2certifier script installing a2c on CentOS with NGINX as webserver
# usage:
#   - download acme2certifer and unpack it into a director
#   - enter the directory
#   - execute the script with "sh ./examples/install_scripts/a2c-entos9-nginx.sh"

# BRANCH="${1:-master}"
# echo "# Install a2c from $BRANCH"

# 1. install neded packages
echo "## Installing missing packages"
sudo yum install -y epel-release
sudo yum update -y

sudo yum install -y python-pip nginx python3-uwsgidecorators.x86_64 tar uwsgi-plugin-python3 policycoreutils-python-utils

# 2. create directory
sudo mkdir /opt/acme2certifier

# echo "## Download software from github"
# 3. download archive
# cd /tmp
# curl https://codeload.github.com/grindsa/acme2certifier/tar.gz/refs/heads/$BRANCH -o a2c-$BRANCH.tgz
# tar xvfz a2c-$BRANCH.tgz
# cd /tmp/acme2certifier-$BRANCH

# 4 install modules
echo "## Install missing python modules"
sudo pip install -r requirements.txt

# copy data
echo "## Copy needed data to /opt/acme2certifier"
sudo cp -R * /opt/acme2certifier/

# 5 copy acme-srv.cfg
sudo cp .github/openssl_ca_handler.py_acme_srv_choosen_handler.cfg /opt/acme2certifier/acme_srv/acme_srv.cfg

# 9 copy db handler
sudo cp /opt/acme2certifier/examples/db_handler/wsgi_handler.py /opt/acme2certifier/acme_srv/db_handler.py

# 10 copy wsgi file
sudo cp /opt/acme2certifier/examples/acme2certifier_wsgi.py /opt/acme2certifier/

# 16 add uswgi plugin
echo "## Modify acme2certifier.ini for Redhat/Centos and deviations"
echo "plugins = python3" >> examples/nginx/acme2certifier.ini
sudo cp examples/nginx/acme2certifier.ini /opt/acme2certifier

# 11-12 fix ownwership and permissions
echo "## Set correct ownership"
sudo chmod a+x /opt/acme2certifier/acme_srv
sudo chown -R nginx /opt/acme2certifier/acme_srv

# 15 - 18 configure and enable uWSGI
echo "## Configure and enable uWSGI services"
sudo cp examples/nginx/uwsgi.service /etc/systemd/system/
sudo systemctl enable uwsgi.service
sudo systemctl start uwsgi

# 19 - 20 configure nginxinsta
echo "## Configure and enable nginx services"
sudo cp examples/nginx/nginx_acme.conf /etc/nginx/conf.d/acme.conf
sudo systemctl enable nginx.service
sudo systemctl restart nginx
sudo systemctl status nginx.service


echo "## Add missing SELinux rules "
sudo checkmodule -M -m -o acme2certifier.mod examples/nginx/acme2certifier.te
sudo semodule_package -o acme2certifier.pp -m acme2certifier.mod
sudo semodule -i acme2certifier.pp

