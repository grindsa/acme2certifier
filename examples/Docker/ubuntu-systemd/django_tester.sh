#!/bin/bash
echo $1
echo $2

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
    apt-get update
    apt-get -y upgrade
    if [ "$2" = "apache2" ]; then
      apt-get install -y apache2  apache2-data  libapache2-mod-wsgi-py3 rsyslog
    elif [ "$2" = "nginx" ]; then
      apt-get install -y python3-pip nginx uwsgi uwsgi-plugin-python3 rsyslog
    fi

    systemctl enable rsyslog
    systemctl start syslog

    echo "install a2c"
    apt-get install -y /tmp/acme2certifier/acme2certifier*.deb

    if [ "$2" = "apache2" ]; then
      echo "configure apache"
      cp /var/www/acme2certifier/examples/apache2/apache_wsgi.conf /etc/apache2/sites-available/acme2certifier.conf
      cp /var/www/acme2certifier/examples/apache2/apache_wsgi_ssl.conf /etc/apache2/sites-available/acme2certifier_ssl.conf
      a2enmod ssl
      a2ensite acme2certifier
      a2ensite acme2certifier_ssl
      rm /etc/apache2/sites-enabled/000-default.conf
    elif [ "$2" = "nginx" ]; then
      echo "configure nginx"
      cp /var/www/acme2certifier/examples/nginx/nginx_acme_srv.conf /etc/nginx/sites-available/acme_srv.conf
      cp /var/www/acme2certifier/examples/nginx/nginx_acme_srv_ssl.conf /etc/nginx/sites-available/acme_srv_ssl.conf
      rm /etc/nginx/sites-enabled/default
      ln -s /etc/nginx/sites-available/acme_srv.conf /etc/nginx/sites-enabled/acme_srv.conf
      ln -s /etc/nginx/sites-available/acme_srv_ssl.conf /etc/nginx/sites-enabled/acme_srv_ssl.conf
      cp /var/www/acme2certifier/examples/nginx/acme2certifier.ini /var/www/acme2certifier
      cp /var/www/acme2certifier/examples/nginx/acme2certifier.service /etc/systemd/system/acme2certifier.service
      systemctl start acme2certifier
      systemctl enable acme2certifier
    fi

    echo "configure django"
    cp -R /var/www/acme2certifier/examples/django/* /var/www/acme2certifier/
    cp -r /var/www/acme2certifier/examples/db_handler/django_handler.py /var/www/acme2certifier/acme_srv/db_handler.py

    echo "copy data"
    mkdir -p /var/www/acme2certifier/volume/
    cp -R /tmp/acme2certifier/volume/* /var/www/acme2certifier/volume/

    if [ -f /var/www/acme2certifier/acme_srv/acme_srv.cfg ]; then
      rm /var/www/acme2certifier/acme_srv/acme_srv.cfg
    fi
    ln -s /var/www/acme2certifier/volume/acme_srv.cfg /var/www/acme2certifier/acme_srv/acme_srv.cfg

    if [ -f /var/www/acme2certifier/acme2certifier/settings.py ]; then
      rm /var/www/acme2certifier/acme2certifier/settings.py
    fi
    ln -s /var/www/acme2certifier/volume/acme2certifier/settings.py /var/www/acme2certifier/acme2certifier/settings.py

    echo "appply migrations"
    cd /var/www/acme2certifier
    python3 tools/django_update.py

    echo "change owner and start service"
    chown -R www-data.www-data /var/www/acme2certifier/volume
    chown -R www-data.www-data /var/www/acme2certifier/

    systemctl start "$2"
    ;;
esac
