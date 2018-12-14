# acme2certifier

### check if wsgi module is enabled

root@rlh:~# apache2ctl -M | grep -i wsgi
 wsgi_module (shared)
root@rlh:~#

### install module
sudo apt-get install libapache2-mod-wsgi

sudo a2enmod wsgi 

