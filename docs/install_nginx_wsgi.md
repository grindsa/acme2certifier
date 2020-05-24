

# Installation on apache2 running on Ubuntu 18.04

1. check of the wsgi module is running on your apache2
```
root@rlh:~# apache2ctl -M | grep -i wsgi
 wsgi_module (shared)
root@rlh:~#
```
if the wsgi_module is not enabled please check the internet how to do this.

2. download the acme2certifier archive from git and unpack it.
3. install the missing modules via pip
```
root@rlh:~# pip3 install -r requirements.txt
```
4. copy the file "examples/apache_acme.conf" to "/etc/apache2/sites-available/acme2certifier.conf" and modify it according to you needs.
5. activate the virtual server
```
root@rlh:~# a2ensite acme2certifier.conf
```
6. create a directory /var/www/acme2certfier
7. copy the file acme2certifier_wsgi.py to /var/www/acme2certifier
8. create a directory /var/www/acme2certifier/acme
9. copy the content of the acme -directory to /var/www/acme2certifier/acme
10. create a configuration file 'acme_srv.cfg' in /var/www/acme2certifier/acme or use the example stored in the example directory
11. modify the [configuration file](docs/acme_srv.md) according to you needs
12. pick the correct ca handler from the examples/ca_handler directory and copy it to /var/www/acme/acme2certifier/ca_handler.py
13. configure the connection to your ca server. [Example for Insta Certifier](docs/certifier.md)
14. activate the wsgi database handler
```
root@rlh:~# cp /var/www/acme2certifier/examples/db_handler/wsgi_handler.py /var/www/acme2certifier/acme/db_handler.py
```
15. ensure that the all files and directories under /var/www/acme2certifier are owned by the user running the webserver (www-data is just an example!)
```
root@rlh:~# chown -R www-data.www-data /var/www/acme2certifier/
```
16. set correct permissions to acme subdirectory
```
root@rlh:~# chmod a+x /var/www/acme2certifier/acme
```
17. restart apache
```
root@rlh:~# service apache2 restart
``` 
18. check access to the directory resource to verify that everything works so far
```
[root@srv ~]# curl http://127.0.0.1/directory
{"newAccount": "http://127.0.0.1/acme/newaccount", "fa8b347d3849421ebc4b234205418805": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417", "keyChange": "http://127.0.0.1/acme/key-change", "newNonce": "http://127.0.0.1/acme/newnonce", "meta": {"home": "https://github.com/grindsa/acme2certifier", "author": "grindsa <grindelsack@gmail.com>"}, "newOrder": "http://127.0.0.1/acme/neworders", "revokeCert": "http://127.0.0.1/acme/revokecert"}[root@srv ~]#
```

You should be able to enroll certificates now. If it fails check the configuration of your ca_handler.