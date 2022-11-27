<!-- markdownlint-disable  MD013 MD014 MD029 -->
<!-- wiki-title Installation on apache2 running on Ubuntu 22.04 -->
# Installation on apache2 running on Ubuntu 22.04

A [readymade shell script](../examples/install_scripts/a2c-ubuntu22-apache2.sh) performing the below tasks will can be found in `examples/install_scripts` directory.

1. Install apache2 and the corresponding wsgi module
$ sudo apt-get install -y apache2 libapache2-mod-wsgi-py3 python3-pip apache2-data

2. check if the wsgi module is activated in your apache configuration

```bash
$ sudo apache2ctl -M | grep -i wsgi
 wsgi_module (shared)
```

if the wsgi_module is not enabled please check the internet how to do...

3. download the acme2certifier from [master](https://github.com/grindsa/acme2certifier/archive/refs/heads/master.tar.gz) and unpack it.

4. install the missing modules via pip

```bash
$ sudo pip3 install -r requirements.txt
```

5. copy the file `examples/apache_wsgi.conf` to `/etc/apache2/sites-available/acme2certifier.conf` and modify it according to you needs.

6. in case you would like to activate TLS copy the file `examples/acme_wsgi_ssl.conf` to `/etc/apache2/sites-available/acme2certifier.conf` and modify it according to your needs. Do not forget to place the key-bundle. This

file must contain the following certificate data in pem format:

- the private key
- the end-entity certificate
- intermediate CA certificates, sorted from leaf to root (root CA certificate should not be included for security reasons)

7. activate the virtual server(s)

```bash
$ sudo a2ensite acme2certifier.conf
$ sudo a2ensite acme2certifier_ssl.conf
```

8. create a directory `/var/www/acme2certifier`
9. copy the file `examples/acme2certifier_wsgi.py` to `/var/www/acme2certifier`
10. copy the directories `examples/ca_hander/`, `examples/eab_handler/`, `examples/hooks/` and `tools` to `/var/www/acme2certifier/`

```bash
$ sudo mkdir /var/www/acme2certifier/examples
$ sudo cp -R examples/ca_handler/ /var/www/acme2certifier/examples/ca_handler
$ sudo cp -R examples/eab_handler/ /var/www/acme2certifier/examples/eab_handler
$ sudo cp -R examples/hooks/ /var/www/acme2certifier/examples/hooks
$ sudo cp -R examples/acme_srv.cfg /var/www/acme2certifier/examples/
$ sudo cp -R tools/ /var/www/acme2certifier/tools
```

11. create a directory `/var/www/acme2certifier/acme_srv`
12. copy the content of the `acme_srv` directory to `/var/www/acme2certifier/acme_srv`

```bash
$ sudo cp -R acme_srv/ /var/www/acme2certifier/acme_srv
```

13. create a configuration file `acme_srv.cfg` in /var/www/acme2certfier/acme or use the example stored in the examples directory
14. modify the [configuration file](acme_srv.md) according to you needs
15. Optional: pick the correct ca handler from `the examples/ca_handler` directory and copy it to `/var/www/acme2certifier/acme_srv/ca_handler.py`
16. configure the the ca_handler in `acme_srv.cfg`. [Example for Insta Certifier](certifier.md)
17. activate the wsgi database handler

```bash
$ sudo cp /var/www/acme2certifier/examples/db_handler/wsgi_handler.py /var/www/acme_srv/acme2certfier/db_handler.py
```

18. ensure that the all files and directories under /var/www/acme2certifier are owned by the user running the webserver (www-data is just an example!)

```bash
$ sudo chown -R www-data.www-data /var/www/acme2certifier/
```

19. set correct permissions to acme subdirectory

```bash
$ sudo chmod a+x /var/www/acme2certifier/acme_srv
```

20. delete default apache configuration file and restart the apache2 service

```bash
$ sudo rm /etc/apache2/sites-enabled/000-default.conf
$ sudo systemctl reload apache2
```

21. Check access to the directory resource to verify that everything works so far

```bash
[root@srv ~]# curl http://127.0.0.1/directory
{"newAccount": "http://127.0.0.1/acme_srv/newaccount", "fa8b347d3849421ebc4b234205418805": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417", "keyChange": "http://127.0.0.1/acme_srv/key-change", "newNonce": "http://127.0.0.1/acme_srv/newnonce", "meta": {"home": "https://github.com/grindsa/acme2certifier", "author": "grindsa <grindelsack@gmail.com>"}, "newOrder": "http://127.0.0.1/acme_srv/neworders", "revokeCert": "http://127.0.0.1/acme_srv/revokecert"}[root@srv ~]#
```

Try to enroll a certificate by using your favorite acme-client. If it fails check the configuration of your ca_handler, logs and enable [debug mode](acme_srv.md) in acme2certifier for further investigation.
