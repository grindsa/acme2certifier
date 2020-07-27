<!-- markdownlint-disable  MD013 MD029 -->
# Installation on apache2 running on Ubuntu 18.04

1. check if the wsgi module is activated in your apache configuration

```bash
root@rlh:~# apache2ctl -M | grep -i wsgi
 wsgi_module (shared)
root@rlh:~#
```

if the wsgi_module is not enabled please check the internet how to do...
2. download the archive and unpack it.
3. install the missing modules via pip

```bash
root@rlh:~# pip3 install -r requirements.txt
```

4. copy the file `examples/apache_wsgi.conf` to `/etc/apache2/sites-available/acme2certifier.conf` and modify it according to you needs.
5. in case you would like to activate TLS copy the file `examples/acme_wsgi_ssl.conf` to `/etc/apache2/sites-available/acme2certifier.conf` and modify it according to your needs. Do not forget to place the key-bundle. This

file must contain the following certificate data in pem format:

- the private key
- the end-entity certificate
- intermediate CA certificates, sorted from leaf to root (root CA certificate should not be included for security reasons)

6. activate the virtual server(s)

```bash
root@rlh:~# a2ensite acme2certifier.conf
root@rlh:~# a2ensite acme2certifier_ssl.conf
```

7. create a directory /var/www/acme2certifier
8. copy the file acme2certifier_wsgi.py to /var/www/acme2certifier
9. create a directory /var/www/acme2certifier/acme
10. copy the content of the acme -directory to /var/www/acme2certifier/acme
11. create a configuration file 'acme_srv.cfg' in /var/www/acme2certfier/acme or use the example stored in the example directory
12. modify the [configuration file](../docs/acme_srv.md) according to you needs
13. pick the correct ca handler from the examples/ca_handler directory and copy it to /var/www/acme/acme/ca_handler.py
14. configure the connection to your ca server. [Example for Insta Certifier](../docs/certifier.md)
15. activate the wsgi database handler

```bash
root@rlh:~# cp /var/www/acme2certifier/examples/db_handler/wsgi_handler.py /var/www/acme/acme2certfier/db_handler.py
```

16. ensure that the all files and directories under /var/www/acme2certifier are owned by the user running the webserver (www-data is just an example!)

```bash
root@rlh:~# chown -R www-data.www-data /var/www/acme2certifier/
```

17. set correct permissions to acme subdirectory

```bash
root@rlh:~# chmod a+x /var/www/acme2certifier/acme
```

18. Check access to the directory resource to verify that everything works so far

```bash
[root@srv ~]# curl http://127.0.0.1/directory
{"newAccount": "http://127.0.0.1/acme/newaccount", "fa8b347d3849421ebc4b234205418805": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417", "keyChange": "http://127.0.0.1/acme/key-change", "newNonce": "http://127.0.0.1/acme/newnonce", "meta": {"home": "https://github.com/grindsa/acme2certifier", "author": "grindsa <grindelsack@gmail.com>"}, "newOrder": "http://127.0.0.1/acme/neworders", "revokeCert": "http://127.0.0.1/acme/revokecert"}[root@srv ~]#
```

Try to enroll a certificate by using your favorite acme-client. If it fails check the configuration of your ca_handler, logs and enable [debug mode](../docs/acme_srv.md) in acme2certifier for further investigation.
