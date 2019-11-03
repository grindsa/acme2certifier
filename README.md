# acme2certifier
![GitHub release](https://img.shields.io/github/release/grindsa/acme2certifier.svg)
![GitHub last commit (branch)](https://img.shields.io/github/last-commit/grindsa/acme2certifier/master.svg?label=last%20commit%20into%20master)
![GitHub last commit (branch)](https://img.shields.io/github/last-commit/grindsa/acme2certifier/devel.svg?label=last%20commit%20into%20devel)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/2581/badge)](https://bestpractices.coreinfrastructure.org/projects/2581)

acme2certifier is development project to create an ACME protocol proxy. Main intention is to provide ACME services on CA servers which do not support this protocol yet. It consists of two libraries:

- acme/*.py - a bunch of classes implementing ACME server functionality based on [rfc8555](https://tools.ietf.org/html/rfc8555)
- ca_handler.py - interface towards CA server. The intention of this library is to be modular that an [adaption to other CA servers](docs/ca_handler.md) should be straight forward. As of today the following handlers are available:
    - [Openssl](docs/openssl.md)
    - [Insta certifier](docs/certifier.md)
    - [NetGuard Certificate Lifecycle Manager](docs/nclm.md)
    - [Generic EST protocol handler](docs/est.md)
    - [Microsoft Certificate Enrollment Web Services](docs/mscertsrv.md)

For more up-to-date information and further documentation, please visit the project's home page at: [https://github.com/grindsa/acme2certifier](https://github.com/grindsa/acme2certifier)

## ChangeLog
Releasenotes and ChangLog can be found at [https://github.com/grindsa/acme2certifier/releases](https://github.com/grindsa/acme2certifier/releases)

## Disclaimer
I am running this project as my RnD guys told me that it won’t be possible :-)

I am using [acme.sh](https://github.com/Neilpang/acme.sh), [Certbot](https://certbot.eff.org/) and [acmeshell](https://github.com/cpu/acmeshell/) to test the server functionality. Other clients are on my list for later testing. In case you are bored, feel free to test other came ACME clients and raise [issues](https://github.com/grindsa/acme2certifier/issues/new) if something does not work as expected.

[Command-line parameters used for testing](docs/acme-clients.md)

I am not a professional developer. Keep this in mind while laughing about my code and don’t forget to send patches.

## Project status

As of today acme2certifier supports the below ACME functions only:

- "directory" resource [(Section 7.1.1)](https://tools.ietf.org/html/rfc8555#section-7.1.1)
- "newNonce" resource  [(Section 7.2)](https://tools.ietf.org/html/rfc8555#section-7.2)
- "newAccount" resource [(Section 7.3)](https://tools.ietf.org/html/rfc8555#section-7.3)
    - Finding an Account URL Given a Key [(Section 7.3.1)](https://tools.ietf.org/html/rfc8555#section-7.3.1)
    - Account update [(Section 7.3.2)](https://tools.ietf.org/html/rfc8555#section-7.3.2)    
    - Key Rollover [(Section 7.3.5)](https://tools.ietf.org/html/rfc8555#section-7.3.5)
    - Account Deactivation [(Section 7.3.6)](https://tools.ietf.org/html/rfc8555#section-7.3.6)
- "new-order" resource [(Section 7.4)](https://tools.ietf.org/html/rfc8555#section-7.4)
- "order finalization" [(Section 7.4)](https://tools.ietf.org/html/rfc8555#section-7.4)
- "certificate download" [(Section 7.4.2)](https://tools.ietf.org/html/draft-ietf-acme-acme-18#section-7.4.2)
- "authz" resource [(Section 7.5)](https://tools.ietf.org/html/rfc8555#section-7.5)
- "challenge" resource [(Section 7.5.1)](https://tools.ietf.org/html/rfc8555#section-7.5.1)
- "certificate revocation" [(Section 7.6)](https://tools.ietf.org/html/rfc8555#section-7.6)

Starting from version 0.4 acme2certifer includes experimental support for [TNAuthList identifiers](https://tools.ietf.org/html/draft-ietf-acme-authority-token-tnauthlist-03) and [tkauth-01](https://tools.ietf.org/html/draft-ietf-acme-authority-token-03) challenges. Check [tnauthlist.md](docs/tnauthlist.md) for further information.

~~IMPORTANT: The current version does NOT perform Identifier validation. In the current version the acme server will change the status of each challenge to "valid" forcing an acme client to send the CSR immediately.~~

Additional functionality will be added over time. If you are badly missing a certain feature please raise an [issue](https://github.com/grindsa/acme2certifier/issues/new) to let me know.

# Installation
The proxy can run either as Django project or as plain wsgi-script

## Installation as wsgi script

### Installation on apache2 running on Ubuntu 18.04

1. check of the wsgi module is running on your apache2
```
root@rlh:~# apache2ctl -M | grep -i wsgi
 wsgi_module (shared)
root@rlh:~#
```
if the wsgi_module is not enabled please check the internet how to do this.

2. download the archive and unpack it.

3. install the missing modules via pip
```
root@rlh:~# pip3 install -r requirements.txt
```
4. copy the file "examples/apache_acme.conf" to "/etc/apache2/sites-available" and modify it according to you needs.

5. activate the virtual server
```
root@rlh:~# a2ensite acme_acme.conf
```
6. create a directory /var/www/acme

7. copy the file acme2certifier_wsgi.py to /var/www/acme

8. create a directory /var/www/acme/acme

9. copy the content of the acme -directory to /var/www/acme/acme

10. create a configuration file 'acme_srv.cfg' in /var/www/acme/acme or use the example stored in the example directory

11. modify the [configuration file](docs/acme_srv.md) according to you needs

12. pick the correct ca handler from the examples/ca_handler directory and copy it to /var/www/acme/acme/ca_handler.py

13. configure the connection to your ca server. [Example for Insta Certifier](docs/certifier.md)

14. activate the wsgi database handler
```
root@rlh:~# cp /var/www/acme/examples/db_handler/wsgi_handler.py /var/www/acme/acme/db_handler.py
```

15. ensure that the all files and directories under /var/www/acme are owned by the user running the webserver (www-data is just an example!)
```
root@rlh:~# chown -R www-data.www-data /var/www/acme/
```

16. set correct permissions to acme subdirectory
```
root@rlh:~# chmod a+x /var/www/acme/acme
```

17. Check access to the directory resource to verify that everything works so far
```
[root@srv ~]# curl http://127.0.0.1/directory
{"newAccount": "http://127.0.0.1/acme/newaccount", "fa8b347d3849421ebc4b234205418805": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417", "keyChange": "http://127.0.0.1/acme/key-change", "newNonce": "http://127.0.0.1/acme/newnonce", "meta": {"home": "https://github.com/grindsa/acme2certifier", "author": "grindsa <grindelsack@gmail.com>"}, "newOrder": "http://127.0.0.1/acme/neworders", "revokeCert": "http://127.0.0.1/acme/revokecert"}[root@srv ~]#
```

## Installation on NGINX runnig on CentOS 7

I barely know NGINX. Main input has been taken from [here](https://hostpresto.com/community/tutorials/how-to-serve-python-apps-using-uwsgi-and-nginx-on-centos-7/). If you see room for improvement let me know.

Setup is done in a way that uWSGI will serve acme2certifier while NGINX will act as reverse proxy to provide better connection handling.

1. setup your project directory
```
[root@srv ~]# mkdir /opt/acme2certifier
```

2. download the archive and unpack it into /opt/acme2certifier.

3. create a configuration file 'acme_srv.cfg' in /opt/acme2certifier/acme/ or use the example stored in the examples directory

4. modify the [configuration file](docs/acme_srv.md) according to you needs

5. pick the correct ca handler from the /opt/acme2certifier/examples/ca_handler directory and copy it to /opt/acme2certifier/acme/ca_handler.py

6. configure the connection to your ca server. [Example for Insta Certifier](docs/certifier.md)

7. activate the wsgi database handler
```
root@rlh:~# cp /opt/acme2certifier/examples/db_handler/wsgi_handler.py /opt/acme2certifier/acme/db_handler.py
```

8. copy the application file "acme2certifer_wsgi.py" from examples directory
```
root@rlh:~# cp /opt/acme2certifier/examples/acme2certifier_wsgi.py /opt/acme2certifier/
```

9. set the correct permissions to the acme-subdirectory
```
[root@srv ~]# chmod a+x /opt/acme2certifier/acme
```

10. set the ownership of the acme subdirectory to the user running nginx
```
[root@srv ~]# chown -R nginx /opt/acme2certifier/acme
```

11. install the missing python modules
```
[root@srv ~]# pip install -r requirements.txt
```

12. Install uswgi by using pip
```
[root@srv ~]# pip install uwsgi
```

13. Test acme2certifier by starting the application
```
[root@srv ~]# uwsgi --socket 0.0.0.0:8000 --protocol=http -w acme2certifier_wsgi
```

14. Check access to directory resource in a parallel session to verify that everything works so far
```
[root@srv ~]# curl http://127.0.0.1:8000/directory
{"newAccount": "http://127.0.0.1:8000/acme/newaccount", "fa8b347d3849421ebc4b234205418805": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417", "keyChange": "http://127.0.0.1:8000/acme/key-change", "newNonce": "http://127.0.0.1:8000/acme/newnonce", "meta": {"home": "https://github.com/grindsa/acme2certifier", "author": "grindsa <grindelsack@gmail.com>"}, "newOrder": "http://127.0.0.1:8000/acme/neworders", "revokeCert": "http://127.0.0.1:8000/acme/revokecert"}[root@srv ~]#
```

15. create an uWSGI config file or use the one stored in examples/nginx directory
```
[root@srv ~]# cp examples/nginx/acme2certifier.ini /opt/acme2certifier
```

16. Create a Systemd Unit File for uWSGI or use the one stored in excample/nginx directory
```
[root@srv ~]# cp examples/nginx/uwsgi.service /etc/systemd/system/
[root@srv ~]# systemctl enable uwsgi.service
```

17. start uWSGI as service
```
[root@srv ~]# systemctl start uwsgi
```

18. configure NGINX as reverse proxy or use example stored in examples/nginx directory and modify it according to your needs
```
[root@srv ~]# cp examples/nginx/nginx_acme.conf /etc/nginx/conf.d/acme.conf
```

19. restart nginx
```
[root@srv ~]# systemctl restart nginx
```

20. test the server by accessing the directory resource
```
[root@srv ~]# curl http://<your server name>/directory
you should get your resource overview now
```

## Installation as Django project

1. create a new Django project called acme2certier
```
missing
```
2. create a new app inside your project called "acme"
```
missing
```
3. copy the content of the folder "examples/django/acme2certifier" into the "acme2certifer" folder of your project
4. copy the content of the folder "examples/django/acme" into the "acme" folder created in step 2

## Contributing

Please read [CONTRIBUTING.md](docs/CONTRIBUTING.md) for details on my code of conduct, and the process for submitting pull requests.
Please note that I have a life besides programming. Thus, expect a delay in answering.

## Versioning

I use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/grindsa/dkb-robo/tags).

## License

This project is licensed under the GPLv3 - see the [LICENSE](LICENSE) file for details