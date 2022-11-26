<!-- markdownlint-disable  MD013 MD014 MD029 -->
<!-- wiki-title Installation on NGINX runnig on CentOS -->
# Installation on NGINX runnig on CentOS

I barely know NGINX. Main input has been taken from [here](https://hostpresto.com/community/tutorials/how-to-serve-python-apps-using-uwsgi-and-nginx-on-centos-7/). If you see room for improvement let me know.

Setup is done in a way that uWSGI will serve acme2certifier while NGINX will act as reverse proxy to provide better connection handling.

1. Install missing packages

```bash
$ sudo yum install -y epel-release
$ sudo yum update -y
$ sudo yum install -y python-pip nginx python3-uwsgidecorators.x86_64 tar uwsgi-plugin-python3 policycoreutils-python-utils
```

2. Setup your project directory

```bash
$ mkdir /opt/acme2certifier
```

3. download the archive and unpack it into a temporary directory.

```bash
$ cd /tmp
$ curl https://codeload.github.com/grindsa/acme2certifier/tar.gz/refs/heads/master -o a2c-master.tgz
$ tar xvfz a2c-master.tgz
$ cd /tmp/acme2certifier-master
```

4. Install the missing python modules

```bash
$ pip install -r /opt/acme2certifier/requirements.txt
```

5. create a configuration file `acme_srv.cfg` in `/opt/acme2certifier/acme_srv/` or use the example stored in the examples directory
6. modify the [configuration file](acme_srv.md) according to you needs
7. set the `handler_file` parameter in `acme_srv.cfg` or copy the correct ca handler from `/opt/acme2certifier/examples/ca_handler directory` to `/opt/acme2certifier/acme_srv/ca_handler.py`
8. configure the connection to your ca server. [Example for Insta Certifier](certifier.md)
9. activate the wsgi database handler

```bash
root@rlh:~# cp /opt/acme2certifier/examples/db_handler/wsgi_handler.py /opt/acme2certifier/acme_srv/db_handler.py
```

10. copy the application file "acme2certifer_wsgi.py" from examples directory

```bash
root@rlh:~# cp /opt/acme2certifier/examples/acme2certifier_wsgi.py /opt/acme2certifier/
```

11. set the correct permissions to the acme_srv-subdirectory

```bash
$ chmod a+x /opt/acme2certifier/acme_srv
```

12. set the ownership of the acme_srv subdirectory to the user running nginx

```bash
$ chown -R nginx /opt/acme2certifier/acme_srv
```

13. Test acme2certifier by starting the application

```bash
cd /opt/acme2certifier
$ uwsgi --http-socket :8000 --plugin python3 --wsgi-file acme2certifier_wsgi.py

```

14. Check access to directory resource in a parallel session to verify that everything works so far

```bash
$ curl http://127.0.0.1:8000/directory
{"newAccount": "http://127.0.0.1:8000/acme_srv/newaccount", "fa8b347d3849421ebc4b234205418805": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417", "keyChange": "http://127.0.0.1:8000/acme_srv/key-change", "newNonce": "http://127.0.0.1:8000/acme_srv/newnonce", "meta": {"home": "https://github.com/grindsa/acme2certifier", "author": "grindsa <grindelsack@gmail.com>"}, "newOrder": "http://127.0.0.1:8000/acme_srv/neworders", "revokeCert": "http://127.0.0.1:8000/acme_srv/revokecert"}$
```

15. create an uWSGI config file or use the one stored in examples/nginx directory

```bash
$ cp examples/nginx/acme2certifier.ini /opt/acme2certifier
```

16. activate python3 module in uWSGI config file

```bash
$ echo "plugins = python3" >> examples/nginx/acme2certifier.ini
```

17. Create a Systemd Unit File for uWSGI or use the one stored in excample/nginx directory

```bash
$ cp examples/nginx/uwsgi.service /etc/systemd/system/
$ systemctl enable uwsgi.service
```

18. start uWSGI as service

```bash
$ systemctl start uwsgi
```

19. configure NGINX as reverse proxy or use example stored in examples/nginx directory and modify it according to your needs

```bash
$ cp examples/nginx/nginx_acme.conf /etc/nginx/conf.d/acme.conf
```

20. restart nginx

```bash
$ systemctl restart nginx
```

20. test the server by accessing the directory resource

```bash
$ curl http://<your server name>/directory
```

the above command should result in an error as the Selinx configuration needs to be adapted