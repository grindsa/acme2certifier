<!-- markdownlint-disable  MD013 MD029 -->
<!-- wiki-title Installation on NGINX runnig on CentOS -->
# Installation on NGINX runnig on CentOS

I barely know NGINX. Main input has been taken from [here](https://hostpresto.com/community/tutorials/how-to-serve-python-apps-using-uwsgi-and-nginx-on-centos-7/). If you see room for improvement let me know.

Setup is done in a way that uWSGI will serve acme2certifier while NGINX will act as reverse proxy to provide better connection handling.

1. setup your project directory

```bash
[root@srv ~]# mkdir /opt/acme2certifier
```

2. download the archive and unpack it into `/opt/acme2certifier`.
3. create a configuration file `acme_srv.cfg` in `/opt/acme2certifier/acme_srv/` or use the example stored in the examples directory
4. modify the [configuration file](acme_srv.md) according to you needs
5. set the `handler_file` parameter in `acme_srv.cfg` or copy the correct ca handler from `/opt/acme2certifier/examples/ca_handler directory` to `/opt/acme2certifier/acme_srv/ca_handler.py`
6. configure the connection to your ca server. [Example for Insta Certifier](certifier.md)
7. activate the wsgi database handler

```bash
root@rlh:~# cp /opt/acme2certifier/examples/db_handler/wsgi_handler.py /opt/acme2certifier/acme_srv/db_handler.py
```

8. copy the application file "acme2certifer_wsgi.py" from examples directory

```bash
root@rlh:~# cp /opt/acme2certifier/examples/acme2certifier_wsgi.py /opt/acme2certifier/
```

9. set the correct permissions to the acme_srv-subdirectory

```bash
[root@srv ~]# chmod a+x /opt/acme2certifier/acme_srv
```

10. set the ownership of the acme_srv subdirectory to the user running nginx

```bash
[root@srv ~]# chown -R nginx /opt/acme2certifier/acme_srv
```

11. install the missing python modules

```bash
[root@srv ~]# pip install -r requirements.txt
```

12. Install uswgi by using pip

```bash
[root@srv ~]# pip install uwsgi
```

13. Test acme2certifier by starting the application

```bash
[root@srv ~]# uwsgi --socket 0.0.0.0:8000 --protocol=http -w acme2certifier_wsgi
```

14. Check access to directory resource in a parallel session to verify that everything works so far

```bash
[root@srv ~]# curl http://127.0.0.1:8000/directory
{"newAccount": "http://127.0.0.1:8000/acme_srv/newaccount", "fa8b347d3849421ebc4b234205418805": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417", "keyChange": "http://127.0.0.1:8000/acme_srv/key-change", "newNonce": "http://127.0.0.1:8000/acme_srv/newnonce", "meta": {"home": "https://github.com/grindsa/acme2certifier", "author": "grindsa <grindelsack@gmail.com>"}, "newOrder": "http://127.0.0.1:8000/acme_srv/neworders", "revokeCert": "http://127.0.0.1:8000/acme_srv/revokecert"}[root@srv ~]#
```

15. create an uWSGI config file or use the one stored in examples/nginx directory

```bash
[root@srv ~]# cp examples/nginx/acme2certifier.ini /opt/acme2certifier
```

16. Create a Systemd Unit File for uWSGI or use the one stored in excample/nginx directory

```bash
[root@srv ~]# cp examples/nginx/uwsgi.service /etc/systemd/system/
[root@srv ~]# systemctl enable uwsgi.service
```

17. start uWSGI as service

```bash
[root@srv ~]# systemctl start uwsgi
```

18. configure NGINX as reverse proxy or use example stored in examples/nginx directory and modify it according to your needs

```bash
[root@srv ~]# cp examples/nginx/nginx_acme.conf /etc/nginx/conf.d/acme.conf
```

19. restart nginx

```bash
[root@srv ~]# systemctl restart nginx
```

20. test the server by accessing the directory resource

```bash
[root@srv ~]# curl http://<your server name>/directory
you should get your resource overview now
```
