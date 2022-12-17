<!-- markdownlint-disable  MD013 MD014 MD029 -->
<!-- wiki-title RPM installation on Alma Linux 9 -->
# RPM installation on AlmaLinux/Redhat EL/CentOS Stream 9

I barely know NGINX. Main input has been taken from [here](https://hostpresto.com/community/tutorials/how-to-serve-python-apps-using-uwsgi-and-nginx-on-centos-7/). If you see room for improvements let me know.

1. Download the latest [RPM package](https://github.com/grindsa/acme2certifier/releases).

2. Install "Extra Packages for Enterprise Linux (EPEL)"

```bash
$ sudo yum install -y epel-release
$ sudo yum update -y
```

3. Install the RPM packages

```bash
$ sudo yum -y localinstall /tmp/acme2certifier/acme2certifier-0.23.1-1.0.noarch.rpm
```

4. Copy NGINX configuration file

```bash
$ cp /opt/acme2certifier/examples/nginx/nginx_acme_srv.conf /etc/nginx/conf.d
```

5. Copy NGINX ssl configuration file (optional)

```bash
$ cp /opt/acme2certifier/examples/nginx/nginx_acme_srv_ssl.conf /etc/nginx/conf.d
```

5. Create a configuration file `acme_srv.cfg` in `/opt/acme2certifier/acme_srv/` or use the example stored in the examples directory
6. Modify the [configuration file](acme_srv.md) according to you needs
7. Configure the CA handler according to your needs. [Example for Insta Certifier](certifier.md)
8. Enable and start the acme2certifier service

```bash
$ systemctl enable acme2certifier.service
$ systemctl start acme2certifier.service
```

9. Enable and start the nginx service

```bash
$ systemctl enable nginx.service
$ systemctl start nginx.service
```

10. Test the server by accessing the directory resource

```bash
$ curl http://<your server name>/directory
{"newAccount": "http://127.0.0.1:8000/acme_srv/newaccount", "fa8b347d3849421ebc4b234205418805": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417", "keyChange": "http://127.0.0.1:8000/acme_srv/key-change", "newNonce": "http://127.0.0.1:8000/acme_srv/newnonce", "meta": {"home": "https://github.com/grindsa/acme2certifier", "author": "grindsa <grindelsack@gmail.com>"}, "newOrder": "http://127.0.0.1:8000/acme_srv/neworders", "revokeCert": "http://127.0.0.1:8000/acme_srv/revokecert"}
```

11. Try to enroll a certificate by using your favourite acme-client. If something does not work enable debugging in `/opt/acme2certifier/acme_srv/acme_srv.cfg` and check `/var/log/messages` for errors.
