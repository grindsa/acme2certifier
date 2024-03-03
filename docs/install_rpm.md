<!-- markdownlint-disable  MD013 MD014 MD029 -->
<!-- wiki-title RPM installation on alma Linux 9 -->
# RPM installation on AlmaLinux/Redhat EL/CentOS Stream 9

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

In case you install on Redhat 8.x you need to upgrade following packages

- [python3-cryptography](https://cryptography.io/en/latest/) to version 36.0.1 or higher
- [python3-dns](https://www.dnspython.org/) to version 2.1 or higher.
- [python3-jwcrypto package](https://jwcrypto.readthedocs.io/en/latest/) to version 0.8 or higher.

Backports of these packages being part of RHEL9 can be found in the [the a2c rpm repository](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/)

- [rpm-repo/RPMs/python3-cryptography-36.0.1-4.el8.x86_64.rpm](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8/python3-cryptography-36.0.1-4.el8.x86_64.rpm)
- [python3-dns-2.1.0-6.el8.noarch.rpm](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8/python3-dns-2.1.0-6.el8.noarch.rpm)
- [python3-jwcrypto-0.8-4.el8.noarch.rpm](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8/python3-jwcrypto-0.8-4.el8.noarch.rpm)

Depending on your ca_handler you may need additional modules:

- [python3-impacket-0.11.0-1.el8.noarch.rpm](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8/python3-impacket-0.11.0-1.el8.noarch.rpm) when using [MS wcce handler](https://github.com/grindsa/acme2certifier/blob/master/docs/mswcce.md)
- [python3-ntlm-auth-1.5.0-2.el8.noarch.rpm](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8/python3-ntlm-auth-1.5.0-2.el8.noarch.rpm) when using [MS wse handler](https://github.com/grindsa/acme2certifier/blob/master/docs/mscertsrv.md)
- [python3-requests_ntlm-1.1.0-14.el8.noarch.rpm](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8/python3-requests_ntlm-1.1.0-14.el8.noarch.rpm) when using [MS wse handler](https://github.com/grindsa/acme2certifier/blob/master/docs/mscertsrv.md)
- [python3-requests-pkcs12-1.16-1.el8.noarch.rpm](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8/python3-requests-pkcs12-1.16-1.el8.noarch.rpm) when using [EST](https://github.com/grindsa/acme2certifier/blob/master/docs/est.md) or [EJBCA](https://github.com/grindsa/acme2certifier/blob/master/docs/ejbca.md) handler

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
