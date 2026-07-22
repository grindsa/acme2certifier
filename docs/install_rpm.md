<!-- markdownlint-disable MD013 MD014 MD029 -->

<!-- wiki-title RPM Installation on AlmaLinux / RHEL / Rocky -->

# RPM Installation on AlmaLinux / Red Hat EL / Rocky / CentOS Stream

One **noarch** RPM installs on **EL8 (Python 3.6)** and **EL9 (Python 3.9)**. The package tree lives under `/opt/acme2certifier` (not system `site-packages`), with `PYTHONPATH=/opt/acme2certifier`.

> **PyPI / pip installs** (e.g. [`a2c-rel-nginx.sh`](../examples/install_scripts/a2c-rel-nginx.sh)) require Python ≥ 3.7 and are **EL9-only**. Use this RPM path for EL8.

## Automated install script

[`examples/install_scripts/a2c-rpm.sh`](../examples/install_scripts/a2c-rpm.sh) installs a local `.rpm`, configures Nginx + uWSGI, and sets `--mode`:

```bash
chmod a+rx examples/install_scripts/a2c-rpm.sh
./examples/install_scripts/a2c-rpm.sh --rpm ./acme2certifier-0.45.dev1-1.0.noarch.rpm
./examples/install_scripts/a2c-rpm.sh -r ../acme2certifier-*.rpm -m django
./examples/install_scripts/a2c-rpm.sh -m wsgi --no-ssl
```

| Option | Meaning |
| --- | --- |
| `-r, --rpm PATH` | path to `acme2certifier-*.rpm` (or auto-find in `.` / `..`) |
| `-m, --mode wsgi\|django` | DB handler + matching uWSGI module (default: `wsgi`) |
| `--no-ssl` | skip SSL nginx vhost / self-signed cert generation |

Works with `dnf` or `yum` on EL8 and EL9. The remainder of this guide is the manual equivalent.

## Layout

| Path | Purpose |
| --- | --- |
| `/opt/acme2certifier/acme2certifier/` | Importable Python package |
| `/opt/acme2certifier/acme_srv.cfg` | Main config (`noreplace`) |
| `/opt/acme2certifier/acme2certifier_wsgi.py` | WSGI entry |
| `/opt/acme2certifier/acme2certifier.ini` | uWSGI (includes `python-path`) |
| `/opt/acme2certifier/share/{nginx,apache2,skeletons}/` | Example web configs |
| `/usr/bin/a2c-*` | CLI wrappers (`PYTHONPATH` set) |

## 1. Download the Latest RPM Package

Download the latest [RPM package](https://github.com/grindsa/acme2certifier/releases).

## 2. Install "Extra Packages for Enterprise Linux (EPEL)"

```bash
sudo yum install -y epel-release
sudo yum update -y
```

## 3. Install the RPM Package

```bash
sudo yum -y localinstall /tmp/acme2certifier/acme2certifier-<version>-1.0.noarch.rpm
```

Nginx and uWSGI are **Recommends**, not hard Requires. For the nginx path:

```bash
sudo yum -y install nginx uwsgi-plugin-python3 python3-uwsgidecorators
```

### Red Hat 8.x: Upgrade Required Packages

If installing on Red Hat 8.x, upgrade the following packages:

- [python3-cryptography](https://cryptography.io/en/latest/) to version 36.0.1 or higher.
- [python3-dns](https://www.dnspython.org/) to version 2.1 or higher.
- [python3-jwcrypto](https://jwcrypto.readthedocs.io/en/latest/) to version 0.8 or higher.

Backports of these packages from RHEL 9 can be found in the [A2C RPM repository](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8):

- [python3-cryptography-36.0.1-4.el8.x86_64.rpm](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8/python3-cryptography-36.0.1-4.el8.x86_64.rpm)
- [python3-dns-2.1.0-6.el8.noarch.rpm](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8/python3-dns-2.1.0-6.el8.noarch.rpm)
- [python3-jwcrypto-0.8-4.el8.noarch.rpm](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8/python3-jwcrypto-0.8-4.el8.noarch.rpm)

### Additional Modules for Specific CA Handlers

Depending on your CA handler, you may need these additional modules:

- [python3-impacket-0.11.0](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8/python3-impacket-0.11.0-2grindsa.el8.noarch.rpm) for [MS WCCE handler](https://github.com/grindsa/acme2certifier/blob/master/docs/mswcce.md).
- [python3-ntlm-auth-1.5.0](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8/python3-ntlm-auth-1.5.0-2.el8.noarch.rpm) for [MS WSE handler](https://github.com/grindsa/acme2certifier/blob/master/docs/mscertsrv.md).
- [python3-requests_ntlm-1.1.0](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8/python3-requests_ntlm-1.1.0-14.el8.noarch.rpm) for [MS WSE handler](https://github.com/grindsa/acme2certifier/blob/master/docs/mscertsrv.md).
- [python3-requests-pkcs12-1.16](https://github.com/grindsa/sbom/raw/main/rpm-repo/RPMs/rhel8/python3-requests-pkcs12-1.16-1.el8.noarch.rpm) for [EST](https://github.com/grindsa/acme2certifier/blob/master/docs/est.md) or [EJBCA](https://github.com/grindsa/acme2certifier/blob/master/docs/ejbca.md) handler.

## 4. Copy the Nginx Configuration File

```bash
sudo cp /opt/acme2certifier/share/nginx/nginx_acme_srv.conf /etc/nginx/conf.d/
```

## 5. Copy the Nginx SSL Configuration File (Optional)

```bash
sudo cp /opt/acme2certifier/share/nginx/nginx_acme_srv_ssl.conf /etc/nginx/conf.d/
```

Apache examples (optional) are under `/opt/acme2certifier/share/apache2/`.

## 6. Configure `acme_srv.cfg`

The package ships `/opt/acme2certifier/acme_srv.cfg` (`%config(noreplace)`). Edit it in place, or replace it with your own.

Default SQLite path: `/opt/acme2certifier/acme_srv.db`.

Modify options per [acme_srv.cfg](acme_srv.md).

## 7. Configure the CA Handler

Set up the CA handler via `handler_module` in `acme_srv.cfg` (preferred). [Example for Insta Certifier](certifier.md). See [Package layout migration](migration_package_layout.md).

## 8. Enable and Start the Acme2Certifier Service

```bash
sudo systemctl enable acme2certifier.service
sudo systemctl start acme2certifier.service
```

## 9. Enable and Start the Nginx Service

```bash
sudo systemctl enable nginx.service
sudo systemctl start nginx.service
```

## 10. Verify the Server

Smoke-check the import path:

```bash
PYTHONPATH=/opt/acme2certifier python3 -c "import acme2certifier.acme_srv; print('ok')"
```

Test the directory resource:

```bash
curl http://<your-server-name>/directory
```

Expected output:

```json
{
  "newAccount": "http://127.0.0.1:8000/acme_srv/newaccount",
  "fa8b347d3849421ebc4b234205418805": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417",
  "keyChange": "http://127.0.0.1:8000/acme_srv/key-change",
  "newNonce": "http://127.0.0.1:8000/acme_srv/newnonce",
  "meta": {
    "home": "https://github.com/grindsa/acme2certifier",
    "author": "grindsa <grindelsack@gmail.com>"
  },
  "newOrder": "http://127.0.0.1:8000/acme_srv/neworders",
  "revokeCert": "http://127.0.0.1:8000/acme_srv/revokecert"
}
```

## 11. Enroll a Certificate

Use your preferred ACME client to enroll a certificate. If an issue occurs, enable debugging in `/opt/acme2certifier/acme_srv.cfg` and check `/var/log/messages` for errors.
