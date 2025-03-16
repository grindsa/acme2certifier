<!-- markdownlint-disable MD013 MD014 MD029 -->
<!-- wiki-title: Installation on Apache2 Running on Ubuntu 22.04 -->

# Installation on Apache2 Running on Ubuntu 22.04

A [ready-made shell script](../examples/install_scripts/a2c-ubuntu22-apache2.sh) performing the tasks below can be found in the `examples/install_scripts` directory.

## 1. Install Apache2 and the Corresponding WSGI Module

```bash
sudo apt-get install -y apache2 libapache2-mod-wsgi-py3 python3-pip apache2-data curl krb5-user libgssapi-krb5-2 libkrb5-3 python3-gssapi
```

## 2. Check if the WSGI Module is Activated in Your Apache Configuration

```bash
sudo apache2ctl -M | grep -i wsgi
 wsgi_module (shared)
```

If the `wsgi_module` is not enabled, refer to online resources on how to enable it.

## 3. Download `acme2certifier` from [master](https://github.com/grindsa/acme2certifier/archive/refs/heads/master.tar.gz) and Unpack It

## 4. Install the Required Python Modules via `pip`

```bash
sudo pip3 install -r requirements.txt
```

## 5. Copy the Apache WSGI Configuration File

Copy `examples/apache2/apache_wsgi.conf` to `/etc/apache2/sites-available/acme2certifier.conf` and modify it according to your needs.

## 6. Enable TLS (Optional)

If you want to enable TLS, copy `examples/acme_wsgi_ssl.conf` to `/etc/apache2/sites-available/acme2certifier.conf` and modify it accordingly. Ensure you place the key bundle correctly. This file must contain the following certificate data in PEM format:

- The private key
- The end-entity certificate
- Intermediate CA certificates (sorted from leaf to root, excluding the root CA certificate for security reasons)

Activate the SSL module:

```bash
sudo a2enmod ssl
```

## 7. Activate the Virtual Server(s)

```bash
sudo a2ensite acme2certifier.conf
sudo a2ensite acme2certifier_ssl.conf
```

## 8. Create Required Directories and Copy Necessary Files

### Create the Main Directory

```bash
sudo mkdir /var/www/acme2certifier
```

### Copy the WSGI Application

```bash
sudo cp examples/acme2certifier_wsgi.py /var/www/acme2certifier
```

### Copy Required Directories

```bash
sudo mkdir /var/www/acme2certifier/examples
sudo cp -R examples/ca_handler/ /var/www/acme2certifier/examples/ca_handler
sudo cp -R examples/eab_handler/ /var/www/acme2certifier/examples/eab_handler
sudo cp -R examples/hooks/ /var/www/acme2certifier/examples/hooks
sudo cp -R examples/acme_srv.cfg /var/www/acme2certifier/examples/
sudo cp -R tools/ /var/www/acme2certifier/tools
```

## 9. Set Up the `acme_srv` Directory

### Create the `acme_srv` Directory

```bash
sudo mkdir /var/www/acme2certifier/acme_srv
```

### Copy the Contents of `acme_srv`

```bash
sudo cp -R acme_srv/ /var/www/acme2certifier/acme_srv
```

###10. Configure `acme_srv.cfg`

Create a configuration file `acme_srv.cfg` in `/var/www/acme2certifier/acme_srv`, or use the example stored in the `examples` directory.

Modify the [configuration file](acme_srv.md) according to your needs.

## 11. Select and Configure the CA Handler

(Optional) Choose the appropriate CA handler from `examples/ca_handler` and copy it to `/var/www/acme2certifier/acme_srv/ca_handler.py`.

Configure the CA handler in `acme_srv.cfg`. [Example for Insta Certifier](certifier.md).

## 12. Activate the WSGI Database Handler

```bash
sudo cp /var/www/acme2certifier/examples/db_handler/wsgi_handler.py /var/www/acme2certifier/acme_srv/db_handler.py
```

## 13. Set Proper Permissions

Ensure that all files and directories under `/var/www/acme2certifier` are owned by the web server user (`www-data` is used as an example):

```bash
sudo chown -R www-data:www-data /var/www/acme2certifier/
```

Set the correct permissions for the `acme_srv` directory:

```bash
sudo chmod a+x /var/www/acme2certifier/acme_srv
```

## 14. Remove the Default Apache Configuration and Restart Apache

```bash
sudo rm /etc/apache2/sites-enabled/000-default.conf
sudo systemctl reload apache2
```

## 15. Verify Installation

Check if access to the directory resource works:

```bash
curl http://127.0.0.1/directory
```

Expected response:

```json
{
  "newAccount": "http://127.0.0.1/acme_srv/newaccount",
  "fa8b347d3849421ebc4b234205418805": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417",
  "keyChange": "http://127.0.0.1/acme_srv/key-change",
  "newNonce": "http://127.0.0.1/acme_srv/newnonce",
  "meta": {
    "home": "https://github.com/grindsa/acme2certifier",
    "author": "grindsa <grindelsack@gmail.com>"
  },
  "newOrder": "http://127.0.0.1/acme_srv/neworders",
  "revokeCert": "http://127.0.0.1/acme_srv/revokecert"
}
```

## 16. Enroll a Certificate

Try enrolling a certificate using your preferred ACME client. If it fails, check your CA handler configuration, logs, and enable [debug mode](acme_srv.md) in `acme2certifier` for further investigation.
