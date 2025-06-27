<!-- markdownlint-disable MD013 -->

<!-- wiki-title: Support for External Databases -->

# Support for External Databases

Acme2certifier supports external databases by using the [Django Python framework](https://www.djangoproject.com/). The default SQLite backend is not designed to handle concurrent write access, which can easily occur in an environment with a high transaction frequency.

All [databases supported by Django](https://docs.djangoproject.com/en/5.0/ref/databases/) should work in theory; MariaDB and PostgreSQL will be tested during [release regression](https://github.com/grindsa/acme2certifier/blob/master/.github/workflows/django_tests..yml).

This guide is written for **Ubuntu 22.04**; however, adapting it to other Linux distributions should not be difficult.

## Preparation

### When Using MariaDB

The steps below assume that MariaDB is already installed and running on your system.

- Open the MySQL command-line client:

```bash
sudo mysql -u  root
```

- create the acme2certifier database and database user

```SQL
CREATE DATABASE acme2certifier CHARACTER SET UTF8;
GRANT ALL PRIVILEGES ON acme2certifier.* TO 'acme2certifier'@'%' IDENTIFIED BY 'a2cpasswd';
FLUSH PRIVILEGES;
```

- Install missing Python modules:

```bash
apt-get install python3-django python3-mysqldb python3-pymysql
```

### When using PostgreSQL

It is assumed that PostgreSQL is already installed and running.

- Open the PostgreSQL command-line client:

```bash
sudo psql -U postgres
```

- Create the acme2certifier database and database user:

```SQL
CREATE DATABASE acme2certifier;
CREATE USER acme2certifier WITH PASSWORD 'a2cpasswd';
ALTER ROLE acme2certifier SET client_encoding TO 'utf8';
ALTER ROLE acme2certifier SET default_transaction_isolation TO 'read committed';
ALTER ROLE acme2certifier SET timezone TO 'UTC';
GRANT ALL PRIVILEGES ON DATABASE acme2certifier TO acme2certifier;
GRANT ALL ON schema public TO acme2certifier;
GRANT USAGE ON schema public TO acme2certifier;
GRANT postgres TO acme2certifier;
```

- Install missing python modules

```bash
sudo apt-get install python3-django python3-psycopg2
```

## Install and Configure acme2certifier

- Download the [latest deb package](https://github.com/grindsa/acme2certifier/releases)
- Install the package locally

```bash
sudo apt-get install -y ./acme2certifier_<version>-1_all.deb
```

- Copy and activate Apache2 configuration file

```bash
sudo cp /var/www/acme2certifier/examples/apache2/apache_django.conf /etc/apache2/sites-available/acme2certifier.conf
sudo a2ensite acme2certifier
```

- Copy and activate the Apache2 SSL configuration file (optional):

```bash
sudo cp /var/www/acme2certifier/examples/apache2/apache_django_ssl.conf /etc/apache2/sites-available/acme2certifier_ssl.conf
sudo a2ensite acme2certifier_ssl
```

- Disable the default sites:

```bash
sudo a2dissite 000-default.conf
sudo a2dissite default-ssl
```

- Copy the Django handler and the Django directory structure:

```bash
sudo cp /var/www/acme2certifier/examples/db_handler/django_handler.py /var/www/acme2certifier/acme_srv/db_handler.py
sudo cp -R /var/www/acme2certifier/examples/django/* /var/www/acme2certifier/
```

- Enable and start the Apache2 service:

```bash
sudo systemctl enable apache2.service
sudo systemctl start apache2.service
```

- Generate a new Django secret key and note it down:

```bash
python3 /var/www/acme2certifier/tools/django_secret_keygen.py
+%*lei)yj9b841=2d5(u)a&7*uwi@l99$(*&ong@g*p1%q)g$e
```

- Modify `/var/www/acme2certifier/acme2certifier/settings.py` and:
  - Insert the secret-key created in the previous step
  - Update the 'ALLOWED_HOSTS'- section with both ip-address and fqdn of the node
  - Configure a connection to mariadb as shown below

```python
SECRET_KEY = "+%*lei)yj9b841=2d5(u)a&7*uwi@l99$(*&ong@g*p1%q)g$e"
ALLOWED_HOSTS = ["192.168.14.132", "ub2204-c1.bar.local"]
(...)
```

### Connecting to MariaDB

- Modify `/var/www/acme2certifier/acme2certifier/settings.py` and configure your database connection as below:

```python
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": "acme2certifier",
        "USER": "acme2certifier",
        "PASSWORD": "a2cpasswd",
        "HOST": "ub2204-c1",
        "OPTIONS": {
            "init_command": "SET sql_mode='STRICT_TRANS_TABLES', innodb_strict_mode=1",
            "charset": "utf8mb4",
            "use_unicode": True,
        },
    },
}
```

### Connecting to PostGres

- Modify `/var/www/acme2certifier/acme2certifier/settings.py` and configure your database connection as below:

```python
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql_psycopg2",
        "NAME": "acme2certifier",
        "USER": "acme2certifier",
        "PASSWORD": "a2cpasswd",
        "HOST": "postgresdbsrv",
        "PORT": "",
    }
}
```

## Finalize acme2cerifier configuration

- Create a Django migration set, apply the migrations, and load fixtures: Modify the [configuration file](acme_srv.md) `/var/www/acme2certifier/volume/acme_srv.cfg`according to your needs. If your CA handler needs runtime information (configuration files, keys, certificate bundles, etc.) to be shared between the nodes, ensure they are loaded from `/var/www/acme2certifier/volume`. Below is an example for the `[CAhandler]` section of the openssl-handler I use during my tests:

```cfg
[CAhandler]
handler_file: /var/www/acme2certifier/examples/ca_handler/openssl_ca_handler.py
ca_cert_chain_list: ["/var/www/acme2certifier/volume/root-ca-cert.pem"]
issuing_ca_key: /var/www/acme2certifier/volume/ca/sub-ca-key.pk8
issuing_ca_key_passphrase_variable: OPENSSL_PASSPHRASE
issuing_ca_cert: /var/www/acme2certifier/volume/ca/sub-ca-cert.pem
issuing_ca_crl: /var/www/acme2certifier/volume/ca/sub-ca-crl.pem
cert_validity_days: 30
cert_validity_adjust: True
cert_save_path: /var/www/acme2certifier/volume/ca/certs
save_cert_as_hex: True
cn_enforce: True
```

- Create a Django migration set, apply the migrations, and load fixtures:

```bash
cd /var/www/acme2certifier
sudo python3 manage.py makemigrations
sudo python3 manage.py migrate
sudo python3 manage.py loaddata acme_srv/fixture/status.yaml
```

- Run the Django update script:

```bash
sudo python3 /var/www/acme2certifier/tools/django_update.py
```

- Restart the apache2 service

```bash
sudo systemctl restart apache2.service
```

- Test the server by accessing the directory resource

```bash
curl http://ub2204-c1.bar.local/directory
```

```bash
{"newAccount": "http://ub2204-c1.bar.local/acme_srv/newaccount", "fa8b347d3849421ebc4b234205418805": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417", "keyChange": "http://ub2204-c1.bar.local/acme_srv/key-change", "newNonce": "http://ub2204-c1.bar.local/acme_srv/newnonce", "meta": {"home": "https://github.com/grindsa/acme2certifier", "author": "grindsa <grindelsack@gmail.com>"}, "newOrder": "http://ub2204-c1.bar.local/acme_srv/neworders", "revokeCert": "http://ub2204-c1.bar.local/acme_srv/revokecert"}
```

## Test enrollment

- Try to enroll certificates by using your favorite ACME client. I am using [lego](https://github.com/go-acme/lego).

```bash
 docker run -i -p 80:80 -v $PWD/lego:/.lego/ --rm --name lego --network acme goacme/lego -s http://ub2204-c1.bar.local -a --email "lego@example.com" -d lego01.bar.local --http run
```
