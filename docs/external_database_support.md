<!-- markdownlint-disable MD013 -->

<!-- wiki-title: Support for External Databases -->

# Support for External Databases

Acme2certifier supports external databases by using the [Django Python framework](https://www.djangoproject.com/). The default SQLite backend is not designed to handle concurrent write access, which can easily occur in an environment with a high transaction frequency.

All [databases supported by Django](https://docs.djangoproject.com/en/5.0/ref/databases/) should work in principle; MariaDB and PostgreSQL will be tested during [release regression](https://github.com/grindsa/acme2certifier/blob/master/.github/workflows/django_tests.yml).

The following documentation explains how to configure Django-based database access depending on your installation method.

This guide focuses on Docker and **Ubuntu 24.04**-based deb deployments; however, adapting it to other Linux distributions should not be difficult.

## Preparation

### When Using MariaDB

The steps below assume that MariaDB is already installed and running on your system.

- Open the MySQL command-line client:

```bash
sudo mysql -u root
```

- Create the acme2certifier database and database user:

```SQL
CREATE DATABASE acme2certifier CHARACTER SET UTF8;
GRANT ALL PRIVILEGES ON acme2certifier.* TO 'acme2certifier'@'%' IDENTIFIED BY 'a2cpasswd';
FLUSH PRIVILEGES;
```

- Install missing Python modules:

```bash
apt-get install python3-django python3-mysqldb python3-pymysql
```

### When Using PostgreSQL

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

- Install missing Python modules:

```bash
sudo apt-get install python3-django python3-psycopg2
```

### When Using SQL Server

_SQL Server support has not been tested in the [release regression](https://github.com/grindsa/acme2certifier/actions/workflows/django_tests.yml) to the same extent as the other two databases._

Note that this part of the guide is written for **Red Hat Enterprise Linux 9**.

It is assumed that SQL Server is already installed and running.

- Open SQL Server Management Studio.

- Create the acme2certifier database and database user:

```SQL
CREATE DATABASE acme2certifier;
CREATE LOGIN acme2certifier WITH PASSWORD = 'a2c+passwd';
CREATE USER acme2certifier FOR LOGIN acme2certifier;
```

- From Object Explorer, open acme2certifier → Security → Logins → acme2certifier Properties. Under User Mapping, map the user to the database and grant the required roles. Under Server Roles, grant `public` and `sysadmin` as needed so the acme2certifier user has full access to the database.

- Install missing Python modules:

```bash
pip install mssql-django pyodbc
sudo dnf install unixODBC
```

- Follow [these instructions](https://learn.microsoft.com/en-us/sql/connect/odbc/linux-mac/installing-the-microsoft-odbc-driver-for-sql-server?view=sql-server-ver15&tabs=redhat18-install%2Credhat17-install%2Cdebian8-install%2Credhat7-13-install%2Crhel7-offline#17) to install Microsoft ODBC 17.

## Install and Configure acme2certifier

### Debian-based deployment

- Download the [latest deb package](https://github.com/grindsa/acme2certifier/releases)
- Install the package locally

```bash
sudo apt-get install -y ./acme2certifier_<version>-1_all.deb
```

- Copy and activate the Apache2 configuration file:

```bash
sudo cp /var/www/acme2certifier/share/apache2/apache_django.conf /etc/apache2/sites-available/acme2certifier.conf
sudo a2ensite acme2certifier
```

- Copy and activate the Apache2 SSL configuration file (optional):

```bash
sudo cp /var/www/acme2certifier/share/apache2/apache_django_ssl.conf /etc/apache2/sites-available/acme2certifier_ssl.conf
sudo a2ensite acme2certifier_ssl
```

- Disable the default sites:

```bash
sudo a2dissite 000-default.conf
sudo a2dissite default-ssl
```

- Configure the Django DB handler (Django app ships in the package):

```bash
# in acme_srv.cfg under [DBhandler]:
#   handler: django
# optional MySQL/Postgres settings template:
#   cp examples/django/settings.py /var/www/acme2certifier/acme2certifier/django_project/settings.py
```

- Enable and start the Apache2 service:

```bash
sudo systemctl enable apache2.service
sudo systemctl start apache2.service
```

- Generate a new Django secret key and note it down:

```bash
a2c-django-secret-keygen
```

- Modify `/var/www/acme2certifier/acme2certifier/django_project/settings.py` and:
  - Insert the secret key created in the previous step
  - Update the `ALLOWED_HOSTS` section with both the IP address and FQDN of the node
  - Configure a connection to MariaDB as shown below

```python
SECRET_KEY = "+%*lei)yj9b841=2d5(u)a&7*uwi@l99$(*&ong@g*p1%q)g$e"
ALLOWED_HOSTS = ["192.168.14.132", "ub2204-c1.bar.local"]
(...)
```

### Docker Deployments (apache2-django / nginx-django)

**No manual file copying is required.**

The official Docker images already contain:

- the Django app under `acme2certifier.django_app` and project under `acme2certifier.django_project`
- a volume-backed settings file (`django_project/settings.py` → `/var/www/acme2certifier/volume/settings.py`)
- the Django database handler (`handler: django` / `acme2certifier.dbhandlers.django_handler`)

Mount a volume or directory from the Docker host into `/var/www/acme2certifier/volume`. When this volume is present, acme2certifier automatically writes `settings.py`, `acme_srv.cfg`, and all Django migration sets into it and maps them back to the appropriate internal locations during container startup.

### Connecting to MariaDB

- Modify `settings.py` and configure your database connection as below:

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

### Connecting to PostgreSQL

- Modify `settings.py` and configure your database connection as below:

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

### Connecting to SQL Server

- Modify `settings.py` and configure your database connection as below:

```python
DATABASES = {
    "default": {
        "ENGINE": "mssql",
        "NAME": "acme2certifier",
        "USER": "acme2certifier",
        "PASSWORD": "a2c+passwd",
        "HOST": "sqlserverdbsrv,1433",
        "PORT": "",
        "OPTIONS": {"driver": "ODBC Driver 17 for SQL Server"},
    }
}
```

- You may also need to disable some SELinux settings for Apache, depending on your server configuration.

## Finalize acme2certifier configuration

- Modify the [configuration file](acme_srv.md) `/var/www/acme2certifier/volume/acme_srv.cfg` according to your needs. If your CA handler needs runtime information (configuration files, keys, certificate bundles, etc.) to be shared between (cluster) nodes, ensure they are loaded from `/var/www/acme2certifier/volume`. Below is an example `[CAhandler]` section for the OpenSSL handler:

```cfg
[CAhandler]
handler_module: acme2certifier.cahandlers.openssl_ca_handler
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

**The below steps are not required for container deployments, as the container automatically performs them during startup.**

- Create a Django migration set, apply the migrations, and load fixtures:

```bash
cd /var/www/acme2certifier
sudo a2c-manage migrate
sudo a2c-manage loaddata status
```

- Run the Django update script:

```bash
sudo python3 -m acme2certifier.tools.a2c_django_update
```

- Restart the Apache2 service:

```bash
sudo systemctl restart apache2.service
```

## Test enrollment

- Test the server by accessing the directory resource:

```bash
curl http://ub2204-c1.bar.local/directory
```

```bash
{"newAccount": "http://ub2204-c1.bar.local/acme_srv/newaccount", "fa8b347d3849421ebc4b234205418805": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417", "keyChange": "http://ub2204-c1.bar.local/acme_srv/key-change", "newNonce": "http://ub2204-c1.bar.local/acme_srv/newnonce", "meta": {"home": "https://github.com/grindsa/acme2certifier", "author": "grindsa <grindelsack@gmail.com>"}, "newOrder": "http://ub2204-c1.bar.local/acme_srv/neworders", "revokeCert": "http://ub2204-c1.bar.local/acme_srv/revokecert"}
```

- Try to enroll certificates by using your favorite ACME client. This example uses [lego](https://github.com/go-acme/lego).

```bash
 docker run -i -p 80:80 -v $PWD/lego:/.lego/ --rm --name lego --network acme goacme/lego run --tls-skip-verify -s https://ub2204-c1.bar.local -a --email "lego@example.com" -d lego01.bar.local --http
```
