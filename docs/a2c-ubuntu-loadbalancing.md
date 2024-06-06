<!-- markdownlint-disable  MD013 -->
<!-- wiki-title # How to build am acme2certifier cluster on Ubuntu 22.04 -->
# How to build am acme2certifier cluster on Ubuntu 22.04

This tutorial describes the configuration of a two-node acme2certifier cluster running in active/active configuration. Although both nodes are active at the same time and provide proxy services via different ip-addresses database, configuration and runtime objects will be replicated among the nodes.

This setup requires the switch to a different database engine as SQLite, which is the default a2c backend, is not designed to handle concurrent write access, which can happen in an active/active setup. Thus, [MariaDB](https://mariadb.org/) will be used. Configuration files and runtime objects will be replicated using [Lsyncd](https://github.com/lsyncd/lsyncd). The following diagram depicts the application stack to be used.

![architecture](a2c-ubuntu-loadbalancing.png "architecture")

The guide is written for **Ubuntu 22.04**, however adapting to other Linux distributions should not be difficult. There is already a guide for [Alma Linux 9](alma-alma-loadbalancing.md) available

## Preparation

To set up the MariaDB Master-Master replication between multiple servers, you will need to ensure each system hostname is resolved to the correct IP address. I recommend setting up the FQDN in /etc/hosts on each server.

```cfg
cat /etc/hosts
...
192.168.14.132 ub2204-c1.bar.local ub2204-c1
192.168.14.133 ub2204-c2.bar.local ub2204-c2
```

Furthermore, Apache2 should already be installed to create the directories to be replicated.

```bash
sudo apt-get install -y apache2  apache2-data  libapache2-mod-wsgi-py3
```

## Installation and configuration of MariaDB

The following instructions are based on [an existing tutorial](https://www.howtoforge.com/how-to-setup-mariadb-master-master-replication-on-debian-11/).

### Setting up ub2204-c1

- install MariaDB-server

```bash
sudo apt install -y mariadb-server
```

- start MariaDB during startup

```bash
sudo systemctl is-enabled mariadb
sudo systemctl status mariadb
```

- modify `/etc/mysql/mariadb.conf.d/50-server.cnf` change the ip-binding and add the follwinng lines

```cfg
# listen on external address
bind-address            = 192.168.14.132

server-id              = 1
report_host            = ub2204-c1

log_bin                = /var/log/mysql/mariadb-bin
log_bin_index          = /var/log/mysql/mariadb-bin.index

relay_log              = /var/log/mysql/relay-bin
relay_log_index        = /var/log/mysql/relay-bin.index

# avoiding  primary key collision
log-slave-updates
auto_increment_increment=2
auto_increment_offset=1
```

- restart MariaDB-server

```bash
sudo systemctl restart mariadb
```

- verify service binding

```bash
ss -plnt
State    Recv-Q   Send-Q        Local Address:Port       Peer Address:Port   Process
...
LISTEN   0        80           192.168.14.132:3306            0.0.0.0:*       users:(("mariadbd",pid=815,fd=43))
...
```

- open the mysql commandclient client

```bash
sudo mysql -u  root
```

- create the replication user

```SQL
CREATE USER 'replusr'@'%' IDENTIFIED BY 'replpasswd';
GRANT REPLICATION SLAVE ON *.* TO 'replusr'@'%';
FLUSH PRIVILEGES;
```

- Next, run the following query to check the current binary log and its exact position of it. In this example, the binary log file for the MariaDB server is "mariadb-bin.000001" with the position "773". These outputs will be used in the next stage for setting up the "ub2204-c2" server.

```bash
SHOW MASTER STATUS;
+--------------------+----------+--------------+------------------+
| File               | Position | Binlog_Do_DB | Binlog_Ignore_DB |
+--------------------+----------+--------------+------------------+
| mariadb-bin.000001 |      773 |              |                  |
+--------------------+----------+--------------+------------------+
1 row in set (0.000 sec)
```

### Setting up ub2204-c2

- install MariaDB-server

```bash
sudo apt install -y mariadb-server
```

- start MariaDB during startup

```bash
sudo systemctl is-enabled mariadb
sudo systemctl status mariadb
```

- modify `/etc/mysql/mariadb.conf.d/50-server.cnf` change the ip-binding and add the follwinng lines

```cfg
# listen on external address
bind-address            = 192.168.14.133

server-id              = 2
report_host            = ub2204-c2

log_bin                = /var/log/mysql/mariadb-bin
log_bin_index          = /var/log/mysql/mariadb-bin.index

relay_log              = /var/log/mysql/relay-bin
relay_log_index        = /var/log/mysql/relay-bin.index

# avoiding  primary key collision
log-slave-updates
auto_increment_increment=2
auto_increment_offset=2
```

- restart MariaDB-server

```bash
sudo systemctl restart mariadb
```

- verify service binding

```bash
ss -plnt
State    Recv-Q   Send-Q        Local Address:Port       Peer Address:Port   Process
...
LISTEN   0        80           192.168.14.133:3306            0.0.0.0:*       users:(("mariadbd",pid=841,fd=41))
...
```

- open the mysql commandclient client

```bash
sudo mysql -u  root
```

- create the replication user

```SQL
CREATE USER 'replusr'@'%' IDENTIFIED BY 'replpasswd';
GRANT REPLICATION SLAVE ON *.* TO 'replusr'@'%';
FLUSH PRIVILEGES;
```

- stop the slave and add information about the ub2204-c1 master node as well as the binlog file name ("mariadb-bin.000001") and position  ("773") from ub2204-c1.

```SQL
STOP SLAVE;
CHANGE MASTER TO MASTER_HOST='ub2204-c1', MASTER_USER='replusr', MASTER_PASSWORD='replpasswd', MASTER_LOG_FILE='mariadb-bin.000001', MASTER_LOG_POS=773;
```

- start the slave again and verify the slave status on the "ub2204-c2" server. You should get "Slave_IO_Running: Yes" and "Slave_SQL_Running: Yes",

```SQL
START SLAVE;
SHOW SLAVE STATUS\G
*************************** 1. row ***************************
                Slave_IO_State: Waiting for master to send event
                   Master_Host: ub2204-c1
...
              Slave_IO_Running: Yes
             Slave_SQL_Running: Yes
...
```

### Configure master-master replication on ub2204-c1

- open the mysql commandclient client and create the replication user

```bash
sudo mysql -u  root
```

- stop the slave and add information about the ub2204-c2 master node as well as the binlog file name and position.

```SQL
STOP SLAVE;
CHANGE MASTER TO MASTER_HOST='ub2204-c2', MASTER_USER='replusr', MASTER_PASSWORD='replpasswd', MASTER_LOG_FILE='mariadb-bin.000001', MASTER_LOG_POS=773;
```

- start the slave again and verify the slave status

```SQL
START SLAVE;
SHOW SLAVE STATUS\G
*************************** 1. row ***************************
                Slave_IO_State: Waiting for master to send event
                   Master_Host: ub2204-c1
...
              Slave_IO_Running: Yes
             Slave_SQL_Running: Yes
...
```

### Test master-master replication

#### on ub2204-c1

-  open the mysql commandline client

```bash
sudo mysql -u  root
```

- create a testdatabase and a test-table

```SQL
CREATE DATABASE testdb;
```

#### on ub2204-c2

-  open the mysql commandline client

```bash
sudo mysql -u  root
```

- create check databases

```SQL
SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| testdb             |
+--------------------+
5 rows in set (0.000 sec)

MariaDB [(none)]>
```

- delete database

```SQL
DROP DATABASE testdb;
Query OK, 1 row affected (0.014 sec)

MariaDB [(none)]>
```

#### on ub2204-c1

- back on ub2204-c1 check the databases to make sure that "testdb" is not present anymore

```SQL
SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
4 rows in set (0.000 sec)

```

## Configure directory replication via Lsyncd

The following instructions are based on [an existing tutorial](https://docs.rackspace.com/docs/set-up-lsyncd-locally-and-over-ssh-to-sync-directories).

To accomplish a remote synchronization using Lsyncd, both nodes must have password-less SSH access to its peer. Further, it is recommended to use the root-user for synchronization  to ensure that permissions, ownership, and group information of the files to be synchronized will be preserved.

### on both nodes to be executed as root-user

- generate ssh keys

```bash
sudo ssh-keygen -t rsa -f /root/.ssh/id_lsyncd
```

- copy the newly created public key `/root/.ssh/id_lsyncd.pub` from each host to peer and add it to `/root/.ssh/authorized_keys` file

- create the acme2certifier directory to be synchronized between the two hosts

```bash
sudo mkdir -p /var/www/acme2certifier/volume
```

- install Lsyncd

```bash
sudo apt-get install -y lsyncd
```

- create the directory storing the configuration and log files

```bash
sudo mkdir /etc/lsyncd /var/log/lsyncd
```

### on ub2204-c1
- test passwordless ssh access by logging in to ub2204-c2

```bash
sudo ssh -i /root/.ssh/id_lsyncd root@ub2204-c2
exit
```

- create a configuration file `/etc/lsyncd/lsyncd.conf.lua` with the following content

```lua
settings {
  logfile = "/var/log/lsyncd/lsyncd.log",
  statusFile = "/var/log/lsyncd/lsyncd.status",
  statusInterval = 20,
  nodaemon   = false
}

sync {
  default.rsyncssh,
  source = "/var/www/acme2certifier/volume/",
  host = "ub2204-c2",
  targetdir = "/var/www/acme2certifier/volume/",
  rsync = {
    rsh = "/usr/bin/ssh -l root -i /root/.ssh/id_lsyncd -o StrictHostKeyChecking=no",
    compress = true,
    owner = true,
    group = true,
    archive = true
 }
}
```

- start Lsyncd and enable automatic startup

```bash
sudo systemctl restart lsyncd
sudo systemctl enable lsyncd
```

### on ub2204-c2

- test passwordless ssh access by logging in to ub2204-c1

```bash
sudo ssh -i /root/.ssh/id_lsyncd root@ub2204-c1
```

- create a configuration file `/etc/lsyncd/lsyncd.conf.lua` with the following content

```lua
settings {
  logfile = "/var/log/lsyncd/lsyncd.log",
  statusFile = "/var/log/lsyncd/lsyncd.status",
  statusInterval = 20,
  nodaemon   = false
}

sync {
  default.rsyncssh,
  source = "/var/www/acme2certifier/volume/",
  host = "ub2204-c1",
  targetdir = "/var/www/acme2certifier/volume/",
  rsync = {
    rsh = "/usr/bin/ssh -l root -i /root/.ssh/id_lsyncd -o StrictHostKeyChecking=no",
    compress = true,
    owner = true,
    group = true,
    archive = true
 }
}
```

- start Lsyncd and enable automatic startup

```bash
sudo systemctl restart lsyncd
sudo systemctl enable lsyncd
```

### Test replication

#### on ub2204-c1

- create a file in `/var/www/acme2certifier/volume` directory

```bash
sudo touch /var/www/acme2certifier/volume/test.txt
```

#### on ub2204-c2

- verify that the '/var/www/acme2certifier/volume/test.txt' has been syncronized to ub2204-c2 (please note that replication can take up to 20s)

```bash
sudo ls -la /var/www/acme2certifier/volume
```

- delete the '/var/www/acme2certifier/volume/test.txt'

```bash
sudo rm /var/www/acme2certifier/volume/test.txt
```

#### on ub2204-c1

- back on ub2204-c1 check `/var/www/acme2certifier/volume` to make sure that "test.txt" has been deleted (please note that replication can take up to 20s)

```bash
sudo ls -la /var/www/acme2certifier/volume
```

In case of problem check the logfiles stored in `/var/log/lsyncd` for errors.

## Install acme2certifier

### on both nodes

- Downlaod the [latest deb package](https://github.com/grindsa/acme2certifier/releases)
- install the package locally

```bash
sudo apt-get install -y ./acme2certifier_<version>-1_all.deb
```

- Copy and activete apache2 configuration file

```bash
sudo cp /var/www/acme2certifier/examples/apache2/apache_django.conf /etc/apache2/sites-available/acme2certifier.conf
sudo a2ensite acme2certifier
```

- Copy and activate apache2 ssl configuration file (optional)

```bash
sudo cp /var/www/acme2certifier/examples/apache2/apache_django_ssl.conf /etc/apache2/sites-available/acme2certifier_ssl.conf
sudo a2ensite acme2certifier_ssl
```

- disable the default sites

```bash
sudo a2dissite 000-default.conf
sudo a2dissite default-ssl
```

- copy the django handler and the django directory structure

```bash
sudo cp /var/www/acme2certifier/examples/db_handler/django_handler.py /var/www/acme2certifier/acme_srv/db_handler.py
sudo cp -R /var/www/acme2certifier/examples/django/* /var/www/acme2certifier/
```

- move the acme2certifier configuration file `acme_srv.cfg` into the mirrored diectory and create a symbolic link

```bash
sudo mv /var/www/acme2certifier/acme_srv/acme_srv.cfg /var/www/acme2certifier/volume/
sudo ln -s /var/www/acme2certifier/volume/acme_srv.cfg  /var/www/acme2certifier/acme_srv/
```

- Enable and start the apache2 service

```bash
sudo systemctl enable apache2.service
sudo systemctl start apache2.service
```

### on ub2204-c1

-  open the mysql commandline client

```bash
sudo mysql -u  root
```

- create a testdatabase and a test-table

```SQL
CREATE DATABASE acme2certifier CHARACTER SET UTF8;
GRANT ALL PRIVILEGES ON acme2certifier.* TO 'acme2certifier'@'%' IDENTIFIED BY 'a2cpasswd';
FLUSH PRIVILEGES;
```

- generate a new django secret-key and note it down

```bash
python3 /var/www/acme2certifier/tools/django_secret_keygen.py
+%*lei)yj9b841=2d5(u)a&7*uwi@l99$(*&ong@g*p1%q)g$e
```

- modify `/var/www/acme2certifier/acme2certifier/settings.py` and
  - insert the secret-key created in the previous step
  - update the 'ALLOWED_HOSTS'- section with both ip-address and fqdn of the node
  - configure a connection to mariadb as shown below


```python
SECRET_KEY = '+%*lei)yj9b841=2d5(u)a&7*uwi@l99$(*&ong@g*p1%q)g$e'
...
ALLOWED_HOSTS = ['192.168.14.132', 'ub2204-c1.bar.local']
...

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'acme2certifier',
        'USER': 'acme2certifier',
        'PASSWORD': 'a2cpasswd',
        'HOST': "ub2204-c1",
        'OPTIONS': {"init_command": "SET sql_mode='STRICT_TRANS_TABLES', innodb_strict_mode=1","charset": "utf8mb4", "use_unicode": True},
    },

}
```

- Modify the [configuration file](acme_srv.md) `/var/www/acme2certifier/volume/acme_srv.cfg`according to you needs. If your ca-handler needs runtime information (configuration files, keys, certificate-bundles etc.) to be shared between the nodes make sure that they get loaded from `/var/www/acme2certifier/volume`. Below an example for the `[CAhandler]` section of the openssl-handler I use during my tests:

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

- create a django migration set, apply the migrations and load fixtures

```bash
cd /var/www/acme2certifier
sudo python3 manage.py makemigrations
sudo python3 manage.py migrate
sudo python3 manage.py loaddata acme_srv/fixture/status.yaml
```

- run the django_update script

```bash
sudo python3 /var/www/acme2certifier/tools/django_update.py
```

- restart the apache2 service

```bash
sudo systemctl restart apache2.service
```

- Test the server by accessing the directory resource

```bash
curl http://ub2204-c1.bar.local/directory
{"newAccount": "http://ub2204-c1.bar.local/acme_srv/newaccount", "fa8b347d3849421ebc4b234205418805": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417", "keyChange": "http://ub2204-c1.bar.local/acme_srv/key-change", "newNonce": "http://ub2204-c1.bar.local/acme_srv/newnonce", "meta": {"home": "https://github.com/grindsa/acme2certifier", "author": "grindsa <grindelsack@gmail.com>"}, "newOrder": "http://ub2204-c1.bar.local/acme_srv/neworders", "revokeCert": "http://ub2204-c1.bar.local/acme_srv/revokecert"}
```

### on ub2204-c2

- generate a new django secret and note it down

```bash
python3 /var/www/acme2certifier/tools/django_secret_keygen.py
5@@wlvvi!hb(6qc%*77j55@jt8ib4^f1o&+pz-^z*#v3e7u3o!
```

- modify `/var/www/acme2certifier/acme2certifier/settings.py` and
  - insert a secret key created in the previous step
  - update the 'ALLOWED_HOSTS'- section with both IP-Adress and fqdn of the node
  - configure a connection to mariadb as shown below

```python
SECRET_KEY = '5@@wlvvi!hb(6qc%*77j55@jt8ib4^f1o&+pz-^z*#v3e7u3o!'
...
ALLOWED_HOSTS = ['192.168.14.133', 'ub2204-c2.bar.local']
...

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'acme2certifier',
        'USER': 'acme2certifier',
        'PASSWORD': 'a2cpasswd',
        'HOST': "ub2204-c2",
        'OPTIONS': {"init_command": "SET sql_mode='STRICT_TRANS_TABLES', innodb_strict_mode=1","charset": "utf8mb4", "use_unicode": True},
    },

}
```

- restart the apache2 service

```bash
sudo systemctl restart apache2.service
```

- Test the server by accessing the directory resource

```bash
curl http://ub2204-c2.bar.local/directory
{"newAccount": "http://ub2204-c2.bar.local/acme_srv/newaccount", "fa8b347d3849421ebc4b234205418805": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417", "keyChange": "http://ub2204-c2.bar.local/acme_srv/key-change", "newNonce": "http://ub2204-c2.bar.local/acme_srv/newnonce", "meta": {"home": "https://github.com/grindsa/acme2certifier", "author": "grindsa <grindelsack@gmail.com>"}, "newOrder": "http://ub2204-c2.bar.local/acme_srv/neworders", "revokeCert": "http://ub2204-c2.bar.local/acme_srv/revokecert"}
```

## Test enrollment

- try to enroll certificates from both nodes by using your favorite acme-client. I am using [lego](https://github.com/go-acme/lego) as this client supports multiple endpoints at once.

- Example for enrollment from ub2204-c1

```bash
 docker run -i -p 80:80 -v $PWD/lego:/.lego/ --rm --name lego --network acme goacme/lego -s http://ub2204-c1.bar.local -a --email "lego@example.com" -d lego01.bar.local --http run
```

- Example for enrollment from ub2204-c2

```bash
 docker run -i -p 80:80 -v $PWD/lego:/.lego/ --rm --name lego --network acme goacme/lego -s http://ub2204-c2.bar.local -a --email "lego@example.com" -d lego01.bar.local --http run
```