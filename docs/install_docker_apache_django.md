# Containerized docker installation using apache2 as webserver

You should run acme2certifier as django project if you are planning to use a different database than sqlite3.  I am using with a MariaDB as backend database.

After installation acme2certifier will run inside a minimalized ubunbtu 18.04 container using apache2 as webserver.

It is expected that the database server is up and running before acme2certifier gets installed. Further the acme2certifier database must be created and a user database user has been created.

As example: database and dbuser can be created on the database server by using the following commands.

```
MariaDB [(none)]> CREATE DATABASE acme2certifier CHARACTER SET UTF8;
MariaDB [(none)]> GRANT ALL PRIVILEGES ON acme2certifier.* TO 'acme2certifier'@'%' IDENTIFIED BY '<password>';
MariaDB [(none)]> FLUSH PRIVILEGES;
```
Acme2certifier needs to store ca_handler (`ca_handler.py`) and configuration file (`acme_srv.cfg`) on a persistent data-storage. Thus, it is recommended to create a volume and mount it during the start of the container.

The volume can be created with the below command.

`root@docker-test:~# docker volume create --name acme2certifier`

I am not planning to provide readymade container images as I do not have the bandwidth to maintain them. Instead, the files and scripts you need to create a container are part of the git repository. 

You can download them by using the link below.

`root@docker-test:~# curl https://raw.githubusercontent.com/grindsa/acme2certifier/master/examples/docker_django.tgz --output docker_django.tgz`

After download the archive must be unpacked.

`root@docker-test:~# tar xvfz docker_django.tgz`

After entering the directory 

`root@docker-test:~# cd acme2certifier`

You can build the container 

`root@docker-test:/home/grindsa/acme2certifier# docker build -t acme2certifier .`

All components needed to create the container will be downloaded automatically. The time to build the container depends from quality and speed of your internet connection but should not take more than 15 min.

If the container creation completed without errors the container can be started by using the command below.

`root@docker-test:/home/grindsa/acme2certifier# docker run -p 80:80 -p 443:443 -v acme2certifier:/var/www/acme2certifier/volume --name=acme2certifier --restart=always -d acme2certifier`

The entry-point script will check during the start process if a configuration file and a ca_handler do exist on the volume. If these files do not exist the below examples will be copied to the volume.

- [acme_srv.cfg file](/examples/acme_srv.cfg) from the example directory
- [stub_handler](/examples/ca_handler/skeleton_ca_handler.py) from the example/ca-handler directory
- [settings.py](/example/django/acme2certifier/settings.py) from the example/django/acme2certifier/settings.py

The container should be visible in the list of active containers

```
root@docker-test:/home/grindsa/acme2certifier# docker ps -a
CONTAINER ID        IMAGE                 COMMAND                  CREATED             STATUS              PORTS                                      NAMES
db925fc41668        acme2certifier        "/docker-entrypoint.…"   13 seconds ago      Up 12 seconds       0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp   acme2certifier
```

Its should already be possible to access the directory Ressource (192.168.14.133 is the IP of my container-host and must be modified according to your setup)

```
root@ub18-04:~# curl http://192.168.14.133/directory
{"newAuthz": "http://192.168.14.133/acme/new-authz", "newNonce": "http://192.168.14.133/acme/newnonce", "newAccount": "http://192.168.14.133/acme/newaccount", "newOrder": "http://192.168.14.133/acme/neworders", "revokeCert": "http://192.168.14.133/acme/revokecert", "keyChange": "http://192.168.14.133/acme/key-change", "meta": {"home": "https://github.com/grindsa/acme2certifier", "author": "grindsa <grindelsack@gmail.com>", "name": "acme2certifier", "version": "0.8"}, "09e7bda62ca443cfb495ca6e36469556": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417"}root@ub18-04:~#
```

Now `settings.py`, configuration file and ca_handler must be modified according to your setup.

The follow parameters must be modified in `settings.py`
```
SECRET_KEY
ALLOWED_HOSTS
DATABASES
```

In case you would like to enable ssl-support in acme2certifer please place a file acme2certifier.pem on the volume. This file must contain the following certificate data in pem format:
- the private key
- the end-entity certificate
- intermediate CA certificates, sorted from leaf to root. The root CA certificate should not be included for security reasons.

```
-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
end-entity certificate data
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
ca certificate(s) data
-----END CERTIFICATE-----
```

To reload the modified files the container should be restarted.

```
root@docker-test:/home/grindsa/acme2certifier# docker stop acme2certifier
root@docker-test:/home/grindsa/acme2certifier# docker start acme2certifier
```

Try to enroll a certificate by using your favorite acme-client. If it fails check the configuration of your ca_handler, logs and enable [debug mode](/docs/acme_srv.md) in acme2certifier for further investigation.
