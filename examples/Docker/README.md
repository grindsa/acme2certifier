<!-- markdownlint-disable  MD013 -->
<!-- wiki-title Containerized installation using apache2 or nginx as webserver and wsgi or django -->
# Containerized installation using apache2 or nginx as webserver and wsgi or django

This should be the fastest and most convenient way to deploy acme2certifier. After installation acme2certifier will run inside a minimalized ubunbtu 20.04 container using either apache2 or nginx as webserver.

Acme2certifier needs to store its database (`acme_srv.db`), ca_handler (`ca_handler.py`) and configuration file (`acme_srv.cfg`) on a persistent data-storage. By default those files are attached to data/ folder and will get mounted inside the container to `/var/www/acme2certifier/volume`. The data folder path can be adjusted in [`docker-compose.yml`](https://github.com/grindsa/acme2certifier/blob/master/examples/Docker/docker-compose.yml) to fit your setup.

By default acme2certifier will run on ports 22280 (http) and 22443 (https optional). These two ports must be exported as ports 80 and 443 to make the a2c-services accessible from outside.

`.env` contains options to switch between master or devel branch, choose between wsgi or django and to select the webserver (apache2 or nginx)

```config
COMPOSE_PROJECT_NAME=acme2certifier
BRANCH=master
CONTEXT=wsgi
WEBSERVER=apache2
```

## Building the docker-compose

```bash
user@docker-host:~/acme2certifier/examples/Docker$ docker-compose build --no-cache
Building srv
Step 1/17 : FROM ubuntu:20.04
 ---> 1d622ef86b13
Step 2/17 : LABEL maintainer="grindelsack@gmail.com"
 ---> Running in 03f043052bc9
Removing intermediate container 03f043052bc9
...
```

## Setting the timezone

By default containers will use UTC as their timezone. This can be fairly inconvenient when trying to correlate logs. As such you can set the timezone for the container by creating a docker-compose.override.yaml file with the following contents:

```yml
version: '3.2'
services:
  acme-srv:
    environment:
      TZ: "Your/Timezone"
```

[List of Timezones](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones)

## Start acme2certifier

`user@docker-host:~/acme2certifier/examples/Docker$ docker-compose up -d`

Whenever changes in `.env` are made, another build is required:

`user@docker-host:~/acme2certifier/examples/Docker$ docker-compose build --no-cache`

The entry-point script will check during the start process if a configuration file and a ca_handler in data/. If these files do not exist the below examples will be copied to the docker image.

- [acme_srv.cfg file](../../examples/acme_srv.cfg) from the example directory
- [stub_handler](../../examples/ca_handler/skeleton_ca_handler.py) from the example/ca-handler directory

In case your are running acme2certifer as django project a project specific `settings.py` will be created and also be stored in data/

The container should be visible in the list of active containers

```bash
user@docker-host:~/acme2certifier/examples/Docker$ docker-compose ps
        Name                      Command               State                       Ports
-------------------------------------------------------------------------------------------------------------
acme2certifier_srv_1   /docker-entrypoint.sh /usr ...   Up      0.0.0.0:22443->443/tcp, 0.0.0.0:22280->80/tcp
```

Its should already be possible to access the directory Resources of our acme2certifer container:

```bash
user@docker-host:~/acme2certifier/examples/Docker$ docker run -it --rm --network acme curlimages/curl http://acme-srv/directory | python -m json.tool
{
    "6a01d6abe3a84de2831d24aa5451b3a2": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417",
    "keyChange": "http://acme2certifier_srv_1/acme_srv/key-change",
    "meta": {
        "author": "grindsa <grindelsack@gmail.com>",
        "home": "https://github.com/grindsa/acme2certifier",
        "name": "acme2certifier",
        "version": "0.9-dev"
    },
    "newAccount": "http://acme2certifier_srv_1/acme_srv/newaccount",
    "newAuthz": "http://acme2certifier_srv_1/acme_srv/new-authz",
    "newNonce": "http://acme2certifier_srv_1/acme_srv/newnonce",
    "newOrder": "http://acme2certifier_srv_1/acme_srv/neworders",
    "revokeCert": "http://acme2certifier_srv_1/acme_srv/revokecert"
}
```

Configuration file, ca_handler and (optionally) settings.py must be modified according to your setup.

To reload the modified files the container should be restarted.

`user@docker-host:~/acme2certifier/examples/Docker$ docker-compose restart`

Try to enroll a certificate by using your favorite acme-client. If it fails check the configuration of your ca_handler, logs and enable [debug mode](../../docs/acme_srv.md) in acme2certifier for further investigation.

## TLS support when using apache2

In case you would like to enable TLS-support in acme2certifer please place a file acme2certifier.pem on the volume. This file must contain the following certificate data in pem format:

- the private key
- the end-entity certificate
- intermediate CA certificates, sorted from leaf to root. The root CA certificate should not be included for security reasons.

```key
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

## TLS support when using nginx

To enable TLS-support in nginx please place two files `acme2certifier_cert.pem` and `acme2certifier_key.pem` on the volume. `acme2certifier_cert.pem` must contain the certificate to be used while `acme2certifier_key.pem` must contain the corresponding private key. Certificate and key must be stored in pem format.

## Run acme2certifier without using docker-compose

The below command will run an a2c container and

- map internal port 22280 to outside port 80
- map internal port 22443 to outside port 443
- mount the directory `/home/grindsa/docker/a2c/data` into the container to store database and configuration files

`user@docker-host:~/acme2certifier/examples/Docker$ docker run -d -p 80:22280 -p 443:22443 --rm --name=a2c-srv -v "/home/grindsa/docker/a2c/data":/var/www/acme2certifier/volume/ grindsa/acme2certifier:apache2-wsgi`
