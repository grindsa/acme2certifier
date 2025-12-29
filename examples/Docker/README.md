<!-- markdownlint-disable MD013 -->

<!-- wiki-title Containerized Installation Using Apache2 or Nginx as Web Server with WSGI or Django -->

# Containerized Installation Using Apache2 or Nginx as Web Server with WSGI or Django

This is the **fastest and most convenient** way to deploy **acme2certifier**. After installation, **acme2certifier** will run inside a **minimal Ubuntu 24.04 container**, using either **Apache2** or **Nginx** as the web server.

## Persistent Storage

**acme2certifier** requires persistent storage for:

- **Configuration File:** `acme_srv.cfg`
- **Customized CA Handlers or runtime data (files and directories) belonging to CA handlers:** `ca_handler.py`
- **Database:** `acme_srv.db` (in case of WSGI installations)
- **Django migration sets** (in case of Django based deployments)

By default, these files are stored in the **`data/`** folder and mounted inside the container at:

```plaintext
/var/www/acme2certifier/volume
```

The **data folder path** can be modified in [`docker-compose.yml`](https://github.com/grindsa/acme2certifier/blob/master/examples/Docker/docker-compose.yml) to match your setup.

## Ports

By default, **acme2certifier** exposes its web services on the following ports **inside the container**:

- **HTTP:** Port **80**
- **HTTPS:** Port **443** (optional, enabled if certificate and key are present)

You can map these internal ports to any available ports on your host system using Docker’s port mapping. For example, in `docker-compose.yml`:

```yaml
ports:
  - "22280:80"   # Maps host port 22280 to container port 80 (HTTP)
  - "22443:443"  # Maps host port 22443 to container port 443 (HTTPS)
```

You may also use the default ports:

```yaml
ports:
  - "80:80"
  - "443:443"
```

**Note:**

- The container does **not** expose ports 22280 or 22443 internally; these are just example host ports for mapping.
- HTTPS (port 443) will only be available if both `acme2certifier_cert.pem` and `acme2certifier_key.pem` are present in `/var/www/acme2certifier/volume`.

## Configuration via `.env`

The `.env` file allows customization, including:

- **Branch Selection:** `master` or `devel`
- **Context:** `wsgi` or `django`
- **Web Server:** `apache2` or `nginx`

Example `.env` file:

```ini
COMPOSE_PROJECT_NAME=acme2certifier
BRANCH=master
CONTEXT=wsgi
WEBSERVER=apache2
```

______________________________________________________________________

## Building the Docker Image

```bash
cd ~/acme2certifier/examples/Docker
docker-compose build --no-cache
```

Expected output:

```bash
Building srv
Step 1/17 : FROM ubuntu:24.04
 ---> 1d622ef86b13
Step 2/17 : LABEL maintainer="grindelsack@gmail.com"
 ---> Running in 03f043052bc9
Removing intermediate container 03f043052bc9
...
```

______________________________________________________________________

## Setting the Timezone

Containers default to **UTC**, which can make log correlation difficult. To set a custom timezone, create a `docker-compose.override.yml` file:

```yaml
version: '3.2'
services:
  acme-srv:
    environment:
      TZ: "Your/Timezone"
```

[List of Timezones](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones)

______________________________________________________________________

## Starting acme2certifier

```bash
docker-compose up -d
```

If you modify `.env`, rebuild the image:

```bash
docker-compose build --no-cache
```

During startup, the **entry-point script** checks for missing configuration files in `data/`:

- **Configuration file:** [`acme_srv.cfg`](../../examples/acme_srv.cfg)
- **Stub handler:** [`skeleton_ca_handler.py`](../../examples/ca_handler/skeleton_ca_handler.py)

For **Django-based deployments**, a **project-specific `settings.py`** will also be created in `data/`.

______________________________________________________________________

## Verifying the Container

Check if the container is running:

```bash
docker-compose ps
```

Expected output:

```plaintext
        Name                      Command               State                       Ports
-------------------------------------------------------------------------------------------------------------
acme2certifier_srv_1   /docker-entrypoint.sh /usr ...   Up      0.0.0.0:22443->443/tcp, 0.0.0.0:22280->80/tcp
```

Test the **ACME directory endpoint**:

```bash
docker run -it --rm --network acme curlimages/curl http://acme-srv/directory | python -m json.tool
```

Expected output:

```json
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

### Restarting the Container

If you modify `acme_srv.cfg`, `ca_handler.py`, or `settings.py`, restart the container:

```bash
docker-compose restart
```

______________________________________________________________________

## Enrolling a Certificate

Use your preferred **ACME client**. If enrollment fails:

1. **Check the CA handler configuration.**
1. **Review logs.**
1. **Enable [debug mode](../../docs/acme_srv.md) in acme2certifier.**

______________________________________________________________________

## Enabling TLS (Apache2)

To enable **TLS support**, place `acme2certifier.pem` in the volume. It must contain:

- **Private key**
- **End-entity certificate**
- **Intermediate CA certificates** (from **leaf to root**; do **not** include the root CA)

Example:

```pem
-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
End-entity certificate data
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
Intermediate CA certificate(s)
-----END CERTIFICATE-----
```

______________________________________________________________________

## Enabling TLS (Nginx)

For **Nginx**, place the following files in the volume:

- **`acme2certifier_cert.pem`** – Certificate file
- **`acme2certifier_key.pem`** – Private key

Both must be in **PEM format**.

______________________________________________________________________

## Running acme2certifier Without Docker-Compose


You can run the **container manually** with:

```bash
docker run -d -p 22280:80 -p 22443:443 --rm --name=a2c-srv   -v "/home/grindsa/docker/a2c/data":/var/www/acme2certifier/volume/   grindsa/acme2certifier:apache2-wsgi
```

This will:

- **Map internal port 80** to **external port 22280**.
- **Map internal port 443** to **external port 22443**.
- **Mount the `data/` directory** for persistent storage.

______________________________________________________________________

### 🎉 Congratulations! acme2certifier is now running in a containerized environment! 🚀
