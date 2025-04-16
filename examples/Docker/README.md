<!-- markdownlint-disable MD013 -->
<!-- wiki-title Containerized Installation Using Apache2 or Nginx as Web Server with WSGI or Django -->
# Containerized Installation Using Apache2 or Nginx as Web Server with WSGI or Django

This is the **fastest and most convenient** way to deploy **acme2certifier**. After installation, **acme2certifier** will run inside a **minimal Ubuntu 20.04 container**, using either **Apache2** or **Nginx** as the web server.

## Persistent Storage

**acme2certifier** requires persistent storage for:

- **Database:** `acme_srv.db`
- **CA Handler:** `ca_handler.py`
- **Configuration File:** `acme_srv.cfg`

By default, these files are stored in the **`data/`** folder and mounted inside the container at:

```plaintext
/var/www/acme2certifier/volume
```

The **data folder path** can be modified in [`docker-compose.yml`](https://github.com/grindsa/acme2certifier/blob/master/examples/Docker/docker-compose.yml) to match your setup.

## Ports

By default, **acme2certifier** runs on:

- **HTTP:** Port **22280**  
- **HTTPS:** Port **22443** *(optional)*

To expose these services externally, **map ports 80 and 443** accordingly.

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

---

## Building the Docker Image

```bash
cd ~/acme2certifier/examples/Docker
docker-compose build --no-cache
```

Expected output:

```bash
Building srv
Step 1/17 : FROM ubuntu:20.04
 ---> 1d622ef86b13
Step 2/17 : LABEL maintainer="grindelsack@gmail.com"
 ---> Running in 03f043052bc9
Removing intermediate container 03f043052bc9
...
```

---

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

---

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

---

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

---

## Enrolling a Certificate

Use your preferred **ACME client**. If enrollment fails:

1. **Check the CA handler configuration.**
2. **Review logs.**
3. **Enable [debug mode](../../docs/acme_srv.md) in acme2certifier.**

---

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

---

## Enabling TLS (Nginx)

For **Nginx**, place the following files in the volume:

- **`acme2certifier_cert.pem`** – Certificate file
- **`acme2certifier_key.pem`** – Private key

Both must be in **PEM format**.

---

## Running acme2certifier Without Docker-Compose

You can run the **container manually** with:

```bash
docker run -d -p 80:22280 -p 443:22443 --rm --name=a2c-srv   -v "/home/grindsa/docker/a2c/data":/var/www/acme2certifier/volume/   grindsa/acme2certifier:apache2-wsgi
```

This will:

- **Map internal port 22280** to **external port 80**.
- **Map internal port 22443** to **external port 443**.
- **Mount the `data/` directory** for persistent storage.

---

### 🎉 Congratulations! acme2certifier is now running in a containerized environment! 🚀
