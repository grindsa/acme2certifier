<!-- markdownlint-disable MD013 MD014 MD029 -->
<!-- wiki-title: Installation on NGINX Running on Alma Linux 9 -->

# Installation on NGINX Running on Alma Linux 9

The setup is designed so that uWSGI serves `acme2certifier`, while NGINX acts as a reverse proxy for better connection handling.

A [ready-made shell script](../examples/install_scripts/a2c-centos9-nginx.sh) performing the tasks below can be found in the `examples/install_scripts` directory.

## 1. Download and Extract the Archive

```bash
cd /tmp
curl https://codeload.github.com/grindsa/acme2certifier/tar.gz/refs/heads/master -o a2c-master.tgz
tar xvfz a2c-master.tgz
cd /tmp/acme2certifier-master
```

## 2. Install Required Packages

```bash
sudo yum install -y epel-release
sudo yum update -y
sudo yum install -y python-pip nginx python3-uwsgidecorators.x86_64 tar uwsgi-plugin-python3 policycoreutils-python-utils
```

## 3. Set Up the Project Directory

```bash
sudo mkdir /opt/acme2certifier
```

## 4. Install Required Python Modules

```bash
sudo pip install -r /opt/acme2certifier/requirements.txt
```

## 5. Configure `acme2certifier`

1. Create a configuration file `acme_srv.cfg` in `/opt/acme2certifier/acme_srv/`, or use the example stored in the `examples` directory.
2. Modify the [configuration file](acme_srv.md) according to your needs.
3. Set the `handler_file` parameter in `acme_srv.cfg`, or copy the appropriate CA handler from `/opt/acme2certifier/examples/ca_handler/` to `/opt/acme2certifier/acme_srv/ca_handler.py`.
4. Configure the connection to your CA server. [Example for Insta Certifier](certifier.md).

## 6. Activate the WSGI Database Handler

```bash
sudo cp /opt/acme2certifier/examples/db_handler/wsgi_handler.py /opt/acme2certifier/acme_srv/db_handler.py
```

## 7. Copy the WSGI Application File

```bash
sudo cp /opt/acme2certifier/examples/acme2certifier_wsgi.py /opt/acme2certifier/
```

## 8. Set Correct Permissions

```bash
sudo chmod a+x /opt/acme2certifier/acme_srv
sudo chown -R nginx /opt/acme2certifier/acme_srv
```

## 9. Test `acme2certifier` by Starting the Application

```bash
cd /opt/acme2certifier
sudo uwsgi --http-socket :8000 --plugin python3 --wsgi-file acme2certifier_wsgi.py
```

## 10. Verify Directory Access

Run the following command in a parallel session to confirm that everything is working:

```bash
curl http://127.0.0.1:8000/directory
```

Expected response:

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

## 11. Set Up uWSGI

1. Create a uWSGI configuration file, or use the one stored in `examples/nginx`:

```bash
sudo cp examples/nginx/acme2certifier.ini /opt/acme2certifier
```

2. Enable the Python3 module in the uWSGI configuration file:

```bash
echo "plugins = python3" | sudo tee -a examples/nginx/acme2certifier.ini
```

3. Create a Systemd Unit File for uWSGI, or use the one in `examples/nginx`:

```bash
sudo cp examples/nginx/uwsgi.service /etc/systemd/system/
sudo systemctl enable uwsgi.service
```

4. Start uWSGI as a service:

```bash
sudo systemctl start uwsgi
```

## 12. Configure NGINX as a Reverse Proxy

1. Use the example stored in `examples/nginx` and modify it as needed:

```bash
sudo cp examples/nginx/nginx_acme.conf /etc/nginx/conf.d/acme.conf
```

2. Restart NGINX:

```bash
sudo systemctl restart nginx
```

## 13. Adapt SELinux Configuration

Apply a customized policy to allow NGINX to communicate with uWSGI over Unix sockets:

```bash
sudo checkmodule -M -m -o acme2certifier.mod examples/nginx/acme2certifier.te
sudo semodule_package -o acme2certifier.pp -m acme2certifier.mod
sudo semodule -i acme2certifier.pp
```

## 14. Test the Server

```bash
curl http://<your-server-name>/directory
```

The above command may result in an error if the SELinux configuration still needs adjustment.
