<!-- markdownlint-disable  MD013 MD029 -->
<!-- wiki-title upgrading acme2certifier -->
# Upgrading acme2certifier

## Upgrade to version 0.17

The `acme` module whch is implementing acme-server functionality has been renamed in acme2certifier v0.17 to `acme_srv`. Renaming has been done to avoid naming conflicts with  [acme-python](https://acme-python.readthedocs.io/en/stable/) and impacts acme2certifier deployments running as django projects as the django application need to be renamed and the database-scheme needs to be updated.

If you are running the ready-made [django containers](https://hub.docker.com/repository/docker/grindsa/acme2certifier/tags?page=1&ordering=last_updated) using either apache2 or nginx the needed modifications will be done automatically when deploying the new containers.

If you installed acme2certifer manually as django project the following steps need to be done.

1. download and unpack the 0.17 archive in `/var/www/acme2certifier`
2. install the `django-rename-app` by using pip

```bash
root@rlh:~# pip install django-rename-app
```

3. add the app to your Django settings.py (should be stored in `/var/www/acme2certifier/acme2certifier`) and rename the existing `acme` app to `acme_srv`

 ```cfg
 INSTALLED_APPS = [
     ...
     'django_rename_app',
     'acme_srv'
     ...
 ]
 ```

4. rename the app

```bash
root@rlh:~# python manage.py rename_app acme acme_srv
```

5. copy `acme_srv.cfg` from `acme` to `acme_srv` directory
6. copy `examples/db_handler/django_handler.py` to `acme_srv/db_hander.py`
7. copy your ca_handler from `examples/ca_handler` into the `acme_srv` directory if there is no `handler_file` parameter in your `acme_srv.cfg`
6. start acme2certifier and try to query the `directory` ressource

```bash
root@rlh:~# curl http[s]://<acme-srv>/directory
```

7. delete the `acme` directory
