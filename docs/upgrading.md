<!-- markdownlint-disable MD013 MD029 -->

<!-- wiki-title Upgrading acme2certifier -->

# Upgrading acme2certifier

For the package-layout restructuring (`acme2certifier.acme_srv`, module-based handler loading, and deprecation of `*_file` config keys), see [Package layout migration](migration_package_layout.md). Compatibility shims and `*_file` keys are planned for removal in **acme2certifier 1.0**.

## Upgrade to Version 0.17

In **acme2certifier v0.17**, the `acme` module (which implements ACME server functionality) has been **renamed** to `acme_srv`.

This renaming was done to **avoid naming conflicts** with [acme-python](https://acme-python.readthedocs.io/en/stable/) and affects **acme2certifier deployments running as Django projects**, as the Django application must be renamed, and the **database schema** must be updated.

### Automatic Upgrade for Container-Based Deployments

If you are using the **prebuilt Django containers** running on **Apache2** or **NGINX**, the necessary modifications will be **applied automatically** when deploying the updated containers:

[acme2certifier Django Containers](https://hub.docker.com/repository/docker/grindsa/acme2certifier/)

### Manual Upgrade for Custom Django Deployments

If you installed **acme2certifier** manually as a **Django project**, follow these steps:

### 1. Download and Extract the v0.17 Archive

```bash
cd /var/www/acme2certifier
wget <new_version_url> -O acme2certifier-0.17.tar.gz
tar -xzf acme2certifier-0.17.tar.gz
```

### 2. Install `django-rename-app`

```bash
pip install django-rename-app
```

### 3. Modify `settings.py`

Edit your **Django settings** file (usually found at `/var/www/acme2certifier/acme2certifier/settings.py`) and rename the existing `acme` app to `acme_srv`:

```python
INSTALLED_APPS = [
    ...
    'acme_srv',
    ...
]
```

### 4. Rename the App

```bash
python manage.py rename_app acme acme_srv
```

### 5. Update Configuration and Handlers

```bash
cp acme/acme_srv.cfg acme_srv/acme_srv.cfg
cp examples/db_handler/django_handler.py acme_srv/db_handler.py

# Prefer handler_module in acme_srv.cfg, for example:
#   handler_module: acme2certifier.cahandlers.openssl_ca_handler
# Legacy handler_file / copy-to-acme_srv/ca_handler.py remain supported but deprecated.
# See docs/migration_package_layout.md
```

### 6. Start acme2certifier and Verify

```bash
systemctl restart acme2certifier
curl http[s]://<acme-srv>/directory
```

### 7. Cleanup

Once the upgrade is verified, remove the old `acme` directory:

```bash
rm -rf acme
```

Your acme2certifier instance is now successfully upgraded to v0.17! 🚀
