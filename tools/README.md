# Tools

CLI and maintenance utilities live in the package. After `pip install .`:

```bash
a2c-cli
a2c-db-update
a2c-django-update
a2c-django-secret-keygen
a2c-eab-chk -c /path/to/acme_srv.cfg -v
a2c-cert-poll
a2c-cliuser-mgmt --list
a2c-invalidator
a2c-report-generator
```

You can also run modules directly (names match the CLI scripts):

```bash
python3 -m acme2certifier.tools.a2c_db_update
python3 -m acme2certifier.tools.a2c_django_update
python3 -m acme2certifier.tools.a2c_eab_chk -c /path/to/acme_srv.cfg -v
python3 -m acme2certifier.tools.a2c_cert_poll
```

Repo-local helpers (not installed):

```bash
tools/check_test_naming.py
tools/make_test_cas.sh   # throwaway CAs for cert_chain_append tests
```

Example configs and skeletons ship as package data under `acme2certifier/share/` (importable via `importlib.resources`).
