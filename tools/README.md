# Tools

CLI and maintenance utilities now live in the package:

```bash
python3 -m acme2certifier.tools.<name> [args...]
```

Examples:

```bash
python3 -m acme2certifier.tools.db_update
python3 -m acme2certifier.tools.django_update
python3 -m acme2certifier.tools.eab_chk -c /path/to/acme_srv.cfg -v
python3 -m acme2certifier.tools.cert_poll
```
