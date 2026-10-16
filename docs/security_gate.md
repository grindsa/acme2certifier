<!-- markdownlint-disable MD013 -->

<!-- wiki-title: Security break-glass gate (ACME2CERTIFIER_I_KNOW_THE_RISK) -->
<!-- wiki-category: Configuration -->

# Security break-glass gate (`ACME2CERTIFIER_I_KNOW_THE_RISK`)

Several `acme_srv.cfg` options disable ACME security controls. Those options are **ignored** unless the process environment acknowledges the risk via:

```text
ACME2CERTIFIER_I_KNOW_THE_RISK=1
```

This is intentional fail-closed behavior for lab/CI/interop testing. **Do not set the variable in production** unless you fully understand every option it unlocks.

Accepted values (case-insensitive): `1`, `true`, `yes`, `on`. Any other value (or unset) leaves the gate closed.

The helper lives in `acme2certifier.acme_srv.helpers.security_gate`. Acknowledgement of active disables is typically logged at `CRITICAL` or `ERROR`.

## Gated options

| Area | Option / behavior | Detail |
| :--- | :--- | :--- |
| `[Nonce]` | `signature_check_disable`, `nonce_check_disable` | [acme_srv.cfg](acme_srv.md) |
| `[Challenge]` | `challenge_validation_disable` **without** `forward_address_check` / `reverse_address_check` | [acme_srv.cfg](acme_srv.md) — address-check combo allowed without the env |
| `[EABhandler]` | `eabkid_check_disable` | [EAB](eab.md) |
| `[Trigger]` | `auth_disable` | [Trigger](trigger.md) |
| `[Order]` | `tnauthlist_support` (accept unverified tkauth-01) | [TNAuthList](tnauthlist.md) |
| `[Order]` | `allow_shortname_without_challenge_validation` | [acme_srv.cfg](acme_srv.md), [EAB profiling](eab_profiling.md) |
| `[Order]` | empty `allowed_header_values` (client-selected header params) | [header_info](header_info.md) |
| `[Authorization]` | full-universe `prevalidated_domainlist=["*"]`, IP `/0` | [Identifier prevalidation](identifier_prevalidation.md) |
| Email hooks | SMTP AUTH over cleartext | [Hooks](hooks.md) / `email_hooks` |

Full option text: [acme_srv.cfg reference](acme_srv.md).

## Not gated by this env

- **EAB profile** full-universe prevalidation (`["*"]`, `/0`) — operator-controlled profile store; not unlocked by this variable. See [Identifier prevalidation](identifier_prevalidation.md).
- `[Challenge] challenge_validation_disable` **with** `forward_address_check` or `reverse_address_check` (enterprise client-IP binding).
- Scoped prevalidation (`*.example.com`, `10.0.0.0/8`, …).

Setting the env only to enable an EAB-profile edge case also unlocks every row in the table above — prefer fixing the profile instead.

## How to set it (by deployment)

The variable must be present in the **worker process** environment (Apache mod_wsgi, uWSGI, or container entrypoint). A shell `export` in an unrelated session has no effect.

| Deploy | Persist where | Restart |
| :--- | :--- | :--- |
| **Docker Compose** | `environment:` / `docker-compose.override.yml`, or the compose `env_file` (e.g. `data/django.env`) | recreate the service so env is applied |
| **Apache2** (pip / DEB) | `/etc/apache2/envvars` → `export ACME2CERTIFIER_I_KNOW_THE_RISK=1` | `sudo systemctl restart apache2` |
| **Nginx + uWSGI** (pip / DEB / RPM) | `${APP_ROOT}/acme2certifier.ini` → `env = ACME2CERTIFIER_I_KNOW_THE_RISK=1` | `sudo systemctl restart acme2certifier` |
| **systemd** (optional) | unit drop-in `Environment=` or manager `DefaultEnvironment=` | `daemon-reload` + restart the unit that runs the app |
| **Local / pip CLI** | export in the same shell before `runserver` / `a2c-manage` | n/a |

`${APP_ROOT}` is `/var/www/acme2certifier` (Debian/Ubuntu) or `/opt/acme2certifier` (Alma/RHEL). Persistence paths match [Django deployment environment variables](django_deploy_env.md).

### Docker Compose

```yaml
# docker-compose.override.yml (next to examples/Docker/docker-compose.yml)
services:
  acme-srv:
    environment:
      ACME2CERTIFIER_I_KNOW_THE_RISK: "1"
```

```bash
cd examples/Docker
docker compose up -d --force-recreate --no-build
```

Or add `ACME2CERTIFIER_I_KNOW_THE_RISK=1` to the compose `env_file` (default `./data/django.env`) and recreate.

### Apache2 (mod_wsgi)

```bash
# /etc/apache2/envvars
export ACME2CERTIFIER_I_KNOW_THE_RISK=1
sudo systemctl restart apache2
```

On DEB + Apache2 the ACME app runs under `apache2.service` — env must reach that process (not only a separate uWSGI unit).

### Nginx + uWSGI

```ini
# ${APP_ROOT}/acme2certifier.ini
env = ACME2CERTIFIER_I_KNOW_THE_RISK=1
```

```bash
sudo systemctl restart acme2certifier
```

### systemd drop-in (alternative)

```bash
# example: Environment on the uWSGI unit
sudo systemctl edit acme2certifier.service
```

```ini
[Service]
Environment=ACME2CERTIFIER_I_KNOW_THE_RISK=1
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart acme2certifier
```

For Apache2-only layouts, edit `apache2.service` the same way (or use `/etc/apache2/envvars` as above).

### Local development

```bash
export ACME2CERTIFIER_I_KNOW_THE_RISK=1
# then start runserver / pytest as usual — see development.md
```

## Verify

1. Restart (or recreate) so workers pick up the env.
2. Enable a gated option in `acme_srv.cfg` and confirm acknowledgement in the app log (`CRITICAL` / `ERROR` mentioning `ACME2CERTIFIER_I_KNOW_THE_RISK`).
3. Without the env, the same option stays ignored (warning/error that checks remain enabled).

Process check (Linux):

```bash
# uWSGI unit
tr '\0' '\n' < /proc/$(systemctl show -p MainPID --value acme2certifier)/environ \
  | grep '^ACME2CERTIFIER_I_KNOW_THE_RISK='
```

## Related

- [acme_srv.cfg options](acme_srv.md)
- [Django deployment environment variables](django_deploy_env.md)
- [Docker](install_docker.md) / [examples/Docker](../examples/Docker/README.md)
- [DEB](install_deb.md) · [RPM](install_rpm.md)
- [Apache2 Ubuntu](install_apache2_ubuntu.md) · [Nginx Ubuntu](install_nginx_ubuntu.md) · [Nginx Alma](install_nginx_alma.md)
- [Development environment](development.md)
