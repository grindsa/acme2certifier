<!-- markdownlint-disable MD013 -->
<!-- wiki-title Proxy Support in acme2certifier -->
# Proxy Support in acme2certifier

Proxy support was introduced in **acme2certifier** version **0.18**.

Currently, both **HTTP** and **SOCKS5** proxies are supported for:

- **Validation of HTTP and TLS-ALPN challenges**
- **Usage in the following CA handlers:**
  - `certifier_ca_handler.py`
  - `est_ca_handler.py`
  - `mscertsrv_ca_handler.py`

## Configuration

Proxies are configured in `acme_srv/acme_srv.cfg` and must be set **per destination**.

Example configuration:

```ini
[DEFAULT]
debug: True
proxy_server_list: {"bar.local$": "socks5://proxy.dmn:1080", "foo.local$": "socks5://proxy.dmn:1080"}
```

### Supported Destination Formats

A **destination** can be defined as:

- A **TLD** (e.g., `.local`)
- A **domain name** (e.g., `bar.local`)
- A **fully qualified domain name (FQDN)** (e.g., `foo.bar.local`)

### Wildcards and Regular Expressions

- Wildcards are supported:
  Example: `host*.bar.local`
- Regular expressions are also supported:
  Example: `^hostname.bar.local$`

### Global Proxy Configuration

To configure a proxy for **all outbound connections**, use a **single asterisk (`*`)**:

```ini
proxy_server_list: {"*": "socks5://proxy.dmn:1080"}
```
