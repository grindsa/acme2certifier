<!-- markdownlint-disable  MD013 -->
<!-- wiki-title Proxy support in  acme2certifier -->
# Proxy support in  acme2certifier

Proxy got introduced along with acme2certifer version 0.18.

As of today both http and socks5 proxies are being supported for:

- validation of http and tls-alpn challenges
- usage in following ca handlers:
  - `certifier_ca_handler.py`
  - `est_ca_handler.py`  
  - `mscertsrv_ca_handler.py`

Proxies will be configured in `acme_srv/acme_srv.cfg` and need to be set per destination:

```cfg
[DEFAULT]
debug: True
proxy_server_list: {"bar.local$": "socks5://proxy.dmn:1080", "foo.local$": "socks5://proxy.dmn:1080"}
```

Destination can be:

- a tld like `.local`
- a domain name like `bar.local`
- an fqdn like `foo.bar.local`

The usage of wildcards (`host*.bar.local`) and regular expressions (`^hostname.bar.local$`) is also supported. To configure a proxy for all outbound connections please use a single asterisk `{"*": "socks5://proxy.dmn:1080"}`
