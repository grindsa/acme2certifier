<!-- markdownlint-disable  MD013 -->
<!-- wiki-title Configuration options for acme2certifier -->
# acme_srv.cfg

## configuration options for acme2certifier

| Section | Option | Description | Values | default|
| :-------| :------| :-----------| :------| :------|
| `DEFAULT` | `debug`  | Debug mode| True/False| False|
| `DEFAULT` | `proxy_server_list`  | [Proxy-server configuration](proxy_support.md)| {"bar.local$": "http​://10.0.0.1:3128", "foo.local$": "socks5://10.0.0.1:1080"}| None|
| `Account` | `ecc_only` | mandates the usage of ECC for account key generation | True/False | False|
| `Account` | `inner_header_nonce_allow` | allow nonce header on inner JWS during key-rollover | True/False | False|
| `Account` | `tos_check_disable` | turn off "Terms of Service" acceptance check  | True/False | False|
| `Authorization` | `expiry_check_disable` | Disable authorization expiration  | True/False | False|
| `Authorization` | `validity` | authorization validity in seconds  | Integer |86400|
| `CAhandler` | `handler_file` | path and name of ca_handler file to be loaded. If not specified `acme_srv/ca_handler.py` will be loaded | examples/ca_handler/openssl_handler.py | `acme_srv/ca_handler.py`|
| `Certificate` | `revocation_reason_check_disable` | disable the check of revocation reason | True/False | False|
| `Certificate` | `cert_reusage_timeframe` | in case a csr will be resend within this timeframe (in seconds) the  certificate already stored in the database will be returned and no enrollment will be triggered| Integer |0 (disabled)|
| `Certificate` | `enrollment_timeout` | timeout in second for asynchronous ca_handler threat| Integer |5|
| `Challenge` | `challenge_validation_disable` | disable challenge validation via http or dns. THIS IS A SEVERE SECURITY ISSUE! Please enable for testing/debugging purposes only. | True/False | False|
| `Challenge` | `challenge_validation_timeout` | Timeout in seconds for challenge validation | Integer | 10 |
| `Challenge` | `dns_server_list` | Use own dns servers for name resolution during challenge verification| ["ip1", "ip2"] | []|
| `DBhandler` | `dbfile` | path and name of database file. If not specified `acme_srv/acme_srv.db` will be used. Parameter is only available for a wsgi handler and will be ignored if django handler is getting used | 'acme/database.db' | `acme_srv/acme_srv.db`|
| `Directory` | `db_check` | check database connection compare schemes and report as OK/NOK in meta information  | True/False | False|
| `Directory` | `supress_version` | Do not show version information when fetching the directory resource | True/False | False|
| `Directory` | `tos_url` | Terms of Service URL | URL | None|
| `Directory` | `url_prefix` | url prefix for acme2certifier resources | '/foo' | None|
| `Helper` | `log_format` | Format of logging information | check the 'LogRecord attributes' Section of the [python logging module](https://docs.python.org/3/library/logging.html)| `%(message)s`|
| `Hooks` | `hooks_file` | path and name of hooks (for pre- and post-enrollment hooks) file to be loaded |  None |
| `Hooks` | `ignore_pre_hook_failure` | True/False | False |
| `Hooks` | `ignore_post_hook_failure` | True/False | True |
| `Hooks` | `ignore_success_hook_failure` | True/False | False |
| `Message`| `signature_check_disable` | disable signature check of incoming JWS messages. THIS IS A SEVERE SECURITY ISSUE bypassing security checks and allowing message manipulations during transit. Please enable for testing/debugging purposes only. | True/False | False|
| `Nonce`| `nonce_check_disable` | disable nonce check. THIS IS A SECURITY ISSUE as it exposes the API for replay attacks! Should be enabled for testing/debugging purposes only. | True/False | False|
| `Order` | `expiry_check_disable` | Disable order expiration  | True/False | False|
| `Order` | `retry_after_timeout` | Retry-After value to be send to client in case a certificate enrollment request gets pending on CA server  | Integer |120|
| `Order` | [`tnauthlist_support`](tnauthlist.md) | accept [TNAuthList identifiers](https://tools.ietf.org/html/draft-ietf-acme-authority-token-tnauthlist-03) and challenges containing [tkauth-01 type](https://tools.ietf.org/html/draft-ietf-acme-authority-token-03) | True/False | False|
| `Order` | `validity` | Order validity in seconds | Integer |86400|

The options for the `CAhandler` section depend on the CA handler.

Further options for the `Hooks` section depend on the concrete hooks class.

Instructions for [Insta Certifier](certifier.md)

Instructions for [NetGuard Certificate Lifecycle Manager](nclm.md)

Instructions for [Microsoft Certification Authority Web Enrollment Service](mscertsrv.md)

Instructions for the [generic EST handler](est.md)

Instructions for the [generic CMPv2 handler](cmp.md)

Instructions for [XCA handler](xca.md)

Instructions for [Openssl based CA handler](openssl.md)
