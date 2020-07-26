<!-- markdownlint-disable  MD013 -->
# acme_srv.cfg

## configuration options for acme2certifier

| Section | Option | Description | Values | default|
| :-------| :------| :-----------| :------| :------|
| `DEFAULT` | `debug`  | Debug mode| True/False| False|
| `Account` | `inner_header_nonce_allow` | allow nonce header on inner JWS during key-rollover | True/False | False|
| `Account` | `ecc_only` | mandantes the usage of ECC for account key generation | True/False | False|
| `Account` | `tos_check_disable` | turn off "Terms of Service" acceptance check  | True/False | False|
| `CAhandler` | `handler_file` | path and name of ca_handler file to be loaded. If not specified `acme/ca_handler.py` will be loaded | examples/ca_handler/openssl_hander.py | `acme/ca_handler.py`|
| `Certificate` | `revocation_reason_check_disable` | disable the check of revocation reason | True/False | False|
| `Challenge` | `challenge_validation_disable` | disable challenge validation via http or dns. THIS IS A SEVERE SECURITY ISSUE! Please enable for testing/debugging purposes only. | True/False | False|
| `Challenge` | `dns_server_list` | Use own dns servers for name resolution during challenge verification| ["ip1", "ip2"] | []|
| `Directory` | `supress_version` | Do not show version information when fetching the directory ressource | True/False | False|
| `Directory` | `tos_url` | Terms of Service URL | URL | None|
| `Helper` | `log_format` | Format of logging information | check the 'LogRecord attributes' Section of the [python logging module](https://docs.python.org/3/library/logging.html)| `%(message)s`|
| `Message`| `signature_check_disable` | disable signature check of incoming JWS messages. THIS IS A SEVERE SECURTIY ISSUE bypassing security checks and allowing message manipulations during transit. Please enable for testing/debugging purposes only. | True/False | False|
| `Nonce`| `nonce_check_disable` | disable nonce check. THIS IS A SECURTIY ISSUE as it exposes the API for replay attacks! Should be enabled for testing/debugging purposes only. | True/False | False|
| `Order` | [`tnauthlist_support`](tnauthlist.md) | accept [TNAuthList identifiers](https://tools.ietf.org/html/draft-ietf-acme-authority-token-tnauthlist-03) and challenges containing [tkauth-01 type](https://tools.ietf.org/html/draft-ietf-acme-authority-token-03) | True/False | False|
| `Order` | `retry_after_timeout` | Retry-After value to be send to client in case a certifcate enrollment request gets pending on CA server  | Integer |120|

The options for the `CAHandler` section depend on the CA handler.

Instructions for [Insta Certifier](certifier.md)

Instructions for [NetGuard Certificate Lifecycle Manager](nclm.md)

Instructions for [Microsoft Certification Authority Web Enrollment Service](mscertsrv.md)

Instructions for the [generic EST handler](est.md)

Instructions for the [generic CMPv2 handler](cmp.md)

Instructions for [XCA handler](xca.md)

Instructions for [Openssl based CA handler](openssl.md)
