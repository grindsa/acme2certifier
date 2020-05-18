# acme-srv.cfg

## configuration options for acme2certifier


| Section | Option | Description | Values | default|
| :-------| :------| :-----------| :------| :------|
| `DEFAULT` | `debug`  | Debug mode| True/False| False|
| `Account` | `inner_header_nonce_allow` | allow nonce header on inner JWS during key-rollover | True/False | False|
| `Certificate` | `revocation_reason_check_disable` | disable the check of revocation reason | True/False | False|
| `Challenge` | `challenge_validation_disable` | disable challenge validation via http or dns. THIS IS A SEVERE SECURITY ISSUE! Please enable for testing/debugging purposes only. | True/False | False|
| `Directory` | `supress_version` | Do not show version information when fetching the directory ressource | True/False | False|
| `Helper` | `log_format` | Format of logging information | check the 'LogRecord attributes' Section of the [python logging module](https://docs.python.org/3/library/logging.html)| `%(message)s`|
| `Message`| `signature_check_disable` | disable signature check of incoming JWS messages. THIS IS A SEVERE SECURTIY ISSUE bypassing security checks and allowing message manipulations during transit. Please enable for testing/debugging purposes only. | True/False | False|
| `Nonce`| `nonce_check_disable` | disable nonce check. THIS IS A SECURTIY ISSUE as it exposes the API for replay attacks! Should be enabled for testing/debugging purposes only. | True/False | False|
| `Order` | [`tnauthlist_support`](tnauthlist.md) | accept [TNAuthList identifiers](https://tools.ietf.org/html/draft-ietf-acme-authority-token-tnauthlist-03) and challenges containing [tkauth-01 type](https://tools.ietf.org/html/draft-ietf-acme-authority-token-03) | True/False | False|

The options for the `CAHandler` section depend on the CA handler.

Instructions for [Insta Certifier](certifier.md)

Instructions for [NetGuard Certificate Lifecycle Manager](nclm.md)

