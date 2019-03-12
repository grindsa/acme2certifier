# acme-srv.cfg

## configuration options for acme2certifier


| Section | Option | Description | Values | default|
| :-------| :------| :-----------| :------| :------|
| `DEFAULT` | `debug`  | Debug mode| True/False| False|
| `Helper` | `log_format` | Format of logging information | check the 'LogRecord attributes' Section of the [python logging module](https://docs.python.org/3/library/logging.html)| `%(message)s`|
| `Nonce`| `nonce_check_disable` | disable nonce check. THIS IS A SECURTIY ISSUE as it exposes the API for replay attackes! Please do only for testing/debugging purposes | True/False | False|
| `Certificate` | `revocation_reason_check_disable` | disable the check of revocation reason | True/False | False|
| `Challenge` | `challenge_validation_disable` | disable challenge validation via http or dns. THIS IS A SEVERE SECURITY ISSUE! Please do only for testing/debugging purposes | True/False | False|

The options for the `CAHandler` section depend on the CA handler.

Instructions for [Insta Certifier](certifier.md)

Instructions for [NetGuard Certificate Lifecycle Manager](nclm.md)

