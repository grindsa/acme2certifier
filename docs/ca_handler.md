<!-- markdownlint-disable MD013 -->

<!-- wiki-title How to Create Your Own CA Handler -->

# How to Create Your Own CA Handler

Built-in CA handlers ship as package modules. Prefer configuring them with `handler_module` (for example `acme2certifier.cahandlers.openssl_ca_handler`). For a custom out-of-tree handler, set `handler_module` to the **filesystem path** of the `.py` file The older `handler_file` option is **deprecated** but still supported; see [Upgrading](upgrading.md).

Creating your own CA handler should be straightforward. All you need to do is create a Python module with a `CAhandler` class that contains the following methods required by `acme2certifier`:

- **`enroll`**: Enrolls a new certificate from the CA server.
- **[`poll`](poll.md)**: Polls a pending certificate request from the CA server.
- **`revoke`**: Revokes an existing certificate on the CA server.
- **[`trigger`](trigger.md)**: Processes triggers sent by the CA server.

The [`skeleton_ca_handler.py`](../acme2certifier/share/skeletons/ca_handler/skeleton_ca_handler.py) file provides a template that you can use to create customized CA handlers.

## Custom handlers: path or package

`handler_module` accepts either:

| Value | How it loads |
| --- | --- |
| Dotted import path | `importlib.import_module` (built-ins and installed packages) |
| Filesystem path (absolute, relative with `/`, or ending in `.py`) | Load from that file (recommended for customer handlers) |

**Out-of-tree / Docker volume (recommended for custom code):**

```ini
[CAhandler]
handler_module: /var/www/acme2certifier/volume/ca_handler.py
```

Place the file on the volume (or any readable path), fix imports to `from acme2certifier.acme_srv.helper import …`, and point `handler_module` at it. No package layout, no `PYTHONPATH` export.

**Built-in or installable package:**

```ini
[CAhandler]
handler_module: acme2certifier.cahandlers.openssl_ca_handler
# or: myorg.handlers.custom_ca_handler
```

Until **1.0**, `handler_file: /path/to/handler.py` still works but emits a deprecation warning — migrate to `handler_module` with the same path.

The following skeleton outlines the input parameters received by `acme2certifier`, as well as the expected return values:

```python
class CAhandler:
    """CA handler"""

    def __init__(self, debug=None, logger=None):
        """
        Input:
            debug - Debug mode (True/False)
            logger - Log handler
        """
        self.debug = debug
        self.logger = logger

    def __enter__(self):
        """Makes CAhandler a context manager"""
        return self

    def __exit__(self, *args):
        """Closes the connection at the end of the context"""
        pass

    def enroll(self, csr):
        """Enrolls a certificate"""
        # Input:
        #     csr - CSR in PKCS#10 format

        # Output:
        #     error - Error message during certificate enrollment (None if no error occurred)
        #     cert_bundle - Certificate chain in PEM format
        #     cert_raw - Certificate in ASN.1 (binary) format, base64 encoded
        #     poll_identifier - Callback identifier to track enrollment requests when the CA server does not
        #                       issue certificates immediately.

        self.logger.debug("Certificate.enroll()")
        ...
        self.logger.debug("Certificate.enroll() ended")
        return None, None, None, None

    def poll(self, cert_name, poll_identifier, csr):
        """Polls the status of a pending CSR and downloads certificates"""
        # Input:
        #     cert_name - Certificate resource name
        #     poll_identifier - Poll identifier
        #     csr - Certificate Signing Request

        # Output:
        #     error - Error message during certificate polling (None if no error occurred)
        #     cert_bundle - Certificate chain in PEM format
        #     cert_raw - Certificate in ASN.1 (binary) format, base64 encoded
        #     poll_identifier - Updated callback identifier for future lookups
        #     rejected - Indicates whether the request has been rejected by the CA administrator.

        self.logger.debug("CAhandler.poll()")
        ...
        return None, None, None, None, False

    def revoke(self, cert, rev_reason="unspecified", rev_date=None):
        """Revokes a certificate"""
        # Input:
        #     cert - Certificate in PEM format
        #     rev_reason - Revocation reason
        #     rev_date - Revocation date

        # Output:
        #     code - HTTP status code to be returned to the client
        #     message - Error message if applicable, None otherwise
        #     detail - Additional error details

        self.logger.debug(f"CAhandler.revoke({rev_reason}: {rev_date})")
        ...
        return 200, None, None

    def trigger(self, payload):
        """Processes triggers sent by the CA server"""
        # Input:
        #     payload - Payload content

        # Output:
        #     error - Error message (if something went wrong)
        #     cert_bundle - Certificate chain in PEM format
        #     cert_raw - Certificate in ASN.1 (binary) format, base64 encoded

        # Handlers that implement a real trigger must also set:
        #     supports_trigger = True
        # on the CAhandler class. Otherwise /trigger stays disabled even when
        # [Trigger] enabled = True in acme_srv.cfg.

        self.logger.debug("CAhandler.trigger()")
        ...
        self.logger.debug("CAhandler.trigger() ended with error: {0}".format(error))
        return (error, cert_bundle, cert_raw)
```

## Additional Customization

You can add additional methods as needed. Additionally, you can configure `acme_srv.cfg` to customize the behavior of the CA handler.

For further details, check [`acme2certifier.cahandlers.certifier_ca_handler`](../acme2certifier/cahandlers/certifier_ca_handler.py), especially the `_config_load()` method.
