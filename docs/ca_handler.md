<!-- markdownlint-disable MD013 -->
<!-- wiki-title How to Create Your Own CA Handler -->

# How to Create Your Own CA Handler

Creating your own CA handler should be straightforward. All you need to do is create a `ca_handler.py` file with a `CAhandler` class that contains the following methods required by `acme2certifier`:

- **`enroll`**: Enrolls a new certificate from the CA server.
- **[`poll`](poll.md)**: Polls a pending certificate request from the CA server.
- **`revoke`**: Revokes an existing certificate on the CA server.
- **[`trigger`](trigger.md)**: Processes triggers sent by the CA server.

The [`skeleton_ca_handler.py`](../examples/ca_handler/skeleton_ca_handler.py) file provides a template that you can use to create customized CA handlers.

The following skeleton outlines the input parameters received by `acme2certifier`, as well as the expected return values:

```python
class CAhandler:
    """ CA handler """

    def __init__(self, debug=None, logger=None):
        """
        Input:
            debug - Debug mode (True/False)
            logger - Log handler
        """
        self.debug = debug
        self.logger = logger

    def __enter__(self):
        """ Makes CAhandler a context manager """
        return self

    def __exit__(self, *args):
        """ Closes the connection at the end of the context """
        pass

    def enroll(self, csr):
        """ Enrolls a certificate """
        # Input:
        #     csr - CSR in PKCS#10 format

        # Output:
        #     error - Error message during certificate enrollment (None if no error occurred)
        #     cert_bundle - Certificate chain in PEM format
        #     cert_raw - Certificate in ASN.1 (binary) format, base64 encoded
        #     poll_identifier - Callback identifier to track enrollment requests when the CA server does not
        #                       issue certificates immediately.

        self.logger.debug('Certificate.enroll()')
        ...
        self.logger.debug('Certificate.enroll() ended')
        return None, None, None, None

    def poll(self, cert_name, poll_identifier, csr):
        """ Polls the status of a pending CSR and downloads certificates """
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

        self.logger.debug('CAhandler.poll()')
        ...
        return None, None, None, None, False

    def revoke(self, cert, rev_reason='unspecified', rev_date=None):
        """ Revokes a certificate """
        # Input:
        #     cert - Certificate in PEM format
        #     rev_reason - Revocation reason
        #     rev_date - Revocation date

        # Output:
        #     code - HTTP status code to be returned to the client
        #     message - Error message if applicable, None otherwise
        #     detail - Additional error details

        self.logger.debug(f'CAhandler.revoke({rev_reason}: {rev_date})')
        ...
        return 200, None, None

    def trigger(self, payload):
        """ Processes triggers sent by the CA server """
        # Input:
        #     payload - Payload content

        # Output:
        #     error - Error message (if something went wrong)
        #     cert_bundle - Certificate chain in PEM format
        #     cert_raw - Certificate in ASN.1 (binary) format, base64 encoded

        self.logger.debug('CAhandler.trigger()')
        ...
        self.logger.debug('CAhandler.trigger() ended with error: {0}'.format(error))
        return (error, cert_bundle, cert_raw)
```

### Additional Customization

You can add additional methods as needed. Additionally, you can configure `acme_srv.cfg` to customize the behavior of the CA handler.

For further details, check [`certifier_ca_handler.py`](../examples/ca_handler/certifier_ca_handler.py), especially the `_config_load()` method.
