<!-- markdownlint-disable MD013 -->

<!-- wiki-title: Pass Information from ACME Client to CA Handler -->

# Pass Information from ACME Client to CA Handler

Since version 0.30, `acme2certifier` allows passing information to the CA handler. To maintain compatibility with [RFC8555](https://datatracker.ietf.org/doc/html/rfc8555), ACME clients need to insert this information as attributes into the HTTP header, which is part of the order-finalization message.

The header attributes, including the payload, must be specified in `acme_srv.cfg`:

```config
[Order]
header_info_list: ["HTTP_USER_AGENT", "CONTENT_TYPE", "REMOTE_ADDR"]
```

The headers will be added to the `header_info` column of the certificates table. The CA handler can retrieve this information using the `header_info_get()` function from `helper.py` as serialized JSON.

```python
class CAHandler(object):
    ...

    def enroll(self, csr):
        """Enroll certificate"""
        self.logger.debug("CAHandler.enroll()")

        cert_bundle = None
        error = None
        cert_raw = None
        poll_identifier = None

        # Lookup HTTP header information from request
        qset = header_info_get(self.logger, csr=csr)
        if qset:
            self.logger.info("Header info: {0}".format(qset[-1]["header_info"]))
            # Perform additional processing with the header information...
        ...
        self.logger.debug("Certificate.enroll() ended")

        return (error, cert_bundle, cert_raw, poll_identifier)
```

The output from the above configuration example would be:

```log
2023-11-03 16:52:14 - acme2certifier - INFO - Header info: {"HTTP_USER_AGENT": "CertbotACMEClient/1.21.0 (certbot; Ubuntu 22.04.3 LTS) Authenticator/standalone Installer/None (certonly; flags: ) Py/3.10.12", "CONTENT_TYPE": "application/jose+json", "REMOTE_ADDR": "192.168.14.131"}
```
