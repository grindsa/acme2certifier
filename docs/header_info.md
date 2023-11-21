<!-- markdownlint-disable  MD013 -->
<!-- wiki-title Pass information from acme client to CA-handler -->
# Pass information from acme client to CA-handler

Since version 0.30 acme2certifier allows to pass information to the CA handler. To avoid breaking compatibility with [RFC8555](https://datatracker.ietf.org/doc/html/rfc8555) acme-clients need to insert these information as attributes into the http-header being part of the order-finalization message.

The header attributes including payload must be specified in `acme_srv.cfg`

```config
[Order]
header_info_list: ["HTTP_USER_AGENT", "CONTENT_TYPE", "REMOTE_ADDR"]
```

The headers will be added into the header_info column of the certificates table; the ca_handle can load these information by using the `heder_info_get()` function from `helper.py` as serialized json.

```python
class CAhandler(object):
    ...
    def enroll(self, csr):
        """ enroll certificate  """
        self.logger.debug('CAhandler.enroll()')

        cert_bundle = None
        error = None
        cert_raw = None
        poll_indentifier = None

        # lookup http header information from request
        qset = header_info_get(self.logger, csr=csr)
        if qset:
            self.logger.info('header_info: {0}'.format(qset[-1]['header_info']))
            # Do other intersting things with the header information...
        ...
        self.logger.debug('Certificate.enroll() ended')

        return (error, cert_bundle, cert_raw, poll_indentifier)
```

Output from the above configuration example would be:

```log
2023-11-03 16:52:14 - acme2certifier - IFNO - header_info: {"HTTP_USER_AGENT": "CertbotACMEClient/1.21.0 (certbot; Ubuntu 22.04.3 LTS) Authenticator/standalone Installer/None (certonly; flags: ) Py/3.10.12", "CONTENT_TYPE": "application/jose+json", "REMOTE_ADDR": "192.168.14.131"}
```
