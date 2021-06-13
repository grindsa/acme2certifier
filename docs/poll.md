<!-- markdownlint-disable  MD013 -->
<!-- wiki-title CA polling to check pending enrollment requests -->
# Ca_handler.poll()

The ```poll``` method has been implemented to cover use-cases in which certificate issuance needs to be manually approved by the CA administrator.

In such a case the acme2certifier will mark the status of the order-resource as "processing" and returns a "Retry-After" header as part of the
response to an order status polling request. (like described in RFC 8555 [Section 7.4](https://tools.ietf.org/html/rfc8555#section-7.4)).

It is further assumed that if a CSR gets into “pending” state the CA server sends information as part of the enrollment response which can
used to lookup the status of the request. This information gets returned by ```ca.handler.enroll()``` method (variable ```poll_identifier)```
and will be stored in the database along with the CSR (table ```certificate``` field ```poll_identifier```).

There is a script [`cert_poll.py`](../tools/cert_poll.py) in the tools directory which can be called via cron. It scans the ```orders``` table for orders in
status ```processing (4)``` and passes the poll_identifier along with other information via the ```certificate.poll()``` method.

```ca_handler.poll()```  checks the status of the CSR on CA server and downloads the certificate (if available). It further builds
the cert-chain and returns the below information back to certificate.poll() which will update the database.

- An error-message (if there is any)
- The Certificate chain in pem-format
- The certificate in asn1 (binary) format - base64 encoded - this is needed for later revocation
- An updated poll_identifier
- An indication (True/False) if the CSR got rejected

In parallel the ```order-status``` will be set to "valid" and a URL to ```certificate```-resource will be provided if an acme-client
polls the ```order```-resource.
In case a CSR got rejected the order status will be changed to “invalid”.

The handler for [NCLM/Insta certifier](certifier.md) contains an example implementation.

Further, an [example acme_srv.db](../examples/acme_srv.db.example) is available to give a better insight on the expected values especially in the certificate table.
