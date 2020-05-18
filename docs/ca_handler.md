# How to create your own CA-Handler

Creating your own CA-handler should be pretty easy.  All you need to do is to create your own ca_handler.py with a "CAhandler" class containing the following methods required by acme2certifier:

- __enroll__: to enroll a new certificate
- __poll__: to poll a pending certificate request
- __revoke__: to revoke an existing certificate

The below skeleton describes the different input parameters given by acme2certifier as well as the expected return values.

```
class CAhandler(object):
    """ CA handler """
    
    def __init__(self, debug=None, logger=None):
        """ 
        input:
            debug - debug mode (True/False)
            logger - log handler
        """
        self.debug = debug
        self.logger = logger

    def __enter__(self):
        """ Makes CAhandler a context manager """
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def enroll(self, csr):
        """ enroll certificate """
        input: 
            csr - csr in pkcs10 format

        output:
            error - error message during cert enrollment (None in case no error occured)
            cert_bundle - certificate chain in pem format
            cert_raw - certificate in PEM format 
            poll_identifier - callback identifier to lookup enrollment request in case the CA server does not issue 
                              certificate immediately. This identifier will be used by the polling method check if 
                              a CSR got accepted
            
        self.logger.debug('Certificate.enroll()')
        ...
        self.logger.debug('Certificate.enroll() ended')
        return(error, cert_bundle, cert_raw, poll_identifier)

    def poll(self, cert_name, poll_identifier, _csr):
        """ poll pending status of pending CSR and download certificates """
        input:
            cert_name - certificate ressource name
            poll_identifier - poll identifier
            csr - certificate signing request
        
        output:
            error - error message during cert polling (None in case no error occured)           
            cert_bundle - certificate chain in pem format
            cert_raw - certificate in PEM format """
            poll_identifier - (updated) callback identifier - will be updated in database for later lookups
            rejected - indicates of request has been rejected by CA admistrator - in case of a request rejection by CA 
                       admistrator, the corresponding order status will be set to "invalid" state
        
        self.logger.debug('CAhandler.poll()')
        ...
        return(error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(self, cert, rev_reason='unspecified', rev_date=uts_to_date_utc(uts_now())):
        """ revoke certificate
        input:
            cert - certificate in pem format
            reason - revocation reason
            rev_date - revocation date

        output:
            code - http status code to be give back to the client
            message - urn:ietf:params:acme:error:serverInternal in case of an error, None in case of no errors
            detail - error details to be added to the client response """
            
        self.logger.debug('CAhandler.revoke({0}: {1})'.format(rev_reason, rev_date))
        ...
        self.logger.debug('Certificate.enroll() ended with: {0}, {1}, {2}'.format(code, message, detail))
        return(code, message, detail)
```

You can add additional methods according to your needs. You can also add configuration options to acme_srv.cfg allowing you to configure the ca_handler according to your needs.
Check the `certifier_ca_handler.py` especially the `_config_load()` method for further input.