<!-- markdownlint-disable  MD013 -->
<!-- wiki-title CA handler for EJBCA -->
# Connecting to Keyfactor's EJBCA

This handler can be used to enroll certificates from the [Open Source version of Keyfactor's EJBCA](https://www.ejbca.org) as ACME support is only available in the Enterprise version.

## Prerequisites

- [EJBCA](https://www.ejbca.org) needs to have the RESTv1-service enabled
- you'll need:
  - a [client certificate and key in p12](https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/authentication-methods) format to authenticate towards the rest-service
  - the name of the CA issuing the certificates from EJBA admin UI
  - a username and enrolment code
  - a [certificate profile name](https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-profiles-overview)
  - an [end-entity profile name](https://download.primekey.com/docs/EJBCA-Enterprise/6_14_1/End_Entity_Profiles.html)

## Configuration

- modify the server configuration (`acme_srv.cfg`) and add the following parameters

```config
[CAhandler]
handler_file: examples/ca_handler/ejbca_ca_handler.py
cert_file: <filename>
cert_passphrase: <passphrase>
ca_bundle: <filename>
cert_profile_name: <name>
ee_profile_name: <name>
username: <name>
enrollment_code: <value>
ca_name: <name>
request_timeout: <seconds>
```

- api_host - URL of the EJBCA-Rest service
- cert_file - certicate and key in pkcs#12 format to authenticate towards EJBCA-Rest service
- cert_passphrase - phassphrase to access the pkcs#12 container
- cert_passphrase_variable - *optional* - name of the environment variable containing the cert_passphrase (a configured `cert_passphrase` parameter in acme_srv.cfg takes precedence)
- ca_bundle - optional - ca certificate chain in pem format needed to validate the ejbca-server certificate - can be True/False or a filename (default: True)
- username - PKI username
- username_variable - *optional* - name of the environment variable containing the EJBCA username (a configured `username` parameter in acme_srv.cfg takes precedence)
- enrollment_code - enrollment code
- enrollment_code_variable - *optional* - name of the environment variable containing the enrollment_code for the EJBCA user (a configured `enrollment_code` parameter in acme_srv.cfg takes precedence)
- cert_profile_name - name of the certificate profile
- ee_profile_name - name of the end entity profile
- ca_name - name of the CA used to enroll certificates
- request_timeout - optional - requests timeout in seconds for requests (default: 5s)

You can test the connection by running the following curl command against your EJBCA server.

```bash
root@rlh:~#  curl https://<api-host>/ejbca/ejbca-rest-api/v1/certificate/status --cert-type P12 --cert <cert_file>:<cert_passphrase> --cacert <ca_bundle>
```

The response to this call will show a dictionary containing status und version number of the server.

```json
{
  "status":"OK",
  "version":"1.0",
  "revision":"EJBCA 7.11.0 Community (8d14e27cda0b32eba35a1fd1423f8e6a31d1ed8e)"
}
```

Use your favorite acme client for certificate enrollment. A list of clients used in our regression can be found in the [disclaimer section of our README file](../README.md)
