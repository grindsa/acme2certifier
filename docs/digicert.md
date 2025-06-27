<!-- markdownlint-disable  MD013 -->

<!-- wiki-title CA handler for Digicert CertCentral -->

# Connecting to DigiCert CertCentral

This handler can be used to enroll certificates from [DigiCert CertCentral](https://dev.digicert.com/en/certcentral-apis.html).

## Prerequisites

- you'll need:
  - a DigiCert CertCentral subscription :-)
  - an [API-Key](https://dev.digicert.com/en/certcentral-apis/authentication.html) for Authentication and Authorization
  - an [Organization](https://dev.digicert.com/en/certcentral-apis/services-api/organizations.html)
  - a [whitelisted domain](https://dev.digicert.com/en/certcentral-apis/services-api/domains.html)

## Configuration

- modify the server configuration (`acme_srv.cfg`) and add the first thre of the below mentioned parameters

```confag
[CAhandler]
handler_file: examples/ca_handler/digicert_ca_handler.py
api_key: <api_key>
organization_name: <organization_name>

allowed_domainlist: <allowed_domainlist>
api_url: <api_url>
organization_id: <organization_id>
cert_type: <cert_type>
signature_hash: <signature_hash>
order_validity: <order_validity>
request_timeout: <seconds>
eab_profiling: <True|False>
```

- api_key - required - API key to access the API
- organization_name - required - Organization name as specified in DigiCert CertCentral
- allowed_domainlist: list of domain-names allowed for enrollment in json format (example: \["bar.local$, bar.foo.local\])
- api_url - optional - URL of the CertCentral API
- organization_id - optional - organization id - configuration prevents additional rest-lookups
- cert_type - optional - [certificte type](https://dev.digicert.com/en/certcentral-apis/services-api/orders.html) to be isused. (default: ssl_basic)
- signature_hash - optional - hash algorithm used for certificate signing - (default: sha256)
- order_validity - optional - oder validity (default: 1 year)
- request_timeout - optional - requests timeout in seconds for requests (default: 5s)
- allowed_domainlist - optional - list of domain-names allowed for enrollment in json format example: \["bar.local$, bar.foo.local\] (default: \[\])
- eab_profiling - optional - [activate eab profiling](eab_profiling.md) (default: False)
- enrollment_config_log - optional - log enrollment parameters (default False)
- enrollment_config_log_skip_list - optional - list enrollment parameters not to be logged in json format example: \[ "parameter1", "parameter2" \] (default: \[\])

Use your favorite acme client for certificate enrollment. A list of clients used in our regression can be found in the [disclaimer section of our README file](../README.md)

*Important:* the DigiCert API expectes a CommonName to be set. Hence, certbot cannot be used for certificate enrollment.

## Passing a cert_type from client to server

acme2certifier supports the [Automated Certificate Management Environment (ACME) Profiles Extension draft](acme_profiling.md) allowing an acme-client to specify a [cert_type](https://dev.digicert.com/en/certcentral-apis/services-api/orders.html) parameter to be submitted to the CA server.

The list of supported profiles must be configured in `acme_srv.cfg`

```config
[Order]
profiles: {"profile1": "http://foo.bar/ssl_basic", "profile2": "http://foo.bar/ssl_securesite_pro", "profile3": "http://foo.bar/ssl_secure"}
```

Once enabled, a client can specify the cert_type to be used as part of an order request. Below an example for lego:

```bash
docker run -i -v $PWD/lego:/.lego/ --rm --name lego goacme/lego -s http://<acme-srv> -a --email "lego@example.com" -d <fqdn> --http run --profile ssl_securesite_pro
```

Further, this handler makes use of the [header_info_list feature](header_info.md) allowing an acme-client to specify a [certificate type](https://dev.digicert.com/en/certcentral-apis/services-api/orders.html) to be used during certificate enrollment. This feature is disabled by default and must be activate in `acme_srv.cfg` as shown below

```config
[Order]
...
header_info_list: ["HTTP_USER_AGENT"]
```

The acme-client can then specify the cert_type as part of its user-agent string.

Example for acme.sh:

```bash
docker exec -i acme-sh acme.sh --server http://<acme-srv> --issue -d <fqdn> --standalone --useragent cert_type=ssl_securesite_pro --debug 3 --output-insecure
```

Example for lego:

```bash
docker run -i -v $PWD/lego:/.lego/ --rm --name lego goacme/lego -s http://<acme-srv> -a --email "lego@example.com" --user-agent cert_type=ssl_securesite_pro -d <fqdn> --http run
```

# eab profiling

This handler can use the [eab profiling feture](eab_profiling.md) to allow individual enrollment configuration per acme-account as well as restriction of CN and SANs to be submitted within the CSR. The feature is disabled by default and must be activated in `acme_srv.cfg`

```cfg
[EABhandler]
eab_handler_file: examples/eab_handler/kid_profile_handler.py
key_file: <profile_file>

[CAhandler]
eab_profiling: True
```

below an example key-file used during regression testing:

```json
{
  "keyid_00": {
    "hmac": "V2VfbmVlZF9hbm90aGVyX3ZlcnkfX2xvbmdfaG1hY190b19jaGVja19lYWJfZm9yX2tleWlkXzAwX2FzX2xlZ29fZW5mb3JjZXNfYW5faG1hY19sb25nZXJfdGhhbl8yNTZfYml0cw",
    "cahandler": {
      "cert_type": ["ssl_basic", "ssl_securesite_pro", "ssl_securesite_flex"],
      "allowed_domainlist": ["www.example.com", "www.example.org", "*.acme"],
      "organization_name": "acme2certifier"
    }
  },
  "keyid_01": {
    "hmac": "YW5vdXRoZXJfdmVyeV9sb25nX2htYWNfZm9yX2tleWlkXzAxX3doaWNoIHdpbGxfYmUgdXNlZF9kdXJpbmcgcmVncmVzc2lvbg",
    "cahandler": {
      "allowed_domainlist": ["www.example.com", "www.example.org", "*.acme"],
      "cert_type": "ssl_securesite_pro"
    }
  },
  "keyid_02": {
    "hmac": "dGhpc19pc19hX3ZlcnlfbG9uZ19obWFjX3RvX21ha2Vfc3VyZV90aGF0X2l0c19tb3JlX3RoYW5fMjU2X2JpdHM",
    "cahandler": {
      "allowed_domainlist": ["www.example.com", "www.example.org"]
    }
  },
  "keyid_03": {
    "hmac": "YW5kX2ZpbmFsbHlfdGhlX2xhc3RfaG1hY19rZXlfd2hpY2hfaXNfbG9uZ2VyX3RoYW5fMjU2X2JpdHNfYW5kX3Nob3VsZF93b3Jr"
  }
}
```
