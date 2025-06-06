<!-- markdownlint-disable  MD013 -->

<!-- wiki-title CA handler for Entrust ECS Enterprise -->

# Connecting to Entrust ECS Enterprise

This handler can be used to enroll certificates from Entrust ECS Enterprise API.

## Prerequisites

- you'll need:
  - Username and Password for HTTP-BASIC authentication
  - if configured - a client certificate for mutual TLS authentication towards the Entrust REST API
  - a pre-validated Organization name

## Configuration

- modify the server configuration (`acme_srv.cfg`) and add the first three of the below mentioned parameters

```config
[CAhandler]
handler_file: examples/ca_handler/entrust_ca_handler.py
username: <Username>
password: <Password>
cert_type: <certificate type>
organization_name: <organization name>

client_cert: <client file>
cert_passphrase: <pkcs#12 passphrase>
cert_validity_days: <certificate validity>
allowed_domainlist: <allowed_domainlist>
request_timeout: <seconds>
eab_profiling: <True|False>
```

- username - required - username access the API
- password - required - password to access the PI
- organization_name - required - Organization name as specified in DigiCert CertCentral
- client_cert - optional - client certificate to access the API (to be stored in either pem or pkcs#12 format)
- client_key - optional - client private key to access the API (must be stored in pem format)
- client_passphrase - passphrase to access the client_cert (if stored in PKCS#12 format)
- cert_type - optional - certificate type to be issued. (default: STANDARD_SSL)
- cert_validity_days - certificate validity in days (default: 365)
- allowed_domainlist: list of domain-names allowed for enrollment in JSON format (example: ["bar.local$, bar.foo.local])
- request_timeout - optional - request timeout in seconds for requests (default: 5s)
- allowed_domainlist - optional - list of domain-names allowed for enrollment in JSON format example: ["bar.local$, bar.foo.local] (default: [])
- eab_profiling - optional - [activate EAB profiling](eab_profiling.md) (default: False)
- enrollment_config_log - optional - log enrollment parameters (default False)
- enrollment_config_log_skip_list - optional - list enrollment parameters not to be logged in json format example: [ "parameter1", "parameter2" ] (default: [])

Use your favorite acme client for certificate enrollment. A list of clients used in our regression can be found in the [disclaimer section of our README file](../README.md)

## Passing a cert_type from client to server

acme2certifier supports the the [Automated Certificate Management Environment (ACME) Profiles Extension draft](acme_profiling.md) allowing an acme-client to specify a `cert_type` parameter to be submitted to the CA server.

The list of supported profiles must be configured in `acme_srv.cfg`

```config
[Order]
profiles: {"STANDARD_SSL": "http://foo.bar/STANDARD_SSL", "ADVANTAGE_SSL": "http://foo.bar/ADVANTAGE_SSL"}
```

Once enabled, a client can specify the cert_type to be used as part of an order request. Below an example for lego:

```bash
docker run -i -v $PWD/lego:/.lego/ --rm --name lego goacme/lego -s http://<acme-srv> -a --email "lego@example.com" -d <fqdn> --http run --profile ADVANTAGE_SSL
```

Further, this handler makes use of the [header_info_list feature](header_info.md) allowing an acme-client to specify a certificate type to be used during certificate enrollment. This feature is disabled by default and must be activated in `acme_srv.cfg` as shown below

```config
[Order]
...
header_info_list: ["HTTP_USER_AGENT"]
```

The acme-client can then specify the cert_type as part of its user-agent string.

Example for acme.sh:

```bash
docker exec -i acme-sh acme.sh --server http://<acme-srv> --issue -d <fqdn> --standalone --useragent cert_type=ADVANTAGE_SSL --debug 3 --output-insecure
```

Example for lego:

```bash
docker run -i -v $PWD/lego:/.lego/ --rm --name lego goacme/lego -s http://<acme-srv> -a --email "lego@example.com" --user-agent cert_type=ADVANTAGE_SSL -d <fqdn> --http run
```

## eab profiling

This handler can use the [EAB profiling feature](eab_profiling.md) to allow individual enrollment configuration per acme-account as well as restriction of CN and SANs to be submitted within the CSR. The feature is disabled by default and must be activatedd in `acme_srv.cfg`

```cfg
[EABhandler]
eab_handler_file: examples/eab_handler/kid_profile_handler.py
key_file: <profile_file>

[CAhandler]
eab_profiling: True
```

below an example key file used during regression testing:

```json
{
  "keyid_00": {
    "hmac": "V2VfbmVlZF9hbm90aGVyX3ZlcnkfX2xvbmdfaG1hY190b19jaGVja19lYWJfZm9yX2tleWlkXzAwX2FzX2xlZ29fZW5mb3JjZXNfYW5faG1hY19sb25nZXJfdGhhbl8yNTZfYml0cw",
    "cahandler": {
      "cert_type": ["ADVANTAGE_SSL", "STANDARD_PLUS_SSL", "WILDCARD_SSL"],
      "allowed_domainlist": ["www.example.com", "www.example.org", "*.acme"],
      "organization_name": "acme2certifier"
    }
  },
  "keyid_01": {
    "hmac": "YW5vdXRoZXJfdmVyeV9sb25nX2htYWNfZm9yX2tleWlkXzAxX3doaWNoIHdpbGxfYmUgdXNlZF9kdXJpbmcgcmVncmVzc2lvbg",
    "cahandler": {
      "allowed_domainlist": ["www.example.com", "www.example.org", "*.acme"],
      "cert_type": "ADVANTAGE_SSL"
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
