<!-- markdownlint-disable  MD013 -->
<!-- wiki-title CA handler for EJBCA -->
# Connecting to Keyfactor's EJBCA

This handler can be used to enroll certificates from the [Open Source version of Keyfactor's EJBCA](https://www.ejbca.org) as ACME support is only available in the Enterprise version.

## Prerequisites

- [EJBCA](https://www.ejbca.org) needs to have the RESTv1-service enabled
- you'll need:
  - a [client certificate and key in p12](https://docs.keyfactor.com/ejbca/latest/authentication-methods) format to authenticate towards the REST service
  - the name of the CA issuing the certificates from EJBA admin UI
  - a username and enrolment code
  - a [certificate profile name](https://docs.keyfactor.com/ejbca/latest/certificate-profiles-overview)
  - an [end-entity profile name](https://docs.keyfactor.com/ejbca/latest/end-entity-profiles-overview)

The handler requires the installation of the python [requests_pkcs12](https://github.com/m-click/requests_pkcs12) module. The module can be installed via [pypi](https://pypi.org/project/requests-pkcs12/), RPMs for RH8 can be found in my [rpm-repo](https://github.com/grindsa/sbom/tree/main/rpm-repo/RPMs)

## Configuration

- modify the server configuration (`acme_srv.cfg`) and add the following parameters

```config
[CAhandler]
handler_file: examples/ca_handler/ejbca_ca_handler.py
api_host: https://<fqdn or ip>:8443
cert_file: <filename>
cert_passphrase: <passphrase>
ca_bundle: <filename>
cert_profile_name: <name>
ee_profile_name: <name>
username: <name>
enrollment_code: <value>
ca_name: <name>
request_timeout: <seconds>
eab_profiling: <True|False>
```

- api_host - URL of the EJBCA-Rest service
- cert_file - certificate and key in pkcs#12 format to authenticate towards EJBCA-Rest service
- cert_passphrase - passphrase to access the pkcs#12 container
- cert_passphrase_variable - *optional* - name of the environment variable containing the cert_passphrase (a configured `cert_passphrase` parameter in acme_srv.cfg takes precedence)
- ca_bundle - optional - ca certificate chain in pem format needed to validate the EJBCA server certificate - can be True/False or a filename (default: True)
- username - PKI username
- username_variable - *optional* - name of the environment variable containing the EJBCA username (a configured `username` parameter in acme_srv.cfg takes precedence)
- enrollment_code - enrollment code
- enrollment_code_variable - *optional* - name of the environment variable containing the enrollment_code for the EJBCA user (a configured `enrollment_code` parameter in acme_srv.cfg takes precedence)
- cert_profile_name - name of the certificate profile
- ee_profile_name - name of the end entity profile
- ca_name - name of the CA used to enroll certificates
- allowed_domainlist - optional - list of domain-names allowed for enrollment in JSON format, for example: ["bar.local$, bar.foo.local] (default: [])
- eab_profiling - optional - [activate eab profiling](eab_profiling.md) (default: False)
- enrollment_config_log - optional - log enrollment parameters (default False)
- enrollment_config_log_skip_list - optional - list of enrollment parameters not to be logged in JSON format, for example: [ "parameter1", "parameter2" ] (default: [])
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

## Passing a profile_id from client to server

The handler makes use of the [header_info_list feature](header_info.md) allowing an ACME client to specify a certificate profile to be used during certificate enrollment. This feature is disabled by default and must be activated in `acme_srv.cfg` as shown below

```config
[Order]
...
header_info_list: ["HTTP_USER_AGENT"]
```

The ACME client can then specify the profileID as part of its user-agent string.

Example for acme.sh:

```bash
docker exec -i acme-sh acme.sh --server http://<acme-srv> --issue -d <fqdn> --standalone --useragent cert_profile_name=acme_clt --debug 3 --output-insecure
```

Example for lego:

```bash
docker run -i -v $PWD/lego:/.lego/ --rm --name lego goacme/lego -s http://<acme-srv> -a --email "lego@example.com" --user-agent cert_profile_name=acme_clt -d <fqdn> --http run
```

# eab profiling

This handler can use the [eab profiling feature](eab_profiling.md) to allow individual enrollment configuration per acme-account as well as restriction of CN and SANs to be submitted within the CSR. The feature is disabled by default and must be activatedd in `acme_srv.cfg`

```cfg
[EABhandler]
eab_handler_file: examples/eab_handler/kid_profile_handler.py
key_file: <profile_file>

[CAhandler]
eab_profiling: True
```

Below is an example key file used during regression testing:

```json
{
  "keyid_00": {
    "hmac": "V2VfbmVlZF9hbm90aGVyX3ZlcnkfX2xvbmdfaG1hY190b19jaGVja19lYWJfZm9yX2tleWlkXzAwX2FzX2xlZ29fZW5mb3JjZXNfYW5faG1hY19sb25nZXJfdGhhbl8yNTZfYml0cw",
    "cahandler": {
      "cert_profile_name": ["acmeca2", "acmeca1"],
      "allowed_domainlist": ["www.example.com", "www.example.org", "*.acme"]
    }
  },
  "keyid_01": {
    "hmac": "YW5vdXRoZXJfdmVyeV9sb25nX2htYWNfZm9yX2tleWlkXzAxX3doaWNoIHdpbGxfYmUgdXNlZF9kdXJpbmcgcmVncmVzc2lvbg",
    "cahandler": {
      "cert_profile_name": "acmeca2",
      "allowed_domainlist": ["www.example.com", "www.example.org", "*.acme"],
      "ca_name": "acmeca"
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
