<!-- markdownlint-disable  MD013 -->

<!-- wiki-title CA handler for NetGuard Certificate Manager and Insta Certifier -->

# Connecting to Insta Certifier

## Prerequisites

- the Certifier needs to have the REST-service activated
- you have a user and password to access Certifier via REST-Service

## Configuration

- modify the server configuration (`/acme_srv/acme_srv.cfg`) and add the following parameters

```config
[CAhandler]
handler_file: examples/ca_handler/certifier_ca_handler.py
api_host: http://<ip>:<port>
api_user: <user>
api_password: <password>
ca_bundle: <value>
ca_name: <ca_name>
profile_id: <value>
polling_timeout: <seconds>
eab_profiling: <True|False>
```

- api_host - URL of the Certifier REST service
- api_user - REST user
- api_user_variable - *optional* - name of the environment variable containing the REST username (a configured `api_user` parameter in acme_srv.cfg takes precedence)
- api_password - password for REST user
- api_password_variable - *optional* - name of the environment variable containing the password for the REST user (a configured `api_password` parameter in acme_srv.cfg takes precedence)
- ca_bundle - optional - certificate bundle needed to validate the server certificate - can be True/False or a filename (default: True)
- ca_name - name of the CA used to enroll certificates
- allowed_domainlist - optional - list of domain-names allowed for enrollment in json format example: ["bar.local$, bar.foo.local] (default: [])
- eab_profiling - optional - [activate eab profiling](eab_profiling.md) (default: False)
- enrollment_config_log - optional - log enrollment parameters (default False)
- enrollment_config_log_skip_list - optional - list enrollment parameters not to be logged in json format example: [ "parameter1", "parameter2" ] (default: [])
- profile_id - optional - profileId
- polling_timeout - optional - polling timeout (default: 60s)

Depending on CA policy configuration a CSR may require approval. In such a situation acme2certifier will poll the CA server to check the CSR status. The polling interval can be configured in acme.server.cfg.

You can get the `ca_name` by running the following REST call against certifier.

```bash
root@rlh:~# curl -u '$api_user':'$api_password' $api_host'/v1/cas
```

The response to this call will return a dictionary containing the list of CAs including description and name. Pick the value in the "name" field.

```REST
  "offset": 0,
  "limit": 50,
  "totalCount": 3,
  "href": "<url>",
  "cas": [
    {
      "href": "<url>/v1/cas/kQg0moMYAHGyG7jrQeT2Fw",
      "name": "Insta Certifier Internal CA",
      "description": "CA for Certifier internal TLS communication and operational use",
      "status": "active",
      "type": "online",
      "certificates": {
        "active": "<url>/v1/certificates/JPnxc-OqxkXdQt6An2vqnw"
      }
    },
    {
      "href": ""<url>/v1/cas/PnOBdgHSiz5c1sR0MsZMtw",
      "name": "ca_name",
      "description": "Test CA for acme2certifier",
      "status": "active",
      "type": "online",
      "certificates": {
        "active": "<url>/v1/certificates/Ur-YAdXw6S8ddGl7ITVTjA"
      }
    }
  ]
```

## Passing a profile_id from client to server

The handler makes use of the [header_info_list feature](header_info.md) allowing an ACME client to specify a profile_id to be used during certificate enrollment. This feature is disabled by default and must be activated in `acme_srv.cfg` as shown below

```config
[Order]
...
header_info_list: ["HTTP_USER_AGENT"]
```

The ACME client can then specify the profileID as part of its user-agent string.

Example for acme.sh:

```bash
docker exec -i acme-sh acme.sh --server http://<acme-srv> --issue -d <fqdn> --standalone --useragent profile_id=101 --debug 3 --output-insecure
```

Example for lego:

```bash
docker run -i -v $PWD/lego:/.lego/ --rm --name lego goacme/lego -s http://<acme-srv> -a --email "lego@example.com" --user-agent profile_id=101 -d <fqdn> --http run
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

Below is an example key-file used during regression testing:

```json
{
  "keyid_00": {
    "hmac": "V2VfbmVlZF9hbm90aGVyX3ZlcnkfX2xvbmdfaG1hY190b19jaGVja19lYWJfZm9yX2tleWlkXzAwX2FzX2xlZ29fZW5mb3JjZXNfYW5faG1hY19sb25nZXJfdGhhbl8yNTZfYml0cw",
    "cahandler": {
      "profile_id": ["p100", "p101", "p102"],
      "allowed_domainlist": ["www.example.com", "www.example.org", "*.acme"]
    }
  },
  "keyid_01": {
    "hmac": "YW5vdXRoZXJfdmVyeV9sb25nX2htYWNfZm9yX2tleWlkXzAxX3doaWNoIHdpbGxfYmUgdXNlZF9kdXJpbmcgcmVncmVzc2lvbg",
    "cahandler": {
      "profile_id": "102",
      "allowed_domainlist": ["www.example.com", "www.example.org", "*.acme"],
      "ca_name": "subca2"
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

## CA policy configuration

A CSR generated by certbot client does not contain any subject name. Such a CSR will be refused by Certifier. To overcome this, you need a CA policy as below setting a subject name.

```policy
(policy
  (receive-request
    (set-validity-period
      (null)
      (length 30)
      (type 86400)
      (end-of-day #f)
      (overwrite #t))
    (issue-automatic
      (null)
      (mode all))
    (issue-manual
      (null)))
  (accept-request
    (conditional-policy
      (null)
      (clause
        (test
          (module match-subject-name)
          (match-subject-name
            (null)
            (pattern)
            (prefix #f)
            (invert-match #f)))
        (chain
          (set-subject-name
            (null)
            (format "CN=%{altname:dns}")))))
    (set-validity-period
      (null)
      (length 1)
      (type 2592000)
      (end-of-day #t)
      (overwrite #t))
    (add-aia
      (null)
      (url http://aia_path/))
    (set-crl-distribution-point
      (null))
    (accept-all
      (null)))
  (view-request
    (accept-all
      (null)))
  (update-request
    (accept-all
      (null))))
```

IMPORTANT: the above policy will configure a certificate lifetime of 30 days only. Please review carefully and modify according to your needs.
