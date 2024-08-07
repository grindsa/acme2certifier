<!-- markdownlint-disable  MD013 -->
<!-- wiki-title ACME CA handler -->
# ACME CA handler

Using acme2certifier to proxy requests towards acme-endpoints sounds like a silly idea?

Not at all... Just think about the following use-cases:

- You would like to use certificates from Letsencrypt or ZeroSSL for servers in your internal network without exposing your systems to the internet
- You are using a commercial acme-server (Entrust, Netnumber, Sectigo) with pre-authenticated domains. You would like to provide access across an organization without sharing the commercial endpoint private key.

Especially the first use-case is an interesting one. However it comes with a couple of requirements related to your network and your dns configuration as CAs used for certificate issuance need to connect to acme2certier for http challenge validation. That means that:

- your acme2certifer server need to be accessible from the Internet.
- the DNS domain you are using internally must be a official one and you need to have ownership on it
- you need to provide different sets of dns information depending on the source address of the DNS request. Your internal clients and server (including acme2certifier) need to resolve the addresses of your internal network while external systems (especially the CA servers) need get the (external) address of acme2certifier when querying the same namespace. In my test environment I fulfill this requirement by:
  - separating external and internal DNS onto different systems
  - creating a wildcard record on my external DNS (`*.foo.com`) pointing to acme2certifier
  - using the internal DNS on my acme2certifier instance
  - optional: using the external DNS server as forwarder for the internal DNS server

As of today the acme_ca_handler supports following operations:

- account registration
- http challenge validation
- certificate enrollment
- certificate revocation

## Supported CAs

- [Letsencrypt.org](https://letsencrypt.org/)
- [BuyPass.com](https://www.buypass.com/)
- [ZeroSSL](https://zerossl.com/)

## Prerequisites

Again, it is important to mention that the handler validates challenges over http. Thus, it must be ensured that the http requests from the CA server are ending up at acme2certifier.

## Configuration

The handler must be configured via `acme_srv`.

| Option | Description | mandantory | default |
| :------| :---------- | :--------: | :------ |
| handler_file | path to ca_handler file | yes | None |
| account_path | path to account ressource on ca server | no | '/acme/acct' |
| acme_url | url of the acme endpoint | yes | None |
| acme_account | acme account name. If not specified acme2certifer will try to lookup the account name based on the key-file | no | None |
| acme_keyfile | Path to private key json-format. If specified in config but not existing on file-system acme2certifer will generate a new key and try to register it | no | None |
| acme_keypath | Path to private key directory. If specified in config acme2certifer store new keys in this directory | no | None |
| acme_account_email | email address used to register a new account | no | None |
| allowed_domainlist | list of domain-names allowed for enrollment in json format example: ["bar.local$, bar.foo.local] | no | [] |
| directory_path | path to directory ressource on ca server | no | '/directory' |
| eab_profiling |  enable eab-profiling  | None |  False |
| ssl_verify | verify certificates on SSL connections | no | True |

- modify the server configuration (`acme_srv/acme_srv.cfg`) and add at least the following parameters.

```cfg
[CAhandler]
# CA specific options
handler_file: examples/ca_handler/acme_ca_handler.py
acme_url: https://some.acme/endpoint
acme_keyfile: /path/to/privkey.json
```

## Example configuration for Letsencrypt

Below the configuration example can be used to connect to Letsencrypt staging server.

```config
[CAhandler]
acme_keyfile: acme_srv/acme/le_staging_private_key.json
# use this url to connect to LE staging server for testing
acme_url: https://acme-staging-v02.api.letsencrypt.org
acme_account_email: email@example.com
```

If you are able to enroll from the LE staging server move to production by changing the `acme_keyfile` and `acme_url` as below.

```cfg
acme_url: https://acme-v02.api.letsencrypt.org
acme_keyfile: /var/www/acme2certifier/volume/acme/le_private_key.json
```

## Example configuration for BuyPass.com CA

Below the configuration example which can be used to connect to Buypass test server.

```config
acme_keyfile: acme_srv/acme/bypass_test_private_key.json
acme_url: https://api.test4.buypass.no/acme
acme_account_email: email@example.com
```

Once you are able to enroll you can move to the production environment with the below changes.

```cfg
acme_keyfile: acme_srv/acme/bypass_prod_private_key.json
acme_url: https://api.buypass.com/acme
acme_account_email: email@example.com
```

# Example for ZeroSSL CA

Below a configuration to connect to ZeroSSL

```cfg
acme_keyfile: acme_srv/acme/zerossl.json
acme_url: https://acme.zerossl.com/v2/DV90
acme_account_email: email@example.com
account_path: /account/
```

# Example for smallstep ca

Below a configuration to connect to a smallstep ca under the assumption that a provisioner called `myacme` has been created.

```cfg
acme_keyfile: acme_srv/acme/smallstep.json
acme_url: https://<fqdn>/acme/myacme
acme_account_email: email@example.com
account_path: /
ssl_verify: False
```

## Example key-file in json format

This is just an example for your reference. DO NOT USE IT ON YOUR SYSTEM!

As said above. The key-file gets generated by the ca-handler if configured but not present on the system.

You can also use existing keys generated by `certbot` which are usually stored in `/etc/letsencrypt/account`

```json
{"e": "AQAB",
 "d": "rL9Rf88G8Jg5zg1PKT1XBDwSIMYZrjld1mpZo-RE3qLBreusf8C6_rr_MIMTV7vneJT-AOPzSJHhELeA-9A2p5458KreekqWkXmFiP7L5gAUPdiZWkDxraOzoyqQdaidxaresxd7aaWH4BENbFimhfcCT453SX7GLSF9W_RKlgWfnE-yYGpT2Wq__Rkn2zOSZ5RvSOjI_Y5dIDBi8fBS-L5p6-5MhDcjyeDH8uUko8xLZZo2T_PGzY2oWu4xrC7iPBSN6fcAlHPyFvi1GqmC1_Flniy4aRooAgOq0fwIgLuVpmZpA5KSaEGRkrIx95eR-GjwgQ",
 "n": "2dGTKkgj7vlQNzLvIOJUuUmEfv8RAQAFHwzijrTm6itEDU4bt5BiqXdaerxesda-dIMDbnTQFDmyaPSi3Gp71ZSuxiPgpv2E9wa-kc5aHnT2zaj3DeGbtKO4_5NWqyD3S2bmsL1ABj6cv2Pr2Z8RqeNBKa4jdaIdifawkdrF0wAXqlpxM8nYvKfKnsOpWyr5qw1cIXcaqq_bQS7znT-hh9ay8fdWiDAvSrJvtv6R-4hPm-iA6kuwRTpDSfreN27dr4pu8PUXw8ukxnF_qdIP0AD_r0BvpmNsHIA0HDyg9afcqUj_K42yiKhr4HHNU3Ih_SSjdtw",
 "q": "5FrWQJ9BEFIf0LD3lm7OxDTc2eyqY9a508vpL9qcd-ZbC7VT24oeeGZEnyVoLoO4n0TFUSFUSmXMI7jAkQqu_wpF-hAhSWx3NY89MwRDWCbLVnvXNk-wlbZcwp8hd10Th7iFCDCFy-y8BCemHAqO5G5NAWW6rxyZzK6KILRJ1AW8",
 "p": "9DAze8mv65CFZizX7NTxMzxp1OLSAqQzt-AiXeaidA32dEY4Qj7wTSVmvZmihsI-lV6Oyax_IWvrISijPS8xR6OxgZb8wSqdLla9sXo92my6lOcdC6GG5bGq_tQXIAfKlt23kUCmwt_WN85Ef8Fm2Ftqd5HAnyMxfaf734Zm_NDk",
 "kty": "RSA",
 "qi": "6X2IOmZ3JYacHF0smIhr6URhnYdUA4O1Hqa4OIZfJGqGfW2jbG1C0X-i38ct-oc3CBoyeEM13BmrSiipyEI0pM1pU4GezXn0TSth1cuaskcy9Z0rDBEb3Y7FL7AwG3RPgoPKVUJ9mbt1z9VESuYZgshnm2a83aduzedfye3WON8PDbOM",
 "dp": "jUURk-0UDKlYs8r_xLFRNb4e0B3FN-f9T8cXPAVcVTlG4kIZTL6XPdlYA1xHJtmD45b90sHZbOEnXNgNTaHQRXvzLQoWCyqMLPYHMRG4oYCz8CBakgxvdMyxSi4lDxNtUhiOfN4RseurCx2Lp8aO9azackaeiadfayx4ek",
 "dq": "cVUb7KqdUgpQO_T4jDKmb_6EdavdzPsu8wzKyLNI4MD1AtSVr-nWwY6QFCQulpdNM86nR0lmwadieuaxaeressdNW5RR0O0CJRTYHM_K1J88X8nKv-vBCiyd0QHFTEZngP51F-FtJg5yKeW7rUMYNAsCMOVaR7p8InelmiGgWpgU"
}
```

## Passing a profileID from client to server

The handler makes use of the [header_info_list feature](header_info.md) allowing an acme-client to specify acme-backend address to be used during certificate enrollment. This feature is disabled by default and must be activate in `acme_srv.cfg` as shown below

```config
[Order]
...
header_info_list: ["HTTP_USER_AGENT"]
```

The acme-client can then specify the acme_url as part of its user-agent string.

Example for acme.sh:

```bash
docker exec -i acme-sh acme.sh --server http://<acme-srv> --issue -d <fqdn> --standalone --useragent acme_url=<acme-server url> --debug 3 --output-insecure
```

Example for lego:

```bash
docker run -i -v $PWD/lego:/.lego/ --rm --name lego goacme/lego -s http://<acme-srv> -a --email "lego@example.com" --user-agent acme_url=<acme-server url> -d <fqdn> --http run
```

# eab profiling

This handler can use the [eab profiling feture](eab_profiling.md) to allow individual enrollment configuration per acme-account as well as restriction of CN and SANs to be submitted within the CSR. The feature is disabled by default and must be activated in `acme_srv.cfg`

**Important**: In case `acme_url` variables will be specified in a profile (like for 'keyid_00' in the below example), the `acme_key_path` parameter must be set in `acme_srv.cfg` to ensure that the different key_files are being stored correctly.

```cfg
[EABhandler]
eab_handler_file: examples/eab_handler/kid_profile_handler.py
acme_key_path: <path>

[CAhandler]
eab_profiling: True
```

below an example key-file:

```json
{
  "keyid_00": {
    "hmac": "V2VfbmVlZF9hbm90aGVyX3ZlcnkfX2xvbmdfaG1hY190b19jaGVja19lYWJfZm9yX2tleWlkXzAwX2FzX2xlZ29fZW5mb3JjZXNfYW5faG1hY19sb25nZXJfdGhhbl8yNTZfYml0cw",
    "cahandler": {
      "acme_url": ["https://acme-staging-v02.api.letsencrypt.org", "https://api.buypass.com/acme", "https://acme.ssl.com/sslcom-dv-rsa"],
      "allowed_domainlist": ["www.example.com", "www.example.org", "*.acme"]
    }
  },
  "keyid_01": {
    "hmac": "YW5vdXRoZXJfdmVyeV9sb25nX2htYWNfZm9yX2tleWlkXzAxX3doaWNoIHdpbGxfYmUgdXNlZF9kdXJpbmcgcmVncmVzc2lvbg",
    "cahandler": {
      "acme_url": "https://acme-staging-v02.api.letsencrypt.org",
      "acme_keyfile": "/var/www/acme2certifier/volume/acme_ca/le_key.json",
      "allowed_domainlist": ["www.example.com", "www.example.org", "*.acme"]
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
