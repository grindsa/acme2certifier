<!-- markdownlint-disable  MD013 -->
<!-- wiki-title ACME CA handler -->
# ACME CA handler

Using acme2certifier to proxy requests towards acme-endpoints sounds like a silly idea?

Not at all... Just think about the following use-cases:

- You are using a commercial acme-server (Entrust, Netnumber, Gobalsign) with pre-authenticated domains. You would like to provide access across an organization without sharing the commercial endpoint private key.
- You would like to use certificates from Letsencrypt or ZeroSSL for servers in your internal network without exposing them to the internet

As of today following operations are supported

- account registration
- http challenge validation
- certificate enrollment
- certificate revocation

## Prerequisites

The handler validates challenges over http. Thus, it must be ensured that the http requests from the acme-CA server are ending up at acme2certifier.

## Configuration

The handler must be configured via `acme_srv`.

| Option | Description | mandantory | default |
| :------| :---------- | :--------: | :------ |
|handler_file | path to ca_handler file | yes | None |
| acme_url | url of the acme endpoint | yes | None |
| acme_account | acme account name. If not specified acme2certifer will try to lookup the account name based on the key-file | yes | None |
| acme_keyfile | Path to private key json-format. If specified in config but not existing on file-system acme2certifer will generate a new key and try to register it |
| acme_account_email | email address used to register a new account | no | None | account_path | path to account ressource on ca server | no | '/acme/acct' |
| directory_path | path to directory ressource on ca server | no | '/directory' |

- copy the ca_handler into the `acme_srv` directory or add a handler_file parameter into (`acme_srv.cfg`

- modify the server configuration (`acme_srv/acme_srv.cfg`) and add the following parameters

Below the configuration example can be used to connect to Letsencrypt staging server .

```config
[CAhandler]
account_path: /acme/acct/
directory_path: /directory
acme_keyfile: acme_srv/acme/le_staging_private_key.json
# use this url to connect to LE staging server for testing
acme_url: https://acme-staging-v02.api.letsencrypt.org
acme_account_email: grinsa@github.com
```

if you are able to enroll from the LE staging server move to production by changing the `acme_keyfile` and `acme_url`.

```cfg
acme_url: https://acme-v02.api.letsencrypt.org
acme_keyfile: /var/www/acme2certifier/volume/acme/le_private_key.json
```

An example key-file

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
