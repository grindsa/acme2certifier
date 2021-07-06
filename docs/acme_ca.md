<!-- markdownlint-disable  MD013 -->
<!-- wiki-title ACME CA handler -->
# ACME CA handler

The ACME CA handler is a very simple ca-handler performing signing and revocation operations using another ACME endpoint.

This only works (and makes any sense) if the back-end ACME endpoint does not issue any challenges, for example commercial services with pre-authenticated domains. The purpose is to provide ACME access across an organization without sharing the commercial endpoint account's private key, replacing it with standard ACME challenges.

Functionality of the handler will be extended across the next acme2certifer releases.

## Configuration

- copy the ca_handler into the `acme_srv` directory or add a handler_file parameter into (`acme_srv.cfg`

- modify the server configuration (`acme_srv/acme_srv.cfg`) and add the following parameters

```config
[CAhandler]
# CA specific options
handler_file: examples/ca_handler/acme_ca_handler.py
acme_url: https://some.acme/endpoint
acme_account: <account-id>
acme_keyfile: /path/to/privkey.json
```

- acme_url:  URL of the acme server issuing certificates
- acme_account: acme account id
- acme_keyfile: path to private key in json format (example below)

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
