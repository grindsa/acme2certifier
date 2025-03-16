<!-- markdownlint-disable MD013 -->
<!-- wiki-title Support for TNAuthList Identifier and tkauth-01 Challenges -->
# TNAuthList Support

Support for the **TNAuthList** identifier and **tkauth-01** challenges is currently **experimental**, as neither the identifier nor the challenge type has been fully standardized.

## Implementation

The current implementation follows these specifications:

- [draft-ietf-acme-authority-token-tnauthlist-08](https://datatracker.ietf.org/doc/html/draft-ietf-acme-authority-token-tnauthlist-08)
- [draft-ietf-acme-authority-token-07](https://tools.ietf.org/html/draft-ietf-acme-authority-token-tnauthlist-07)
- **ATIS-1000080**

## Enabling TNAuthList Support

By default, TNAuthList support is **disabled**. To enable it, modify the **`Order`** section of the configuration file (`acme_srv.cfg`) and add:

```ini
[Order]
tnauthlist_support: True
```

## ACME Client Support

Currently, **no ACME client** officially supports the TNAuthList extension. However, for testing purposes, I have added support to a modified version of **[acme.sh](https://github.com/grindsa/acme.sh)**. These changes have **not yet been merged** into the main repository.

If you choose to use this modified version, please proceed **at your own risk** and provide feedback.

## Enrolling a Certificate with TNAuthList

To enroll a certificate that includes a **TNAuthList** certificate extension, use the following command:

```sh
acme.sh --server http://<server-name> --issue -d <fqdn>         --tnauth <TN Authorization List> --spctoken <Service Provider Code Token>         --standalone -w /tmp --debug 2 --output-insecure --force --log acme.log
```

