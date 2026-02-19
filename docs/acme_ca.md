<!-- markdownlint-disable MD013 -->

<!-- wiki-title ACME CA handler -->

# ACME CA Handler

Using `acme2certifier` to proxy requests towards ACME endpoints sounds like a silly idea?

Not at all... Just think about the following use cases:

- You would like to use certificates from Let's Encrypt or ZeroSSL for servers in your internal network without exposing your systems to the internet.
- You are using a commercial ACME server (Entrust, Netnumber, Sectigo) with pre-authenticated domains. You would like to provide access across an organization without sharing the commercial endpoint's private key.

Especially the first use case is an interesting one. However, it requires specific your network and DNS configuration as CA used for certificate issuance needs to validate the acme-challenges by using either HTTP (default) or DNS.

If you are planning to use DNS Challenge validation please note:

Your `acme2certifier` server must be able to reach the CA and needs to have access to your DNS server to provision the [key-authorization record](https://datatracker.ietf.org/doc/html/rfc8555/#section-8.4).
I’ve decided to implement a script-based mechanism for DNS challenge provisioning, providing flexibility in how DNS challenges are handled. This implementation will be compatible with [acme.sh dns plugins](https://github.com/acmesh-official/acme.sh/wiki/dnsapi) allowing a reuse of the acme-dns plugin library.
Therefore, you’ll need to download acme.sh (it won’t be executed directly) as well as the DNS API plugin for your DNS provider.

The configuration will be managed through the acme_srv.cfg file. The below example configuration refers to the [CloudFlare DNS plugin](https://github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_cf)

```cfg
[CAhandler]
handler_file: /opt/acme2certifier/examples/ca_handler/acme_ca_handler.py
acme_sh_script: /opt/acme2certifier/volume/acme.sh
acme_sh_shell: /bin/bash
# setting the dns_update_script parameter will force a2c to use dns-challenges for validation only
dns_update_script: /opt/acme2certifier/volume/dns_cf.sh
dns_update_script_variables: {"CF_Token": "your_cf_token", "CF_Zone_ID": "your_cf_zone-id"}
dns_validation_timeout: 10
```

In case you are planning to use HTTP Challenge validaton:

- Your `acme2certifier` server must be able to reach the CA.
- Your `acme2certifier` server needs to be accessible from the internet.
- The DNS domain you are using internally must be an official one, and you need to have ownership of it.
- You need to provide different sets of DNS information depending on the source address of the DNS request. Your internal clients and servers (including `acme2certifier`) need to resolve the addresses of your internal network, while external systems (especially the CA servers) need to get the (external) address of `acme2certifier` when querying the same namespace. In my test environment, I fulfill this requirement by:
  - Separating external and internal DNS onto different systems.
  - Creating a wildcard record on my external DNS (`*.foo.com`) pointing to `acme2certifier`.
  - Using the internal DNS on my `acme2certifier` instance.
  - Optional: Using the external DNS server as a forwarder for the internal DNS server.

As of today, the `acme_ca_handler` supports the following operations:

- Account registration
- HTTP or DNS challenge validation
- Certificate enrollment
- Certificate revocation

## Supported CAs

- [Let's Encrypt](https://letsencrypt.org/)
- [BuyPass](https://www.buypass.com/)
- [ZeroSSL](https://zerossl.com/)

## Prerequisites

Again, it is important to mention that the handler validates challenges over HTTP. Thus, it must be ensured that the HTTP requests from the CA server reach `acme2certifier`.

## Configuration

The handler must be configured via `acme_srv`.

| Option                          | Description                                                                                                                                                    | Mandatory | Default      |
| :------------------------------ | :------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-------: | :----------- |
| handler_file                    | Path to CA handler file                                                                                                                                        |    Yes    | None         |
| account_path                    | Path to account resource on CA server                                                                                                                          |    No     | `/acme/acct` |
| acme_url                        | URL of the ACME endpoint                                                                                                                                       |    Yes    | None         |
| acme_account                    | ACME account name. If not specified, `acme2certifier` will try to look up the account name based on the key file                                               |    No     | None         |
| acme_keyfile                    | Path to private key (JSON format). If specified in config but not existing on the file system, `acme2certifier` will generate a new key and try to register it |    No     | None         |
| acme_keypath                    | Path to private key directory. If specified in config, `acme2certifier` stores new keys in this directory                                                      |    No     | None         |
| acme_account_email              | Email address used to register a new account                                                                                                                   |    No     | None         |
| acme_sh_script                  | path to the acme_sh.sh script to be used for DNS challenge provisioning                                                                                        |    No     | None         |
| acme_sh_shell                   | shell to be used to execute acme_sh                                                                                                                            |    No     | /bin/bash    |
| allowed_domainlist              | List of domain names allowed for enrollment in JSON format, e.g., `["bar.local", "bar.foo.local"]`                                                             |    No     | `[]`         |
| directory_path                  | Path to directory resource on CA server                                                                                                                        |    No     | `/directory` |
| dns_update_script               | Path to the script script to provision DNS records for DNS challenge validation. Setting the dns_update_script will force a2c to trigger dns-challenge validation.   | No  | None         |
| dns_update_script_variables.    | Environment variables for the DNS update script in JSON format, e.g. `{"CF_Token": "your_cf_token", "CF_Zone_ID": "your_cf_zone-id"}`                          |    No     | None         |
| dns_validation_timeout          | sleep timer after dns provisioning                                                                                                                             |    No     | 10           |
| enrollment_config_log           | Log enrollment parameters                                                                                                                                      |    No     | `False`      |
| enrollment_config_log_skip_list | List of enrollment parameters not to be logged in JSON format, e.g., `["parameter1", "parameter2"]`                                                            |    No     | `[]`         |
| ssl_verify                      | Verify certificates on SSL connections                                                                                                                         |    No     | `True`       |

Modify the server configuration (`acme_srv/acme_srv.cfg`) and add at least the following parameters:

```cfg
[CAhandler]
# CA specific options
handler_file: examples/ca_handler/acme_ca_handler.py
acme_url: https://some.acme/endpoint
acme_keyfile: /path/to/privkey.json
```

## Example Configurations

### Let's Encrypt

```cfg
[CAhandler]
acme_keyfile: acme_srv/acme/le_staging_private_key.json
acme_url: https://acme-staging-v02.api.letsencrypt.org
acme_account_email: email@example.com
```

For production:

```cfg
acme_url: https://acme-v02.api.letsencrypt.org
acme_keyfile: /var/www/acme2certifier/volume/acme/le_private_key.json
```

### BuyPass

```cfg
acme_keyfile: acme_srv/acme/buypass_test_private_key.json
acme_url: https://api.test4.buypass.no/acme
acme_account_email: email@example.com
```

For production:

```cfg
acme_keyfile: acme_srv/acme/buypass_prod_private_key.json
acme_url: https://api.buypass.com/acme
acme_account_email: email@example.com
```

### ZeroSSL

```cfg
acme_keyfile: acme_srv/acme/zerossl.json
acme_url: https://acme.zerossl.com/v2/DV90
acme_account_email: email@example.com
account_path: /account/
```

### Smallstep CA

```cfg
acme_keyfile: acme_srv/acme/smallstep.json
acme_url: https://<fqdn>/acme/myacme
acme_account_email: email@example.com
account_path: /
ssl_verify: False
```

## Example Key File

```json
{
  "kty": "RSA",
  "n": "...",
  "e": "AQAB",
  "d": "..."
}
```

## Passing a Profile ID

To allow an ACME client to specify an ACME backend address, enable this feature in `acme_srv.cfg`:

```cfg
[Order]
header_info_list: ["HTTP_USER_AGENT"]
```

Example for `acme.sh`:

```bash
docker exec -i acme-sh acme.sh --server http://<acme-srv> --issue -d <fqdn> --standalone --useragent acme_url=<acme-server url> --debug 3 --output-insecure
```

Example for `lego`:

```bash
docker run -i -v $PWD/lego:/.lego/ --rm --name lego goacme/lego --tls-skip-verify -s https://<acme-srv> -a --email "lego@example.com" --user-agent acme_url=<acme-server url> -d <fqdn> --http run
```

# EAB Profiling

To enable EAB profiling:

```cfg
[EABhandler]
eab_handler_file: examples/eab_handler/kid_profile_handler.py
acme_key_path: <path>
eab_profiling: True

[CAhandler]
...
```

Example key-file:

```json
{
  "keyid_00": {
    "hmac": "...",
    "cahandler": {
      "acme_url": ["https://acme-staging-v02.api.letsencrypt.org"],
      "allowed_domainlist": ["www.example.com"]
    }
  }
}
```
