<!-- markdownlint-disable MD013 -->

<!-- wiki-title CA handler for Insta -->

# Connecting to Insta ActiveCMS

## Prerequisites

- ActiveCMS needs to have the Active Security API activated.
- You need to have a user, password, and an API key to access the ASA.
- You need to have permissions to revoke and enroll certificates.

## Configuration

Modify the server configuration (`/acme_srv/acme_srv.cfg`) and add the following parameters:

```config
[CAhandler]
handler_file: examples/ca_handler/asa_ca_handler.py
api_host: http://<ip>:<port>
api_user: <user>
api_password: <password>
api_key: <api_key>
ca_bundle: <value>
ca_name: <ca_name>
profile_name: <value>
cert_validity_days: <days>
```

### Parameter Descriptions

- `api_host` - URL of the Active Security API.
- `api_user` - REST user.
- `api_user_variable` - *Optional* - Name of the environment variable containing the REST username (a configured `api_user` parameter in `acme_srv.cfg` takes precedence).
- `api_password` - Password for the REST user.
- `api_password_variable` - *Optional* - Name of the environment variable containing the password for the REST user (a configured `api_password` parameter in `acme_srv.cfg` takes precedence).
- `api_key` - Key for the REST user.
- `api_key_variable` - *Optional* - Name of the environment variable containing the API key for REST access (a configured `api_key` parameter in `acme_srv.cfg` takes precedence).
- `ca_bundle` - Certificate bundle needed to validate the server certificate. Can be `True`/`False` or a filename (default: `None`).
- `ca_name` - Name of the CA used to enroll certificates.
- `profile_name` - Profile name.
- `cert_validity_days` - *Optional* - Polling timeout (default: `60s`).
- `enrollment_config_log` - *Optional* - Log enrollment parameters (default: `False`).
- `enrollment_config_log_skip_list` - *Optional* - List of enrollment parameters not to be logged, in JSON format. Example: `["parameter1", "parameter2"]` (default: `[]`).
- `allowed_domainlist` - *Optional* - List of domain names allowed for enrollment, in JSON format. Example: `["bar.local$", "bar.foo.local"]` (default: `[]`).

### Increase Enrollment Timeout

It is recommended to increase the enrollment timeout to prevent `acme2certifier` from closing the connection too early.

```config
[Certificate]
enrollment_timeout: 15
```

### Retrieving CA and Profile Information

You can retrieve the list of certificate authorities by running the following REST call against ASA:

```bash
root@rlh:~# curl -u "$api_user":"$api_password" -H "x-api-key: <api_key>" $api_host'/list_issuers'
```

You can retrieve the list of profiles by running the following REST call against ASA (the `ca_name` parameter must be [URL-encoded](https://en.wikipedia.org/wiki/Percent-encoding)):

```bash
root@rlh:~# curl -u "$api_user":"$api_password" -H "x-api-key: <api_key>" $api_host'/list_profiles?issuerName=<ca_name>'
```

The CA handler will verify the `ca_name` and `profile_name` parameters before enrollment.

## Passing a Profile ID from Client to Server

acme2certifier supports the the [Automated Certificate Management Environment (ACME) Profiles Extension draft](acme_profiling.md) allowing an acme-client to specify a `profile_name` parameter to be submitted to the CA server.

The list of supported profiles must be configured in `acme_srv.cfg`

```config
[Order]
profiles: {"profile1": "http://foo.bar/profile1", "profile2": "http://foo.bar/profile2", "profile3": "http://foo.bar/profile3"}
```

Once enabled, a client can specify the profile_name to be used as part of an order request. Below an example for lego:

```bash
docker run -i -v $PWD/lego:/.lego/ --rm --name lego goacme/lego --tls-skip-verify -s https://<acme-srv> -a --email "lego@example.com" -d <fqdn> --http run --profile profile2
```

Further, this handler makes use of the [header_info_list feature](header_info.md), allowing an ACME client to specify a `profile_name` to be used during certificate enrollment. This feature is disabled by default and must be activated in `acme_srv.cfg` as shown below:

```config
[Order]
...
header_info_list: ["HTTP_USER_AGENT"]
```

The ACME client can then specify the `profile_name` as part of its user-agent string.

### Example for acme.sh

```bash
docker exec -i acme-sh acme.sh --server http://<acme-srv> --issue -d <fqdn> --standalone --useragent profile_name=<profile-name> --debug 3 --output-insecure
```

### Example for Lego

```bash
docker run -i -v $PWD/lego:/.lego/ --rm --name lego goacme/lego --tls-skip-verify -s https://<acme-srv> -a --email "lego@example.com" --user-agent profile_name=<profile_name> -d <fqdn> --http run
```
