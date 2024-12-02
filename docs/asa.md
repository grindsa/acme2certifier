<!-- markdownlint-disable  MD013 -->
<!-- wiki-title CA handler for Insta -->
# Connecting to Insta ActiveCMS

## Prerequisites

- ActiveCMS needs to have Active Security API activated
- you need to have user, password and an api key to access the ASA
- you need ot have permissions to revoke and enroll certificates

## Configuration

- modify the server configuration (`/acme_srv/acme_srv.cfg`) and add the following parameters

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

- api_host - URL of Active Security API
- api_user - REST user
- api_user_variable - *optional* - name of the environment variable containing the REST username (a configured `api_user` parameter in acme_srv.cfg takes precedence)
- api_password - password for REST user
- api_password_variable - *optional* - name of the environment variable containing the password for the REST user (a configured `api_password` parameter in acme_srv.cfg takes precedence)
- api_key - key for REST user
- api_key_variable - *optional* - name of the environment variable containing the api_key for the REST access (a configured `api_key` parameter in acme_srv.cfg takes precedence)
- ca_bundle - certificate bundle needed to validate the server certificate - can be True/False or a filename (default: None)
- ca_name - name of the CA used to enroll certificates
- profile_name - profile name
- cert_validity_days - optional - polling timeout (default: 60s)

It is also recommended to increase the enrollment timeout to avoid that acme2certifier is closing the connection to early.

```config
[Certificate]
enrollment_timeout:15
```

You can get the list of certificate authrities by running the following REST call against ASA.

```bash
root@rlh:~# curl -u '$api_user':'$api_password' -H "x-api-key: <api_key> $api_host'/list_issuers
```

You can get the list of profiles by running the following REST call against ASA (ca_name parameter must be [url-encoded](https://en.wikipedia.org/wiki/Percent-encoding)).

```bash
root@rlh:~# curl -u '$api_user':'$api_password' -H "x-api-key: <api_key> $api_host'/list_profiles?issuerName=<ca_name>
```

The CA handler will verify ca_name and profile_name parameters before enrollment.

## Passing a profileID from client to server

The handler makes use of the [header_info_list feature](header_info.md) allowing an acme-client to specify a profile_name to be used during certificate enrollment. This feature is disabled by default and must be activate in `acme_srv.cfg` as shown below

```config
[Order]
...
header_info_list: ["HTTP_USER_AGENT"]
```

The acme-client can then specify the profile_name as part of its user-agent string.

Example for acme.sh:

```bash
docker exec -i acme-sh acme.sh --server http://<acme-srv> --issue -d <fqdn> --standalone --useragent profile_name=<profile-name> --debug 3 --output-insecure
```

Example for lego:

```bash
docker run -i -v $PWD/lego:/.lego/ --rm --name lego goacme/lego -s http://<acme-srv> -a --email "lego@example.com" --user-agent profile_name=<profile_name> -d <fqdn> --http run
```
