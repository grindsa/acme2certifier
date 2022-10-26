<!-- markdownlint-disable  MD013 -->
<!-- wiki-title CA handler for NetGuard Certificate Lifecycle Manager -->
# Connecting to NetGuard Certificate Lifecycle Manager

## Pre-requisites

- NCLM 19.0.0 or higher needs to be up and running
- username and password to access NCLM via REST-Service
- is a container created in NCLM which can be used to store the certificates

## Configuration

- copy the ca_handler into the acme directory

```bash
root@rlh:~# cp example\nclm_ca_handler.py acme\ca_handler.py
```

- modify the server configuration (/acme_srv/acme_srv.cfg) and add the following parameters

```config
[CAhandler]
api_host: http://<ip>:<port>
api_user: <user>
api_password: <password>
ca_bundle: <value>
ca_name: <ca_name>
tsg_name: <tsg_name>
template_name: <template_name>
```

- api_host - URL of the Certifier-REST service
- api_user - REST user
- api_user_variable - *optional* - name of the environment variable containing the REST username (a configured `api_user` parameter in acme_srv.cfg takes precedence)
- api_password - password for REST user
- api_password_variable - *optional* - name of the environment variable containing the password for the REST user (a configured `api_password` parameter in acme_srv.cfg takes precedence)
- ca_bundle - optional - certificate bundle needed to validate the server certificate - can be True/False or a filename (default: True)
- ca_name - name of the CA used to enroll certificates
- tsg_name - name of the target system group to store the certificates
- template_name - optional - name of the template to be applied to CSR
