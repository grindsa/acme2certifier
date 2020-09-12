<!-- markdownlint-disable  MD013 -->
<!-- wiki-title CA handler for NetGuard Certificate Lifecycle Manager -->
# Connecting to NetGuard Certificate Lifecycle Manager

## Pre-requisites

- NCLM 19.0.5 or higher needs to be up and running
- you need username and password to access NCLM via REST-Service
- there is a container created in NCLM which can be used to store the certificates

## Configuration

- copy the ca_handler into the acme directory

```bash
root@rlh:~# cp example\nclm_ca_handler.py acme\ca_handler.py
```

- modify the server configuration (/acme/acme_srv.cfg) and add the following parameters

```config
[CAhandler]
api_host: http://<ip>:<port>
api_user: <user>
api_password: <password>
ca_bundle: <value>
ca_name: <ca_name>
tsg_name: <tsg_name>
ca_id_list: <ca_id_list>
```

- api_host - URL of the Certifier-REST service
- api_user - REST user
- api_password - password for REST user
- ca_bundle - optional - certificate bundle needed to validate the server certificate - can be True/False or a filename (default: True)
- ca_name - name of the CA used to enroll certificates
- tsg_name - name of the target system group to store the certificates
- ca_id_list - list of CA certificates ids to be used to create the certificate bundle
