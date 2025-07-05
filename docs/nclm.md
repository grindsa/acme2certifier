<!-- markdownlint-disable MD013 -->

<!-- wiki-title CA Handler for NetGuard Certificate Lifecycle Manager -->

# Connecting to NetGuard Certificate Lifecycle Manager

## Prerequisites

Ensure the following conditions are met before configuring the connection:

- **NCLM 24.2.0 or higher** must be up and running.
- The **external REST API** must be enabled.
- You must have a **username and password** to access NCLM via the REST service.
- A **container must be created in NCLM** to store the certificates.

## Configuration

Modify the server configuration file (`/acme_srv/acme_srv.cfg`) and add the following parameters:

```ini
[CAhandler]
handler_file: examples/ca_handler/nclm_ca_handler.py
api_host: http://<ip>:<port>
api_user: <user>
api_password: <password>
ca_bundle: <value>
ca_name: <ca_name>
container_name: <container_name>
template_name: <template_name>
```

### Parameter Explanations

- **api_host** – URL of the Certifier REST service.
- **api_user** – Username for the REST API.
- **api_user_variable** *(optional)* – Environment variable containing the REST username (overridden if `api_user` is set in `acme_srv.cfg`).
- **api_password** – Password for the REST API user.
- **api_password_variable** *(optional)* – Environment variable containing the REST password (overridden if `api_password` is set in `acme_srv.cfg`).
- **ca_bundle** *(optional)* – Certificate bundle used to validate the server certificate. Can be `True`, `False`, or a filename (default: `True`).
- **ca_name** – Name of the CA used for certificate enrollment.
- **container_name** – Name of the container where certificates will be stored.
- **template_name** *(optional)* – Name of the template to be applied to the CSR.
- **allowed_domainlist** *(optional)* – List of allowed domain names for enrollment (JSON format). Example: `["bar.local", "bar.foo.local"]` (default: `[]`).
- **eab_profiling** *(optional)* – [Enable EAB profiling](eab_profiling.md) (default: `False`).
- **enrollment_config_log** *(optional)* – Enable logging of enrollment parameters (default: `False`).
- **enrollment_config_log_skip_list** *(optional)* – List of enrollment parameters to exclude from logs (JSON format). Example: `["parameter1", "parameter2"]` (default: `[]`).
