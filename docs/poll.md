<!-- markdownlint-disable MD013 -->
<!-- wiki-title CA Polling to Check Pending Enrollment Requests -->
# `Ca_handler.poll()`

The `poll` method has been implemented to support use cases where certificate issuance requires manual approval by the CA administrator.

In such cases, **acme2certifier** marks the status of the order resource as **"processing"** and includes a **"Retry-After"** header in the response to an order status polling request, as described in [RFC 8555, Section 7.4](https://tools.ietf.org/html/rfc8555#section-7.4).

Additionally, when a CSR enters the **"pending"** state, it is assumed that the CA server provides information in the enrollment response that can be used to look up the request's status. This information is returned by the `ca.handler.enroll()` method (stored in the variable `poll_identifier`) and is saved in the database alongside the CSR in the **`certificate`** table under the **`poll_identifier`** field.

## Polling Implementation

The script [`cert_poll.py`](../tools/cert_poll.py) is located in the **tools** directory and can be scheduled via **cron**. It scans the **`orders`** table for orders with status **"processing" (4)** and passes the `poll_identifier`, along with other necessary information, to the `certificate.poll()` method.

### `ca_handler.poll()` Responsibilities

The `ca_handler.poll()` method:

1. **Checks the status of the CSR** on the CA server.
2. **Downloads the certificate** if it is available.
3. **Builds the certificate chain** and returns the following details to `certificate.poll()`, which then updates the database:

   - An **error message**, if any.
   - The **certificate chain** in PEM format.
   - The **certificate** in ASN.1 (binary) format, Base64-encoded (needed for revocation).
   - An **updated poll_identifier**.
   - An indication (`True`/`False`) of whether the CSR was rejected.

### Status Updates

- If the certificate is issued, the **order status** is set to **"valid"**, and a **URL to the `certificate` resource** is provided when an ACME client polls the `order` resource.
- If the CSR is rejected, the **order status** changes to **"invalid"**.

## Example Implementations

An example implementation is available in the handler for **[NCLM/Insta Certifier](certifier.md)**.

Additionally, an **[example `acme_srv.db`](../examples/acme_srv.db.example)** is provided to give insight into expected values, particularly in the **certificate** table.
