<!-- markdownlint-disable MD013 -->

<!-- wiki-title: Support for ACME profiling -->

# Support for ACME Profiles Extension

The [Automated Certificate Management Environment (ACME) Profiles Extension draft](https://datatracker.ietf.org/doc/draft-aaron-acme-profiles/) proposes a method for ACME servers to offer multiple certificate profiles, allowing clients to select certificates that align with specific requirements, such as validity periods or key usage constraints. This enhancement aims to provide greater flexibility and security by enabling clients to choose from predefined profiles advertised by the server, thereby reducing reliance on custom Certificate Signing Requests (CSRs).

acme2certifier supports acme profiling starting from version v0.38.

ACME profiling must be must be specified in `acme_srv.cfg`:

```config
[Order]
profiles: {"profile1": "http://foo.bar/profile1", "profile2": "http://foo.bar/profile2", "profile3": "http://foo.bar/profile3"}
```

Below an example for lego submitting a profile "profile2":

```bash
docker run -i -v $PWD/lego:/.lego/ --rm --name lego goacme/lego -s http://<acme-srv> -a --email "lego@example.com" -d <fqdn> --http run --profile profile2
```

acme2certifier will check a submitted profile-name against the list of advertised profiles. If a client submits an order for an unknown profile the order the order will get refused with an "invalidProfile" error. acme2certifier can be configured to skip this check and accept any profile name as long as profiling gets enabled in the config.

```config
[Order]
profiles: {"profile1": "http://foo.bar/profile1", "profile2": "http://foo.bar/profile2", "profile3": "http://foo.bar/profile3"}
profiles_check_disable: True
```

Depending on the CA-handler the profile value replaces a certain value in the CA-handler configuration. The below table provides an overview about the individual paramters:

| CA-handler                                                                           | configuration parameter |
| ------------------------------------------------------------------------------------ | ----------------------- |
| [ACME Handler](docs/acme_ca.md)                                                      | profile                 |
| [DigiCert® CertCentral](docs/digicert.md)                                            | cert_type               |
| [EJBCA](docs/ejbca.md)                                                               | cert_profile_name       |
| [Insta ActiveCMS](docs/asa.md)                                                       | profile_name            |
| [Microsoft Certificate Enrollment Web Services](docs/mscertsrv.md)                   | template                |
| [Microsoft Windows Client Certificate Enrollment Protocol (MS-WCCE)](docs/mswcce.md) | template                |
| [NetGuard Certificate Manager/Insta Certifier](docs/certifier.md)                    | profile_id              |
| [OpenXPKI](docs/openxpki.md)                                                         | cert_profile_name       |
| [XCA](docs/xca.md)                                                                   | template_name           |

The profile value will be added to the `profile` column of the orders table. A CA handler can obtail the value using the `eab_profile_header_info_check()` function from `helper.py`.

```python
from acme_srv.helper import (
    eab_profile_header_info_check,
    ...
)  # pylint: disable=e0401

class CAHandler(object):
    ...
    def __init__(self, _debug: bool = False, logger: object = None):
        template = None

    def enroll(self, csr):
        """Enroll certificate"""
        self.logger.debug('CAHandler.enroll()')

        cert_bundle = None
        error = None
        cert_raw = None
        poll_identifier = None

        # Lookup HTTP header information from request
        error = eab_profile_header_info_check(
            self.logger, self, csr, "template"
        )
        if not error:
            self.logger.info('Profile: {0}'.format(self.template))
            # Perform additional processing with the profile information...
        ...
        self.logger.debug('Certificate.enroll() ended')

        return (error, cert_bundle, cert_raw, poll_identifier)
```
