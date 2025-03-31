<!-- markdownlint-disable MD013 -->
<!-- wiki-title: Hooks -->

# Hooks

`acme2certifier` allows for the specification of pre- and post-enrollment hooks. Hooks are disabled by default and must be activated in `acme_srv.cfg` by specifying a file containing the required `Hooks` class and methods.

```config
[Hooks]
hooks_file: examples/hooks/skeleton_hooks.py
```

## How to Create Your Own Hooks

Creating your own hook handler is straightforward. All you need to do is create a `handler.py` file with a `Hooks` class containing the following methods:

- `pre_hook` - Executed before certificate enrollment.
- `post_hook` - Executed after certificate enrollment, regardless of the result.
- `success_hook` - Executed in case of a successful certificate enrollment; this runs *before* the `post_hook`.

The [skeleton_hooks.py](../examples/hooks/skeleton_hooks.py) file contains a template that can be used to create a customized handler.

The following code describes the different input parameters provided by `acme2certifier`, as well as the expected return values:

```python
class Hooks:
    """ EAB file handler """

    def __init__(self, logger) -> None:
        self.logger = logger

    def pre_hook(self, certificate_name, order_name, csr) -> None:
        """ Run before obtaining any certificates """
        self.logger.debug('Hook.pre_hook()')

    def post_hook(self, certificate_name, order_name, csr, error) -> None:
        """ Run after *attempting* to obtain/renew certificates """
        self.logger.debug('Hook.post_hook()')

    def success_hook(self, certificate_name, order_name, csr, certificate, certificate_raw, poll_identifier) -> None:
        """ Run after each successful certificate enrollment/renewal """
        self.logger.debug('Hook.success_hook()')
```

### Input Parameters

- `self.logger` - Reference to a logging object.
- `certificate` - Certificate in `application/pem-certificate-chain` format.
- `certificate_name` - Name of the certificate resource in `acme2certifier`.
- `certificate_raw` - Certificate in base64-encoded binary format.
- `csr` - Certificate Signing Request in base64-encoded binary format.
- `error` - Error message in case of certificate enrollment failure.
- `order_name` - Name of the order resource in `acme2certifier`.

The different methods must not return any data. Exceptions during hook execution are handled by `acme2certifier`, as described below.

## Handling Exceptions

By default, certificate enrollment/renewal is aborted (and `acme2certifier` returns an error code to the client) if either the `pre_hook` or `success_hook` fails. In such cases, later hooks are also not executed:

- If the `pre_hook` fails, neither the `success_hook` nor `post_hook` is executed.
- If the `success_hook` fails, the `post_hook` is not executed.

If the `post_hook` throws an exception, the error is logged, but it has no effect on the enrollment/renewal process. That is, the process completes successfully as long as no other errors occur.

This behavior can be controlled through the configuration options `allow_pre_hook_failure`, `allow_post_hook_failure`, and `allow_success_hook_failure`. See [the configuration table](acme_srv.md#configuration-options-for-acme2certifier) for more details.
