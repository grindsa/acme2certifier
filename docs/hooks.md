<!-- markdownlint-disable  MD013 -->
<!-- wiki-title Hooks -->
# Hooks

acme2certifer allows for the specification of pre and post enrollment hooks. Hooks are disabled by default and must be activated in `acme_srv.cfg` by specifying a file containing the required Hook class and methods.

```config
[Hooks]
hooks_file:  examples/hooks/skeleton_hooks.py
```

## How to create your own hooks

Creating your own hook-handler is pretty straightforward.  All you need to do is to create your own handler.py with a "Hooks" class containing the following methods.

- `pre_hook` - to be executed before certificate enrollment
- `post_hook` - to be executed after certificate enrollment regardless of the result
- `success_hook`  - to be executed in case of a successful certificate enrollment; this is executed *before* the `post_hook`

The [skeleton_hooks.py](../examples/hooks/skeleton_hooks.py) contains a skeleton which can be used to create a customized handler.

The below code describes the different input parameters given by acme2certifier as well as the expected return values.

```python
class Hooks(object):
    """ EAB file handler """

    def __init__(self, logger) -> None:
        self.logger = logger

    def pre_hook(self, certificate_name, order_name, csr) -> None:
        """ run before obtaining any certificates """
        self.logger.debug('Hook.pre_hook()')

    def post_hook(self, certificate_name, order_name, csr, error) -> None:
        """ run after *attempting* to obtain/renew certificates """
        self.logger.debug('Hook.post_hook()')

    def success_hook(self, certificate_name, order_name, csr, certificate, certificate_raw, poll_identifier) -> None:
        """ run after each successful certificate enrollment/renewal """
        self.logger.debug('Hook.success_hook()')
```

- self.logger - reference to a logging object
- certificate - certificate in `application/pem-certificate-chain` format
- certificate_name - name of the certificate resource in acme2certifier
- certificate_raw - certificate in base64 encoded binary format
- csr - certificate signing request in base64 encoded binary format
- error - error message in case of certificate enrollment
- order_name - name of the order resource in acme2certifier

The different methods must not return any data. Exceptions during hook execution are handled by
acme2certifier, see [below](#handling-of-exceptions).

## Handling of exceptions

By default, certificate enrollment/renewal is aborted (and acme2certifier returns an error code to
the client) if either the `pre_hook` or `success_hook` fails. In either case, later hooks are also not executed:

- If the `pre_hook` fails, neither `success_hook` nor `post_hook` is executed.
- If the `success_hook` fails, the `post_hook` is not executed.

If the `post_hook` throws an exception, the error is logged but it has no effect on the
enrollment/renewal; i.e., it finishes successfully (given that no other error occurred).

This behavior can be controlled through the configuration options `allow_pre_hook_failure`,
`allow_post_hook_failure`, and `allow_success_hook_failure`, see [the configuration
table](acme_srv.md#configuration-options-for-acme2certifier).
