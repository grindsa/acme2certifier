class Hooks:
    """
    This class provides three different methods:
    - pre_hook (run before obtaining any certificates)
    - post_hook (run after *attempting* to obtain/renew certificates; runs regardless of whether
      obtain/renew succeeded or failed)
    - success_hook (run after each successfully renewed certificate)

    Each method should throw an Exception if an unrecoverable error occurs.

    This class contains dummy implementations of these hooks. To actually use hooks, create a
    subclass and overwrite one or multiple of the methods.
    """

    def __init__(self, logger) -> None:
        self.logger = logger

    def pre_hook(
        self,
        certificate_name,
        order_name,
        csr,
    ):
        pass

    def post_hook(
        self,
        certificate_name,
        order_name,
        csr,
        error,
    ):
        pass

    def success_hook(
        self,
        certificate_name,
        order_name,
        csr,
        certificate,
        certificate_raw,
        poll_identifier,
    ):
        pass
