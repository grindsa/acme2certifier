# -*- coding: utf-8 -*-
# pylint: disable=c0209, r0913, w0613
""" example hook class """


class Hooks:
    """
    This class provides three different methods:
    - pre_hook (run before obtaining any certificates)
    - post_hook (run after *attempting* to obtain/renew certificates; runs regardless of whether
      obtain/renew succeeded or failed)
    - success_hook (run after each successfully renewed certificate)

    Each method should throw an Exception if an unrecoverable error occurs.

    This class contains dummy implementations of these hooks. To actually use hooks, create a class
    that contains all three methods; alternatively, you can create a subclass of this class and
    overwrite one or multiple of the methods.
    """

    def __init__(self, logger) -> None:
        self.logger = logger

    def pre_hook(self, certificate_name, order_name, csr) -> None:
        """ run before obtaining any certificates """
        self.logger.debug('Hook.pre_hook()')

        _hook_list = [certificate_name, order_name, csr]

    def post_hook(self, certificate_name, order_name, csr, error) -> None:
        """ run after *attempting* to obtain/renew certificates """
        self.logger.debug('Hook.post_hook()')

        _hook_list = [certificate_name, order_name, csr, error]

    def success_hook(self, certificate_name, order_name, csr, certificate, certificate_raw, poll_identifier) -> None:
        """ run after each successful certificate enrollment/renewal """
        self.logger.debug('Hook.success_hook()')

        _hook_list = [certificate_name, order_name, csr, certificate, certificate_raw, poll_identifier]
