# -*- coding: utf-8 -*-
# pylint: disable=c0209, e0401, r0913, w0613
""" exception hook class for testing only """
from acme_srv.helper import load_config


class Hooks:
    """ This handler does not do anything useful and is used to test proper exception handling during hook execution """

    def __init__(self, logger) -> None:
        self.logger = logger
        self.raise_pre_hook_exception = False
        self.raise_success_hook_exception = False
        self.raise_post_hook_exception = False
        self._config_load()

    def __enter__(self):
        """ Makes hook handler context manager """
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _config_load(self):
        """" load config from file """
        # pylint: disable=R0912, R0915
        self.logger.debug('CAhandler._config_load()')
        config_dic = load_config(self.logger, 'Hooks')
        if 'Hooks' in config_dic:
            self.raise_pre_hook_exception = config_dic.getboolean('Hooks', 'raise_pre_hook_exception', fallback=False)
            self.raise_success_hook_exception = config_dic.getboolean('Hooks', 'raise_success_hook_exception', fallback=False)
            self.raise_post_hook_exception = config_dic.getboolean('Hooks', 'raise_post_hook_exception', fallback=False)

    def pre_hook(self, certificate_name, order_name, _csr) -> None:
        """ run before obtaining any certificates """
        self.logger.debug('Hook.pre_hook({0}/{1})'.format(certificate_name, order_name))
        if self.raise_pre_hook_exception:
            raise SystemError('raise_pre_hook_exception')

    def post_hook(self, certificate_name, order_name, _csr, _error) -> None:
        """ run after *attempting* to obtain/renew certificates """
        self.logger.debug('Hook.post_hook({0}/{1})'.format(certificate_name, order_name))
        if self.raise_post_hook_exception:
            raise SystemError('raise_post_hook_exception')

    def success_hook(self, certificate_name, order_name, _csr, _certificate, _certificate_raw, _poll_identifier) -> None:
        """ run after each successful certificate enrollment/renewal """
        self.logger.debug('Hook.success_hook({0}/{1})'.format(certificate_name, order_name))
        if self.raise_success_hook_exception:
            raise SystemError('raise_success_hook_exception')
