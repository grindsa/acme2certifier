# -*- coding: utf-8 -*-
# pylint: disable=C0209, E0401, R0913, W0613
""" hook class for testing """
import json
from acme_srv.helper import load_config, cert_san_get, csr_san_get


class Hooks:
    """ this handler dumps csr/cn common-names into text files """

    def __init__(self, logger) -> None:
        self.logger = logger
        self.save_path = None
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
        if 'Hooks' in config_dic and 'save_path' in config_dic['Hooks']:
            self.save_path = config_dic['Hooks']['save_path']

    def _file_append(self, filename, content):
        """ save content to file """
        self.logger.debug('Hooks._file_append({0})'.format(filename))
        with open(filename, 'a', encoding='utf-8') as fso:
            fso.write(content)
        self.logger.debug('Hooks._file_append() ended')

    def pre_hook(self, _certificate_name, _order_name, csr):
        """ run before obtaining any certificates """
        self.logger.debug('Hook.pre_hook()')
        san_list = csr_san_get(self.logger, csr)
        self._file_append('{0}/pre_hook.txt'.format(self.save_path), json.dumps(san_list) + '\n')

    def post_hook(self, _certificate_name, _order_name, csr, _error):
        """ run after *attempting* to obtain/renew certificates """
        self.logger.debug('Hook.post_hook()')
        san_list = csr_san_get(self.logger, csr)
        self._file_append('{0}/post_hook.txt'.format(self.save_path), json.dumps(san_list) + '\n')

    def success_hook(self, _certificate_name, _order_name, _csr, _certificate, certificate_raw, _poll_identifier):
        """ run after each successfully certificate enrollment/renewal """
        self.logger.debug('Hook.success_hook()')
        san_list = cert_san_get(self.logger, certificate_raw)
        self._file_append('{0}/success_hook.txt'.format(self.save_path), json.dumps(san_list) + '\n')
