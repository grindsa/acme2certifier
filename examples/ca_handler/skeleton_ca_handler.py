# -*- coding: utf-8 -*-
""" skeleton for customized CA handler """
from __future__ import print_function
from typing import Tuple
# pylint: disable=C0209, E0401
from acme_srv.helper import load_config, header_info_get


class CAhandler(object):
    """ EST CA  handler """

    def __init__(self, _debug: bool = None, logger: object = None):
        self.logger = logger
        self.parameter = None

    def __enter__(self):
        """ Makes CAhandler a Context Manager """
        if not self.parameter:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _config_load(self):
        """" load config from file """
        self.logger.debug('CAhandler._config_load()')

        config_dic = load_config(self.logger, 'CAhandler')
        if 'CAhandler' in config_dic and 'parameter' in config_dic['CAhandler']:
            self.parameter = config_dic['CAhandler']['parameter']

        self.logger.debug('CAhandler._config_load() ended')

    def _stub_func(self, parameter: str):
        """" load config from file """
        self.logger.debug('CAhandler._stub_func({0})'.format(parameter))

        self.logger.debug('CAhandler._stub_func() ended')

    def enroll(self, csr: str) -> Tuple[str, str, str, str]:
        """ enroll certificate  """
        self.logger.debug('CAhandler.enroll()')

        cert_bundle = None
        error = None
        cert_raw = None
        poll_indentifier = None

        # optional: lookup http header information from request
        qset = header_info_get(self.logger, csr=csr)
        if qset:
            self.logger.info(qset[-1]['header_info'])

        self._stub_func(csr)
        self.logger.debug('Certificate.enroll() ended')

        return (error, cert_bundle, cert_raw, poll_indentifier)

    def poll(self, cert_name: str, poll_identifier: str, _csr: str) -> Tuple[str, str, str, str, bool]:
        """ poll status of pending CSR and download certificates """
        self.logger.debug('CAhandler.poll()')

        error = None
        cert_bundle = None
        cert_raw = None
        rejected = False
        self._stub_func(cert_name)

        self.logger.debug('CAhandler.poll() ended')
        return (error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(self, _cert: str, _rev_reason: str, _rev_date: str) -> Tuple[int, str, str]:
        """ revoke certificate """
        self.logger.debug('CAhandler.revoke()')

        code = 500
        message = 'urn:ietf:params:acme:error:serverInternal'
        detail = 'Revocation is not supported.'

        self.logger.debug('Certificate.revoke() ended')
        return (code, message, detail)

    def trigger(self, payload: str) -> Tuple[str, str, str]:
        """ process trigger message and return certificate """
        self.logger.debug('CAhandler.trigger()')

        error = None
        cert_bundle = None
        cert_raw = None
        self._stub_func(payload)

        self.logger.debug('CAhandler.trigger() ended with error: {0}'.format(error))
        return (error, cert_bundle, cert_raw)
