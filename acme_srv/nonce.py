#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Nonce class """
# pylint: disable=c0209
from __future__ import print_function
import uuid
from acme_srv.db_handler import DBstore


class Nonce(object):
    """ Nonce handler """

    def __init__(self, debug=None, logger=None):
        self.debug = debug
        self.logger = logger
        self.dbstore = DBstore(self.debug, self.logger)

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _check_and_delete(self, nonce):
        """ check if nonce exists and delete it """
        self.logger.debug('Nonce.nonce._check_and_delete({0})'.format(nonce))

        try:
            nonce_chk_result = self.dbstore.nonce_check(nonce)
        except Exception as err_:
            self.logger.critical('acme2certifier database error during nonce_check() in Nonce._check_and_delete(): {0}'.format(err_))
            nonce_chk_result = False

        if nonce_chk_result:
            try:
                self.dbstore.nonce_delete(nonce)
            except Exception as err_:
                self.logger.critical('acme2certifier database error during nonce_delete() in Nonce._check_and_delete(): {0}'.format(err_))
            code = 200
            message = None
            detail = None
        else:
            code = 400
            message = 'urn:ietf:params:acme:error:badNonce'
            detail = nonce
        self.logger.debug('Nonce._check_and_delete() ended with:{0}'.format(code))
        return (code, message, detail)

    def _new(self):
        """ generate a new nonce """
        self.logger.debug('Nonce.nonce__new()')
        return uuid.uuid4().hex

    def check(self, protected_decoded):
        """ check nonce """
        self.logger.debug('Nonce.check_nonce()')
        if 'nonce' in protected_decoded:
            (code, message, detail) = self._check_and_delete(protected_decoded['nonce'])
        else:
            code = 400
            message = 'urn:ietf:params:acme:error:badNonce'
            detail = 'NONE'
        self.logger.debug('Nonce.check_nonce() ended with:{0}'.format(code))
        return (code, message, detail)

    def generate_and_add(self):
        """ generate new nonce and store it """
        self.logger.debug('Nonce.nonce_generate_and_add()')
        nonce = self._new()
        self.logger.debug('got nonce: {0}'.format(nonce))
        # self.logger.critical('foo')
        try:
            _id = self.dbstore.nonce_add(nonce)  # lgtm [py/unused-local-variable]
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Nonce.generate_and_add(): {0}'.format(err_))
        self.logger.debug('Nonce.generate_and_add() ended with:{0}'.format(nonce))
        return nonce
