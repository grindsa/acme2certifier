#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Nonce class """
# pylint: disable=c0209
from __future__ import print_function
import uuid
from acme_srv.db_handler import DBstore


class Renewalinfo(object):
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

