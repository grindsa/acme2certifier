#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Directory class """
# pylint: disable=c0209, e0401, r0913
from __future__ import print_function
import uuid
from .version import __version__, __dbversion__
from .helper import load_config
from .db_handler import DBstore


class Directory(object):
    """ class for directory handling """

    def __init__(self, debug=None, srv_name=None, logger=None):
        self.server_name = srv_name
        self.logger = logger
        self.dbstore = DBstore(debug, self.logger)
        self.supress_version = False
        self.tos_url = None
        self.version = __version__
        self.dbversion = __dbversion__
        self.db_check = False
        self.eab = False
        self.url_prefix = ""

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _config_load(self):
        """" load config from file """
        self.logger.debug('Directory._config_load()')
        config_dic = load_config(self.logger, 'Directory')
        if 'Directory' in config_dic:
            if 'supress_version' in config_dic['Directory']:
                self.supress_version = config_dic.getboolean('Directory', 'supress_version', fallback=False)
            if 'tos_url' in config_dic['Directory']:
                self.tos_url = config_dic['Directory']['tos_url']
            if 'db_check' in config_dic['Directory']:
                self.db_check = config_dic.getboolean('Directory', 'db_check', fallback=False)
        if 'EABhandler' in config_dic and 'eab_handler_file' in config_dic['EABhandler']:
            self.eab = True
        if 'Directory' in config_dic and 'url_prefix' in config_dic['Directory']:
            self.url_prefix = config_dic['Directory']['url_prefix']

        self.logger.debug('CAhandler._config_load() ended')

    def directory_get(self):
        """ return response to ACME directory call """
        self.logger.debug('Directory.directory_get()')

        d_dic = {
            'newAuthz': self.server_name + self.url_prefix + '/acme/new-authz',
            'newNonce': self.server_name + self.url_prefix + '/acme/newnonce',
            'newAccount': self.server_name + self.url_prefix + '/acme/newaccount',
            "newOrder": self.server_name + self.url_prefix + '/acme/neworders',
            'revokeCert': self.server_name + self.url_prefix + '/acme/revokecert',
            'keyChange': self.server_name + self.url_prefix + '/acme/key-change',
            'meta': {
                'home': 'https://github.com/grindsa/acme2certifier',
                'author': 'grindsa <grindelsack@gmail.com>',
                'name': 'acme2certifier'
            },
        }

        # show version information in meta tags if not disabled....
        if not self.supress_version:
            d_dic['meta']['version'] = self.version

        # add terms of service
        if self.tos_url:
            d_dic['meta']['termsOfService'] = self.tos_url

        # indicate eab requirement
        if self.eab:
            d_dic['meta']['externalAccountRequired'] = True

        if self.db_check:
            try:
                (version, _script_name) = self.dbstore.dbversion_get()
                if version == self.dbversion:
                    d_dic['meta']['db_check'] = 'OK'
                else:
                    self.logger.error('acme2certifier database error: version mismatch: detected: {0}/ expected: {1}'.format(version, __dbversion__))
                    d_dic['meta']['db_check'] = 'NOK'

            except Exception as err_:
                self.logger.critical('acme2certifier database error in Directory.dbversion_check(): {0}'.format(err_))
                d_dic['meta']['db_check'] = 'NOK'

        # generate random key in json as recommended by LE
        d_dic[uuid.uuid4().hex] = 'https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417'
        return d_dic

    def servername_get(self):
        """ dumb function to return servername """
        self.logger.debug('Directory.servername_get()')
        return self.server_name
