#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Directory class """
from __future__ import print_function
import uuid
from .version import __version__
from .helper import load_config

class Directory(object):
    """ class for directory handling """

    def __init__(self, _debug=None, srv_name=None, logger=None):
        self.server_name = srv_name
        self.logger = logger
        self.supress_version = False
        self.tos_url = None
        self.version = __version__
        self.eab = False

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
        if 'Account' in config_dic:
            if 'eab_handler_file' in config_dic['Account']:
                self.eab = True

        self.logger.debug('CAhandler._config_load() ended')

    def directory_get(self):
        """ return response to ACME directory call """
        self.logger.debug('Directory.directory_get()')

        d_dic = {
            'newAuthz' : self.server_name + '/acme/new-authz',
            'newNonce': self.server_name + '/acme/newnonce',
            'newAccount': self.server_name + '/acme/newaccount',
            "newOrder": self.server_name + '/acme/neworders',
            'revokeCert' : self.server_name + '/acme/revokecert',
            'keyChange' : self.server_name + '/acme/key-change',
            'meta' : {
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

        # generate random key in json as recommended by LE
        d_dic[uuid.uuid4().hex] = 'https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417'
        return d_dic

    def servername_get(self):
        """ dumb function to return servername """
        self.logger.debug('Directory.servername_get()')
        return self.server_name
