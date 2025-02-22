# -*- coding: utf-8 -*-
""" Directory class """
# pylint: disable=e0401, r0913
from __future__ import print_function
import uuid
from typing import Dict
from .version import __version__, __dbversion__
from .helper import load_config, ca_handler_load
from .db_handler import DBstore


GH_HOME = 'https://github.com/grindsa/acme2certifier'


class Directory(object):
    """ class for directory handling """

    def __init__(self, debug=None, srv_name=None, logger=None):
        self.server_name = srv_name
        self.logger = logger
        self.dbstore = DBstore(debug, self.logger)
        self.cahandler = None
        self.supress_version = False
        self.suppress_product_information = False
        self.home = GH_HOME
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
            cfg_dic = dict(config_dic['Directory'])
            self.tos_url = cfg_dic.get('tos_url', None)
            self.url_prefix = cfg_dic.get('url_prefix', "")
            self.home = cfg_dic.get('home', GH_HOME)
            if 'supress_version' in config_dic['Directory']:
                self.supress_version = config_dic.getboolean('Directory', 'supress_version', fallback=False)
            if 'db_check' in config_dic['Directory']:
                self.db_check = config_dic.getboolean('Directory', 'db_check', fallback=False)
        if 'EABhandler' in config_dic and 'eab_handler_file' in config_dic['EABhandler']:
            self.eab = True
        try:
            self.suppress_product_information = config_dic.getboolean('Directory', 'suppress_product_information', fallback=False)
        except Exception as err_:
            self.logger.error('Directory._config_load() suppress_product_information not set: %s', err_)

        # load ca_handler according to configuration
        ca_handler_module = ca_handler_load(self.logger, config_dic)
        if ca_handler_module:
            # store handler in variable
            self.cahandler = ca_handler_module.CAhandler
        else:
            self.logger.critical('Certificate._config_load(): No ca_handler loaded')

        self.logger.debug('Directory._config_load() ended')

    def _directory_get(self) -> Dict[str, str]:
        """ return response to ACME directory call """
        self.logger.debug('Directory._directory_get()')
        d_dic = {
            'newAuthz': self.server_name + self.url_prefix + '/acme/new-authz',
            'newNonce': self.server_name + self.url_prefix + '/acme/newnonce',
            'newAccount': self.server_name + self.url_prefix + '/acme/newaccount',
            "newOrder": self.server_name + self.url_prefix + '/acme/neworders',
            'revokeCert': self.server_name + self.url_prefix + '/acme/revokecert',
            'keyChange': self.server_name + self.url_prefix + '/acme/key-change',
            'renewalInfo': self.server_name + self.url_prefix + '/acme/renewal-info',
            'meta': {}
        }

        if not self.suppress_product_information:
            d_dic['meta'] = {
                'home': self.home,
                'author': 'grindsa <grindelsack@gmail.com>',
                'name': 'acme2certifier'
            }
            # show version information in meta tags if not disabled....
            if not self.supress_version:
                d_dic['meta']['version'] = self.version
        else:
            if self.home != GH_HOME:
                d_dic['meta']['home'] = self.home

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
                    self.logger.error('acme2certifier database error: version mismatch: detected: %s/ expected: %s', version, __dbversion__)
                    d_dic['meta']['db_check'] = 'NOK'

            except Exception as err_:
                self.logger.critical('acme2certifier database error in Directory.dbversion_check(): %s', err_)
                d_dic['meta']['db_check'] = 'NOK'

        # generate random key in json as recommended by LE
        d_dic[uuid.uuid4().hex] = 'https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417'

        self.logger.debug('Directory._directory_get() ended')
        return d_dic

    def directory_get(self) -> Dict[str, str]:
        """ return response to ACME directory call """
        self.logger.debug('Directory.directory_get()')

        if self.cahandler:
            with self.cahandler(None, self.logger) as ca_handler:
                if 'handler_check' in dir(ca_handler):
                    error = ca_handler.handler_check()
                else:
                    error = None
        else:
            error = 'No handler loaded'

        if not error:
            d_dic = self._directory_get()
        else:
            self.logger.critical('Directory.directory_get() error: %s', error)
            d_dic = {
                'error': 'error in ca_handler configuration'
            }

        return d_dic

    def servername_get(self) -> str:
        """ dumb function to return servername """
        self.logger.debug('Directory.servername_get()')
        return self.server_name
