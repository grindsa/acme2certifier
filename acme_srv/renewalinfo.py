#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Nonce class """
# pylint: disable=c0209
from __future__ import print_function
from acme_srv.db_handler import DBstore
from acme_srv.helper import string_sanitize, certid_hex_get, uts_to_date_utc, error_dic_get


class Renewalinfo(object):
    """ Nonce handler """

    def __init__(self, debug=None, srv_name=None, logger=None):
        self.debug = debug
        self.logger = logger
        self.server_name = srv_name
        self.path_dic = {'renewalinfo': '/acme/renewal-info/'}
        self.dbstore = DBstore(self.debug, self.logger)
        self.renewaltreshold_pctg = 85
        self.retry_after = 86400
        self.err_msg_dic = error_dic_get(self.logger)

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _lookup(self, certid_hex):
        """ lookup expiry dates based on renewal info """
        self.logger.debug('Renewalinfo._lookup()')

        try:
            result_dic = self.dbstore.certificate_lookup('renewal_info', certid_hex, ('cert_raw', 'expire_uts', 'issue_uts', 'created_at', 'id'))
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Renewalinfo._lookup(): {0}'.format(err_))
            result_dic = None

        return result_dic

    def _renewalinfo_get(self, certid_hex):
        """ create dictionary containing renwal infor data """
        self.logger.debug('Renewalinfo.get()')

        # lookup database for certificate data
        cert_dic = self._lookup(certid_hex)

        if 'expire_uts' in cert_dic and cert_dic['expire_uts']:

            start_uts = int((cert_dic['expire_uts'] - cert_dic['issue_uts']) * self.renewaltreshold_pctg / 100) + cert_dic['issue_uts']

            # for debugging trigger immedeate rewwal
            # start_uts = int(cert_dic['expire_uts'] * self.renewaltreshold_pctg/100)
            renewalinfo_dic = {
                'suggestedWindow': {
                    'start': uts_to_date_utc(start_uts),
                    'end': uts_to_date_utc(cert_dic['expire_uts'])
                }
            }

        else:
            renewalinfo_dic = {}

        return renewalinfo_dic

    def get(self, url):
        """ get renewal information """
        self.logger.debug('Renewalinfo.get()')

        # parse renewalinfo
        renewalinfo_string = string_sanitize(self.logger, url.replace('{0}{1}'.format(self.server_name, self.path_dic['renewalinfo']), ''))

        # get certid in hex
        certid_hex = certid_hex_get(self.logger, renewalinfo_string)

        # get renewal window datas
        rewalinfo_dic = self._renewalinfo_get(certid_hex)

        response_dic = {}
        if rewalinfo_dic:
            response_dic['code'] = 200
            # filter certificate and decode it
            response_dic['data'] = rewalinfo_dic
            response_dic['header'] = {}
            # order status is processing - ratelimiting
            response_dic['header'] = {'Retry-After': '{0}'.format(self.retry_after)}

        else:
            response_dic['code'] = 400
            response_dic['data'] = self.err_msg_dic['malformed']

        return response_dic
