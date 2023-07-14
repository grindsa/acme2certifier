# -*- coding: utf-8 -*-
""" Nonce class """
# pylint: disable=c0209
from __future__ import print_function
from acme_srv.db_handler import DBstore
from acme_srv.message import Message
from acme_srv.helper import string_sanitize, certid_hex_get, uts_to_date_utc, error_dic_get, load_config, uts_now


class Renewalinfo(object):
    """ Nonce handler """

    def __init__(self, debug=None, srv_name=None, logger=None):
        self.debug = debug
        self.logger = logger
        self.server_name = srv_name
        self.path_dic = {'renewalinfo': '/acme/renewal-info/'}
        self.dbstore = DBstore(self.debug, self.logger)
        self.message = Message(self.debug, self.server_name, self.logger)
        self.renewaltreshold_pctg = 85
        self.retry_after_timeout = 86400
        self.renewal_force = False
        self.err_msg_dic = error_dic_get(self.logger)

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _config_load(self):
        """" load config from file """
        self.logger.debug('Certificate._config_load()')
        config_dic = load_config()

        if 'Renewalinfo' in config_dic:

            self.renewal_force = config_dic.getboolean('Renewalinfo', 'renewal_force', fallback=False)

            if 'renewaltreshold_pctg' in config_dic['Renewalinfo']:
                try:
                    self.renewaltreshold_pctg = float(config_dic['Renewalinfo']['renewaltreshold_pctg'])
                except Exception as err_:
                    self.logger.error('acme2certifier Renewalinfo._config_load() renewaltreshold_pctg parsing error: {0}'.format(err_))

            if 'retry_after_timeout' in config_dic['Renewalinfo']:
                try:
                    self.retry_after_timeout = int(config_dic['Renewalinfo']['retry_after_timeout'])
                except Exception as err_:
                    self.logger.error('acme2certifier Renewalinfo._config_load() retry_after_timeout parsing error: {0}'.format(err_))

    def _lookup(self, certid_hex):
        """ lookup expiry dates based on renewal info """
        self.logger.debug('Renewalinfo._lookup()')

        try:
            result_dic = self.dbstore.certificate_lookup('renewal_info', certid_hex, ('id', 'name', 'cert', 'cert_raw', 'expire_uts', 'issue_uts', 'created_at'))
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

            # we may need to set issue_uts to cover some cornercases
            if 'issue_uts' not in cert_dic or not cert_dic['issue_uts']:
                cert_dic['issue_uts'] = uts_now()

            # for debugging trigger immedeate rewwal
            if self.renewal_force:
                self.logger.debug('Renewalinfo.get() - foce renewal')
                cert_dic['expire_uts'] = uts_now() + 86400
                start_uts = int(cert_dic['expire_uts'] - (365 * 86400))
            else:
                start_uts = int((cert_dic['expire_uts'] - cert_dic['issue_uts']) * self.renewaltreshold_pctg / 100) + cert_dic['issue_uts']

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
        (mda, certid_hex) = certid_hex_get(self.logger, renewalinfo_string)

        response_dic = {}
        if mda == '300b0609608648016503040201':
            # get renewal window datas
            rewalinfo_dic = self._renewalinfo_get(certid_hex)
            if rewalinfo_dic:
                response_dic['code'] = 200
                # filter certificate and decode it
                response_dic['data'] = rewalinfo_dic
                response_dic['header'] = {}
                # order status is processing - ratelimiting
                response_dic['header'] = {'Retry-After': '{0}'.format(self.retry_after_timeout)}
            else:
                response_dic['code'] = 404
                response_dic['data'] = self.err_msg_dic['malformed']
        else:
            response_dic['code'] = 400
            response_dic['data'] = self.err_msg_dic['malformed']

        return response_dic

    def update(self, content):
        """ update renewalinfo request """
        self.logger.debug('Renewalinfo.update({0})')

        response_dic = {'data': {}}
        # check message
        (code, _message, _detail, _protected, payload, _account_name) = self.message.check(content)

        response_dic = {}
        if code == 200 and 'certid' in payload and 'replaced' in payload:

            (_mda, certid_hex) = certid_hex_get(self.logger, payload['certid'])

            cert_dic = self._lookup(certid_hex)

            if cert_dic and payload['replaced']:
                cert_dic['replaced'] = True
                cert_id = self.dbstore.certificate_add(cert_dic)

                if cert_id:
                    response_dic['code'] = 200
                else:
                    response_dic['code'] = 400
            else:
                response_dic['code'] = 400
        else:
            response_dic['code'] = 400

        return response_dic
