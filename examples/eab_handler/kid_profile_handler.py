#!/usr/bin/python
# -*- coding: utf-8 -*-
""" eab json handler """
from __future__ import print_function
import json
import re
from typing import List, Tuple
# pylint: disable=C0209, E0401
from acme_srv.helper import load_config, csr_cn_get, csr_san_get


class EABhandler(object):
    """ EAB file handler """

    def __init__(self, logger: object = None):
        self.logger = logger
        self.key_file = None

    def __enter__(self):
        """ Makes EABhandler a Context Manager """
        if not self.key_file:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _config_load(self):
        """" load config from file """
        self.logger.debug('EABhandler._config_load()')

        config_dic = load_config(self.logger, 'EABhandler')
        if 'EABhandler' in config_dic and 'key_file' in config_dic['EABhandler']:
            self.key_file = config_dic['EABhandler']['key_file']

        self.logger.debug('EABhandler._config_load() ended')

    def _chk_san_lists_get(self, csr: str) -> Tuple[List[str], List[bool]]:
        """ check lists  """
        self.logger.debug('EABhandler._chk_san_lists_get()')

        # get sans and build a list
        _san_list = csr_san_get(self.logger, csr)

        check_list = []
        san_list = []

        if _san_list:
            for san in _san_list:
                try:
                    # SAN list must be modified/filtered)
                    (_san_type, san_value) = san.lower().split(':')
                    san_list.append(san_value)
                except Exception:
                    # force check to fail as something went wrong during parsing
                    check_list.append(False)
                    self.logger.info('EABhandler._csr_check(): san_list parsing failed at entry: {0}'.format(san))

        self.logger.debug('EABhandler._chk_san_lists_get() ended')
        return (san_list, check_list)

    def _cn_add(self, csr: str, san_list: List[str]) -> Tuple[List[str], str]:
        """ add CN if required """
        self.logger.debug('EABhandler._cn_add()')

        # get common name and attach it to san_list
        cn_ = csr_cn_get(self.logger, csr)

        if cn_:
            cn_ = cn_.lower()
            if cn_ not in san_list:
                # append cn to san_list
                self.logger.debug('EABhandler._csr_check(): append cn to san_list')
                san_list.append(cn_)

        self.logger.debug('EABhandler._cn_add() ended')
        return san_list

    def _list_regex_check(self, entry: str, list_: List[str]) -> bool:
        """ check entry against regex """
        self.logger.debug('EABhandler._list_regex_check()')

        check_result = False
        for regex in list_:
            if regex.startswith('*.'):
                regex = regex.replace('*.', '.')
            regex_compiled = re.compile(regex)
            if bool(regex_compiled.search(entry)):
                # parameter is in set flag accordingly and stop loop
                check_result = True

        self.logger.debug('EABhandler._list_regex_check() ended with: {0}'.format(check_result))
        return check_result

    def _wllist_check(self, entry: str, list_: List[str], toggle: bool = False) -> bool:
        """ check string against list """
        self.logger.debug('EABhandler._wllist_check({0}:{1})'.format(entry, toggle))
        self.logger.debug('check against list: {0}'.format(list_))

        # default setting
        check_result = False

        if entry:
            if list_:
                check_result = self._list_regex_check(entry, list_)
            else:
                # empty list, flip parameter to make the check successful
                check_result = True

        if toggle:
            # toggle result if this is a blocked_domainlist
            check_result = not check_result

        self.logger.debug('EABhandler._wllist_check() ended with: {0}'.format(check_result))
        return check_result

    def allowed_domains_check(self, csr: str, domain_list: List[str]) -> str:
        """ check allowed domains """
        self.logger.debug('EABhandler.allowed_domains_check()')

        (san_list, check_list) = self._chk_san_lists_get(csr)
        (san_list) = self._cn_add(csr, san_list)

        # go over the san list and check each entry
        for san in san_list:
            check_list.append(self._wllist_check(san, domain_list))

        if check_list:
            # cover a cornercase with empty checklist (no san, no cn)
            if False in check_list:
                result = "Either CN or SANs are not allowed by profile"
            else:
                result = False

        self.logger.debug('EABhandler.allowed_domains_check() ended with: %s', result)
        return result

    def eab_kid_get(self, csr: str) -> str:
        """ get eab kid  from datbases based on csr"""
        self.logger.debug('EABhandler.eab_kid_get()')
        try:
            # look up eab_kid from database based on csr
            from acme_srv.db_handler import DBstore  # pylint: disable=c0415
            dbstore = DBstore(False, self.logger)
            result_dic = dbstore.certificate_lookup('csr', csr, vlist=['name', 'order__name', 'order__account__name', 'order__account__eab_kid'])
            if result_dic and 'order__account__eab_kid' in result_dic:
                eab_kid = result_dic['order__account__eab_kid']
            else:
                eab_kid = None
        except Exception as err:
            self.logger.error('EABhandler._eab_profile_get() database error: {0}'.format(err))
            eab_kid = None

        self.logger.debug('EABhandler.eab_kid_get() ended with: %s', eab_kid)
        return eab_kid

    def eab_profile_get(self, csr: str) -> str:
        """ get eab profile """
        self.logger.debug('EABhandler._eab_profile_get()')

        # load profiles from key_file
        profiles_dic = self.key_file_load()

        # get eab_kid from database
        eab_kid = self.eab_kid_get(csr)

        # get profile from profiles_dic
        if profiles_dic and eab_kid and eab_kid in profiles_dic and 'cahandler' in profiles_dic[eab_kid]:
            profile_dic = profiles_dic[eab_kid]['cahandler']
        else:
            profile_dic = {}

        self.logger.debug('EABhandler._eab_profile_get() ended with: %s', bool(profile_dic))
        return profile_dic

    def key_file_load(self):
        """ load profiles from key_file """
        self.logger.debug('EABhandler.key_file_load()')

        if self.key_file:
            try:
                with open(self.key_file, encoding='utf8') as json_file:
                    profiles_dic = json.load(json_file)
            except Exception as err:
                self.logger.error('EABhandler.key_file_load() error: {0}'.format(err))
                profiles_dic = {}
        else:
            self.logger.error('EABhandler.key_file_load() no key_file specified')
            profiles_dic = {}

        self.logger.debug('EABhandler.key_file_load() ended with %s', bool(profiles_dic))
        return profiles_dic

    def mac_key_get(self, kid: str = None) -> str:
        """ check external account binding """
        self.logger.debug('EABhandler.mac_key_get({})'.format(kid))

        mac_key = None
        try:
            if self.key_file and kid:
                with open(self.key_file, encoding='utf8') as json_file:
                    data_dic = json.load(json_file)
                    if kid in data_dic and 'hmac' in data_dic[kid]:
                        mac_key = data_dic[kid]['hmac']
        except Exception as err:
            self.logger.error('EABhandler.mac_key_get() error: {0}'.format(err))

        self.logger.debug('EABhandler.mac_key_get() ended with: {0}'.format(bool(mac_key)))
        return mac_key
