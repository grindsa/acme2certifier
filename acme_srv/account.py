#!/usr/bin/python
# -*- coding: utf-8 -*-
# pylint: disable=C0209
""" Account class """
from __future__ import print_function
import json
from acme_srv.helper import generate_random_string, validate_email, date_to_datestr, load_config, eab_handler_load, b64decode_pad, error_dic_get
from acme_srv.db_handler import DBstore
from acme_srv.message import Message
from acme_srv.signature import Signature


class Account(object):
    """ ACME server class """

    def __init__(self, debug=None, srv_name=None, logger=None):
        self.server_name = srv_name
        self.logger = logger
        self.dbstore = DBstore(debug, self.logger)
        self.message = Message(debug, self.server_name, self.logger)
        self.path_dic = {'acct_path': '/acme/acct/'}
        self.err_msg_dic = error_dic_get(self.logger)
        self.ecc_only = False
        self.contact_check_disable = False
        self.tos_check_disable = False
        self.inner_header_nonce_allow = False
        self.tos_url = None
        self.eab_check = False
        self.eab_handler = None

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _account_lookup(self, jwk):
        """ lookup account """
        self.logger.debug('Account._account_lookup(}')

        try:
            result = self.dbstore.account_lookup('jwk', json.dumps(jwk))
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Account._onlyreturnexisting(): {0}'.format(err_))
            result = None

        if result:
            code = 200
            message = result['name']
            detail = None
        else:
            code = 400
            message = self.err_msg_dic['accountdoesnotexist']
            detail = None

        self.logger.debug('Account._account_lookup() ended with:{0}'.format(code))
        return (code, message, detail)

    def _account_add_check(self, account_name, data_dic):
        """ perform database operation """
        self.logger.debug('Account.account._account_add_check({0})'.format(account_name))

        try:
            (db_name, new) = self.dbstore.account_add(data_dic)
        except Exception as err_:
            self.logger.critical('Account.account._add(): Database error: {0}'.format(err_))
            db_name = None
            new = False

        self.logger.debug('got account_name:{0} new:{1}'.format(db_name, new))

        if new:
            code = 201
            message = account_name
        else:
            code = 200
            message = db_name
        detail = None

        self.logger.debug('Account.account._account_add_check() ended with: {0}'.format(account_name))
        return (code, message, detail)

    def _account_eab_add(self, payload, data_dic):
        """ prepare add keyid """
        self.logger.debug('Account.account._account_eab_add()')

        if payload and 'externalaccountbinding' in payload and payload['externalaccountbinding']:
            if 'protected' in payload['externalaccountbinding']:
                eab_kid = self._eab_kid_get(payload['externalaccountbinding']['protected'])
                self.logger.info('add eab_kid: {0} to data_dic'.format(eab_kid))
                if eab_kid:
                    data_dic['eab_kid'] = eab_kid

        self.logger.debug('Account.account._account_eab_add()')
        return data_dic

    def _account_add(self, account_name, content, contact, payload):
        """ prepare db insert and call DBstore helper """
        self.logger.debug('Account.account._account_add({0})'.format(account_name))

        # ecc_only check
        if self.ecc_only and not content['alg'].startswith('ES'):
            code = 403
            message = self.err_msg_dic['badpubkey']
            detail = 'Only ECC keys are supported'
        else:
            # check jwk
            data_dic = {
                'name': account_name,
                'alg': content['alg'],
                'jwk': json.dumps(content['jwk']),
                'contact': json.dumps(contact),
            }
            # add eab_kid to data_dic if eab_check is enabled and kid is part of the request
            if self.eab_check:
                data_dic = self._account_eab_add(payload, data_dic)

            # check code to be returned
            (code, message, detail) = self._account_add_check(account_name, data_dic)

        self.logger.debug('Account.account._account_add() ended with: {0}'.format(account_name))
        return (code, message, detail)

    def _add(self, content, payload, contact):
        """ prepare db insert and call DBstore helper """
        self.logger.debug('Account.account._add()')

        account_name = generate_random_string(self.logger, 12)

        # check request
        if 'alg' in content and 'jwk' in content:

            if not self.contact_check_disable and not contact:
                code = 400
                message = self.err_msg_dic['malformed']
                detail = 'incomplete protected payload'
            else:
                # add account
                (code, message, detail) = self._account_add(account_name, content, contact, payload)
        else:
            code = 400
            message = self.err_msg_dic['malformed']
            detail = 'incomplete protected payload'

        self.logger.debug('Account.account._add() ended with:{0}'.format(code))
        return (code, message, detail)

    def _contact_check(self, content):
        """ check contact information from payload"""
        self.logger.debug('Account._contact_check()')
        code = 200
        message = None
        detail = None
        if 'contact' in content:
            contact_check = validate_email(self.logger, content['contact'])
            if not contact_check:
                # invalidcontact message
                code = 400
                message = self.err_msg_dic['invalidcontact']
                detail = ', '.join(content['contact'])
        else:
            code = 400
            message = self.err_msg_dic['invalidcontact']
            detail = 'no contacts specified'

        self.logger.debug('Account._contact_check() ended with:{0}'.format(code))
        return (code, message, detail)

    def _contact_list_build(self, payload):
        """ build contact list """
        self.logger.debug('Account._contact_list_build()')

        if 'contact' in payload:
            contact_list = payload['contact']
        else:
            contact_list = []

        self.logger.debug('Account._contact_list_build() ended')
        return contact_list

    def _contacts_update(self, aname, payload):
        """ update account """
        self.logger.debug('Account.update()')
        (code, message, detail) = self._contact_check(payload)
        if code == 200:
            data_dic = {'name': aname, 'contact': json.dumps(payload['contact'])}
            try:
                result = self.dbstore.account_update(data_dic)
            except Exception as err_:
                self.logger.critical('acme2certifier database error in Account._contacts_update(): {0}'.format(err_))
                result = None

            if result:
                code = 200
            else:
                code = 400
                message = self.err_msg_dic['accountdoesnotexist']
                detail = 'update failed'

        return (code, message, detail)

    def _delete(self, aname):
        """ delete account """
        self.logger.debug('Account._delete({0})'.format(aname))
        try:
            result = self.dbstore.account_delete(aname)
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Account._delete(): {0}'.format(err_))
            result = None

        if result:
            code = 200
            message = None
            detail = None
        else:
            code = 400
            message = self.err_msg_dic['accountdoesnotexist']
            detail = 'deletion failed'

        self.logger.debug('Account._delete() ended with:{0}'.format(code))
        return (code, message, detail)

    def _eab_jwk_compare(self, protected, payload):
        """ compare jwk from outer header with jwk in eab playload """
        self.logger.debug('_eab_jwk_compare()')
        result = False
        if 'jwk' in protected:
            # convert outer jwk into string for better comparison
            if isinstance(protected, dict):
                jwk_outer = json.dumps(protected['jwk'])
                # decode inner jwk
                jwk_inner = b64decode_pad(self.logger, payload)
                jwk_inner = json.dumps(json.loads(jwk_inner))
                if jwk_outer == jwk_inner:
                    result = True

        self.logger.debug('_eab_jwk_compare() ended with: {0}'.format(result))
        return result

    def _eab_kid_get(self, protected):
        """ get key identifier for eab validation """
        self.logger.debug('_eab_kid_get()')
        # load protected into json format
        protected_dic = json.loads(b64decode_pad(self.logger, protected))
        # extract kid
        if isinstance(protected_dic, dict):
            eab_key_id = protected_dic.get('kid', None)
        else:
            eab_key_id = None

        self.logger.debug('_eab_kid_get() ended with: {0}'.format(eab_key_id))
        return eab_key_id

    def _eab_verify(self, payload):
        """" check for external account binding """
        self.logger.debug('_eab_check()')

        # get key identifier
        eab_kid = self._eab_kid_get(payload['externalaccountbinding']['protected'])
        if eab_kid:
            # get eab_mac_key
            with self.eab_handler(self.logger) as eab_handler:
                eab_mac_key = eab_handler.mac_key_get(eab_kid)
        else:
            eab_mac_key = None

        if eab_mac_key:
            (result, error) = self._eab_signature_verify(payload['externalaccountbinding'], eab_mac_key)
            if result:
                code = 200
                message = None
                detail = None
            else:
                code = 403
                message = self.err_msg_dic['unauthorized']
                detail = 'eab signature verification failed'
                self.logger.error('Account._eab_check() returned error: {0}'.format(error))
        else:
            code = 403
            message = self.err_msg_dic['unauthorized']
            detail = 'eab kid lookup failed'

        self.logger.debug('_eab_check() ended with: {0}'.format(code))
        return (code, message, detail)

    def _eab_check(self, protected, payload):
        """" check for external account binding """
        self.logger.debug('_eab_check()')

        if self.eab_handler and protected and payload and 'externalaccountbinding' in payload and payload['externalaccountbinding']:
            # compare JWK from protected (outer) header if jwk included in payload of external account binding
            jwk_compare = self._eab_jwk_compare(protected, payload['externalaccountbinding']['payload'])

            if jwk_compare and 'protected' in payload['externalaccountbinding']:
                # verify eab signature
                (code, message, detail) = self._eab_verify(payload)
            else:
                code = 403
                message = self.err_msg_dic['malformed']
                detail = 'Malformed request'
        else:
            # no external account binding key in payload - error
            code = 403
            message = self.err_msg_dic['externalaccountrequired']
            detail = 'external account binding required'

        self.logger.debug('Account._eab_check() ended with:{0}'.format(code))
        return (code, message, detail)

    def _eab_signature_verify(self, content, mac_key):
        """ verify inner signature """
        self.logger.debug('Account._eab_signature_verify()')

        if content and mac_key:
            signature = Signature(None, self.server_name, self.logger)
            jwk_ = json.dumps({'k': mac_key, 'kty': 'oct'})
            (sig_check, error) = signature.eab_check(json.dumps(content), jwk_)
        else:
            sig_check = False
            error = None
        self.logger.debug('Account._eab_signature_verify() ended with: {0}'.format(sig_check))
        return (sig_check, error)

    def _header_url_compare(self, outer_protected, inner_protected):
        """ compare url header of inner and outer header """
        self.logger.debug('Account._header_url_compare()')

        if outer_protected['url'] == inner_protected['url']:
            if self.inner_header_nonce_allow or 'nonce' not in inner_protected:
                code = 200
                message = None
                detail = None
            else:
                code = 400
                message = self.err_msg_dic['malformed']
                detail = 'inner jws must omit nonce header'
        else:
            code = 400
            message = self.err_msg_dic['malformed']
            detail = 'url parameter differ in inner and outer jws'

        self.logger.debug('Account._header_url_compare() ended with: {0}'.format(code))
        return (code, message, detail)

    def _info(self, account_obj):
        """ account info """
        self.logger.debug('Account._info()')

        if account_obj:
            response_dic = {}
            response_dic['status'] = 'valid'
            response_dic['key'] = json.loads(account_obj['jwk'])
            response_dic['contact'] = json.loads(account_obj['contact'])
            response_dic['createdAt'] = date_to_datestr(account_obj['created_at'])
            if 'eab_kid' in account_obj and account_obj['eab_kid']:
                response_dic['eab_kid'] = account_obj['eab_kid']

        self.logger.debug('Account._info() returns: {0}'.format(json.dumps(response_dic)))
        return response_dic

    def _inner_jws_check(self, outer_protected, inner_protected):
        """ RFC8655 7.3.5 checs of inner JWS """
        self.logger.debug('Account._inner_jws_check()')

        # check for jwk header
        if 'jwk' in inner_protected:
            if 'url' in outer_protected and 'url' in inner_protected:
                # inner and outer JWS must have the same "url" header parameter
                (code, message, detail) = self._header_url_compare(outer_protected, inner_protected)
            else:
                code = 400
                message = self.err_msg_dic['malformed']
                detail = 'inner or outer jws is missing url header parameter'
        else:
            code = 400
            message = self.err_msg_dic['malformed']
            detail = 'inner jws is missing jwk'

        self.logger.debug('Account._inner_jws_check() ended with: {0}:{1}'.format(code, detail))
        return (code, message, detail)

    def _inner_payload_check(self, aname, outer_protected, inner_payload):
        """ RFC8655 7.3.5 checs of inner payload """
        self.logger.debug('Account._inner_payload_check()')

        if 'kid' in outer_protected:
            if 'account' in inner_payload:
                if outer_protected['kid'] == inner_payload['account']:
                    if 'oldkey' in inner_payload:
                        # compare oldkey with database
                        (code, message, detail) = self._key_compare(aname, inner_payload['oldkey'])
                    else:
                        code = 400
                        message = self.err_msg_dic['malformed']
                        detail = 'old key is missing'
                else:
                    code = 400
                    message = self.err_msg_dic['malformed']
                    detail = 'kid and account objects do not match'
            else:
                code = 400
                message = self.err_msg_dic['malformed']
                detail = 'account object is missing on inner payload'
        else:
            code = 400
            message = self.err_msg_dic['malformed']
            detail = 'kid is missing in outer header'

        self.logger.debug('Account._inner_payload_check() ended with: {0}:{1}'.format(code, detail))
        return (code, message, detail)

    def _key_change_validate(self, aname, outer_protected, inner_protected, inner_payload):
        """ validate key_change before exectution """
        self.logger.debug('Account._key_change_validate({0})'.format(aname))
        if 'jwk' in inner_protected:
            # check if we already have the key stored in DB
            key_exists = self._lookup(json.dumps(inner_protected['jwk']), 'jwk')
            if not key_exists:
                (code, message, detail) = self._inner_jws_check(outer_protected, inner_protected)

                if code == 200:
                    (code, message, detail) = self._inner_payload_check(aname, outer_protected, inner_payload)
            else:
                code = 400
                message = self.err_msg_dic['badpubkey']
                detail = 'public key does already exists'
        else:
            code = 400
            message = self.err_msg_dic['malformed']
            detail = 'inner jws is missing jwk'

        self.logger.debug('Account._key_change_validate() ended with: {0}:{1}'.format(code, detail))
        return (code, message, detail)

    def _key_rollover(self, aname, protected, inner_protected, inner_payload):
        """ key update after key change """
        self.logger.debug('Account._key_rollover({0})'.format(aname))

        (code, message, detail) = self._key_change_validate(aname, protected, inner_protected, inner_payload)
        if code == 200:
            data_dic = {'name': aname, 'jwk': json.dumps(inner_protected['jwk'])}
            try:
                result = self.dbstore.account_update(data_dic)
            except Exception as err_:
                self.logger.critical('acme2certifier database error in Account._key_change(): {0}'.format(err_))
                result = None
            if result:
                code = 200
                message = None
                detail = None
            else:
                code = 500
                message = self.err_msg_dic['serverinternal']
                detail = 'key rollover failed'

        self.logger.debug('Account._key_rollover() ended with: {0}'.format(code))
        return (code, message, detail)

    def _key_change(self, aname, payload, protected):
        """ key change for a given account """
        self.logger.debug('Account._key_change({0})'.format(aname))

        if 'url' in protected:
            if 'key-change' in protected['url']:
                # check message
                (code, message, detail, inner_protected, inner_payload, _account_name) = self.message.check(json.dumps(payload), use_emb_key=True, skip_nonce_check=True)
                if code == 200:
                    # key rollover
                    (code, message, detail) = self._key_rollover(aname, protected, inner_protected, inner_payload)
            else:
                code = 400
                message = self.err_msg_dic['malformed']
                detail = 'malformed request. not a key-change'
        else:
            code = 400
            message = self.err_msg_dic['malformed']
            detail = 'malformed request'

        self.logger.debug('Account._key_change() ended with: {0}'.format(code))
        return (code, message, detail)

    def _key_compare(self, aname, old_key):
        """ compare key with the one stored in database """
        self.logger.debug('Account._key_compare({0})'.format(aname))

        # load current public key from database
        try:
            pub_key = self.dbstore.jwk_load(aname)
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Account._key_compare(): {0}'.format(err_))
            pub_key = None

        if old_key and pub_key:
            # rewrite alg statement in pubkey statement
            if 'alg' in pub_key and 'alg' in old_key:
                if pub_key['alg'].startswith('ES') and old_key['alg'] == 'ECDSA':
                    pub_key['alg'] = 'ECDSA'

            if old_key == pub_key:
                code = 200
                message = None
                detail = None
            else:
                code = 401
                message = self.err_msg_dic['unauthorized']
                detail = 'wrong public key'
        else:
            code = 401
            message = self.err_msg_dic['unauthorized']
            detail = 'wrong public key'

        self.logger.debug('Account._key_compare() ended with: {0}'.format(code))
        return (code, message, detail)

    def _config_load(self):
        """" load config from file """
        self.logger.debug('Account._config_load()')
        config_dic = load_config()
        if 'Account' in config_dic:
            self.inner_header_nonce_allow = config_dic.getboolean('Account', 'inner_header_nonce_allow', fallback=False)
            self.ecc_only = config_dic.getboolean('Account', 'ecc_only', fallback=False)
            self.tos_check_disable = config_dic.getboolean('Account', 'tos_check_disable', fallback=False)
            self.contact_check_disable = config_dic.getboolean('Account', 'contact_check_disable', fallback=False)

        if 'EABhandler' in config_dic:
            self.logger.debug('Account._config.load(): loading eab_handler')
            # mandate eab check regardless if handler is configured or could get loaded or not
            self.eab_check = True
            if 'eab_handler_file' in config_dic['EABhandler']:
                # load eab_handler according to configuration
                eab_handler_module = eab_handler_load(self.logger, config_dic)
                if eab_handler_module:
                    # store handler in variable
                    self.eab_handler = eab_handler_module.EABhandler
                else:
                    self.logger.critical('Account._config_load(): EABHandler could not get loaded')
            else:
                self.logger.critical('Account._config_load(): EABHandler configuration incomplete')

        if 'Directory' in config_dic:
            if 'tos_url' in config_dic['Directory']:
                self.tos_url = config_dic['Directory']['tos_url']
            if 'url_prefix' in config_dic['Directory']:
                self.path_dic = {k: config_dic['Directory']['url_prefix'] + v for k, v in self.path_dic.items()}
        self.logger.debug('Account._config_load() ended')

    def _lookup(self, value, field='name'):
        """ lookup account """
        self.logger.debug('Account._lookup({0}:{1})'.format(field, value))
        try:
            result = self.dbstore.account_lookup(field, value)
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Account._lookup(): {0}'.format(err_))
            result = None
        return result

    # pylint: disable=W0212
    def _name_get(self, content):
        """ get id for account depricated"""
        self.logger.debug('Account._name_get()')
        # _deprecated
        return self.message._name_get(content)

    def _onlyreturnexisting(self, protected, payload):
        """ check onlyreturnexisting """
        self.logger.debug('Account._onlyreturnexisting(}')

        if 'onlyreturnexisting' in payload:
            if payload['onlyreturnexisting']:
                code = None
                message = None
                detail = None

                if 'jwk' in protected:
                    (code, message, detail) = self._account_lookup(protected['jwk'])
                else:
                    code = 400
                    message = self.err_msg_dic['malformed']
                    detail = 'jwk structure missing'

            else:
                code = 400
                message = self.err_msg_dic['useractionrequired']
                detail = 'onlyReturnExisting must be true'
        else:
            code = 500
            message = self.err_msg_dic['serverinternal']
            detail = 'onlyReturnExisting without payload'

        self.logger.debug('Account.onlyreturnexisting() ended with:{0}'.format(code))
        return (code, message, detail)

    def _parse_deactivation(self, account_name, payload):
        self.logger.debug('Account._parse_deactivation({0})'.format(account_name))
        data = None
        # account deactivation
        if payload['status'].lower() == 'deactivated':
            (code, message, detail) = self._delete(account_name)
            if code == 200:
                data = payload
        else:
            code = 400
            message = self.err_msg_dic['malformed']
            detail = 'status attribute without sense'

        self.logger.debug('Account._parse_deactivation() ended')
        return (code, message, detail, data)

    def _parse_contacts_update(self, account_name, payload):
        """ update contacts """
        self.logger.debug('Account._parse_contacts_update({0})'.format(account_name))
        data = None
        (code, message, detail) = self._contacts_update(account_name, payload)
        if code == 200:
            account_obj = self._lookup(account_name)
            data = self._info(account_obj)
        else:
            code = 400
            message = self.err_msg_dic['accountdoesnotexist']
            detail = 'update failed'

        self.logger.debug('Account._parse_contacts_update() ended')
        return (code, message, detail, data)

    def _parse_query(self, account_name):
        """ update contacts """
        self.logger.debug('Account._parse_query({0})'.format(account_name))

        # this is a query for account information
        account_obj = self._lookup(account_name)
        if account_obj:
            data = self._info(account_obj)
            data['status'] = 'valid'
        else:
            data = {'status': 'invalid'}

        self.logger.debug('Account._parse_query() ended')
        return data

    def _tos_check(self, content):
        """ check terms of service """
        self.logger.debug('Account._tos_check()')
        if 'termsofserviceagreed' in content:
            self.logger.debug('tos:{0}'.format(content['termsofserviceagreed']))
            if content['termsofserviceagreed']:
                code = 200
                message = None
                detail = None
            else:
                code = 403
                message = self.err_msg_dic['useractionrequired']
                detail = 'tosfalse'
        else:
            self.logger.debug('no tos statement found.')
            code = 403
            message = self.err_msg_dic['useractionrequired']
            detail = 'tosfalse'

        self.logger.debug('Account._tos_check() ended with:{0}'.format(code))
        return (code, message, detail)

    def _new(self, code, payload, protected):
        """ generate a new account """
        self.logger.debug('Account._new()')

        # onlyReturnExisting check
        if 'onlyreturnexisting' in payload:
            (code, message, detail) = self._onlyreturnexisting(protected, payload)
        else:
            # tos check
            if self.tos_url and not self.tos_check_disable:
                (code, message, detail) = self._tos_check(payload)

            # check for external account binding
            if code == 200 and self.eab_check:
                (code, message, detail) = self._eab_check(protected, payload)

            # contact check
            if code == 200 and not self.contact_check_disable:
                (code, message, detail) = self._contact_check(payload)

            # add account to database
            if code == 200:
                contact_list = self._contact_list_build(payload)

                # add new account
                (code, message, detail) = self._add(protected, payload, contact_list)

        self.logger.debug('Account._new() ended with: {0}'.format(code))
        return (code, message, detail)

    def new(self, content):
        """ generate a new account """
        self.logger.debug('Account.account_new()')

        response_dic = {}
        # check message but skip signature check as this is a new account (True)
        (code, message, detail, protected, payload, _account_name) = self.message.check(content, True)
        if code == 200:
            (code, message, detail) = self._new(code, payload, protected)

        if code in (200, 201):
            response_dic['data'] = {}
            if code == 201:
                response_dic['data'] = {
                    'status': 'valid',
                    'orders': '{0}{1}{2}/orders'.format(self.server_name, self.path_dic['acct_path'], message),
                }
                if 'contact' in payload:
                    response_dic['data']['contact'] = payload['contact']

            response_dic['header'] = {}
            response_dic['header']['Location'] = '{0}{1}{2}'.format(self.server_name, self.path_dic['acct_path'], message)

            # add exernal account binding
            if self.eab_check and 'externalaccountbinding' in payload:
                response_dic['data']['externalaccountbinding'] = payload['externalaccountbinding']

        else:
            if detail == 'tosfalse':
                detail = 'Terms of service must be accepted'

        # prepare/enrich response
        status_dic = {'code': code, 'type': message, 'detail': detail}
        response_dic = self.message.prepare_response(response_dic, status_dic)

        self.logger.debug('Account.account_new() returns: {0}'.format(json.dumps(response_dic)))
        return response_dic

    def parse(self, content):
        """ parse message """
        self.logger.debug('Account.parse()')

        response_dic = {}

        data = None
        # check message
        (code, message, detail, protected, payload, account_name) = self.message.check(content)
        if code == 200:
            if 'status' in payload:
                (code, message, detail, data) = self._parse_deactivation(account_name, payload)

            elif 'contact' in payload:
                (code, message, detail, data) = self._parse_contacts_update(account_name, payload)

            elif 'payload' in payload:
                # this could be a key-change
                (code, message, detail) = self._key_change(account_name, payload, protected)
                if code == 200:
                    response_dic['data'] = {}
            elif not payload:
                data = self._parse_query(account_name)
            else:
                code = 400
                message = self.err_msg_dic['malformed']
                detail = 'dont know what to do with this request'

        if data:
            response_dic['data'] = data

        # prepare/enrich response
        status_dic = {'code': code, 'type': message, 'detail': detail}
        response_dic = self.message.prepare_response(response_dic, status_dic)

        self.logger.debug('Account.account_parse() returns: {0}'.format(json.dumps(response_dic)))
        return response_dic
