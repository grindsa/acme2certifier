#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Challenge class """
from __future__ import print_function
import json
from acme.helper import generate_random_string, parse_url, load_config, jwk_thumbprint_get, url_get, sha256_hash, sha256_hash_hex, b64_encode, b64_url_encode, txt_get, fqdn_resolve, uts_now, uts_to_date_utc, servercert_get, cert_san_get, cert_extensions_get, fqdn_in_san_check
from acme.db_handler import DBstore
from acme.message import Message

class Challenge(object):
    """ Challenge handler """

    def __init__(self, debug=None, srv_name=None, logger=None, expiry=3600):
        # self.debug = debug
        self.server_name = srv_name
        self.logger = logger
        self.dbstore = DBstore(debug, self.logger)
        self.message = Message(debug, self.server_name, self.logger)
        self.path_dic = {'chall_path' : '/acme/chall/', 'authz_path' : '/acme/authz/'}
        self.expiry = expiry
        self.challenge_validation_disable = False
        self.tnauthlist_support = False
        self.dns_server_list = None

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        self._config_load()
        return self

    def __exit__(self, *args):
        """ close the connection at the end of the context """

    def _challengelist_search(self, key, value, vlist=('name', 'type', 'status__name', 'token')):
        """ get exsting challegnes for a given authorization """
        self.logger.debug('Challenge._challengelist_search()')

        try:
            challenge_list = self.dbstore.challenges_search(key, value, vlist)
        except BaseException as err_:
            self.logger.critical('acme2certifier database error in Challenge._challengelist_search(): {0}'.format(err_))
            challenge_list = []

        challenge_dic = {}
        for challenge in challenge_list:
            if challenge['type'] not in challenge_dic:
                challenge_dic[challenge['type']] = {}

            challenge_dic[challenge['type']]['token'] = challenge['token']
            challenge_dic[challenge['type']]['type'] = challenge['type']
            challenge_dic[challenge['type']]['url'] = challenge['name']
            challenge_dic[challenge['type']]['url'] = '{0}{1}{2}'.format(self.server_name, self.path_dic['chall_path'], challenge['name'])
            challenge_dic[challenge['type']]['name'] = challenge['name']

        challenge_list = []
        for challenge in challenge_dic:
            challenge_list.append(challenge_dic[challenge])

        self.logger.debug('Challenge._challengelist_search() ended with: {0}'.format(challenge_list))
        return challenge_list

    def _check(self, challenge_name, payload):
        """ challenge check """
        self.logger.debug('Challenge._check({0})'.format(challenge_name))
        try:
            challenge_dic = self.dbstore.challenge_lookup('name', challenge_name, ['type', 'status__name', 'token', 'authorization__name', 'authorization__type', 'authorization__value', 'authorization__token', 'authorization__order__account__name'])
        except BaseException as err_:
            self.logger.critical('acme2certifier database error in Challenge._check() lookup: {0}'.format(err_))
            challenge_dic = {}

        if 'type' in challenge_dic and 'authorization__value' in challenge_dic and 'token' in challenge_dic and 'authorization__order__account__name' in challenge_dic:
            try:
                pub_key = self.dbstore.jwk_load(challenge_dic['authorization__order__account__name'])
            except BaseException as err_:
                self.logger.critical('acme2certifier database error in Challenge._check() jwk: {0}'.format(err_))
                pub_key = None

            if  pub_key:
                jwk_thumbprint = jwk_thumbprint_get(self.logger, pub_key)
                if challenge_dic['type'] == 'http-01' and jwk_thumbprint:
                    (result, invalid) = self._validate_http_challenge(challenge_name, challenge_dic['authorization__value'], challenge_dic['token'], jwk_thumbprint)
                elif challenge_dic['type'] == 'dns-01' and jwk_thumbprint:
                    (result, invalid) = self._validate_dns_challenge(challenge_name, challenge_dic['authorization__value'], challenge_dic['token'], jwk_thumbprint)
                elif challenge_dic['type'] == 'tls-alpn-01' and jwk_thumbprint:
                    (result, invalid) = self._validate_alpn_challenge(challenge_name, challenge_dic['authorization__value'], challenge_dic['token'], jwk_thumbprint)
                elif challenge_dic['type'] == 'tkauth-01' and jwk_thumbprint and self.tnauthlist_support:
                    (result, invalid) = self._validate_tkauth_challenge(challenge_name, challenge_dic['authorization__value'], challenge_dic['token'], jwk_thumbprint, payload)
                else:
                    self.logger.debug('unknown challenge type "{0}". Setting check result to False'.format(challenge_dic['type']))
                    result = False
                    invalid = True
            else:
                result = False
                invalid = False
        else:
            result = False
            invalid = False
        self.logger.debug('challenge._check() ended with: {0}/{1}'.format(result, invalid))
        return (result, invalid)

    def _existing_challenge_validate(self, challenge_list):
        """ validate an existing challenge set """
        self.logger.debug('Challenge._existing_challenge_validate()')
        for challenge in challenge_list:
            _challenge_check = self._validate(challenge, {})

    def _info(self, challenge_name):
        """ get challenge details """
        self.logger.debug('Challenge._info({0})'.format(challenge_name))
        try:
            challenge_dic = self.dbstore.challenge_lookup('name', challenge_name, vlist=('type', 'token', 'status__name', 'validated'))
        except BaseException as err_:
            self.logger.critical('acme2certifier database error in Challenge._info(): {0}'.format(err_))
            challenge_dic = {}

        if 'status' in challenge_dic and challenge_dic['status'] == 'valid':
            if 'validated' in challenge_dic:
                # convert validated timestamp to RFC3339 format - if it fails remove key from dictionary
                try:
                    challenge_dic['validated'] = uts_to_date_utc(challenge_dic['validated'])
                except BaseException:
                    challenge_dic.pop('validated')
        else:
            if 'validated' in challenge_dic:
                challenge_dic.pop('validated')

        self.logger.debug('Challenge._info({0}) ended'.format(challenge_name))
        return challenge_dic

    def _config_load(self):
        """" load config from file """
        self.logger.debug('Challenge._config_load()')
        config_dic = load_config()
        if 'Challenge' in config_dic:
            self.challenge_validation_disable = config_dic.getboolean('Challenge', 'challenge_validation_disable', fallback=False)
            if 'dns_server_list' in config_dic['Challenge']:
                try:
                    self.dns_server_list = json.loads(config_dic['Challenge']['dns_server_list'])
                except BaseException as err_:
                    self.logger.warning('Challenge._config_load() failed with error: {0}'.format(err_))

        if 'Order' in config_dic:
            self.tnauthlist_support = config_dic.getboolean('Order', 'tnauthlist_support', fallback=False)
        self.logger.debug('Challenge._config_load() ended.')

    def _name_get(self, url):
        """ get challenge """
        self.logger.debug('Challenge.get_name({0})'.format(url))
        url_dic = parse_url(self.logger, url)
        challenge_name = url_dic['path'].replace(self.path_dic['chall_path'], '')
        if '/' in challenge_name:
            (challenge_name, _sinin) = challenge_name.split('/', 1)
        return challenge_name

    def _new(self, authz_name, mtype, token):
        """ new challenge """
        self.logger.debug('Challenge._new({0})'.format(mtype))

        challenge_name = generate_random_string(self.logger, 12)

        data_dic = {
            'name' : challenge_name,
            'expires' : self.expiry,
            'type' : mtype,
            'token' : token,
            'authorization' : authz_name,
            'status': 2
        }

        try:
            chid = self.dbstore.challenge_add(data_dic)
        except BaseException as err_:
            self.logger.critical('acme2certifier database error in Challenge._new(): {0}'.format(err_))
            chid = None

        challenge_dic = {}
        if chid:
            challenge_dic['type'] = mtype
            challenge_dic['url'] = '{0}{1}{2}'.format(self.server_name, self.path_dic['chall_path'], challenge_name)
            challenge_dic['token'] = token
            if mtype == 'tkauth-01':
                challenge_dic['tkauth-type'] = 'atc'
        return challenge_dic

    def _update(self, data_dic):
        """ update challenge """
        self.logger.debug('Challenge._update({0})'.format(data_dic))
        try:
            self.dbstore.challenge_update(data_dic)
        except BaseException as err_:
            self.logger.critical('acme2certifier database error in Challenge._update(): {0}'.format(err_))
        self.logger.debug('Challenge._update() ended')

    def _update_authz(self, challenge_name, data_dic):
        """ update authorizsation based on challenge_name """
        self.logger.debug('Challenge._update_authz({0})'.format(challenge_name))
        try:
            # lookup autorization based on challenge_name
            authz_name = self.dbstore.challenge_lookup('name', challenge_name, ['authorization__name'])['authorization']
        except BaseException as err_:
            self.logger.critical('acme2certifier database error in Challenge._update_authz() lookup: {0}'.format(err_))
            authz_name = None

        if authz_name:
            data_dic['name'] = authz_name
        try:
            # update authorization
            self.dbstore.authorization_update(data_dic)
        except BaseException as err_:
            self.logger.critical('acme2certifier database error in Challenge._update_authz() upd: {0}'.format(err_))

        self.logger.debug('Challenge._update_authz() ended')

    def _validate(self, challenge_name, payload):
        """ validate challenge"""
        self.logger.debug('Challenge._validate({0}: {1})'.format(challenge_name, payload))
        if self.challenge_validation_disable:
            self.logger.debug('CHALLENGE VALIDATION DISABLED. SETTING challenge status to valid')
            challenge_check = True
            invalid = False
        else:
            (challenge_check, invalid) = self._check(challenge_name, payload)

        if invalid:
            self._update({'name' : challenge_name, 'status' : 'invalid'})
            # authorization update to valid state
            self._update_authz(challenge_name, {'status' : 'invalid'})
        elif challenge_check:
            self._update({'name' : challenge_name, 'status' : 'valid', 'validated': uts_now()})
            # authorization update to valid state
            self._update_authz(challenge_name, {'status' : 'valid'})

        if payload:
            if 'keyAuthorization' in payload:
                # update challenge to ready state
                data_dic = {'name' : challenge_name, 'keyauthorization' : payload['keyAuthorization']}
                self._update(data_dic)

        self.logger.debug('Challenge._validate() ended with:{0}'.format(challenge_check))
        return challenge_check

    def _validate_alpn_challenge(self, challenge_name, fqdn, token, jwk_thumbprint):
        """ validate dns challenge """
        self.logger.debug('Challenge._validate_alpn_challenge({0}:{1}:{2})'.format(challenge_name, fqdn, token))

        # resolve name
        (response, invalid) = fqdn_resolve(fqdn, self.dns_server_list)
        self.logger.debug('fqdn_resolve() ended with: {0}/{1}'.format(response, invalid))

        # we are expecting a certifiate extension which is the sha256 hexdigest of token in a byte structure
        # which is base 64 encoded '0420' has been taken from acme.sh sources
        sha256_digest = sha256_hash_hex(self.logger, '{0}.{1}'.format(token, jwk_thumbprint))
        extension_value = b64_encode(self.logger, bytearray.fromhex('0420{0}'.format(sha256_digest)))
        self.logger.debug('computed value: {0}'.format(extension_value))

        if not invalid:
            cert = servercert_get(self.logger, fqdn)
            if cert:
                san_list = cert_san_get(self.logger, cert, recode=False)
                fqdn_in_san = fqdn_in_san_check(self.logger, san_list, fqdn)
                if fqdn_in_san:
                    extension_list = cert_extensions_get(self.logger, cert, recode=False)
                    if extension_value in extension_list:
                        self.logger.debug('alpn validation successful')
                        result = True
                    else:
                        self.logger.debug('alpn validation not successful')
                        result = False
                else:
                    self.logger.debug('fqdn check against san failed')
                    result = False
            else:
                self.logger.debug('no cert returned...')
                result = False

        self.logger.debug('Challenge._validate_alpn_challenge() ended with: {0}/{1}'.format(result, invalid))
        return (result, invalid)

    def _validate_dns_challenge(self, challenge_name, fqdn, token, jwk_thumbprint):
        """ validate dns challenge """
        self.logger.debug('Challenge._validate_dns_challenge({0}:{1}:{2})'.format(challenge_name, fqdn, token))

        # handle wildcard domain
        fqdn = self._wcd_manipulate(fqdn)

        # rewrite fqdn
        fqdn = '_acme-challenge.{0}'.format(fqdn)

        # resolve name
        (_response, invalid) = fqdn_resolve(fqdn)

        if not invalid:
            # compute sha256 hash
            _hash = b64_url_encode(self.logger, sha256_hash(self.logger, '{0}.{1}'.format(token, jwk_thumbprint)))
            # query dns
            txt = txt_get(self.logger, fqdn, self.dns_server_list)

            # compare computed hash with result from DNS query
            self.logger.debug('response_got: {0} response_expected: {1}'.format(txt, _hash))
            if _hash == txt:
                self.logger.debug('validation successful')
                result = True
            else:
                self.logger.debug('validation not successful')
                result = False
        else:
            result = False

        self.logger.debug('Challenge._validate_dns_challenge() ended with: {0}/{1}'.format(result, invalid))
        return (result, invalid)

    def _validate_http_challenge(self, challenge_name, fqdn, token, jwk_thumbprint):
        """ validate http challenge """
        self.logger.debug('Challenge._validate_http_challenge({0}:{1}:{2})'.format(challenge_name, fqdn, token))
        # resolve name
        (response, invalid) = fqdn_resolve(fqdn, self.dns_server_list)
        self.logger.debug('fqdn_resolve() ended with: {0}/{1}'.format(response, invalid))
        if not invalid:
            req = url_get(self.logger, 'http://{0}/.well-known/acme-challenge/{1}'.format(fqdn, token), self.dns_server_list)
            # make challenge validation unsuccessful
            # req = url_get(self.logger, 'http://{0}/.well-known/acme-challenge/{1}'.format('test.test', 'foo.bar.some.not.existing.ressource'))
            if req:
                response_got = req.splitlines()[0]
                response_expected = '{0}.{1}'.format(token, jwk_thumbprint)
                self.logger.debug('response_got: {0} response_expected: {1}'.format(response_got, response_expected))
                if response_got == response_expected:
                    self.logger.debug('validation successful')
                    result = True
                else:
                    self.logger.debug('validation not successful')
                    result = False
            else:
                self.logger.debug('validation not successfull.. no request object')
                result = False
        else:
            result = False

        self.logger.debug('Challenge._validate_http_challenge() ended with: {0}/{1}'.format(result, invalid))
        return (result, invalid)

    def _validate_tkauth_challenge(self, challenge_name, tnauthlist, _token, _jwk_thumbprint, payload):
        """ validate tkauth challenge """
        self.logger.debug('Challenge._validate_tkauth_challenge({0}:{1}:{2})'.format(challenge_name, tnauthlist, payload))

        result = True
        invalid = False
        self.logger.debug('Challenge._validate_tkauth_challenge() ended with: {0}/{1}'.format(result, invalid))
        return (result, invalid)

    def _validate_tnauthlist_payload(self, payload, challenge_dic):
        """ check payload in cae tnauthlist option has been set """
        self.logger.debug('Challenge._validate_tnauthlist_payload({0}:{1})'.format(payload, challenge_dic))

        code = 400
        message = None
        detail = None

        if 'type' in challenge_dic:
            if challenge_dic['type'] == 'tkauth-01':
                self.logger.debug('tkauth identifier found')
                # check if we havegot an atc claim in the challenge request
                if 'atc' in payload:
                    # check if we got a SPC token in the challenge request
                    if not bool(payload['atc']):
                        code = 400
                        message = 'urn:ietf:params:acme:error:malformed'
                        detail = 'SPC token is missing'
                    else:
                        code = 200
                else:
                    code = 400
                    message = 'urn:ietf:params:acme:error:malformed'
                    detail = 'atc claim is missing'
            else:
                code = 200
        else:
            message = 'urn:ietf:params:acme:error:malformed'
            detail = 'invalid challenge: {0}'.format(challenge_dic)

        self.logger.debug('Challenge._validate_tnauthlist_payload() ended with:{0}'.format(code))
        return(code, message, detail)

    def _wcd_manipulate(self, fqdn):
        """ wildcard domain handling """
        self.logger.debug('Challenge._wc_manipulate() for fqdn: {0}'.format(fqdn))
        if fqdn.startswith('*.'):
            fqdn = fqdn[2:]
        self.logger.debug('Challenge._wc_manipulate() ended with: {0}'.format(fqdn))
        return fqdn

    def challengeset_get(self, authz_name, auth_status, token, tnauth):
        """ get the challengeset for an authorization """
        self.logger.debug('Challenge.challengeset_get() for auth: {0}'.format(authz_name))
        # check database if there are exsting challenges for a particular authorization
        challenge_list = self._challengelist_search('authorization__name', authz_name)

        if challenge_list:
            self.logger.debug('Challenges found.')
            # trigger challenge validation
            challenge_name_list = []
            for challenge in challenge_list:
                challenge_name_list.append(challenge.pop('name'))
            if auth_status == 'pending':
                self._existing_challenge_validate(challenge_name_list)

        else:
            # new challenges to be created
            self.logger.debug('Challenges not found. Create a new set.')
            challenge_list = self.new_set(authz_name, token, tnauth)

        return challenge_list

    def get(self, url):
        """ get challenge details based on get request """
        self.logger.debug('Challenge.get({0})'.format(url))
        challenge_name = self._name_get(url)
        response_dic = {}
        response_dic['code'] = 200
        response_dic['data'] = self._info(challenge_name)
        return response_dic

    def new_set(self, authz_name, token, tnauth=False):
        """ net challenge set """
        self.logger.debug('Challenge.new_set({0}, {1})'.format(authz_name, token))
        challenge_list = []
        if not tnauth:
            challenge_list.append(self._new(authz_name, 'http-01', token))
            challenge_list.append(self._new(authz_name, 'dns-01', token))
            challenge_list.append(self._new(authz_name, 'tls-alpn-01', token))
        else:
            challenge_list.append(self._new(authz_name, 'tkauth-01', token))
        self.logger.debug('Challenge._new_set returned ({0})'.format(challenge_list))
        return challenge_list

    def parse(self, content):
        """ new oder request """
        self.logger.debug('Challenge.parse()')

        response_dic = {}
        # check message
        (code, message, detail, protected, payload, _account_name) = self.message.check(content)

        if code == 200:
            if 'url' in protected:
                challenge_name = self._name_get(protected['url'])
                if challenge_name:
                    challenge_dic = self._info(challenge_name)

                    if challenge_dic:
                        # check tnauthlist payload
                        if self.tnauthlist_support:
                            (code, message, detail) = self._validate_tnauthlist_payload(payload, challenge_dic)

                        if code == 200:
                            # start validation
                            if 'status' in challenge_dic:
                                if challenge_dic['status'] != 'valid':
                                    _validation = self._validate(challenge_name, payload)
                                    # query challenge again (bcs. it could get updated by self._validate)
                                    challenge_dic = self._info(challenge_name)
                            else:
                                # rather unlikely that we run in this situation but you never know
                                _validation = self._validate(challenge_name, payload)
                                # query challenge again (bcs. it could get updated by self._validate)
                                challenge_dic = self._info(challenge_name)

                            response_dic['data'] = {}
                            challenge_dic['url'] = protected['url']
                            code = 200
                            response_dic['data'] = {}
                            response_dic['data'] = challenge_dic
                            response_dic['header'] = {}
                            response_dic['header']['Link'] = '<{0}{1}>;rel="up"'.format(self.server_name, self.path_dic['authz_path'])
                    else:
                        code = 400
                        message = 'urn:ietf:params:acme:error:malformed'
                        detail = 'invalid challenge: {0}'.format(challenge_name)
                else:
                    code = 400
                    message = 'urn:ietf:params:acme:error:malformed'
                    detail = 'could not get challenge'
            else:
                code = 400
                message = 'urn:ietf:params:acme:error:malformed'
                detail = 'url missing in protected header'

        # prepare/enrich response
        status_dic = {'code': code, 'message' : message, 'detail' : detail}
        response_dic = self.message.prepare_response(response_dic, status_dic)
        self.logger.debug('challenge.parse() returns: {0}'.format(json.dumps(response_dic)))
        return response_dic
