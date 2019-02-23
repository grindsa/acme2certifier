#!/usr/bin/python
# -*- coding: utf-8 -*-
""" helper functions for acme2certifier """
from __future__ import print_function
import re
import base64
import json
import random
import calendar
import copy
import configparser
import time
import os
import sys
import textwrap
from datetime import datetime
from string import digits, ascii_letters
from urlparse import urlparse
import logging
import hashlib
from jwcrypto import jwk, jws
import requests
import pytz
import dns.resolver
import OpenSSL

def b64decode_pad(logger, string):
    """ b64 decoding and padding of missing "=" """
    logger.debug('b64decode_pad()')
    string += '=' * (-len(string) % 4)  # restore stripped '='s
    try:
        b64dec = base64.b64decode(string)
    except TypeError:
        b64dec = 'ERR: b64 decoding error'
    return b64dec

def b64_encode(logger, string):
    """ encode a bytestream in base64 """
    logger.debug('b64_encode()')
    return base64.b64encode(string)

def b64_url_encode(logger, string):
    """ encode a bytestream in base64 url and remove padding """
    logger.debug('b64_url_encode()')
    encoded = base64.urlsafe_b64encode(string)
    return encoded.rstrip("=")

def b64_url_recode(logger, string):
    """ recode base64_url to base64 """
    logger.debug('b64_url_recode()')
    padding_factor = (4 - len(string) % 4) % 4
    string += "="*padding_factor
    # return base64.b64decode(unicode(string).translate(dict(zip(map(ord, u'-_'), u'+/'))))
    return unicode(string).translate(dict(zip(map(ord, u'-_'), u'+/')))

def build_pem_file(logger, existing, certificate, wrap):
    """ construct pem_file """
    logger.debug('build_pem_file()')
    if existing:
        if wrap:
            pem_file = '{0}-----BEGIN CERTIFICATE-----\n{1}\n-----END CERTIFICATE-----\n'.format(existing, textwrap.fill(certificate, 64))
        else:
            pem_file = '{0}-----BEGIN CERTIFICATE-----\n{1}\n-----END CERTIFICATE-----\n'.format(existing, certificate)
    else:
        if wrap:
            pem_file = '-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n'.format(textwrap.fill(certificate, 64))
        else:
            pem_file = '-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n'.format(certificate)
    return pem_file

def cert_san_get(logger, certificate):
    """ get subject alternate names from certificate """
    logger.debug('cert_san_get()')
    pem_file = build_pem_file(logger, None, b64_url_recode(logger, certificate), True)
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_file)
    san = []
    ext_count = cert.get_extension_count()
    for i in range(0, ext_count):
        ext = cert.get_extension(i)
        if 'subjectAltName' in str(ext.get_short_name()):
            san_list = ext.__str__().split(',')
            for san_name in san_list:
                san_name = san_name.rstrip()
                san_name = san_name.lstrip()
                san.append(san_name)

    logger.debug('cert_san_get() ended')
    return san

def cert_serial_get(logger, certificate):
    """ get serial number form certificate """
    logger.debug('cert_serial_get()')
    pem_file = build_pem_file(logger, None, b64_url_recode(logger, certificate), True)
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_file)
    return cert.get_serial_number()

def decode_deserialize(logger, string):
    """ decode and deserialize string """
    logger.debug('decode_deserialize()')
    # b64 decode
    string_decode = b64decode_pad(logger, string)
    # deserialize if b64 decoding was successful
    if string_decode and string_decode != 'ERR: b64 decoding error':
        try:
            string_decode = json.loads(string_decode)
        except ValueError:
            string_decode = 'ERR: Json decoding error'

    return string_decode

def decode_message(logger, message):
    """ decode jwstoken and return header, payload and signature """
    logger.debug('decode_message()')
    jwstoken = jws.JWS()
    result = False
    error = None
    try:
        jwstoken.deserialize(message)
        protected = json.loads(jwstoken.objects['protected'])
        if jwstoken.objects['payload'] != "":
            payload = json.loads(jwstoken.objects['payload'])
        else:
            payload = None
        signature = jwstoken.objects['signature']
        result = True
    except BaseException as err:
        error = str(err)
        protected = None
        payload = None
        signature = None
    return(result, error, protected, payload, signature)

def generate_random_string(logger, length):
    """ generate random string to be used as name """
    logger.debug('generate_random_string()')
    char_set = digits + ascii_letters
    return ''.join(random.choice(char_set) for _ in range(length))

def get_url(environ, include_path=False):
    """ get url """
    server_name = environ['HTTP_HOST']
    port = environ['SERVER_PORT']
    if port == 443:
        proto = 'https'
    else:
        proto = 'http'

    if include_path:
        return '{0}://{1}{2}'.format(proto, server_name, environ['PATH_INFO'])
    else:
        return '{0}://{1}'.format(proto, server_name)

def load_config(logger=None, mfilter=None, cfg_file=os.path.dirname(__file__)+'/'+'acme_srv.cfg'):
    """ small configparser wrappter to load a config file """
    if logger:
        logger.debug('load_config({1}:{0})'.format(mfilter, cfg_file))
    config = configparser.ConfigParser()
    config.read(cfg_file)
    return config

def parse_url(logger, url):
    """ split url into pieces """
    logger.debug('parse_url({0})'.format(url))
    url_dic = {
        'proto' : urlparse(url).scheme,
        'host' : urlparse(url).netloc,
        'path' : urlparse(url).path
    }
    return url_dic

def logger_info(logger, addr, url, dat_dic):
    """ log responses """

    # create a copy of the dictionary
    data_dic = copy.deepcopy(dat_dic)

    if 'header' in data_dic:
        if 'Replay-Nonce' in data_dic['header']:
            data_dic['header']['Replay-Nonce'] = '- modified -'

    if 'data' in data_dic:
        # remove cert from log entry
        if url.startswith('/acme/cert'):
            data_dic['data'] = ' - certificate - '

        # remove token from challenge
        if 'token' in data_dic['data']:
            data_dic['data']['token'] = '- modified -'

        # remove tokens
        if 'challenges' in data_dic['data']:
            for challenge in data_dic['data']['challenges']:
                if 'token' in challenge:
                    challenge.update((k, "- modified - ") for k, v in challenge.iteritems() if k == "token")

    logger.info('{0} {1} {2}'.format(addr, url, str(data_dic)))

def logger_setup(debug):
    """ setup logger """
    if debug:
        log_mode = logging.DEBUG
    else:
        log_mode = logging.INFO

    logging.basicConfig(
        # format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        format='%(asctime)s - acme2certifier - %(levelname)s - %(message)s',
        datefmt="%Y-%m-%d %H:%M:%S",
        level=log_mode)
    logger = logging.getLogger('acme2certifier')
    return logger


def print_debug(debug, text):
    """ little helper to print debug messages
        args:
            debug = debug flag
            text  = text to print
        returns:
            (text)
    """
    if debug:
        print('{0}: {1}'.format(datetime.now(), text))

def jwk_thumbprint_get(logger, pub_key):
    """ get thumbprint """
    logger.debug('jwk_thumbprint_get()')
    if pub_key:
        try:
            jwkey = jwk.JWK(**pub_key)
            thumbprint = jwkey.thumbprint()
        except BaseException:
            jwkey = None
            thumbprint = None
    else:
        thumbprint = None

    logger.debug('jwk_thumbprint_get() ended with: {0}'.format(thumbprint))
    return thumbprint

def sha256_hash(logger, string):
    """ hash string """
    logger.debug('sha256_hash()')

    result = hashlib.sha256(string.encode('utf-8')).digest()

    logger.debug('sha256_hash() ended with {0} (base64-encoded)'.format(b64_encode(logger, result)))
    return result

def signature_check(logger, message, pub_key):
    """ check JWS """
    logger.debug('signature_check()')

    result = False
    error = None

    if pub_key:
        # load key
        try:
            jwkey = jwk.JWK(**pub_key)
        except BaseException as err:
            jwkey = None
            result = False
            error = str(err)

        # verify signature
        if jwkey:
            jwstoken = jws.JWS()
            jwstoken.deserialize(message)
            try:
                jwstoken.verify(jwkey)
                result = True
            except BaseException as err:
                error = str(err)
    else:
        error = 'No key specified.'

    # return result
    return(result, error)

def url_get(logger, url):
    """ http get """
    logger.debug('url_get({0})'.format(url))
    try:
        req = requests.get(url)
        result = req.text
    except BaseException:
        result = None
    logger.debug('url_get() ended with: {0}'.format(result))
    return result

def txt_get(logger, fqdn):
    """ dns query to get the TXt record """
    logger.debug('txt_get({0})'.format(fqdn))
    try:
        result = dns.resolver.query(fqdn, 'TXT').response.answer[0][-1].strings[0]
    except BaseException:
        result = None
    logger.debug('txt_get() ended with: {0}'.format(result))
    return result

def uts_now():
    """ return unixtimestamp in utc """
    return calendar.timegm(datetime.utcnow().utctimetuple())

def uts_to_date_utc(uts, tformat='%Y-%m-%dT%H:%M:%SZ'):
    """ convert unix timestamp to date format """
    return datetime.fromtimestamp(int(uts), tz=pytz.utc).strftime(tformat)

def date_to_uts_utc(date_human, tformat='%Y-%m-%dT%H:%M:%S'):
    """ convert date to unix timestamp """
    return int(calendar.timegm(time.strptime(date_human, tformat)))

def validate_csr(logger, order_dic, _csr):
    """ validate certificate signing request against order"""
    logger.debug('validate_csr({0})'.format(order_dic))
    return True

def validate_email(logger, contact_list):
    """ validate contact against RFC608"""
    logger.debug('validate_email()')
    result = True
    pattern = r"\"?([-a-zA-Z0-9.`?{}]+@\w+\.\w+)\"?"
    # check if we got a list or single address
    if isinstance(contact_list, list):
        for contact in contact_list:
            contact = contact.replace('mailto:', '')
            contact = contact.lstrip()
            tmp_result = bool(re.search(pattern, contact))
            logger.debug('# validate: {0} result: {1}'.format(contact, tmp_result))
            if not tmp_result:
                result = tmp_result
    else:
        contact_list = contact_list.replace('mailto:', '')
        contact_list = contact_list.lstrip()
        result = bool(re.search(pattern, contact_list))
        logger.debug('# validate: {0} result: {1}'.format(contact_list, result))
    return result

def handle_exception(exc_type, exc_value, exc_traceback):
    """ exception handler """
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    # logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))
    logging.error("Uncaught exception")
