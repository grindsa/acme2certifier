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
import os
import sys
import textwrap
from datetime import datetime
from string import digits, ascii_letters
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse
import logging
import hashlib
from urllib3.util import connection
from jwcrypto import jwk, jws
from dateutil.parser import parse
import requests
import pytz
import dns.resolver
import OpenSSL
from .version import __version__

def b64decode_pad(logger, string):
    """ b64 decoding and padding of missing "=" """
    logger.debug('b64decode_pad()')
    try:
        b64dec = base64.urlsafe_b64decode(string + '=' * (4 - len(string) % 4))
    except BaseException:
        b64dec = b'ERR: b64 decoding error'
    return b64dec.decode('utf-8')

def b64_decode(logger, string):
    """ b64 decoding """
    logger.debug('b64decode()')
    return convert_byte_to_string(base64.b64decode(string))
    #if sys.version_info[0] >= 3:
    #    return base64.b64decode(string).decode()
    #else:
    #    return base64.b64decode(string)

def b64_encode(logger, string):
    """ encode a bytestream in base64 """
    logger.debug('b64_encode()')
    return convert_byte_to_string(base64.b64encode(string))

def b64_url_encode(logger, string):
    """ encode a bytestream in base64 url and remove padding """
    logger.debug('b64_url_encode()')
    string = convert_string_to_byte(string)
    encoded = base64.urlsafe_b64encode(string)
    return encoded.rstrip(b"=")

def b64_url_recode(logger, string):
    """ recode base64_url to base64 """
    logger.debug('b64_url_recode()')
    padding_factor = (4 - len(string) % 4) % 4
    string = convert_byte_to_string(string)
    string += "="*padding_factor
    # differ between py2 and py3
    # pylint: disable=E0602
    if sys.version_info[0] >= 3:
        result = str(string).translate(dict(zip(map(ord, u'-_'), u'+/')))
    else:
        result = unicode(string).translate(dict(zip(map(ord, u'-_'), u'+/')))
    return result

def build_pem_file(logger, existing, certificate, wrap, csr=False):
    """ construct pem_file """
    logger.debug('build_pem_file()')
    if csr:
        pem_file = '-----BEGIN CERTIFICATE REQUEST-----\n{0}\n-----END CERTIFICATE REQUEST-----\n'.format(textwrap.fill(convert_byte_to_string(certificate), 64))
        # req = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_ASN1, base64.b64decode(certificate))
        # pem_file = convert_byte_to_string(OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM,req))
    else:
        if existing:
            if wrap:
                pem_file = '{0}-----BEGIN CERTIFICATE-----\n{1}\n-----END CERTIFICATE-----\n'.format(convert_byte_to_string(existing), textwrap.fill(convert_byte_to_string(certificate), 64))
            else:
                pem_file = '{0}-----BEGIN CERTIFICATE-----\n{1}\n-----END CERTIFICATE-----\n'.format(convert_byte_to_string(existing), convert_byte_to_string(certificate))
        else:
            if wrap:
                pem_file = '-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n'.format(textwrap.fill(convert_byte_to_string(certificate), 64))
            else:
                pem_file = '-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n'.format(convert_byte_to_string(certificate))
    return pem_file

def cert_pem2der(pem_file):
    """ convert certificate pem to der """
    certobj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_file)
    return OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, certobj)

def cert_der2pem(pem_file):
    """ convert certificate der to pem """
    certobj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, pem_file)
    return OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, certobj)

def cert_pubkey_get(logger, cert):
    """ get public key from certificate  """
    logger.debug('CAhandler.cert_pubkey_get()')
    req = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    pubkey = req.get_pubkey()
    pubkey_str = convert_byte_to_string(OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, pubkey))
    logger.debug('CAhandler.cert_pubkey_get() ended with: {0}'.format(pubkey_str))
    return convert_byte_to_string(pubkey_str)

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

def cert_extensions_get(logger, certificate):
    """ get extenstions from certificate certificate """
    logger.debug('cert_extensions_get()')
    pem_file = build_pem_file(logger, None, b64_url_recode(logger, certificate), True)
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_file)

    extension_list = []
    ext_count = cert.get_extension_count()
    for i in range(0, ext_count):
        ext = cert.get_extension(i)
        extension_list.append(convert_byte_to_string(base64.b64encode(ext.get_data())))

    logger.debug('cert_extensions_get() ended with: {0}'.format(extension_list))
    return extension_list

def cert_serial_get(logger, certificate):
    """ get serial number form certificate """
    logger.debug('cert_serial_get()')
    pem_file = build_pem_file(logger, None, b64_url_recode(logger, certificate), True)
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_file)
    logger.debug('cert_serial_get() ended with: {0}'.format(cert.get_serial_number()))
    return cert.get_serial_number()

def convert_byte_to_string(value):
    """ convert a variable to string if needed """
    if hasattr(value, 'decode'):
        try:
            return value.decode()
        except BaseException:
            return value
    else:
        return value

def convert_string_to_byte(value):
    """ convert a variable to byte if needed """
    if hasattr(value, 'encode'):
        result = value.encode()
    else:
        result = value
    return result

def csr_cn_get(logger, csr):
    """ get cn from certificate request """
    logger.debug('CAhandler.csr_cn_get()')
    pem_file = build_pem_file(logger, None, b64_url_recode(logger, csr), True, True)
    req = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, pem_file)
    subject = req.get_subject()
    components = dict(subject.get_components())
    result = None
    if 'CN' in components:
        result = components['CN']
    elif b'CN' in components:
        result = convert_byte_to_string(components[b'CN'])

    logger.debug('CAhandler.csr_cn_get() ended with: {0}'.format(result))
    return result

def csr_dn_get(logger, csr):
    """ get subject from certificate request in openssl notation """
    logger.debug('CAhandler.csr_dn_get()')
    pem_file = build_pem_file(logger, None, b64_url_recode(logger, csr), True, True)
    req = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, pem_file)
    subject = req.get_subject()
    subject_str = "".join("/{0:s}={1:s}".format(name.decode(), value.decode()) for name, value in subject.get_components())
    logger.debug('CAhandler.csr_dn_get() ended with: {0}'.format(subject_str))
    return subject_str

def csr_pubkey_get(logger, csr):
    """ get public key from certificate request """
    logger.debug('CAhandler.csr_pubkey_get()')
    pem_file = build_pem_file(logger, None, b64_url_recode(logger, csr), True, True)
    req = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, pem_file)
    pubkey = req.get_pubkey()
    pubkey_str = convert_byte_to_string(OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, pubkey))
    logger.debug('CAhandler.csr_pubkey_get() ended with: {0}'.format(pubkey_str))
    return pubkey_str

def csr_san_get(logger, csr):
    """ get subject alternate names from certificate """
    logger.debug('cert_san_get()')
    san = []
    if csr:
        pem_file = build_pem_file(logger, None, b64_url_recode(logger, csr), True, True)
        req = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, pem_file)
        for ext in req.get_extensions():
            if 'subjectAltName' in str(ext.get_short_name()):
                san_list = ext.__str__().split(',')
                for san_name in san_list:
                    san_name = san_name.rstrip()
                    san_name = san_name.lstrip()
                    san.append(san_name)
    logger.debug('cert_san_get() ended with: {0}'.format(str(san)))
    return san

def csr_extensions_get(logger, csr):
    """ get extensions from certificate """
    logger.debug('csr_extensions_get()')
    pem_file = build_pem_file(logger, None, b64_url_recode(logger, csr), True, True)
    req = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, pem_file)

    extension_list = []
    for ext in req.get_extensions():
        # decoding based on python version
        if sys.version_info[0] >= 3:
            extension_list.append(base64.b64encode(ext.get_data()).decode())
        else:
            extension_list.append(base64.b64encode(ext.get_data()))

    logger.debug('csr_extensions_get() ended with: {0}'.format(extension_list))
    return extension_list

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
        if bool(jwstoken.objects['payload']):
            payload = json.loads(jwstoken.objects['payload'])
        else:
            payload = {}
        signature = jwstoken.objects['signature']
        result = True
    except BaseException as err:
        error = str(err)
        protected = {}
        payload = {}
        signature = None

    if payload:
        payload = dkeys_lower(payload)
    return(result, error, protected, payload, signature)

def dkeys_lower(tree):
    """ lower characters in payload string """
    if isinstance(tree, dict):
        result = {k.lower() : dkeys_lower(v) for k, v in tree.items()}
    elif isinstance(tree, list):
        result = [dkeys_lower(ele) for ele in tree]
    else:
        result = tree
    return result

def generate_random_string(logger, length):
    """ generate random string to be used as name """
    logger.debug('generate_random_string()')
    char_set = digits + ascii_letters
    return ''.join(random.choice(char_set) for _ in range(length))

def get_url(environ, include_path=False):
    """ get url """
    if 'HTTP_HOST' in environ:
        server_name = environ['HTTP_HOST']
    else:
        server_name = 'localhost'

    if 'SERVER_PORT' in environ:
        port = environ['SERVER_PORT']
    else:
        port = 80

    if 'wsgi.url_scheme' in environ:
        proto = environ['wsgi.url_scheme']
    elif port == 443:
        proto = 'https'
    else:
        proto = 'http'

    if include_path and 'PATH_INFO' in environ:
        result = '{0}://{1}{2}'.format(proto, server_name, environ['PATH_INFO'])
    else:
        result = '{0}://{1}'.format(proto, server_name)
    return result

def load_config(logger=None, mfilter=None, cfg_file=os.path.dirname(__file__)+'/'+'acme_srv.cfg'):
    """ small configparser wrappter to load a config file """
    if logger:
        logger.debug('load_config({1}:{0})'.format(mfilter, cfg_file))
    config = configparser.RawConfigParser()
    config.optionxform = str
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
                    try:
                        # python2
                        challenge.update((k, "- modified - ") for k, v in challenge.iteritems() if k == "token")
                    except AttributeError:
                        # python3
                        challenge.update((k, "- modified - ") for k, v in challenge.items() if k == "token")

    logger.info('{0} {1} {2}'.format(addr, url, str(data_dic)))

def logger_setup(debug):
    """ setup logger """
    if debug:
        log_mode = logging.DEBUG
    else:
        log_mode = logging.INFO

    config_dic = load_config()

    # define standard log format
    log_format = '%(message)s'
    if 'Helper' in config_dic:
        if 'log_format' in config_dic['Helper']:
            log_format = config_dic['Helper']['log_format']

    logging.basicConfig(
        format=log_format,
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
            logger.error('load key failed {0}'.format(err))
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
                logger.error('verify failed {0}'.format(err))
                error = str(err)
    else:
        error = 'No key specified.'

    # return result
    return(result, error)

def patch_resolver(host, dnssrv):
    """ patch resolver to use a specific DNS server """
    req = dns.resolver.Resolver()
    req.nameservers = dnssrv
    answers = req.query(host, 'A')
    for rdata in answers:
        return str(rdata)

def dns_server_list_load():
    """ load dns-server from config file """
    config_dic = load_config()

    if 'Challenge' in config_dic:
        if 'dns_server_list' in config_dic['Challenge']:
            try:
                dns_server_list = json.loads(config_dic['Challenge']['dns_server_list'])
            except BaseException:
                dns_server_list = ['9.9.9.9', '8.8.8.8']
        else:
            dns_server_list = ['9.9.9.9', '8.8.8.8']
    else:
        dns_server_list = ['9.9.9.9', '8.8.8.8']

    return dns_server_list

def patched_create_connection(address, *args, **kwargs):
    """ Wrap urllib3's create_connection to resolve the name elsewhere"""
    # load dns-servers from config file
    dns_server_list = dns_server_list_load()
    # resolve hostname to an ip address; use your own resolver
    host, port = address
    hostname = patch_resolver(host, dns_server_list)
    # pylint: disable=W0212
    return connection._orig_create_connection((hostname, port), *args, **kwargs)

def url_get_with_own_dns(logger, url):
    """ request by using an own dns resolver """
    logger.debug('url_get_with_own_dns({0})'.format(url))
    # patch an own connection handler into URL lib
    # pylint: disable=W0212
    connection._orig_create_connection = connection.create_connection
    connection.create_connection = patched_create_connection
    try:
        req = requests.get(url, headers={'Connection':'close', 'Accept-Encoding': 'gzip', 'User-Agent': 'acme2certifier/{0}'.format(__version__)})
        result = req.text
    except BaseException as err_:
        result = None
        logger.error('url_get error: {0}'.format(err_))
    # cleanup
    connection.create_connection = connection._orig_create_connection
    return result

def url_get(logger, url, dns_server_list=None):
    """ http get """
    logger.debug('url_get({0})'.format(url))
    if dns_server_list:
        result = url_get_with_own_dns(logger, url)
    else:
        try:
            req = requests.get(url, headers={'Connection':'close', 'Accept-Encoding': 'gzip', 'User-Agent': 'acme2certifier/{0}'.format(__version__)})
            result = req.text
        except BaseException as err_:
            result = None
            logger.error('url_get error: {0}'.format(err_))
    logger.debug('url_get() ended with: {0}'.format(result))
    return result

def txt_get(logger, fqdn, dns_srv=None):
    """ dns query to get the TXt record """
    logger.debug('txt_get({0}: {1})'.format(fqdn, dns_srv))

    # rewrite dns resolver if configured
    if dns_srv:
        dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
        dns.resolver.default_resolver.nameservers = dns_srv
    try:
        result = dns.resolver.query(fqdn, 'TXT').response.answer[0][-1].strings[0]
    except BaseException as err_:
        logger.error('txt_get() error: {0}'.format(err_))
        result = None
    logger.debug('txt_get() ended with: {0}'.format(result))
    return result

def uts_now():
    """ return unixtimestamp in utc """
    return calendar.timegm(datetime.utcnow().utctimetuple())

def uts_to_date_utc(uts, tformat='%Y-%m-%dT%H:%M:%SZ'):
    """ convert unix timestamp to date format """
    return datetime.fromtimestamp(int(uts), tz=pytz.utc).strftime(tformat)

def date_to_uts_utc(date_human, _tformat='%Y-%m-%dT%H:%M:%S'):
    """ convert date to unix timestamp """
    # return int(time.mktime(parse(date_human).timetuple()))
    return int(calendar.timegm(parse(date_human).timetuple()))

def date_to_datestr(date, tformat='%Y-%m-%dT%H:%M:%SZ'):
    """ convert dateobj to datestring """
    try:
        result = date.strftime(tformat)
    except BaseException:
        result = None
    return result

def datestr_to_date(datestr, tformat='%Y-%m-%dT%H:%M:%S'):
    """ convert datestr to dateobj """
    try:
        result = datetime.strptime(datestr, tformat)
    except BaseException:
        result = None
    return result

def validate_csr(logger, order_dic, _csr):
    """ validate certificate signing request against order"""
    logger.debug('validate_csr({0})'.format(order_dic))
    return True

def validate_email(logger, contact_list):
    """ validate contact against RFC608"""
    logger.debug('validate_email()')
    result = True
    pattern = r"^[A-Za-z0-9\.\+_-]+@[A-Za-z0-9\._-]+\.[a-zA-Z]*$"
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
