# pylint: disable=c0209, c0302, e0401, r0913
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
import importlib
import textwrap
from datetime import datetime
from string import digits, ascii_letters
import socket
import ssl
import logging
import hashlib
import html
import ipaddress
from urllib.parse import urlparse, quote
from urllib3.util import connection
import socks
from jwcrypto import jwk, jws
from dateutil.parser import parse
import pytz
import dns.resolver
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import load_pem_x509_certificate, ocsp
import requests
import requests.packages.urllib3.util.connection as urllib3_cn
from .version import __version__


USER_AGENT = 'acme2certifier/{0}'.format(__version__)


def b64decode_pad(logger, string):
    """ b64 decoding and padding of missing "=" """
    logger.debug('b64decode_pad()')
    try:
        b64dec = base64.urlsafe_b64decode(string + '=' * (4 - len(string) % 4))
    except Exception:
        b64dec = b'ERR: b64 decoding error'
    return b64dec.decode('utf-8')


def b64_decode(logger, string):
    """ b64 decoding """
    logger.debug('b64decode()')
    return convert_byte_to_string(base64.b64decode(string))


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
    string += "=" * padding_factor
    result = str(string).translate(dict(zip(map(ord, '-_'), '+/')))
    return result


def build_pem_file(logger, existing, certificate, wrap, csr=False):
    """ construct pem_file """
    logger.debug('build_pem_file()')
    if csr:
        pem_file = '-----BEGIN CERTIFICATE REQUEST-----\n{0}\n-----END CERTIFICATE REQUEST-----\n'.format(textwrap.fill(convert_byte_to_string(certificate), 64))
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


def ca_handler_load(logger, config_dic):
    """ load and return ca_handler """
    logger.debug('Helper.ca_handler_load()')

    if 'CAhandler' not in config_dic:
        logger.error('Helper.ca_handler_load(): CAhandler configuration missing in config file')
        return None

    if 'handler_file' in config_dic['CAhandler']:
        # try to load handler from file
        try:
            spec = importlib.util.spec_from_file_location('CAhandler', config_dic['CAhandler']['handler_file'])
            ca_handler_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(ca_handler_module)
            return ca_handler_module
        except Exception as err_:
            logger.critical('Helper.ca_handler_load(): loading CAhandler configured in cfg failed with err: {0}'.format(err_))

    # if no 'handler_file' provided or loading was unsuccessful, try to load default handler
    try:
        ca_handler_module = importlib.import_module('acme_srv.ca_handler')
    except Exception as err_:
        logger.critical('Helper.ca_handler_load(): loading default CAhandler failed with err: {0}'.format(err_))
        ca_handler_module = None

    return ca_handler_module


def config_check(logger, config_dic):
    """ check configuration """
    logger.debug('Helper.config_check()')

    for section, section_dic in config_dic.items():
        for key, value in section_dic.items():
            if value.startswith('"') or value.endswith('"'):
                logger.warning('config_check(): section {0} option: {1} contains " characters. Check if this is really needed!'.format(section, key))


def eab_handler_load(logger, config_dic):
    """ load and return eab_handler """
    logger.debug('Helper.eab_handler_load()')
    # pylint: disable=w0621
    if 'EABhandler' in config_dic and 'eab_handler_file' in config_dic['EABhandler']:
        # try to load handler from file
        try:
            spec = importlib.util.spec_from_file_location('EABhandler', config_dic['EABhandler']['eab_handler_file'])
            eab_handler_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(eab_handler_module)
        except Exception as err_:
            logger.critical('Helper.eab_handler_load(): loading EABhandler configured in cfg failed with err: {0}'.format(err_))
            try:
                eab_handler_module = importlib.import_module('acme_srv.eab_handler')
            except Exception as err_:
                eab_handler_module = None
                logger.critical('Helper.eab_handler_load(): loading default EABhandler failed with err: {0}'.format(err_))
    else:
        if 'EABhandler' in config_dic:
            try:
                eab_handler_module = importlib.import_module('acme_srv.eab_handler')
            except Exception as err_:
                logger.critical('Helper.eab_handler_load(): loading default EABhandler failed with err: {0}'.format(err_))
                eab_handler_module = None
        else:
            logger.error('Helper.eab_handler_load(): EABhandler configuration missing in config file')
            eab_handler_module = None

    return eab_handler_module


def hooks_load(logger, config_dic):
    """ load and return hooks """
    logger.debug('Helper.hooks_load()')

    hooks_module = None
    if 'Hooks' in config_dic and 'hooks_file' in config_dic['Hooks']:
        # try to load hooks from file
        try:
            spec = importlib.util.spec_from_file_location('Hooks', config_dic['Hooks']['hooks_file'])
            hooks_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(hooks_module)
        except Exception as err_:
            logger.critical('Helper.hooks_load(): loading Hooks configured in cfg failed with err: {0}'.format(err_))

    return hooks_module


def cert_load(logger, certificate, recode):
    """ load certificate object from pem _Format """
    logger.debug('cert_load({0})'.format(recode))
    if recode:
        pem_data = convert_string_to_byte(build_pem_file(logger, None, b64_url_recode(logger, certificate), True))
    else:
        pem_data = convert_string_to_byte(certificate)
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())

    return cert


def cert_dates_get(logger, certificate):
    """ get date number form certificate """
    logger.debug('cert_dates_get()')
    issue_date = 0
    expiration_date = 0

    try:
        cert = cert_load(logger, certificate, recode=True)
        issue_date = date_to_uts_utc(cert.not_valid_before, _tformat='%Y-%m-%d %H:%M:%S')
        expiration_date = date_to_uts_utc(cert.not_valid_after, _tformat='%Y-%m-%d %H:%M:%S')
    except Exception:
        issue_date = 0
        expiration_date = 0

    logger.debug('cert_dates_get() ended with: {0}/{1}'.format(issue_date, expiration_date))
    return (issue_date, expiration_date)


def cert_cn_get(logger, certificate):
    """ get cn from certificate  """
    logger.debug('CAhandler.cert_cn_get()')

    cert = cert_load(logger, certificate, recode=True)
    # get subject and look for common name
    subject = cert.subject
    result = None
    for attr in subject:
        if attr.oid == x509.NameOID.COMMON_NAME:
            result = attr.value
            break
    logger.debug('CAhandler.cert_cn_get() ended with: {0}'.format(result))
    return result


def cert_der2pem(der_cert):
    """ convert certificate der to pem """
    cert = x509.load_der_x509_certificate(der_cert)
    pem_cert = cert.public_bytes(serialization.Encoding.PEM)
    return pem_cert


def cert_issuer_get(logger, certificate):
    """ get serial number form certificate """
    logger.debug('cert_issuer_get()')

    cert = cert_load(logger, certificate, recode=True)
    result = cert.issuer.rfc4514_string()
    logger.debug('CAhandler.cert_issuer_get() ended with: {0}'.format(result))
    return result


def cert_pem2der(pem_cert):
    """ convert certificate pem to der """
    cert = x509.load_pem_x509_certificate(pem_cert.encode(), default_backend())
    der_cert = cert.public_bytes(serialization.Encoding.DER)
    return der_cert


def cert_pubkey_get(logger, certificate):
    """ get public key from certificate  """
    logger.debug('CAhandler.cert_pubkey_get()')
    cert = cert_load(logger, certificate, recode=False)
    public_key = cert.public_key()
    pubkey_str = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    logger.debug('CAhandler.cert_pubkey_get() ended with: {0}'.format(pubkey_str))
    return convert_byte_to_string(pubkey_str)


def cert_san_get(logger, certificate, recode=True):
    """ get subject alternate names from certificate """
    logger.debug('cert_san_get({0})'.format(recode))

    cert = cert_load(logger, certificate, recode=recode)
    sans = []
    try:
        ext = cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
        sans_list = ext.value.get_values_for_type(x509.DNSName)
        for san in sans_list:
            sans.append('DNS:{0}'.format(san))
        sans_list = ext.value.get_values_for_type(x509.IPAddress)
        for san in sans_list:
            sans.append('IP:{0}'.format(san))
    except Exception as err:
        logger.error('cert_san_get(): Error: {0}'.format(err))

    logger.debug('cert_san_get() ended')
    return sans


def cert_extensions_get(logger, certificate, recode=True):
    """ get extenstions from certificate certificate """
    logger.debug('cert_extensions_get()')

    cert = cert_load(logger, certificate, recode=recode)

    extension_list = []
    for extension in cert.extensions:
        extension_list.append(convert_byte_to_string(base64.b64encode(extension.value.public_bytes())))

    logger.debug('cert_extensions_get() ended with: {0}'.format(extension_list))
    return extension_list


def cert_serial_get(logger, certificate, hexformat=False):
    """ get serial number form certificate """
    logger.debug('cert_serial_get()')
    cert = cert_load(logger, certificate, recode=True)
    if hexformat:
        serial_number = '{0:x}'.format(cert.serial_number)
    else:
        serial_number = cert.serial_number
    logger.debug('cert_serial_get() ended with: {0}'.format(serial_number))
    return serial_number


def convert_byte_to_string(value):
    """ convert a variable to string if needed """
    if hasattr(value, 'decode'):
        try:
            return value.decode()
        except Exception:
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


def csr_load(logger, csr):
    """ load certificate object from pem _Format """
    logger.debug('cert_load({0})')
    pem_data = convert_string_to_byte(build_pem_file(logger, None, b64_url_recode(logger, csr), True, True))
    csr_data = x509.load_pem_x509_csr(pem_data)

    return csr_data


def csr_cn_get(logger, csr):
    """ get cn from certificate request """
    logger.debug('CAhandler.csr_cn_get()')
    csr_obj = csr_load(logger, csr)

    subject = csr_obj.subject
    result = None
    for attr in subject:
        if attr.oid == x509.NameOID.COMMON_NAME:
            result = attr.value
            break
    logger.debug('CAhandler.csr_cn_get() ended with: {0}'.format(result))
    return result


def csr_dn_get(logger, csr):
    """ get subject from certificate request in openssl notation """
    logger.debug('CAhandler.csr_dn_get()')

    csr_obj = csr_load(logger, csr)
    subject = csr_obj.subject.rfc4514_string()

    logger.debug('CAhandler.csr_dn_get() ended with: {0}'.format(subject))
    return subject


def csr_pubkey_get(logger, csr):
    """ get public key from certificate request """
    logger.debug('CAhandler.csr_pubkey_get()')
    csr_obj = csr_load(logger, csr)
    public_key = csr_obj.public_key()
    pubkey_str = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    logger.debug('CAhandler.cert_pubkey_get() ended with: {0}'.format(pubkey_str))
    return convert_byte_to_string(pubkey_str)


def csr_san_get(logger, csr):
    """ get subject alternate names from certificate """
    logger.debug('cert_san_get()')
    sans = []
    if csr:

        csr_obj = csr_load(logger, csr)
        sans = []
        try:
            ext = csr_obj.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)

            sans_list = ext.value.get_values_for_type(x509.DNSName)
            for san in sans_list:
                sans.append('DNS:{0}'.format(san))
            sans_list = ext.value.get_values_for_type(x509.IPAddress)
            for san in sans_list:
                sans.append('IP:{0}'.format(san))

        except Exception as err:
            logger.error('csr_san_get(): Error: {0}'.format(err))

    logger.debug('csr_san_get() ended with: {0}'.format(str(sans)))
    return sans


def csr_extensions_get(logger, csr):
    """ get extensions from certificate """
    logger.debug('csr_extensions_get()')

    csr_obj = csr_load(logger, csr)

    extension_list = []
    for extension in csr_obj.extensions:
        extension_list.append(convert_byte_to_string(base64.b64encode(extension.value.public_bytes())))

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
    except Exception as err:
        logger.error('decode_message() err: {0}'.format(err))
        error = str(err)
        protected = {}
        payload = {}
        signature = None

    if payload:
        payload = dkeys_lower(payload)
    return (result, error, protected, payload, signature)


def dkeys_lower(tree):
    """ lower characters in payload string """
    if isinstance(tree, dict):
        result = {k.lower(): dkeys_lower(v) for k, v in tree.items()}
    elif isinstance(tree, list):
        result = [dkeys_lower(ele) for ele in tree]
    else:
        result = tree
    return result


def fqdn_in_san_check(logger, san_list, fqdn):
    """ check if fqdn is in a list of sans """
    logger.debug('fqdn_in_san_check([%s], %s)', san_list, fqdn)

    result = False
    if fqdn and san_list:
        for san in san_list:
            try:
                (_type, value) = san.lower().split(':', 1)
                if fqdn == value:
                    result = True
                    break
            except Exception:
                logger.error('ERROR: fqdn_in_san_check() SAN split failed: {0}'.format(san))

    logger.debug('fqdn_in_san_check() ended with: {}'.format(result))
    return result


def generate_random_string(logger, length):
    """ generate random string to be used as name """
    logger.debug('generate_random_string()')
    char_set = digits + ascii_letters
    return ''.join(random.choice(char_set) for _ in range(length))


def get_url(environ, include_path=False):
    """ get url """
    if 'HTTP_HOST' in environ:
        server_name = html.escape(environ['HTTP_HOST'])
    else:
        server_name = 'localhost'

    if 'SERVER_PORT' in environ:
        port = html.escape(environ['SERVER_PORT'])
    else:
        port = 80

    if 'HTTP_X_FORWARDED_PROTO' in environ:
        proto = html.escape(environ['HTTP_X_FORWARDED_PROTO'])
    elif 'wsgi.url_scheme' in environ:
        proto = html.escape(environ['wsgi.url_scheme'])
    elif int(port) == 443:
        proto = 'https'
    else:
        proto = 'http'

    if include_path and 'PATH_INFO' in environ:
        result = '{0}://{1}{2}'.format(proto, server_name, html.escape(environ['PATH_INFO']))
    else:
        result = '{0}://{1}'.format(proto, server_name)
    return result


def header_info_get(logger, csr, vlist=('id', 'name', 'header_info')):
    """ lookup header information """
    logger.debug('header_info_get()')

    from acme_srv.db_handler import DBstore  # pylint: disable=c0415
    dbstore = DBstore(logger=logger)
    result = dbstore.certificates_search('csr', csr, vlist)

    return result


def load_config(logger=None, mfilter=None, cfg_file=None):
    """ small configparser wrappter to load a config file """
    if not cfg_file:
        if 'ACME_SRV_CONFIGFILE' in os.environ:
            cfg_file = os.environ['ACME_SRV_CONFIGFILE']
        else:
            cfg_file = os.path.dirname(__file__) + '/' + 'acme_srv.cfg'
    if logger:
        logger.debug('load_config({1}:{0})'.format(mfilter, cfg_file))
    config = configparser.ConfigParser(interpolation=None)
    config.optionxform = str
    config.read(cfg_file, encoding='utf8')
    return config


def parse_url(logger, url):
    """ split url into pieces """
    logger.debug('parse_url({0})'.format(url))
    url_dic = {
        'proto': urlparse(url).scheme,
        'host': urlparse(url).netloc,
        'path': urlparse(url).path
    }
    return url_dic


def encode_url(logger, input_string):
    """ urlencoding """
    logger.debug('encode_url({0})'.format(input_string))

    return quote(input_string)


def _logger_nonce_modify(data_dic):
    """ remove nonce from log entry """
    if 'header' in data_dic and 'Replay-Nonce' in data_dic['header']:
        data_dic['header']['Replay-Nonce'] = '- modified -'
    return data_dic


def _logger_certificate_modify(data_dic, locator):
    """ remove cert from log entry """
    if '/acme/cert' in locator:
        data_dic['data'] = ' - certificate - '
    return data_dic


def _logger_token_modify(data_dic):
    """ remove token from challenge """
    if 'token' in data_dic['data']:
        data_dic['data']['token'] = '- modified -'
    return data_dic


def _logger_challenges_modify(data_dic):
    """ remove token from challenge """
    if 'challenges' in data_dic['data']:
        for challenge in data_dic['data']['challenges']:
            if 'token' in challenge:
                challenge.update((k, "- modified - ") for k, v in challenge.items() if k == "token")
    return data_dic


def logger_info(logger, addr, locator, dat_dic):
    """ log responses """
    # create a copy of the dictionary
    data_dic = copy.deepcopy(dat_dic)

    data_dic = _logger_nonce_modify(data_dic)
    if 'data' in data_dic:
        # remove cert from log entry
        data_dic = _logger_certificate_modify(data_dic, locator)

        # remove token
        data_dic = _logger_token_modify(data_dic)

        # remove token from challenge
        data_dic = _logger_challenges_modify(data_dic)

    logger.info('{0} {1} {2}'.format(addr, locator, str(data_dic)))


def logger_setup(debug):
    """ setup logger """
    if debug:
        log_mode = logging.DEBUG
    else:
        log_mode = logging.INFO

    config_dic = load_config()

    # define standard log format
    log_format = '%(message)s'
    if 'Helper' in config_dic and 'log_format' in config_dic['Helper']:
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
        except Exception as err:
            logger.error('jwk_thumbprint_get(): error: {0}'.format(err))
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


def sha256_hash_hex(logger, string):
    """ hash string """
    logger.debug('sha256_hash_hex()')
    result = hashlib.sha256(string.encode('utf-8')).hexdigest()
    logger.debug('sha256_hash_hex() ended with {0}'.format(result))
    return result


def signature_check(logger, message, pub_key, json_=False):
    """ check JWS """
    logger.debug('signature_check({0})'.format(json_))

    result = False
    error = None

    if pub_key:
        # load key
        try:
            if json_:
                jwkey = jwk.JWK.from_json(pub_key)
            else:
                jwkey = jwk.JWK(**pub_key)
        except Exception as err:
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
            except Exception as err:
                logger.error('verify failed {0}'.format(err))
                error = str(err)
    else:
        error = 'No key specified.'

    return (result, error)


def string_sanitize(logger, unsafe_str):
    """ sanitize string """
    logger.debug('string_sanitize()')
    allowed_range = set(range(32, 127))
    safe_str = ''
    for char in unsafe_str:
        cp_ = ord(char)
        if cp_ in allowed_range:
            safe_str += char
        elif cp_ == 9:
            safe_str += ' ' * 4
    return re.sub(r'\s+', ' ', safe_str)


def _fqdn_resolve(req, host):
    """ resolve hostname """
    for rrtype in ['A', 'AAAA']:
        try:
            result = None
            invalid = True
            answers = req.resolve(host, rrtype)
            for rdata in answers:
                result = str(rdata)
                invalid = False
                break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            result = None
            invalid = True
        except Exception:
            result = None
            invalid = False
        if result is not None:
            break

    return (result, invalid)


def fqdn_resolve(host, dnssrv=None):
    """ dns resolver """
    req = dns.resolver.Resolver()

    # hack to cover github workflows
    if '.' in host:
        if dnssrv:
            # add specific dns server
            req.nameservers = dnssrv
        # resolve hostname
        (result, invalid) = _fqdn_resolve(req, host)

    else:
        result = None
        invalid = False

    return (result, invalid)


def dns_server_list_load():
    """ load dns-server from config file """
    config_dic = load_config()

    # define default dns servers
    default_dns_server_list = ['9.9.9.9', '8.8.8.8']

    if 'Challenge' in config_dic:
        if 'dns_server_list' in config_dic['Challenge']:
            try:
                dns_server_list = json.loads(config_dic['Challenge']['dns_server_list'])
            except Exception:
                dns_server_list = default_dns_server_list
        else:
            dns_server_list = default_dns_server_list
    else:
        dns_server_list = default_dns_server_list

    return dns_server_list


def error_dic_get(logger):
    """ load acme error messages """
    logger.debug('error_dict_get()')
    # this is the main dictionary
    error_dic = {
        'badcsr': 'urn:ietf:params:acme:error:badCSR',
        'malformed': 'urn:ietf:params:acme:error:malformed',
        'invalidcontact': 'urn:ietf:params:acme:error:invalidContact',
        'accountdoesnotexist': 'urn:ietf:params:acme:error:accountDoesNotExist',
        'unauthorized': 'urn:ietf:params:acme:error:unauthorized',
        'externalaccountrequired': 'urn:ietf:params:acme:error:externalAccountRequired',
        'badpubkey': 'urn:ietf:params:acme:error:badPublicKey',
        'useractionrequired': 'urn:ietf:params:acme:error:userActionRequired',
        'alreadyrevoked': 'urn:ietf:params:acme:error:alreadyRevoked',
        'serverinternal': 'urn:ietf:params:acme:error:serverInternal',
        'unsupportedidentifier': 'urn:ietf:params:acme:error:unsupportedIdentifier',
        'ordernotready': 'urn:ietf:params:acme:error:orderNotReady',
        'ratelimited': 'urn:ietf:params:acme:error:rateLimited',
        'badrevocationreason': 'urn:ietf:params:acme:error:badRevocationReason'}

    return error_dic


def patched_create_connection(address, *args, **kwargs):  # pragma: no cover
    """ Wrap urllib3's create_connection to resolve the name elsewhere"""
    # load dns-servers from config file
    dns_server_list = dns_server_list_load()
    # resolve hostname to an ip address; use your own resolver
    host, port = address
    (hostname, _invalid) = fqdn_resolve(host, dns_server_list)
    # pylint: disable=W0212
    return connection._orig_create_connection((hostname, port), *args, **kwargs)


def proxy_check(logger, fqdn, proxy_server_list):
    """ check proxy server """
    logger.debug('proxy_check({0})'.format(fqdn))

    # remove leading *.
    proxy_server_list_new = {k.replace('*.', ''): v for k, v in proxy_server_list.items()}

    proxy = None
    for regex in sorted(proxy_server_list_new.keys(), reverse=True):
        if regex != '*':
            regex_compiled = re.compile(regex)
            if bool(regex_compiled.search(fqdn)):
                # parameter is in - set flag accordingly and stop loop
                proxy = proxy_server_list_new[regex]
                logger.debug('proxy_check() match found: fqdn: {0}, regex: {1}'.format(fqdn, regex))
                break

    if '*' in proxy_server_list_new.keys() and not proxy:
        logger.debug('proxy_check() wildcard match found: fqdn: {0}'.format(fqdn))
        proxy = proxy_server_list_new['*']

    logger.debug('proxy_check() ended with {0}'.format(proxy))
    return proxy


def url_get_with_own_dns(logger, url, verify=True):
    """ request by using an own dns resolver """
    logger.debug('url_get_with_own_dns({0})'.format(url))
    # patch an own connection handler into URL lib
    # pylint: disable=W0212
    connection._orig_create_connection = connection.create_connection
    connection.create_connection = patched_create_connection
    try:
        req = requests.get(url, verify=verify, headers={'Connection': 'close', 'Accept-Encoding': 'gzip', 'User-Agent': USER_AGENT}, timeout=20)
        result = req.text
    except Exception as err_:
        result = None
        logger.error('url_get_with_own_dns error: {0}'.format(err_))
    # cleanup
    connection.create_connection = connection._orig_create_connection
    return result


def allowed_gai_family():
    """ set family """
    family = socket.AF_INET    # force IPv4
    return family


def url_get_with_default_dns(logger, url, proxy_list, verify, timeout):
    """ http get with default dns server """
    logger.debug('url_get_with_default_dns({0}) vrf={1}, timout:{2}'.format(url, verify, timeout))

    # we need to tweak headers and url for ipv6 addresse
    (headers, url) = v6_adjust(logger, url)

    try:
        req = requests.get(url, verify=verify, timeout=timeout, headers=headers, proxies=proxy_list)
        result = req.text
    except Exception as err_:
        logger.debug('url_get({0}): error'.format(err_))
        # force fallback to ipv4
        logger.debug('url_get({0}): fallback to v4'.format(url))
        old_gai_family = urllib3_cn.allowed_gai_family
        try:
            urllib3_cn.allowed_gai_family = allowed_gai_family
            req = requests.get(url, verify=verify, timeout=timeout, headers={'Connection': 'close', 'Accept-Encoding': 'gzip', 'User-Agent': USER_AGENT}, proxies=proxy_list)
            result = req.text
        except Exception as err:
            result = None
            logger.error('url_get error: {0}'.format(err))
        urllib3_cn.allowed_gai_family = old_gai_family

    return result


def url_get(logger, url, dns_server_list=None, proxy_server=None, verify=True, timeout=20):
    """ http get """
    logger.debug('url_get({0}) vrf={1}, timout:{2}'.format(url, verify, timeout))
    # pylint: disable=w0621
    # configure proxy servers if specified
    if proxy_server:
        proxy_list = {'http': proxy_server, 'https': proxy_server}
    else:
        proxy_list = {}
    if dns_server_list and not proxy_server:
        result = url_get_with_own_dns(logger, url, verify)
    else:
        result = url_get_with_default_dns(logger, url, proxy_list, verify, timeout)

    logger.debug('url_get() ended with: {0}'.format(result))
    return result


def txt_get(logger, fqdn, dns_srv=None):
    """ dns query to get the TXt record """
    logger.debug('txt_get({0}: {1})'.format(fqdn, dns_srv))

    # rewrite dns resolver if configured
    if dns_srv:
        dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
        dns.resolver.default_resolver.nameservers = dns_srv
    txt_record_list = []
    try:
        response = dns.resolver.resolve(fqdn, 'TXT')
        for rrecord in response:
            txt_record_list.append(rrecord.strings[0])
    except Exception as err_:
        logger.error('txt_get() error: {0}'.format(err_))
    logger.debug('txt_get() ended with: {0}'.format(txt_record_list))
    return txt_record_list


def uts_now():
    """ unixtimestamp in utc """
    return calendar.timegm(datetime.utcnow().utctimetuple())


def uts_to_date_utc(uts, tformat='%Y-%m-%dT%H:%M:%SZ'):
    """ convert unix timestamp to date format """
    return datetime.fromtimestamp(int(uts), tz=pytz.utc).strftime(tformat)


def date_to_uts_utc(date_human, _tformat='%Y-%m-%dT%H:%M:%S'):
    """ convert date to unix timestamp """
    if isinstance(date_human, datetime):
        # we already got an datetime object as input
        result = calendar.timegm(date_human.timetuple())
    else:
        result = int(calendar.timegm(parse(date_human).timetuple()))
    return result


def date_to_datestr(date, tformat='%Y-%m-%dT%H:%M:%SZ'):
    """ convert dateobj to datestring """
    try:
        result = date.strftime(tformat)
    except Exception:
        result = None
    return result


def datestr_to_date(datestr, tformat='%Y-%m-%dT%H:%M:%S'):
    """ convert datestr to dateobj """
    try:
        result = datetime.strptime(datestr, tformat)
    except Exception:
        result = None
    return result


def proxystring_convert(logger, proxy_server):
    """ convert proxy string """
    logger.debug('proxystring_convert({0})'.format(proxy_server))
    proxy_proto_dic = {'http': socks.PROXY_TYPE_HTTP, 'socks4': socks.PROXY_TYPE_SOCKS4, 'socks5': socks.PROXY_TYPE_SOCKS5}
    try:
        (proxy_proto, proxy) = proxy_server.split('://')
    except Exception:
        logger.error('proxystring_convert(): error splitting proxy_server string: {0}'.format(proxy_server))
        proxy = None
        proxy_proto = None

    if proxy:
        try:
            (proxy_addr, proxy_port) = proxy.split(':')
        except Exception:
            logger.error('proxystring_convert(): error splitting proxy into host/port: {0}'.format(proxy))
            proxy_addr = None
            proxy_port = None
    else:
        proxy_addr = None
        proxy_port = None

    if proxy_proto and proxy_addr and proxy_port:
        try:
            proto_string = proxy_proto_dic[proxy_proto]
        except Exception:
            logger.error('proxystring_convert(): unknown proxy protocol: {0}'.format(proxy_proto))
            proto_string = None
    else:
        logger.error('proxystring_convert(): proxy_proto ({0}), proxy_addr ({1}) or proxy_port ({2}) missing'.format(proxy_proto, proxy_addr, proxy_port))
        proto_string = None

    try:
        proxy_port = int(proxy_port)
    except Exception:
        logger.error('proxystring_convert(): unknown proxy port: {0}'.format(proxy_port))
        proxy_port = None

    logger.debug('proxystring_convert() ended with {0}, {1}, {2}'.format(proto_string, proxy_addr, proxy_port))
    return (proto_string, proxy_addr, proxy_port)


def servercert_get(logger, hostname, port=443, proxy_server=None, sni=None):
    """ get server certificate from an ssl connection """
    logger.debug('servercert_get({0}:{1})'.format(hostname, port))

    pem_cert = None

    if ipv6_chk(logger, hostname):
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    else:
        sock = socks.socksocket()

    # backup - set sni to hostname
    if not sni:
        sni = hostname

    context = ssl.create_default_context()  # NOSONAR
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # NOSONAR
    context.options |= ssl.PROTOCOL_TLS_CLIENT
    context.set_alpn_protocols(["acme-tls/1"])
    # reject insecure ssl version
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_SSLv3
    context.options |= ssl.OP_NO_TLSv1
    context.options |= ssl.OP_NO_TLSv1_1

    if proxy_server:
        (proxy_proto, proxy_addr, proxy_port) = proxystring_convert(logger, proxy_server)
        if proxy_proto and proxy_addr and proxy_port:
            logger.debug('servercert_get() configure proxy')
            sock.setproxy(proxy_proto, proxy_addr, port=proxy_port)
    try:
        sock.connect((hostname, port))
        with context.wrap_socket(sock, server_hostname=sni) as sslsock:
            logger.debug('servercert_get(): {0}:{1}:{2} version: {3}'.format(hostname, sni, port, sslsock.version()))
            der_cert = sslsock.getpeercert(True)
            # from binary DER format to PEM
            if der_cert:
                pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
    except Exception as err_:
        logger.error('servercert_get() failed with: {0}'.format(err_))
        pem_cert = None

    if pem_cert:
        logger.debug('servercert_get() ended with: {0}'.format(b64_encode(logger, convert_string_to_byte(pem_cert))))
    else:
        logger.debug('servercert_get() ended with: None')
    return pem_cert


def validate_csr(logger, order_dic, _csr):
    """ validate certificate signing request against order"""
    logger.debug('validate_csr({0})'.format(order_dic))
    return True


def validate_email(logger, contact_list):
    """ validate contact against RFC608"""
    logger.debug('validate_email()')
    result = True
    pattern = r"^[A-Za-z0-9\.\+_-]+@[A-Za-z]+[A-Za-z0-9\._-]+[A-Za-z0-9]+\.[a-zA-Z\.]+[a-zA-Z]+$"
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


def handle_exception(exc_type, exc_value, exc_traceback):  # pragma: no cover
    """ exception handler """
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    # logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))
    logging.error("Uncaught exception")


def pembundle_to_list(logger, pem_bundle):
    """ split pem bundle into a list of certificates """
    logger.debug('pembundle_to_list()')
    cert_list = []
    pem_data = ""
    if '-----BEGIN CERTIFICATE-----' in pem_bundle:
        for line in pem_bundle.splitlines():
            line = line.strip()
            if line.startswith("-----BEGIN CERTIFICATE-----") and pem_data:
                cert_list.append(pem_data)
                pem_data = ""
            pem_data += line + "\n"
        if pem_data:
            cert_list.append(pem_data)
    logger.debug('pembundle_to_list() returned {0} certificates'.format(len(cert_list)))
    return cert_list


def certid_asn1_get(logger, cert_pem, issuer_pem):
    """ get renewal information from certificate """
    logger.debug('certid_asn1_get()')

    cert = load_pem_x509_certificate(convert_string_to_byte(cert_pem))
    issuer = load_pem_x509_certificate(convert_string_to_byte(issuer_pem))

    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer, hashes.SHA256())
    ocsprequest = builder.build()
    ocsprequest_hex = ocsprequest.public_bytes(serialization.Encoding.DER).hex()

    # this is ugly but i did not find a better way to do this
    _header, certid_hex = ocsprequest_hex.split('0420', 1)

    return certid_hex


def certid_hex_get(logger, renewal_info):
    """ get certid in hex from renewal_info field """
    logger.debug('certid_hex_get()')

    renewal_info_b64 = b64_url_recode(logger, renewal_info)
    renewal_info_hex = b64_decode(logger, renewal_info_b64).hex()

    # this is ugly but i did not find a better way to do this
    mda, certid_renewal = renewal_info_hex.split('0420', 1)
    mda = mda[4:]

    logger.debug('certid_hex_get() endet with {0}'.format(certid_renewal))
    return mda, certid_renewal


def certid_check(logger, renewal_info, certid_database):
    """ compare certid with renewal info """
    logger.debug('certid_check()')

    renewal_info_b64 = b64_url_recode(logger, renewal_info)
    renewal_info_hex = b64_decode(logger, renewal_info_b64).hex()

    # this is ugly but i did not find a better way to do this
    _header, certid_renewal = renewal_info_hex.split('0420', 1)
    result = certid_renewal == certid_database

    logger.debug('certid_check() ended with: {0}'.format(result))
    return result


def ip_validate(logger, ip_addr):
    """  validate ip address """
    logger.debug('ip_validate({0})'.format(ip_addr))

    try:
        reverse_pointer = ipaddress.ip_address(ip_addr).reverse_pointer
        invalid = False
    except ValueError:
        reverse_pointer = None
        invalid = True
    logger.debug('ip_validate() ended with: {0}:{1}'.format(reverse_pointer, invalid))
    return (reverse_pointer, invalid)


def v6_adjust(logger, url):
    """ corner case for v6 addresses """
    logger.debug('v6_adjust({0})'.format(url))

    headers = {'Connection': 'close', 'Accept-Encoding': 'gzip', 'User-Agent': USER_AGENT}

    url_dic = parse_url(logger, url)

    # adjust headers and url in case we have an ipv6address
    if ipv6_chk(logger, url_dic['host']):
        headers['Host'] = url_dic['host']
        url = '{0}://[{1}]/{2}'.format(url_dic['proto'], url_dic['host'], url_dic['path'])

    logger.debug('v6_adjust() ended')
    return (headers, url)


def ipv6_chk(logger, address):
    """ check if an address is ipv6 """
    logger.debug('ipv6_chk({0})'.format(address))

    try:
        # we need to set a host header and braces for ipv6 headers and
        if isinstance(ipaddress.ip_address(address), ipaddress.IPv6Address):
            logger.debug('v6_adjust(}): ipv6 address detected')
            result = True
        else:
            result = False
    except Exception:
        result = False

    logger.debug('ipv6_chk() ended with {0}'.format(result))
    return result
