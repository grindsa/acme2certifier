#!/usr/bin/python
# -*- coding: utf-8 -*-
""" helper functions for acme2certifier """
from __future__ import print_function
import re
import base64
import json
import random
import calendar
import time
from datetime import datetime
from string import digits, ascii_letters
import pytz
from jwcrypto import jwk, jws

def get_url(environ):
    """ get url """
    server_name = environ['HTTP_HOST']
    port = environ['SERVER_PORT']
    if port == 443:
        proto = 'https'
    else:
        proto = 'http'
    return '{0}://{1}'.format(proto, server_name)

def b64decode_pad(debug, string):
    """ b64 decoding and padding of missing "=" """
    print_debug(debug, 'b64decode_pad()')
    string += '=' * (-len(string) % 4)  # restore stripped '='s
    try:
        b64dec = base64.b64decode(string)
    except TypeError:
        b64dec = 'ERR: b64 decoding error'
    return b64dec

def decode_deserialize(debug, string):
    """ decode and deserialize string """
    print_debug(debug, 'decode_deserialize()')
    # b64 decode
    string_decode = b64decode_pad(debug, string)
    # deserialize if b64 decoding was successful
    if string_decode and string_decode != 'ERR: b64 decoding error':
        try:
            string_decode = json.loads(string_decode)
        except ValueError:
            string_decode = 'ERR: Json decoding error'

    return string_decode

def decode_message(debug, message):
    """ decode jwstoken and return header, payload and signature """
    print_debug(debug, 'decode_message()')
    jwstoken = jws.JWS()

    result = False
    error = None
    try:
        jwstoken.deserialize(message)
        protected = json.loads(jwstoken.objects['protected'])
        payload = json.loads(jwstoken.objects['payload'])
        signature = jwstoken.objects['signature']
        result = True
    except BaseException as err:
        error = str(err)
        protected = None
        payload = None
        signature = None
    return(result, error, protected, payload, signature)

def generate_random_string(debug, length):
    """ generate random string to be used as name """
    print_debug(debug, 'generate_random_string()')
    char_set = digits + ascii_letters
    return ''.join(random.choice(char_set) for _ in range(length))

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

def signature_check(debug, message, pub_key):
    """ check JWS """
    print_debug(debug, 'signature_check()')

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

def validate_email(debug, contact_list):
    """ validate contact against RFC608"""
    print_debug(debug, 'validate_email()')
    result = True
    pattern = r"\"?([-a-zA-Z0-9.`?{}]+@\w+\.\w+)\"?"
    # check if we got a list or single address
    if isinstance(contact_list, list):
        for contact in contact_list:
            contact = contact.replace('mailto:', '')
            contact = contact.lstrip()
            tmp_result = bool(re.search(pattern, contact))
            print_debug(debug, '# validate: {0} result: {1}'.format(contact, tmp_result))
            if not tmp_result:
                result = tmp_result
    else:
        contact_list = contact_list.replace('mailto:', '')
        contact_list = contact_list.lstrip()
        result = bool(re.search(pattern, contact_list))
        print_debug(debug, '# validate: {0} result: {1}'.format(contact_list, result))

    return result

def uts_now():
    """ return unixtimestamp in utc """
    return calendar.timegm(datetime.utcnow().utctimetuple())

def uts_to_date_utc(uts, tformat='%Y-%m-%dT%H:%M:%S'):
    """ convert unix timestamp to date format """
    return datetime.fromtimestamp(int(uts), tz=pytz.utc).strftime(tformat)

def date_to_uts_utc(date_human, tformat='%Y-%m-%dT%H:%M:%S'):
    """ convert date to unix timestamp """
    return int(calendar.timegm(time.strptime(date_human, tformat)))
