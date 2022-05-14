#!/usr/bin/python3
# -*- coding: utf-8 -*-
# pylint: disable=c0209, e5110,
""" acme2certifier cli client """
import logging
import datetime
import re
import os.path
import time
import random
from string import digits, ascii_letters
from jwcrypto import jwk, jws
from jwcrypto.common import json_encode


VERSION = "0.0.1"

CLI_INTRO = """acme2certifier command-line interfac

Copyright (c) 2022 GrindSa

This software is provided free of charge. Copying and redistribution is
encouraged.

If you appreciate this software and you would like to support future
development please consider donating to me.

Type /help for available commands
"""

def generate_random_string(logger, length):
    """ generate random string to be used as name """
    logger.debug('generate_random_string()')
    char_set = digits + ascii_letters
    return ''.join(random.choice(char_set) for _ in range(length))

def file_dump(logger, filename, data_):
    """ dump content json file """
    logger.debug('file_dump({0})'.format(filename))
    with open(filename, 'w', encoding='utf8') as file_:
        file_.write(data_)  # lgtm [py/clear-text-storage-sensitive-data]


def file_load(logger, filename):
    """ load file at once """
    logger.debug('file_open({0})'.format(filename))
    with open(filename, encoding='utf8') as _file:
        lines = _file.read()
    return lines


def is_url(string):
    """ check if sting is a valid url """
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    return re.match(regex, string)


def logger_setup(debug):
    """ setup logger """
    if debug:
        log_mode = logging.DEBUG
    else:
        log_mode = logging.INFO

    # config_dic = load_config()

    # define standard log format
    # log_format = '%(message)s'
    log_format = '%(asctime)s - a2c_cli - %(levelname)s - %(message)s'
    # if 'Helper' in config_dic:
    #    if 'log_format' in config_dic['Helper']:
    #        log_format = config_dic['Helper']['log_format']

    logging.basicConfig(
        format=log_format,
        datefmt="%Y-%m-%d %H:%M:%S",
        level=log_mode)
    logger = logging.getLogger('a2c_cli')
    return logger


class KeyOperations(object):
    """ key operations class """
    def __init__(self, logger=None, printcommand=None):
        # CLIParser(self)
        self.logger = logger
        self.print = printcommand

    def generate(self, filename):
        """ generate and store key """
        self.logger.debug('KeyOperations.generate({0})'.format(filename))
        key = jwk.JWK.generate(kty='RSA', size=2048, alg='RSA-OAEP-256', use='sig', kid=generate_random_string(self.logger, 12))
        public_key = key.export_public()
        private_key = key.export_private()
        self.print('generating keys...', printreturn=False)
        try:
            file_dump(self.logger, '{0}.pub'.format(filename), public_key)
            file_dump(self.logger, '{0}.private'.format(filename), private_key)
            self.print('done...', printreturn=False)
            self.print('Keep the private key {0}.pub for yourself'.format(filename), printreturn=False)
            self.print('Give the public key {0}.pub to your acme2certifier administrator'.format(filename))
        except Exception as err_:
            self.logger.error('KeyOperations.generate() failed with err: {0}'.format(err_))
            self.print('Key generation failed with error: {0}'.format(err_))
        return key

    def load(self, filename):
        """ load existing key """
        self.logger.debug('KeyOperations.load({0})'.format(filename))
        if os.path.exists(filename):
            self.print('loading {0}'.format(filename), printreturn=False)
            content = file_load(self.logger, filename)
            key = jwk.JWK.from_json(content)
            self.print('done...', printreturn=False)
        else:
            self.print('Could not find {0}'.format(filename))
            key = None
        return key


class MessageOperations(object):
    """ message operations class """
    def __init__(self, logger=None, printcommand=None):
        # CLIParser(self)
        self.logger = logger
        self.print = printcommand

    def sign(self, key, message):
        """ sign message """
        self.logger.debug('MessageOperations.sign()')
        protected = {"typ": "JOSE+JSON",
                     "kid": key['kid'],
                     "alg": "RS256"}
        plaintext = {"sub": message,
                     "exp": int(time.time()) + (5 * 60)}
        mjws = jws.JWS(payload=json_encode(plaintext))
        mjws.add_signature(key, None, json_encode(protected))
        return mjws.serialize()

    def send(self, message):
        """ send message """
        self.logger.debug('MessageOperations.send()')
        self.print(message)

class CommandLineInterface(object):
    """ cli class """
    def __init__(self, logger=None):
        # CLIParser(self)
        self.logger = logger
        self.status = 'server missing'
        self.server = None
        self.key = None

    def _cli_print(self, text, date_print=True, printreturn=True):
        """ print text """
        self.logger.debug('CommandLineInterface._cli_print()')
        if text:
            if date_print:
                now = datetime.datetime.now().strftime('%H:%M:%S')
                if printreturn:
                    print('{0} {1}\n'.format(now, text))
                else:
                    print('{0} {1}'.format(now, text))
            else:
                print(text)

    def _command_check(self, command):
        """ check command """
        self.logger.debug('CommandLineInterface._commend_check(): {0}'.format(command))
        if command in ('help', 'H'):
            self.help_print()
        elif command.startswith('server'):
            self._server_set(command)
        elif command.startswith('key'):
            self._key_operations(command)

        elif self.status == 'configured':
            if command.startswith('message'):
                self._message_operations(command)
            elif command.startswith('certificate search'):
                self._cli_print('jupp, jupp')
            else:
                if command:
                    self._cli_print('unknown command: "/{0}"'.format(command))
                    self.help_print()
        else:
            self._cli_print('Please set a2c server first')

    def _exec_cmd(self, cmdinput):
        """ execute command """
        self.logger.debug('CommandLineInterface._exec_cmd(): {0}'.format(cmdinput))
        cmdinput = cmdinput.rstrip()

        # skip empty commands
        if not len(cmdinput) > 1:
            return

        if cmdinput.startswith("/"):
            cmdinput = cmdinput[1:]
        else:
            self._cli_print('Please enter a valid command!')
            self.help_print()
            return

        self._command_check(cmdinput)

    def _intro_print(self):
        """ print cli intro """
        self.logger.debug('CommandLineInterface._intro_print()')
        self._cli_print(CLI_INTRO.format(cliversion=VERSION))

    def _key_operations(self, command):
        """ key operations """
        self.logger.debug('CommandLineInterface._key_operations({0})'.format(command))

        try:
            (_key, command, argument) = command.split(' ', 2)
        except Exception:
            self._cli_print('incomplete command: "{0}"'.format(command))
            _key = None
            command = None
            argument = None

        if command and argument:
            key = KeyOperations(self.logger, self._cli_print)
            if command == 'generate':
                self.key = key.generate(argument)
            elif command == 'load':
                self.key = key.load(argument)
            else:
                self._cli_print('unknown key command: "{0}"'.format(command))

            if self.server:
                self.status = 'Configured'

    def _message_operations(self, command):
        """ message operations"""

        try:
            (_key, command, argument) = command.split(' ', 2)
        except Exception:
            self._cli_print('incomplete command: "{0}"'.format(command))
            _key = None
            command = None
            argument = None

        if command and argument:
            message = MessageOperations(self.logger, self._cli_print)

        if command == 'sign':
            signed_message = message.sign(key=self.key, message=argument)
            print(signed_message)

    def _prompt_get(self):
        """ get prompt """
        self.logger.debug('CommandLineInterface._prompt_get()')
        return '[{0}]:'.format(self.status)

    def _server_set(self, server):
        """ print text """
        self.logger.debug('CommandLineInterface._server_set({0})'.format(server))

        (_command, url) = server.split(' ')
        if is_url(url):
            self.server = url
            if self.key:
                self.status = 'configured'
            else:
                self.status = 'key missing'
        else:
            self._cli_print('{0} is not a valid url'.format(url))

    def help_print(self):
        """ print help """
        self.logger.debug('CommandLineInterface.help_print()')
        helper = """-------------------------------------------------------------------------------
/connect   /L       - connect to acme2certifier
/certificate search <parameter> <string> - search certificate for a certain parameter
/certificate revoke <identifier>- revoce certificate on given uuid
/key generate
/key load
"""
        self._cli_print(helper, date_print=False)

    def start(self):
        """ start """
        self.logger.debug('CommandLineInterface.start()')
        self._intro_print()

        while True:
            cmd = input(self._prompt_get()).strip()
            self._exec_cmd(cmd)


if __name__ == "__main__":

    DEBUG = True

    LOGGER = logger_setup(DEBUG)

    CLI = CommandLineInterface(logger=LOGGER)
    CLI.start()
