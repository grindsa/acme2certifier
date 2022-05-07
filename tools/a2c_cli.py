#!/usr/bin/python3
# -*- coding: utf-8 -*-
# pylint: disable=c0209, e5110,
""" acme2certifier cli client """
import logging
import datetime

VERSION = "0.0.1"

CLI_INTRO = """acme2certifier command-line interfac

Copyright (c) 2022 Grindelsack

This software is provided free of charge. Copying and redistribution is
encouraged.

If you appreciate this software and you would like to support future
development please consider donating to me.

Type /help for available commands
"""


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


class CommandLineInterface(object):
    """ cli class """
    def __init__(self, logger=None):
        # CLIParser(self)
        self.logger = logger
        self.status = 'offline'

    def _command_check(self, command):
        """ check command """
        self.logger.debug('CommandLineInterface._commend_check(): {0}'.format(command))
        if command in ('help', 'H'):
            self.help_print()
        # elif(command == 'connect' or command == 'L'):
        #    self.connect_server()
        # elif(command == 'disconnect'):
        #    self.disconnect_server()

        elif command.startswith('server'):
            self.logger('server command')
        elif self.status == 'online':
            if command.startswith('certificates search'):
                self._conten_print('jupp, jupp')

            else:
                if command:
                    self.logger('unknown command: "/{0}"'.format(command))
                    self.help_print()
        else:
            self._cli_print('No active connection. Please connect first!')

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

    def help_print(self):
        """ print help """
        self.logger.debug('CommandLineInterface.help_print()')
        helper = """-------------------------------------------------------------------------------
/connect   /L       - connect to acme2certifier
/certificate search <parameter> <string> - search certificate for a certain parameter
/certificate revoke <identifier>- revoce certificate on given uuid
"""
        self._cli_print(helper)

    def _prompt_get(self):
        """ get prompt """
        self.logger.debug('CommandLineInterface._prompt_get()')
        return '[{0}]:'.format(self.status)

    def _intro_print(self):
        """ print cli intro """
        self.logger.debug('CommandLineInterface._intro_print()')
        print(CLI_INTRO.format(cliversion=VERSION))

    def _cli_print(self, text):
        """ print text """
        self.logger.debug('CommandLineInterface._cli_print()')
        if text:
            now = datetime.datetime.now().strftime('%H:%M:%S')
            print('{0} {1}\n'.format(now, text))

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
