#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for account.py """
# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212
import unittest
import importlib
import configparser
import sys
import datetime
from unittest.mock import patch, Mock, mock_open

sys.path.insert(0, '.')
sys.path.insert(1, '..')

class FakeDBStore(object):
    """ face DBStore class needed for mocking """
    # pylint: disable=W0107, R0903
    pass

class TestACMEHandler(unittest.TestCase):
    """ test class for ACMEHandler """
    acme = None

    @patch('tools.a2c_cli.CommandLineInterface._load_cfg')
    @patch('argparse.ArgumentParser')
    def setUp(self, mock_arg, mock_lcfg):
        """ setup unittest """
        import logging
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')
        from tools.a2c_cli import CommandLineInterface, KeyOperations, MessageOperations, is_url, csv_dump, generate_random_string, file_dump, file_load
        self.a2ccli = CommandLineInterface()
        self.keyops = KeyOperations(logger=self.logger)
        self.msgops = MessageOperations(logger=self.logger)
        self.is_url = is_url
        self.csv_dump = csv_dump
        self.file_dump = file_dump
        self.generate_random_string = generate_random_string
        self.file_load = file_load

    def test_001_always_pass(self):
        """ test successful tos check """
        self.assertTrue('foo')

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    def test_002_help_print(self, mock_cliprint):
        """ test print help """
        self.a2ccli.help_print()
        self.assertTrue(mock_cliprint.called)

    def test_003_prompt_get(self):
        """ test _prompt_get default status """
        self.assertEqual('[server missing]:', self.a2ccli._prompt_get())

    def test_004_prompt_get(self):
        """ test _prompt_get changed status  """
        self.a2ccli.status = 'status'
        self.assertEqual('[status]:', self.a2ccli._prompt_get())

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    def test_005_intro_print(self, mock_cliprint):
        """ test print help """
        self.a2ccli._intro_print()
        self.assertTrue(mock_cliprint.called)

    @patch('tools.a2c_cli.CommandLineInterface._command_check')
    @patch('tools.a2c_cli.CommandLineInterface.help_print')
    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    def test_006_exec_cmd(self, mock_cliprint, mock_help_print, mock_cmdchk):
        """ test exec_cmd correct command """
        cmdinput = '/foo'
        self.a2ccli._exec_cmd(cmdinput)
        self.assertFalse(mock_cliprint.called)
        self.assertFalse(mock_help_print.called)
        self.assertTrue(mock_cmdchk.called)

    @patch('tools.a2c_cli.CommandLineInterface._command_check')
    @patch('tools.a2c_cli.CommandLineInterface.help_print')
    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    def test_007_exec_cmd(self, mock_cliprint, mock_help_print, mock_cmdchk):
        """ test exec_cmd command without leading slash """
        cmdinput = 'foo'
        self.a2ccli._exec_cmd(cmdinput)
        self.assertTrue(mock_cliprint.called)
        self.assertTrue(mock_help_print.called)
        self.assertFalse(mock_cmdchk.called)

    @patch('tools.a2c_cli.CommandLineInterface._command_check')
    @patch('tools.a2c_cli.CommandLineInterface.help_print')
    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    def test_008_exec_cmd(self, mock_cliprint, mock_help_print, mock_cmdchk):
        """ test exec_cmd command only one char """
        cmdinput = '1'
        self.a2ccli._exec_cmd(cmdinput)
        self.assertFalse(mock_cliprint.called)
        self.assertFalse(mock_help_print.called)
        self.assertFalse(mock_cmdchk.called)

    @patch('builtins.print')
    @patch('tools.a2c_cli.datetime')
    def test_009_cli_print(self, mock_datetime, mock_print):
        """ test _cli_print """
        mock_datetime.datetime.now.return_value.strftime.return_value = 'datetime'
        self.a2ccli._cli_print('foo')
        self.assertTrue(mock_print.called)

    @patch('builtins.print')
    @patch('tools.a2c_cli.datetime.datetime')
    def test_010_cli_print(self, mock_datetime, mock_print):
        """ test _cli_print without text """
        mock_datetime.datetime.now.return_value.strftime.return_value = 'datetime'
        self.a2ccli._cli_print(None)
        self.assertFalse(mock_print.called)
        # self.assertTrue(mock_datetime.called)

    @patch('builtins.print')
    @patch('tools.a2c_cli.datetime')
    def test_011_cli_print(self, mock_datetime, mock_print):
        """ test _cli_print """
        mock_datetime.datetime.now.return_value.strftime.return_value = 'datetime'
        self.a2ccli._cli_print('foo', date_print=False)
        self.assertTrue(mock_print.called)
        mock_print.assert_called_with('foo')
        self.assertFalse(mock_datetime.called)


    @patch('builtins.print')
    @patch('tools.a2c_cli.datetime')
    def test_012_cli_print(self, mock_datetime, mock_print):
        """ test _cli_print """
        mock_datetime.datetime.now.return_value.strftime.return_value = 'datetime'
        self.a2ccli._cli_print('foo', date_print=True)
        self.assertTrue(mock_print.called)
        mock_print.assert_called_with('datetime foo\n')
        self.assertFalse(mock_datetime.called)

    @patch('builtins.print')
    @patch('tools.a2c_cli.datetime')
    def test_013_cli_print(self, mock_datetime, mock_print):
        """ test _cli_print """
        mock_datetime.datetime.now.return_value.strftime.return_value = 'datetime'
        self.a2ccli._cli_print('foo')
        self.assertTrue(mock_print.called)
        mock_print.assert_called_with('datetime foo\n')
        self.assertFalse(mock_datetime.called)

    @patch('builtins.print')
    @patch('tools.a2c_cli.datetime')
    def test_014_cli_print(self, mock_datetime, mock_print):
        """ test _cli_print """
        mock_datetime.datetime.now.return_value.strftime.return_value = 'datetime'
        self.a2ccli._cli_print('foo', printreturn=True)
        self.assertTrue(mock_print.called)
        mock_print.assert_called_with('datetime foo\n')
        self.assertFalse(mock_datetime.called)

    @patch('builtins.print')
    @patch('tools.a2c_cli.datetime')
    def test_015_cli_print(self, mock_datetime, mock_print):
        """ test _cli_print """
        mock_datetime.datetime.now.return_value.strftime.return_value = 'datetime'
        self.a2ccli._cli_print('foo', printreturn=False)
        self.assertTrue(mock_print.called)
        mock_print.assert_called_with('datetime foo')
        self.assertFalse(mock_datetime.called)

    @patch('tools.a2c_cli.CommandLineInterface.help_print')
    def test_016_command_check(self, mock_help_print):
        """ test _command check with help paramter """
        command = 'help'
        self.a2ccli._command_check(command)
        self.assertTrue(mock_help_print.called)

    @patch('tools.a2c_cli.CommandLineInterface.help_print')
    def test_017_command_check(self, mock_help_print):
        """ test _command check with help paramter """
        command = 'H'
        self.a2ccli._command_check(command)
        self.assertTrue(mock_help_print.called)

    @patch('tools.a2c_cli.CommandLineInterface._server_set')
    def test_018_command_check(self, mock_server_set):
        """ test __servr_set() """
        command = 'server foo'
        self.a2ccli._command_check(command)
        self.assertTrue(mock_server_set.called)

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    @patch('tools.a2c_cli.CommandLineInterface.help_print')
    def test_019_command_check(self, mock_help_print, mock_cli_print):
        """ test _command check with unconfigured environement """
        command = '/foo'
        self.a2ccli._command_check(command)
        self.assertTrue(mock_cli_print.called)
        self.assertTrue(mock_help_print.called)

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    @patch('tools.a2c_cli.CommandLineInterface.help_print')
    def test_020_command_check(self, mock_help_print, mock_cli_print):
        """ test _command check with unknown command """
        self.a2ccli.status = 'Configured'
        command = '/foo'
        self.a2ccli._command_check(command)
        self.assertTrue(mock_cli_print.called)
        self.assertTrue(mock_help_print.called)

    @patch('tools.a2c_cli.CommandLineInterface._key_operations')
    def test_021_command_check(self, mock_keyops):
        """ test _command check with key generator """
        command = 'key foo'
        self.a2ccli._command_check(command)
        self.assertTrue(mock_keyops.called)

    @patch('tools.a2c_cli.CommandLineInterface._quit')
    def test_022_command_check(self, mock_quit):
        """ test _command check with quit """
        command = 'quit'
        self.a2ccli._command_check(command)
        self.assertTrue(mock_quit.called)

    @patch('tools.a2c_cli.CommandLineInterface._quit')
    def test_023_command_check(self, mock_quit):
        """ test _command check with key quit """
        command = 'Q'
        self.a2ccli._command_check(command)
        self.assertTrue(mock_quit.called)

    @patch('tools.a2c_cli.CommandLineInterface._config_operations')
    def test_024_command_check(self, mock_cfg):
        """ test _command check with config """
        command = 'config foo'
        self.a2ccli._command_check(command)
        self.assertTrue(mock_cfg.called)

    @patch('tools.a2c_cli.CommandLineInterface._report_operations')
    def test_025_command_check(self, mock_report):
        """ test _command check with _report_operations """
        self.a2ccli.status = 'Configured'
        command = 'report foo'
        self.a2ccli._command_check(command)
        self.assertTrue(mock_report.called)

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    @patch('tools.a2c_cli.CommandLineInterface._report_operations')
    def test_026_command_check(self, mock_report, mock_cli):
        """ test _command check with report operations but incomplete config """
        command = 'report foo'
        self.a2ccli._command_check(command)
        self.assertFalse(mock_report.called)
        self.assertTrue(mock_cli.called)

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    @patch('tools.a2c_cli.CommandLineInterface._certificate_operations')
    @patch('tools.a2c_cli.CommandLineInterface._message_operations')
    @patch('tools.a2c_cli.CommandLineInterface._report_operations')
    def test_027_command_check(self, mock_report, mock_message, mock_cert, mock_cli):
        """ test _command check with report command """
        command = 'report foo'
        self.a2ccli.status = 'Configured'
        self.a2ccli._command_check(command)
        self.assertTrue(mock_report.called)
        self.assertFalse(mock_message.called)
        self.assertFalse(mock_cert.called)
        self.assertFalse(mock_cli.called)

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    @patch('tools.a2c_cli.CommandLineInterface._certificate_operations')
    @patch('tools.a2c_cli.CommandLineInterface._message_operations')
    @patch('tools.a2c_cli.CommandLineInterface._report_operations')
    def test_028_command_check(self, mock_report, mock_message, mock_cert, mock_cli):
        """ test _command check with report command """
        command = 'message foo'
        self.a2ccli.status = 'Configured'
        self.a2ccli._command_check(command)
        self.assertFalse(mock_report.called)
        self.assertFalse(mock_cert.called)
        self.assertTrue(mock_message.called)
        self.assertFalse(mock_cli.called)

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    @patch('tools.a2c_cli.CommandLineInterface._certificate_operations')
    @patch('tools.a2c_cli.CommandLineInterface._message_operations')
    @patch('tools.a2c_cli.CommandLineInterface._report_operations')
    def test_029_command_check(self, mock_report, mock_message, mock_cert, mock_cli):
        """ test _command check with report command """
        command = 'certificate foo'
        self.a2ccli.status = 'Configured'
        self.a2ccli._command_check(command)
        self.assertFalse(mock_report.called)
        self.assertTrue(mock_cert.called)
        self.assertFalse(mock_message.called)
        self.assertFalse(mock_cli.called)

    @patch('tools.a2c_cli.is_url')
    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    def test_030_server_set(self, mock_cli_print, mock_is_url):
        """ test _server_set all good """
        command = 'server foo'
        mock_is_url.return_value = True
        self.a2ccli._server_set(command)
        self.assertEqual(self.a2ccli.server, 'foo')
        self.assertEqual(self.a2ccli.status, 'Key missing')
        self.assertFalse(mock_cli_print.called)

    @patch('tools.a2c_cli.is_url')
    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    def test_031_server_set(self, mock_cli_print, mock_is_url):
        """ test _server_set all good """
        command = 'server foo'
        mock_is_url.return_value = True
        self.a2ccli.key = 'key'
        self.a2ccli._server_set(command)
        self.assertEqual(self.a2ccli.server, 'foo')
        self.assertEqual(self.a2ccli.status, 'Configured')
        self.assertFalse(mock_cli_print.called)

    @patch('tools.a2c_cli.is_url')
    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    def test_032_server_set(self, mock_cli_print, mock_is_url):
        """ test _server_set all wrong url specified """
        command = 'server foo'
        mock_is_url.return_value = False
        self.a2ccli._server_set(command)
        self.assertFalse(self.a2ccli.server)
        self.assertEqual(self.a2ccli.status, 'server missing')
        self.assertTrue(mock_cli_print.called)

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    @patch('tools.a2c_cli.KeyOperations.generate')
    @patch('tools.a2c_cli.KeyOperations.load')
    def test_033_key_operations(self, mock_load, mock_gen, mock_print):
        """ test key operations generate command """
        command = 'key generate foo'
        self.a2ccli._key_operations(command)
        self.assertTrue(mock_gen.called)
        self.assertFalse(mock_load.called)
        self.assertFalse(mock_print.called)

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    @patch('tools.a2c_cli.KeyOperations.generate')
    @patch('tools.a2c_cli.KeyOperations.load')
    def test_034_key_operations(self, mock_load, mock_gen, mock_print):
        """ test key operations load command """
        command = 'key load foo'
        self.a2ccli._key_operations(command)
        self.assertFalse(mock_gen.called)
        self.assertTrue(mock_load.called)
        self.assertFalse(mock_print.called)

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    @patch('tools.a2c_cli.KeyOperations.generate')
    @patch('tools.a2c_cli.KeyOperations.load')
    def test_035_key_operations(self, mock_load, mock_gen, mock_print):
        """ test key operations unknown command """
        command = 'key bar foo'
        self.a2ccli._key_operations(command)
        self.assertFalse(mock_gen.called)
        self.assertFalse(mock_load.called)
        self.assertTrue(mock_print.called)

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    @patch('tools.a2c_cli.KeyOperations.generate')
    @patch('tools.a2c_cli.KeyOperations.load')
    def test_036_key_operations(self, mock_load, mock_gen, mock_print):
        """ test key operations incomplete command """
        command = 'key foo'
        self.a2ccli._key_operations(command)
        self.assertFalse(mock_gen.called)
        self.assertFalse(mock_load.called)
        self.assertTrue(mock_print.called)

    @patch('json.dumps')
    @patch('jwcrypto.jwk.JWK.generate.export_public')
    @patch('jwcrypto.jwk.JWK.generate.export_private')
    @patch('jwcrypto.jwk.JWK.generate')
    @patch('tools.a2c_cli.file_dump')
    def test_037_key_generate(self, mock_fd, mock_jwk, mock_exp_priv, mock_export_public, mock_json_dump):
        """ test key generation  all ok """
        self.keyops.print = Mock()
        mock_exp_priv.return_value = {'foo': 'bar'}
        mock_export_public.return_value = {'foo': 'bar'}
        mock_json_dump.return_value = 'json_dump'
        self.keyops.generate('file_name')
        self.assertTrue(mock_jwk.called)
        self.assertTrue(mock_fd.called)

    @patch('json.dumps')
    @patch('jwcrypto.jwk.JWK.generate')
    @patch('tools.a2c_cli.file_dump')
    def test_038_key_generate(self, mock_fd, mock_jwk, mock_json_dump):
        """ test key generation  exception during filedump """
        mock_fd.side_effect = Exception('exc_fd')
        self.keyops.print = Mock()
        mock_json_dump.return_value = 'json_dump'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.keyops.generate('file_name')
        self.assertIn('ERROR:test_a2c:KeyOperations.generate() failed with err: exc_fd', lcm.output)
        self.assertTrue(mock_jwk.called)
        self.assertTrue(mock_fd.called)

    def test_039_isurl(self):
        """ test is_url """
        url = 'http://foo.bar'
        self.assertTrue(self.is_url(url))

    def test_040_isurl(self):
        """ test is_url """
        url = 'https://foo.bar'
        self.assertTrue(self.is_url(url))

    def test_041_isurl(self):
        """ test is_url """
        url = 'https://foo.bar/foo'
        self.assertTrue(self.is_url(url))

    def test_042_isurl(self):
        """ test is_url """
        url = 'https://foo.bar:80/foo'
        self.assertTrue(self.is_url(url))

    def test_043_isurl(self):
        """ test is_url """
        url = 'foo.bar'
        self.assertFalse(self.is_url(url))

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    @patch('tools.a2c_cli.MessageOperations.send')
    @patch('tools.a2c_cli.MessageOperations.sign')
    def test_044_message_operations(self, mock_sign, mock_send, mock_print):
        """ test message operations all ok """
        command = 'message sign foo'
        self.a2ccli._message_operations(command)
        self.assertTrue(mock_sign.called)
        self.assertFalse(mock_send.called)
        self.assertTrue(mock_print.called)

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    @patch('tools.a2c_cli.MessageOperations.send')
    @patch('tools.a2c_cli.MessageOperations.sign')
    def test_045_message_operations(self, mock_sign, mock_send, mock_print):
        """ test message operations all ok """
        command = 'message send foo'
        self.a2ccli._message_operations(command)
        self.assertTrue(mock_sign.called)
        self.assertTrue(mock_send.called)
        self.assertFalse(mock_print.called)

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    @patch('tools.a2c_cli.MessageOperations.send')
    @patch('tools.a2c_cli.MessageOperations.sign')
    def test_046_message_operations(self, mock_sign, mock_send, mock_print):
        """ test message operations all ok """
        command = 'message send'
        self.a2ccli._message_operations(command)
        self.assertFalse(mock_sign.called)
        self.assertFalse(mock_send.called)
        self.assertTrue(mock_print.called)

    @patch('jwcrypto.jws.JWS.serialize')
    @patch('jwcrypto.jws.JWS.add_signature')
    def test_047_msgops_sign(self, mock_add_sig, mock_serialize):
        """ test add signature """
        key = {'kid': 'kid'}
        message = 'message'
        mock_serialize.return_value = 'foo'
        self.assertEqual('foo', self.msgops.sign(key, message))

    @patch('requests.post')
    def test_048_msgops_send(self, mock_post):
        """ test add signature """
        mock_post.return_value = 'foo'
        self.assertEqual('foo', self.msgops.send('server', 'message'))

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    @patch('csv.writer')
    def test_049__csv_dump(self, mock_csv):
        """ test csv dump """
        self.csv_dump(self.logger, 'filename', 'content')
        self.assertTrue(mock_csv.called)

    def test_050_helper_generate_random_string(self):
        """ test date_to_uts_utc without format """
        self.assertEqual(5, len(self.generate_random_string(self.logger, 5)))

    def test_051_helper_generate_random_string(self):
        """ test date_to_uts_utc without format """
        self.assertEqual(15, len(self.generate_random_string(self.logger, 15)))

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    def test_052__file_dump(self):
        """ test csv dump """
        self.file_dump(self.logger, 'filename', 'content')

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    def test_053__file_load(self):
        """ test csv dump """
        self.assertEqual('foo', self.file_load(self.logger, 'filename'))

    @patch('time.sleep')
    @patch('tools.a2c_cli.CommandLineInterface._command_check')
    @patch("builtins.open", mock_open(read_data='foo\nbar'), create=True)
    def test_054__load_cfg(self, mock_check, mock_sleep):
        """ test _load_cfg"""
        self.a2ccli._load_cfg('filename')
        self.assertTrue(mock_check.called)
        self.assertFalse(mock_sleep.called)

    @patch('time.sleep')
    @patch('tools.a2c_cli.CommandLineInterface._command_check')
    @patch("builtins.open", mock_open(read_data='sleep 10\nbar'), create=True)
    def test_055__load_cfg(self, mock_check, mock_sleep):
        """ test _load_cfg with sleep command """
        self.a2ccli._load_cfg('filename')
        self.assertTrue(mock_check.called)
        self.assertTrue(mock_sleep.called)

    @patch('time.sleep')
    @patch('tools.a2c_cli.CommandLineInterface._command_check')
    @patch("builtins.open", mock_open(read_data='sleep\nbar'), create=True)
    def test_056__load_cfg(self, mock_check, mock_sleep):
        """ test _load_cfg with sleep command - slit failes """
        self.a2ccli._load_cfg('filename')
        self.assertTrue(mock_check.called)
        self.assertTrue(mock_sleep.called)


    @patch('time.sleep')
    @patch('tools.a2c_cli.CommandLineInterface._command_check')
    @patch("builtins.open", mock_open(read_data='#foo\n#bar'), create=True)
    def test_057__load_cfg(self, mock_check, mock_sleep):
        """ test _load_cfg"""
        self.a2ccli._load_cfg('filename')
        self.assertFalse(mock_check.called)
        self.assertFalse(mock_sleep.called)

    @patch('sys.exit')
    def test_058__quit(self, mock_exit):
        """ test _quit() """
        self.a2ccli._quit()
        self.assertTrue(mock_exit.called)


    @patch('jwcrypto.jwk.JWK.from_json')
    @patch('tools.a2c_cli.file_load')
    @patch('os.path.exists')
    def test_059_keyops_load(self, mock_exists, mock_fload, mock_json):
        """ test keyoperations.load() """
        self.keyops.print = Mock()
        mock_exists.return_value = False
        mock_json.return_value = 'key'
        self.assertFalse(self.keyops.load('filename'))
        self.assertFalse(mock_fload.called)
        self.assertFalse(mock_json.called)
        self.assertTrue(self.keyops.print.called)

    @patch('jwcrypto.jwk.JWK.from_json')
    @patch('tools.a2c_cli.file_load')
    @patch('os.path.exists')
    def test_060_keyops_load(self, mock_exists, mock_fload, mock_json):
        """ test keyoperations.load() """
        self.keyops.print = Mock()
        mock_exists.return_value = True
        mock_json.return_value = 'key'
        self.assertEqual('key', self.keyops.load('filename'))
        self.assertTrue(mock_fload.called)
        self.assertTrue(mock_json.called)
        self.assertTrue(self.keyops.print.called)

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    def test_061_config_ops(self, mock_print):
        """ test config_operations """
        self.a2ccli._config_operations('foo')
        self.assertTrue(mock_print.called)

    def test_062_certificate_operations(self):
        """ test certificate operations """
        self.a2ccli._certificate_operations('foo')

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    @patch('tools.a2c_cli.file_dump')
    @patch('tools.a2c_cli.csv_dump')
    @patch('tools.a2c_cli.MessageOperations.send')
    @patch('tools.a2c_cli.MessageOperations.sign')
    def test_063_report_operations(self, mock_sign, mock_send, mock_cdump, mock_fdump, mock_print):
        """ test report operations with incomplete command """
        self.a2ccli._report_operations('report bar')
        self.assertTrue(mock_print.called)
        self.assertFalse(mock_fdump.called)
        self.assertFalse(mock_cdump.called)
        self.assertFalse(mock_send.called)
        self.assertFalse(mock_sign.called)

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    @patch('tools.a2c_cli.file_dump')
    @patch('tools.a2c_cli.csv_dump')
    @patch('tools.a2c_cli.MessageOperations.send')
    @patch('tools.a2c_cli.MessageOperations.sign')
    def test_064_report_operations(self, mock_sign, mock_send, mock_cdump, mock_fdump, mock_print):
        """ test report operations with unknown format """
        self.a2ccli._report_operations('report text foo.txt')
        self.assertTrue(mock_print.called)
        self.assertFalse(mock_fdump.called)
        self.assertFalse(mock_cdump.called)
        self.assertFalse(mock_send.called)
        self.assertFalse(mock_sign.called)

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    @patch('tools.a2c_cli.file_dump')
    @patch('tools.a2c_cli.csv_dump')
    @patch('tools.a2c_cli.MessageOperations.send')
    @patch('tools.a2c_cli.MessageOperations.sign')
    def test_065_report_operations(self, mock_sign, mock_send, mock_cdump, mock_fdump, mock_print):
        """ test report operations without fileextension """
        self.a2ccli._report_operations('report text foo')
        self.assertTrue(mock_print.called)
        self.assertFalse(mock_fdump.called)
        self.assertFalse(mock_cdump.called)
        self.assertFalse(mock_send.called)
        self.assertFalse(mock_sign.called)

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    @patch('tools.a2c_cli.file_dump')
    @patch('tools.a2c_cli.csv_dump')
    @patch('tools.a2c_cli.MessageOperations.send')
    @patch('tools.a2c_cli.MessageOperations.sign')
    def test_066_report_operations(self, mock_sign, mock_send, mock_cdump, mock_fdump, mock_print):
        """ test report operations request error - no message tag in json response """
        mockresponse = Mock()
        mock_send.return_value = mockresponse
        mockresponse.status_code = 400
        mockresponse.json = lambda: {'foo': 'bar'}
        self.a2ccli._report_operations('report text foo.csv')
        self.assertTrue(mock_print.called)
        self.assertFalse(mock_fdump.called)
        self.assertFalse(mock_cdump.called)
        self.assertTrue(mock_send.called)
        self.assertTrue(mock_sign.called)

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    @patch('tools.a2c_cli.file_dump')
    @patch('tools.a2c_cli.csv_dump')
    @patch('tools.a2c_cli.MessageOperations.send')
    @patch('tools.a2c_cli.MessageOperations.sign')
    def test_067_report_operations(self, mock_sign, mock_send, mock_cdump, mock_fdump, mock_print):
        """ test report operations request error - message tag in json response """
        mockresponse = Mock()
        mock_send.return_value = mockresponse
        mockresponse.status_code = 400
        mockresponse.json = lambda: {'message': 'mesasge'}
        self.a2ccli._report_operations('report text foo.csv')
        self.assertTrue(mock_print.called)
        self.assertFalse(mock_fdump.called)
        self.assertFalse(mock_cdump.called)
        self.assertTrue(mock_send.called)
        self.assertTrue(mock_sign.called)

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    @patch('tools.a2c_cli.file_dump')
    @patch('tools.a2c_cli.csv_dump')
    @patch('tools.a2c_cli.MessageOperations.send')
    @patch('tools.a2c_cli.MessageOperations.sign')
    def test_068_report_operations(self, mock_sign, mock_send, mock_cdump, mock_fdump, mock_print):
        """ test report operations request error - detail tag in json response """
        mockresponse = Mock()
        mock_send.return_value = mockresponse
        mockresponse.status_code = 400
        mockresponse.json = lambda: {'detail': 'detail'}
        self.a2ccli._report_operations('report text foo.csv')
        self.assertTrue(mock_print.called)
        self.assertFalse(mock_fdump.called)
        self.assertFalse(mock_cdump.called)
        self.assertTrue(mock_send.called)
        self.assertTrue(mock_sign.called)


    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    @patch('tools.a2c_cli.file_dump')
    @patch('tools.a2c_cli.csv_dump')
    @patch('tools.a2c_cli.MessageOperations.send')
    @patch('tools.a2c_cli.MessageOperations.sign')
    def test_069_report_operations(self, mock_sign, mock_send, mock_cdump, mock_fdump, mock_print):
        """ test report operations request success - csv dump """
        mockresponse = Mock()
        mock_send.return_value = mockresponse
        mockresponse.status_code = 200
        mockresponse.json = lambda: {'foo': 'bar'}
        self.a2ccli._report_operations('report text foo.csv')
        self.assertTrue(mock_print.called)
        self.assertFalse(mock_fdump.called)
        self.assertTrue(mock_cdump.called)
        self.assertTrue(mock_send.called)
        self.assertTrue(mock_sign.called)

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    @patch('tools.a2c_cli.file_dump')
    @patch('tools.a2c_cli.csv_dump')
    @patch('tools.a2c_cli.MessageOperations.send')
    @patch('tools.a2c_cli.MessageOperations.sign')
    def test_070_report_operations(self, mock_sign, mock_send, mock_cdump, mock_fdump, mock_print):
        """ test report operations request success - csv dump """
        mockresponse = Mock()
        mock_send.return_value = mockresponse
        mockresponse.status_code = 200
        mockresponse.json = lambda: {'foo': 'bar'}
        self.a2ccli._report_operations('report text foo.json')
        self.assertTrue(mock_print.called)
        self.assertTrue(mock_fdump.called)
        self.assertFalse(mock_cdump.called)
        self.assertTrue(mock_send.called)
        self.assertTrue(mock_sign.called)

    @patch('tools.a2c_cli.CommandLineInterface._intro_print')
    @patch('builtins.input', side_effect=['5', '6', '/Q'])
    def test_071_start(self, mock_input, mock_intro):
        """ mock start """
        with self.assertRaises(SystemExit) as cm:
            self.a2ccli.start()
        self.assertEqual(cm.exception.code, 0)
        self.assertRaises(SystemExit)


if __name__ == '__main__':
    unittest.main()
