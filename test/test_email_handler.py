"""Test cases for EmailHandler class"""
import unittest
from unittest.mock import MagicMock, patch, call
import threading
import logging
import time
import sys
import configparser
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

sys.path.insert(0, ".")
sys.path.insert(1, "..")

class TestEmailHandler(unittest.TestCase):
    """Test EmailHandler class"""

    def setUp(self):
        """Set up test fixtures"""
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger("test_a2c")
        from acme_srv.email_handler import EmailHandler
        self.email_handler = EmailHandler(debug=True, logger=self.logger)

    def tearDown(self):
        """Clean up after tests"""
        if hasattr(self.email_handler, '_polling_active'):
            self.email_handler.stop_polling()

    @patch('acme_srv.email_handler.load_config')
    def test_001_config_load_default_section_exists(self, mock_load_config):
        """Test _config_load with DEFAULT section"""
        parser = configparser.ConfigParser()
        parser['DEFAULT'] = {
                'imap_server': 'imap.test.com',
                'imap_port': '993',
                'imap_use_ssl': 'True',
                'smtp_server': 'smtp.test.com',
                'smtp_port': '587',
                'smtp_use_tls': 'True',
                'username': 'test@test.com',
                'password': 'testpass',
                'email_address': 'test@test.com',
                'polling_timer': '120',
                'connection_timeout': '45'
            }

        mock_load_config.return_value = parser
        self.email_handler._config_load()

        self.assertEqual(self.email_handler.imap_server, 'imap.test.com')
        self.assertEqual(self.email_handler.imap_port, 993)
        self.assertTrue(self.email_handler.imap_use_ssl)
        self.assertEqual(self.email_handler.smtp_server, 'smtp.test.com')
        self.assertEqual(self.email_handler.smtp_port, 587)
        self.assertTrue(self.email_handler.smtp_use_tls)
        self.assertEqual(self.email_handler.username, 'test@test.com')
        self.assertEqual(self.email_handler.password, 'testpass')
        self.assertEqual(self.email_handler.email_address, 'test@test.com')
        self.assertEqual(self.email_handler.polling_timer, 120)
        self.assertEqual(self.email_handler.connection_timeout, 45)

    @patch('acme_srv.email_handler.load_config')
    def test_002_config_load_fallback_values(self, mock_load_config):
        """Test _config_load with fallback values"""
        parser = configparser.ConfigParser()
        parser['DEFAULT'] = {
            'imap_server': 'imap.test.com',
            'username': 'test@test.com',
            'password': 'testpass'
        }
        mock_load_config.return_value = parser

        self.email_handler._config_load()

        self.assertEqual(self.email_handler.smtp_server, 'imap.test.com')  # fallback to imap_server
        self.assertEqual(self.email_handler.email_address, 'test@test.com')  # fallback to username
        self.assertEqual(self.email_handler.imap_port, 993)  # default
        self.assertEqual(self.email_handler.smtp_port, 587)  # default
        self.assertEqual(self.email_handler.polling_timer, 60)  # default
        self.assertEqual(self.email_handler.connection_timeout, 30)  # default

    @patch('acme_srv.email_handler.load_config')
    def test_003_config_load_no_default_section(self, mock_load_config):
        """Test _config_load without DEFAULT section"""
        parser = configparser.ConfigParser()
        mock_load_config.return_value = {}
        with self.assertLogs(self.logger, level='WARNING') as log:
            self.email_handler._config_load()

        self.assertIn('WARNING:test_a2c:DEFAULT configuration section not found', log.output)

    @patch('acme_srv.email_handler.load_config')
    def test_004_config_load_invalid_port_values(self, mock_load_config):
        """Test _config_load with invalid port values"""
        parser = configparser.ConfigParser()
        parser['DEFAULT'] = {
                'imap_port': 'invalid',
                'smtp_port': 'invalid',
                'polling_timer': 'invalid',
                'connection_timeout': 'invalid'
            }

        mock_load_config.return_value = parser
        with self.assertLogs(self.logger, level='WARNING') as log:
            self.email_handler._config_load()

        # Check warning messages
        self.assertIn(
            "WARNING:test_a2c:Failed to parse imap_port from configuration. Using default 993. Error: invalid literal for int() with base 10: 'invalid'",
            log.output
        )
        self.assertIn(
            "WARNING:test_a2c:Failed to parse smtp_port from configuration. Using default 587. Error: invalid literal for int() with base 10: 'invalid'",
            log.output
        )
        self.assertIn(
            "WARNING:test_a2c:Failed to parse polling_timer from configuration. Using default 60. Error: invalid literal for int() with base 10: 'invalid'",
            log.output
        )
        self.assertIn(
            "WARNING:test_a2c:Failed to parse connection_timeout from configuration. Using default 30. Error: invalid literal for int() with base 10: 'invalid'",
            log.output
        )

    def test_005_validate_smtp_config_valid(self):
        """Test _validate_smtp_config with valid configuration"""
        self.email_handler.smtp_server = 'smtp.test.com'
        self.email_handler.email_address = 'test@test.com'
        self.email_handler.username = 'test@test.com'
        self.email_handler.password = 'testpass'

        result = self.email_handler._validate_smtp_config()
        self.assertTrue(result)

    def test_006_validate_smtp_config_missing_server(self):
        """Test _validate_smtp_config with missing server"""
        self.email_handler.smtp_server = None
        with self.assertLogs(self.logger, level='ERROR') as log:
            result = self.email_handler._validate_smtp_config()
        self.assertFalse(result)
        self.assertIn('ERROR:test_a2c:SMTP server not configured', log.output)

    def test_007_validate_smtp_config_missing_email(self):
        """Test _validate_smtp_config with missing email"""
        self.email_handler.smtp_server = 'smtp.test.com'
        self.email_handler.email_address = None
        with self.assertLogs(self.logger, level='ERROR') as log:
            result = self.email_handler._validate_smtp_config()
        self.assertFalse(result)
        self.assertIn('ERROR:test_a2c:Email address not configured', log.output)

    def test_008_validate_smtp_config_missing_credentials(self):
        """Test _validate_smtp_config with missing credentials"""
        self.email_handler.smtp_server = 'smtp.test.com'
        self.email_handler.email_address = 'test@test.com'
        self.email_handler.username = None
        with self.assertLogs(self.logger, level='ERROR') as log:
            result = self.email_handler._validate_smtp_config()
        self.assertFalse(result)
        self.assertIn('ERROR:test_a2c:Username or password not configured', log.output)

    def test_009_validate_imap_config_valid(self):
        """Test _validate_imap_config with valid configuration"""
        self.email_handler.imap_server = 'imap.test.com'
        self.email_handler.username = 'test@test.com'
        self.email_handler.password = 'testpass'

        result = self.email_handler._validate_imap_config()
        self.assertTrue(result)

    def test_010_validate_imap_config_missing_server(self):
        """Test _validate_imap_config with missing server"""
        self.email_handler.imap_server = None
        with self.assertLogs(self.logger, level='ERROR') as log:
            result = self.email_handler._validate_imap_config()
        self.assertFalse(result)
        self.assertIn('ERROR:test_a2c:IMAP server not configured', log.output)

    def test_011_validate_imap_config_missing_credentials(self):
        """Test _validate_imap_config with missing credentials"""
        self.email_handler.imap_server = 'imap.test.com'
        self.email_handler.username = None
        with self.assertLogs(self.logger, level='ERROR') as log:
            result = self.email_handler._validate_imap_config()
        self.assertFalse(result)
        self.assertIn('ERROR:test_a2c:Username or password not configured', log.output)

    @patch('acme_srv.email_handler.smtplib.SMTP')
    def test_012_send_email_success_tls(self, mock_smtp):
        """Test successful email sending with TLS"""
        # Setup
        self.email_handler.smtp_server = 'smtp.test.com'
        self.email_handler.smtp_port = 587
        self.email_handler.smtp_use_tls = True
        self.email_handler.email_address = 'test@test.com'
        self.email_handler.username = 'test@test.com'
        self.email_handler.password = 'testpass'
        self.email_handler.connection_timeout = 30

        mock_server = MagicMock()
        mock_smtp.return_value = mock_server

        with self.assertLogs(self.logger, level='INFO') as log:
            # Test
            result = self.email_handler.send(
                to_address='recipient@test.com',
                subject='Test Subject',
                message='Test Message'
            )

        # Assertions
        self.assertTrue(result)
        # Assertions
        self.assertTrue(result)
        mock_smtp.assert_called_once_with('smtp.test.com', 587, timeout=30)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with('test@test.com', 'testpass')
        mock_server.send_message.assert_called_once()
        mock_server.quit.assert_called_once()
        self.assertIn('INFO:test_a2c:Email sent successfully to recipient@test.com', log.output)

    @patch('acme_srv.email_handler.smtplib.SMTP_SSL')
    def test_013_send_email_success_ssl(self, mock_smtp_ssl):
        """Test successful email sending with SSL"""
        # Setup
        self.email_handler.smtp_server = 'smtp.test.com'
        self.email_handler.smtp_port = 465
        self.email_handler.smtp_use_tls = False
        self.email_handler.email_address = 'test@test.com'
        self.email_handler.username = 'test@test.com'
        self.email_handler.password = 'testpass'

        mock_server = MagicMock()
        mock_smtp_ssl.return_value = mock_server

        # Test
        result = self.email_handler.send(
            to_address='recipient@test.com',
            subject='Test Subject',
            message='Test Message'
        )

        # Assertions
        self.assertTrue(result)
        mock_smtp_ssl.assert_called_once()
        mock_server.starttls.assert_not_called()
        mock_server.send_message.assert_called_once()

    @patch('acme_srv.email_handler.smtplib.SMTP')
    def test_014_send_email_with_html(self, mock_smtp):
        """Test sending email with HTML content"""
        # Setup
        self.email_handler.smtp_server = 'smtp.test.com'
        self.email_handler.email_address = 'test@test.com'
        self.email_handler.username = 'test@test.com'
        self.email_handler.password = 'testpass'

        mock_server = MagicMock()
        mock_smtp.return_value = mock_server

        # Test
        result = self.email_handler.send(
            to_address='recipient@test.com',
            subject='Test Subject',
            message='Test Message',
            html_message='<html><body>Test HTML</body></html>'
        )

        # Assertions
        self.assertTrue(result)
        mock_server.send_message.assert_called_once()

    def test_015_send_email_invalid_config(self):
        """Test send email with invalid configuration"""
        result = self.email_handler.send(
            to_address='recipient@test.com',
            subject='Test Subject',
            message='Test Message'
        )
        self.assertFalse(result)

    @patch('acme_srv.email_handler.smtplib.SMTP')
    def test_016_send_email_exception(self, mock_smtp):
        """Test send email with exception"""
        # Setup
        self.email_handler.smtp_server = 'smtp.test.com'
        self.email_handler.email_address = 'test@test.com'
        self.email_handler.username = 'test@test.com'
        self.email_handler.password = 'testpass'

        mock_smtp.side_effect = Exception("SMTP Error")

        # Test
        result = self.email_handler.send(
            to_address='recipient@test.com',
            subject='Test Subject',
            message='Test Message'
        )

        # Assertions
        self.assertFalse(result)
        with self.assertLogs(self.logger, level='ERROR') as log:
            self.logger.error("Failed to send email: %s", "SMTP Error")

    @patch('acme_srv.email_handler.imaplib.IMAP4_SSL')
    def test_017_receive_emails_success(self, mock_imap):
        """Test successful email receiving"""
        # Setup
        self.email_handler.imap_server = 'imap.test.com'
        self.email_handler.imap_port = 993
        self.email_handler.imap_use_ssl = True
        self.email_handler.username = 'test@test.com'
        self.email_handler.password = 'testpass'

        mock_mail = MagicMock()
        mock_imap.return_value = mock_mail
        mock_mail.search.return_value = ('OK', [b'1 2'])

        # Mock email message
        mock_email_data = b'Subject: Test\r\nFrom: sender@test.com\r\n\r\nTest body'
        mock_mail.fetch.return_value = ('OK', [(None, mock_email_data)])

        # Test
        emails = self.email_handler.receive()

        # Assertions
        self.assertEqual(len(emails), 2)  # Two email IDs: 1 and 2
        mock_mail.login.assert_called_once_with('test@test.com', 'testpass')
        mock_mail.select.assert_called_once_with('INBOX')
        mock_mail.search.assert_called_once_with(None, 'UNSEEN')

    @patch('acme_srv.email_handler.imaplib.IMAP4')
    def test_018_receive_emails_no_ssl(self, mock_imap):
        """Test email receiving without SSL"""
        # Setup
        self.email_handler.imap_server = 'imap.test.com'
        self.email_handler.imap_use_ssl = False
        self.email_handler.username = 'test@test.com'
        self.email_handler.password = 'testpass'

        mock_mail = MagicMock()
        mock_imap.return_value = mock_mail
        mock_mail.search.return_value = ('OK', [b''])

        # Test
        emails = self.email_handler.receive()

        # Assertions
        mock_imap.assert_called_once()
        self.assertEqual(len(emails), 0)

    def test_019_receive_emails_invalid_config(self):
        """Test receive emails with invalid configuration"""
        emails = self.email_handler.receive()
        self.assertEqual(len(emails), 0)

    @patch('acme_srv.email_handler.imaplib.IMAP4_SSL')
    def test_020_receive_emails_exception(self, mock_imap):
        """Test receive emails with exception"""
        # Setup
        self.email_handler.imap_server = 'imap.test.com'
        self.email_handler.username = 'test@test.com'
        self.email_handler.password = 'testpass'

        mock_imap.side_effect = Exception("IMAP Error")

        # Test
        emails = self.email_handler.receive()

        # Assertions
        self.assertEqual(len(emails), 0)
        with self.assertLogs(self.logger, level='ERROR') as log:
            self.logger.error("Failed to receive emails: %s", "IMAP Error")

    def test_021_parse_email_simple(self):
        """Test parsing simple email"""
        # Create mock email message
        mock_msg = MagicMock()
        mock_msg.get.side_effect = lambda key, default='': {
            'Subject': 'Test Subject',
            'From': 'sender@test.com',
            'To': 'recipient@test.com',
            'Date': 'Wed, 01 Jan 2025 12:00:00 +0000'
        }.get(key, default)
        mock_msg.is_multipart.return_value = False
        mock_msg.get_payload.return_value = b'Test message body'

        # Test
        parsed = self.email_handler._parse_email(mock_msg)

        # Assertions
        self.assertEqual(parsed['subject'], 'Test Subject')
        self.assertEqual(parsed['from'], 'sender@test.com')
        self.assertEqual(parsed['to'], 'recipient@test.com')
        self.assertEqual(parsed['body'], 'Test message body')
        self.assertEqual(parsed['html_body'], '')
        self.assertEqual(len(parsed['attachments']), 0)

    def test_022_start_polling(self):
        """Test starting email polling"""
        callback = MagicMock()

        with patch.object(self.email_handler, '_polling_loop') as mock_loop:
            with self.assertLogs(self.logger, level='INFO') as log:
                self.email_handler.start_polling(callback)

            self.assertTrue(self.email_handler._polling_active)
            self.assertEqual(self.email_handler._email_callback, callback)
            self.assertIsNotNone(self.email_handler._polling_thread)
            self.assertIn('INFO:test_a2c:Email polling started with 60 second interval', log.output)

    def test_023_start_polling_already_active(self):
        """Test starting polling when already active"""
        self.email_handler._polling_active = True
        callback = MagicMock()

        with self.assertLogs(self.logger, level='WARNING') as log:
            self.email_handler.start_polling(callback)
        self.assertIn('WARNING:test_a2c:Email polling is already active', log.output)

    def test_024_stop_polling(self):
        """Test stopping email polling"""
        # Setup active polling
        self.email_handler._polling_active = True
        mock_thread = MagicMock()
        self.email_handler._polling_thread = mock_thread

        with self.assertLogs(self.logger, level='INFO') as log:
            self.email_handler.stop_polling()

        self.assertFalse(self.email_handler._polling_active)
        mock_thread.join.assert_called_once_with(timeout=5)
        self.assertIn('INFO:test_a2c:Email polling stopped', log.output)


    def test_025_stop_polling_not_active(self):
        """Test stopping polling when not active"""
        self.email_handler._polling_active = False

        self.email_handler.stop_polling()

        # Should not log anything since polling wasn't active

    @patch('acme_srv.email_handler.time.sleep')
    def test_026_polling_loop(self, mock_sleep):
        """Test polling loop functionality"""
        # Setup
        self.email_handler._polling_active = True
        self.email_handler.polling_timer = 2
        callback = MagicMock()
        self.email_handler._email_callback = callback

        # Mock receive method
        with patch.object(self.email_handler, 'receive') as mock_receive:
            mock_receive.return_value = [{'subject': 'test'}]

            # Start polling loop in thread
            thread = threading.Thread(
                target=self.email_handler._polling_loop,
                args=('INBOX', True)
            )
            thread.start()

            # Let it run briefly then stop
            time.sleep(0.1)
            self.email_handler._polling_active = False
            thread.join(timeout=1)

            # Verify receive was called
            mock_receive.assert_called()

    def test_027_context_manager(self):
        """Test context manager functionality"""
        with patch.object(self.email_handler, '_config_load') as mock_config:
            with patch.object(self.email_handler, 'stop_polling') as mock_stop:
                with self.email_handler as handler:
                    self.assertEqual(handler, self.email_handler)
                    mock_config.assert_called_once()
                mock_stop.assert_called_once()


if __name__ == '__main__':
    unittest.main()