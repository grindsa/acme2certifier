"""email handler for ACME server"""
import time
import email
import smtplib
import imaplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Callable, Optional, Any
from acme_srv.helper import load_config


class EmailHandler:
    """Email handler class for sending and receiving emails"""

    def __init__(self, debug: bool = False, logger=None):
        """Initialize EmailHandler"""
        self.debug = debug
        self.logger = logger

        # IMAP configuration
        self.imap_server = None
        self.imap_port = 993
        self.imap_use_ssl = True

        # SMTP configuration
        self.smtp_server = None
        self.smtp_port = 587
        self.smtp_use_tls = True

        # Authentication
        self.username = None
        self.password = None
        self.email_address = None

        # Polling configuration
        self.polling_timer = 60  # seconds
        self.connection_timeout = 30  # seconds

        # Polling control
        self._polling_active = False
        self._polling_thread = None
        self._email_callback = None

    def __enter__(self):
        """Enter context manager"""
        self._config_load()
        return self

    def __exit__(self, *args):
        """Exit context manager"""
        self.stop_polling()

    def _config_load(self):
        """Load configuration from config file"""
        self.logger.debug("EmailHandler._config_load()")

        config_dic = load_config(self.logger, "acme_srv.cfg")

        # Load from DEFAULT section
        if "DEFAULT" in config_dic:
            # IMAP configuration
            self.imap_server = config_dic.get("DEFAULT", "imap_server", fallback=None)
            try:
                self.imap_port = int(
                    config_dic.get("DEFAULT", "imap_port", fallback=993)
                )
            except ValueError as err:
                self.logger.warning(
                    "Failed to parse imap_port from configuration. Using default 993. Error: %s",
                    err,
                )
                self.imap_port = 993

            self.imap_use_ssl = config_dic.getboolean(
                "DEFAULT", "imap_use_ssl", fallback=True
            )

            # SMTP configuration (fallback to IMAP server if not specified)
            self.smtp_server = config_dic.get(
                "DEFAULT", "smtp_server", fallback=self.imap_server
            )
            try:
                self.smtp_port = int(
                    config_dic.get("DEFAULT", "smtp_port", fallback=587)
                )
            except ValueError as err:
                self.logger.warning(
                    "Failed to parse smtp_port from configuration. Using default 587. Error: %s",
                    err,
                )
                self.smtp_port = 587

            self.smtp_use_tls = config_dic.getboolean(
                "DEFAULT", "smtp_use_tls", fallback=True
            )

            # Authentication
            self.username = config_dic.get("DEFAULT", "username", fallback=None)
            self.password = config_dic.get("DEFAULT", "password", fallback=None)
            self.email_address = config_dic.get(
                "DEFAULT", "email_address", fallback=self.username
            )

            # Timing configuration
            try:
                self.polling_timer = int(
                    config_dic.get("DEFAULT", "polling_timer", fallback=60)
                )
            except ValueError as err:
                self.logger.warning(
                    "Failed to parse polling_timer from configuration. Using default 60. Error: %s",
                    err,
                )
                self.polling_timer = 60

            try:
                self.connection_timeout = int(
                    config_dic.get("DEFAULT", "connection_timeout", fallback=30)
                )
            except ValueError as err:
                self.logger.warning(
                    "Failed to parse connection_timeout from configuration. Using default 30. Error: %s",
                    err,
                )
                self.connection_timeout = 30
        else:
            self.logger.warning("DEFAULT configuration section not found")

        self.logger.debug("EmailHandler._config_load() ended")

    def send(
        self,
        to_address: str,
        subject: str,
        message: str,
        from_address: Optional[str] = None,
        html_message: Optional[str] = None,
    ) -> bool:
        """Send email via SMTP"""
        self.logger.debug("EmailHandler.send()")

        if not self._validate_smtp_config():
            return False

        try:
            # Create message
            msg = MIMEMultipart("alternative") if html_message else MIMEText(message)
            msg["Subject"] = subject
            msg["From"] = from_address or self.email_address
            msg["To"] = to_address

            if html_message:
                # Add both plain text and HTML parts
                part1 = MIMEText(message, "plain")
                part2 = MIMEText(html_message, "html")
                msg.attach(part1)
                msg.attach(part2)

            # Connect to SMTP server
            if self.smtp_use_tls:
                server = smtplib.SMTP(
                    self.smtp_server, self.smtp_port, timeout=self.connection_timeout
                )
                server.starttls()
            else:
                server = smtplib.SMTP_SSL(
                    self.smtp_server, self.smtp_port, timeout=self.connection_timeout
                )

            # Authenticate and send
            if self.username and self.password:
                server.login(self.username, self.password)

            server.send_message(msg)
            server.quit()

            self.logger.info("Email sent successfully to %s", to_address)
            return True

        except Exception as err:
            self.logger.error("Failed to send email: %s", err)
            return False

    def receive(
        self,
        callback: Optional[Callable] = None,
        folder: str = "INBOX",
        mark_as_read: bool = True,
    ) -> List[Dict[str, Any]]:
        """Receive emails via IMAP"""
        self.logger.debug("EmailHandler.receive()")

        if not self._validate_imap_config():
            return []

        emails = []
        try:
            # Connect to IMAP server
            if self.imap_use_ssl:
                mail = imaplib.IMAP4_SSL(self.imap_server, self.imap_port)
            else:
                mail = imaplib.IMAP4(self.imap_server, self.imap_port)

            mail.socket().settimeout(self.connection_timeout)

            # Login
            mail.login(self.username, self.password)
            mail.select(folder)

            # Search for unread emails
            status, messages = mail.search(None, "UNSEEN")
            if status == "OK":
                email_ids = messages[0].split()

                for email_id in email_ids:
                    status, msg_data = mail.fetch(email_id, "(RFC822)")
                    if status == "OK":
                        email_body = msg_data[0][1]
                        email_message = email.message_from_bytes(email_body)

                        parsed_email = self._parse_email(email_message)
                        # Call callback if provided
                        if callback:
                            result = callback(parsed_email)
                            if result:
                                self.logger.info(
                                    "Email passed filter: %s", result["subject"]
                                )
                                emails = result  # return this email only if callback returns a value
                                break
                            else:
                                self.logger.debug(
                                    "mailHandler.receive(): email did not pass filter: %s",
                                    parsed_email["subject"],
                                )
                        else:
                            # no callback provided just add the email to the queue
                            emails.append(parsed_email)
                        # Mark as read if requested
                        if mark_as_read:
                            mail.store(email_id, "+FLAGS", "\\Seen")
                        else:
                            mail.store(email_id, "-FLAGS", "\\Seen")
            mail.close()
            mail.logout()

            self.logger.debug(
                "EmailHandler.receive(): retrieved emails: %d", bool(emails)
            )

        except Exception as err:
            self.logger.error("Failed to receive emails: %s", err)
        return emails

    def start_polling(
        self, callback: Callable, folder: str = "INBOX", mark_as_read: bool = True
    ):
        """Start polling for emails in a separate thread"""
        self.logger.debug("EmailHandler.start_polling()")

        if self._polling_active:
            self.logger.warning("Email polling is already active")
            return

        self._email_callback = callback
        self._polling_active = True
        self._polling_thread = threading.Thread(
            target=self._polling_loop, args=(folder, mark_as_read)
        )
        self._polling_thread.daemon = True
        self._polling_thread.start()

        self.logger.info(
            "Email polling started with %d second interval", self.polling_timer
        )

    def stop_polling(self):
        """Stop email polling"""
        self.logger.debug("EmailHandler.stop_polling()")

        if self._polling_active:
            self._polling_active = False
            if self._polling_thread:
                self._polling_thread.join(timeout=5)
            self.logger.info("Email polling stopped")

    def _polling_loop(self, folder: str, mark_as_read: bool):
        """Main polling loop (runs in separate thread)"""
        while self._polling_active:
            try:
                emails = self.receive(
                    callback=self._email_callback,
                    folder=folder,
                    mark_as_read=mark_as_read,
                )
                self.logger.debug(
                    "Polling check completed, found %d new emails", len(emails)
                )

            except Exception as err:
                self.logger.error("Error during email polling: %s", err)

            # Sleep in small increments to allow for responsive shutdown
            for _ in range(self.polling_timer):
                if not self._polling_active:
                    break
                time.sleep(1)

    def _parse_email(self, email_message) -> Dict[str, Any]:
        """Parse email message into dictionary"""
        parsed = {
            "subject": email_message.get("Subject", ""),
            "from": email_message.get("From", ""),
            "to": email_message.get("To", ""),
            "date": email_message.get("Date", ""),
            "body": "",
            "html_body": "",
            "attachments": [],
        }

        # Extract body content
        if email_message.is_multipart():
            for part in email_message.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                if (
                    content_type == "text/plain"
                    and "attachment" not in content_disposition
                ):
                    parsed["body"] = part.get_payload(decode=True).decode(
                        "utf-8", errors="ignore"
                    )
                elif (
                    content_type == "text/html"
                    and "attachment" not in content_disposition
                ):
                    parsed["html_body"] = part.get_payload(decode=True).decode(
                        "utf-8", errors="ignore"
                    )
                elif "attachment" in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        parsed["attachments"].append(
                            {
                                "filename": filename,
                                "content_type": content_type,
                                "content": part.get_payload(decode=True),
                            }
                        )
        else:
            parsed["body"] = email_message.get_payload(decode=True).decode(
                "utf-8", errors="ignore"
            )

        return parsed

    def _validate_smtp_config(self) -> bool:
        """Validate SMTP configuration"""
        if not self.smtp_server:
            self.logger.error("SMTP server not configured")
            return False
        if not self.email_address:
            self.logger.error("Email address not configured")
            return False
        if not self.username or not self.password:
            self.logger.error("Username or password not configured")
            return False
        return True

    def _validate_imap_config(self) -> bool:
        """Validate IMAP configuration"""
        if not self.imap_server:
            self.logger.error("IMAP server not configured")
            return False
        if not self.username or not self.password:
            self.logger.error("Username or password not configured")
            return False
        return True
