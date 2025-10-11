#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pylint: disable=r0913, w0613
"""email hook class"""

"""
Copy this file from examples to f.ex /opt/acme2certifier then add this config to acme_srv.cfg

Example config:

[Hooks]
hooks_file: email_hooks.py
appname: acme2certifier
sender: acme2certifier@acme.example.com
rcpt: admin@example.com
report_failures: True
report_successes: False

# Optional advanced configuration:
smtp_server: localhost
smtp_port: 25
subject_prefix: [ACME]

Configuration options:
- hooks_file: Path to this hooks file (required)
- appname: Application name for email headers (required)
- sender: Email sender address (required)
- rcpt: Primary recipient email address (required)
- report_failures: Send emails for certificate failures (default: True)
- report_successes: Send emails for certificate successes (default: True)
- smtp_server: SMTP server hostname (default: localhost)
- smtp_port: SMTP server port (default: 25)
- subject_prefix: Prefix for email subjects (optional)
"""

import smtplib

from acme_srv.helper import (
    load_config,
    cert_san_get,
    csr_san_get,
    build_pem_file,
)

from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12


class Hooks:
    """Hook class to send email notifications on certificate events"""

    def __init__(self, logger) -> None:
        self.logger = logger

        self.config_dic = load_config(self.logger, "Hooks")

        self.msg: list[str] = []
        self.san = ""

        # Enhanced configuration validation
        self._validate_configuration()
        self._load_configuration()

    def _validate_configuration(self) -> None:
        """Validate configuration"""
        self.logger.debug("Hooks._validate_configuration()")
        if not self.config_dic:
            raise ValueError("Configuration dictionary is empty or None")

        if "Hooks" not in self.config_dic:
            raise ValueError("Missing 'Hooks' section in configuration.")

        # Mandatory keys with validation
        required_keys = ["appname", "sender", "rcpt"]
        missing = []
        empty = []

        for key in required_keys:
            if key not in self.config_dic["Hooks"]:
                missing.append(key)
            elif not self.config_dic["Hooks"][key].strip():
                empty.append(key)

        if missing:
            raise ValueError(
                f"Missing required configuration key(s) in [Hooks]: {', '.join(missing)}"
            )
        if empty:
            raise ValueError(
                f"Empty required configuration key(s) in [Hooks]: {', '.join(empty)}"
            )

        self.logger.debug("Hooks._validate_configuration() ended successfully")

    def _load_configuration(self) -> None:
        """Load and assign configuration values"""
        self.logger.debug("Hooks._load_configuration()")
        self.appname = self.config_dic["Hooks"]["appname"].strip()
        self.sender = self.config_dic["Hooks"]["sender"].strip()
        self.rcpt = self.config_dic["Hooks"]["rcpt"].strip()

        # Optionals, that default to True
        self.report_failures = self.config_dic.getboolean(
            "Hooks", "report_failures", fallback=True
        )
        self.report_successes = self.config_dic.getboolean(
            "Hooks", "report_successes", fallback=True
        )

        # Additional email configuration options
        self.smtp_server = self.config_dic.get(
            "Hooks", "smtp_server", fallback="localhost"
        )
        self.smtp_port = self.config_dic.getint("Hooks", "smtp_port", fallback=25)
        self.email_subject_prefix = self.config_dic.get(
            "Hooks", "subject_prefix", fallback=""
        )

        self._setup_email_envelope()
        self.logger.debug("Hooks._load_configuration() ended")

    def _setup_email_envelope(self) -> None:
        """Setup email envelope with enhanced configuration"""
        self.logger.debug("Hooks._setup_email_envelope()")
        self.envelope = MIMEMultipart()
        self.envelope["From"] = f"{self.appname} <{self.sender}>"
        self.envelope["To"] = self.rcpt
        self.envelope["Date"] = formatdate()

        self.done = False
        self.logger.debug("Hooks._setup_email_envelope() ended")

    def _done(self):
        """Send the email with enhanced error handling and logging"""
        self.logger.debug("Hooks._done()")
        if self.done:
            raise RuntimeError("unexpected usage: email already sent")

        self.done = True

        try:
            self.logger.debug(
                f"Attempting to send email notification via {self.smtp_server}:{self.smtp_port}"
            )
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as smtp:
                smtp.helo()
                self.envelope.attach(MIMEText("\n\n".join(self.msg), "plain"))

                # Log email details before sending
                subject = self.envelope["Subject"]
                self.logger.debug(
                    f"Sending email - From: {self.sender}, To: {self.rcpt}, "
                    f"Subject: {subject}"
                )

                smtp.sendmail(self.sender, [self.rcpt], self.envelope.as_string())
                smtp.quit()

            recipient_info = f"{self.rcpt}"
            self.logger.info(
                f"Email notification sent successfully to {recipient_info} - Subject: {subject}"
            )

        except Exception as e:
            self.logger.error(f"Unexpected error occurred while sending email: {e}")
            raise RuntimeError(f"Failed to send email notification: {e}") from e
        self.logger.debug("Hooks._done() ended")

    def _clean_san(self, sans):
        """Clean and extract SAN with improved error handling"""
        self.logger.debug(f"Hooks._clean_san() called with SANs: {sans}")
        if not sans:
            self.logger.warning("Empty SAN list provided")
            return "unknown"

        if not isinstance(sans, list):
            self.logger.warning(f"SAN is not a list, got type: {type(sans)}")
            return "unknown"

        if len(sans) == 0:
            self.logger.warning("SAN list is empty")
            return "unknown"

        # Grab the first one, file names can't be too long anyway
        san_entry = sans[0]

        if not san_entry or ":" not in san_entry:
            self.logger.warning(f"Invalid SAN format: {san_entry}")
            return "unknown"

        # Format: DNS:a.example.com
        try:
            cleaned = san_entry.split(":")[1].strip()
            self.logger.debug(f"Cleaned SAN: {san_entry} -> {cleaned}")
            result = cleaned
        except (IndexError, AttributeError) as e:
            self.logger.error(f'Error parsing SAN entry "{san_entry}": {e}')
            result = "unknown"

        self.logger.debug(f"Final cleaned SAN: {san_entry} -> {result}")
        return result

    def _attach_csr(self, request_key, csr):
        """Attach CSR with enhanced error handling"""
        self.logger.debug(f"Attaching CSR for request_key: {request_key}")
        try:
            self.logger.debug(f"Attaching CSR for request_key: {request_key}")

            # Attach CSR
            fn = f"{self.san}_{request_key}.csr"
            csr_pem = build_pem_file(self.logger, None, csr, 64, True)

            if not csr_pem:
                self.logger.error("Failed to build PEM file from CSR")
                raise ValueError("CSR PEM generation failed")

            part = MIMEApplication(csr_pem, Name=fn)
            part["Content-Disposition"] = f'attachment; filename="{fn}"'
            part["Content-Type"] = "application/x-pem-file"
            self.envelope.attach(part)

            self.msg.append(
                f"To read {fn} using CMD on Windows:\\ncertutil -dump %USERPROFILE%\\Downloads\\{fn}"
            )
            self.logger.debug(f"Successfully attached CSR file: {fn}")

        except Exception as e:
            self.logger.error(f"Failed to attach CSR: {e}")
            raise RuntimeError(f"CSR attachment failed: {e}") from e
        self.logger.debug("Hooks._attach_csr() ended")

    def _attach_cert(self, request_key, certificate):
        """Attach certificate with enhanced error handling"""
        self.logger.debug(f"Attaching certificate for request_key: {request_key}")
        try:
            self.logger.debug(f"Attaching certificate for request_key: {request_key}")

            # Add crt to email
            # But cannot send as .crt because Outlook blocks that, sooo I make a pfx to wrap it inside,
            # bonus, because of pfx, i can send the CA cert too!
            cert_list = x509.load_pem_x509_certificates(certificate.encode("utf-8"))

            if len(cert_list) != 2:
                error_msg = f"Expected exactly 2 certificates (cert and CA), but got {len(cert_list)}"
                self.logger.error(error_msg)
                raise ValueError(error_msg)

            cert, ca = cert_list
            fn = f"{self.san}_{request_key}.pfx"

            pfx = pkcs12.serialize_key_and_certificates(
                self.san.encode("utf-8"),
                None,  # We don't even have the key, and obviously no need for it
                cert,
                [ca],
                serialization.NoEncryption(),  # No keys included so no encryption needed
            )

            part = MIMEApplication(pfx, Name=fn)
            part["Content-Disposition"] = f'attachment; filename="{fn}"'
            part["Content-Type"] = "application/x-pkcs12"
            self.envelope.attach(part)

            self.msg.append(
                f"To read {fn} using CMD on Windows:\\ncertutil -dump %USERPROFILE%\\Downloads\\{fn}"
            )
            self.logger.debug(f"Successfully attached certificate file: {fn}")
        except Exception as e:
            self.logger.error(f"Unexpected error while attaching certificate: {e}")
            raise RuntimeError(f"Certificate attachment failed: {e}") from e
        self.logger.debug("Hooks._attach_cert() ended")

    def _format_subject(self, status: str, san: str) -> str:
        """Format email subject with optional prefix and standardized format"""
        self.logger.debug("Hooks._format_subject()")
        base_subject = f"{self.appname} {status}: {san}"
        if self.email_subject_prefix:
            return f"{self.email_subject_prefix} {base_subject}"
        self.logger.debug(f"Final email subject: {base_subject}")
        return base_subject

    def _format_message_header(self, status: str, san: str) -> str:
        """Format standardized message header with timestamp and details"""
        self.logger.debug("Hooks._format_message_header()")
        from datetime import datetime

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        header_lines = [
            f"ACME Certificate {status.title()} Notification",
            f"Timestamp: {timestamp}",
            f"Application: {self.appname}",
            f"Subject Alternative Name: {san}",
            "-" * 50,
        ]
        self.logger.debug("Hooks._format_message_header() ended")
        return "\n".join(header_lines)

    def pre_hook(self, _certificate_name, _order_name, csr) -> None:
        """Hook called before certificate processing - currently no action needed"""
        self.logger.debug("Hook.pre_hook() called - no action required")
        pass

    def post_hook(self, request_key, _order_name, csr, error) -> None:
        """run after *attempting* to obtain/renew certificates"""
        self.logger.debug("Hook.post_hook() called")

        if not self.report_failures:
            self.logger.debug(
                "Hook.post_hook() disabled because report_failures is False"
            )
            return

        try:
            self.san = self._clean_san(csr_san_get(self.logger, csr))

            self.envelope["Subject"] = self._format_subject("failure", self.san)

            # Create formatted message with header and error details
            message_header = self._format_message_header("failure", self.san)
            error_details = f"Error Details:\n{error}\n\nRequest Key: {request_key}"

            self.msg.append(message_header)
            self.msg.append(error_details)

            self._attach_csr(request_key, csr)
            self._done()

        except Exception as e:
            self.logger.error(f"Error in post_hook: {e}")
            raise RuntimeError(f"post_hook execution failed: {e}") from e
        self.logger.debug("Hooks.post_hook() ended")

    def success_hook(
        self,
        request_key,
        _order_name,
        csr,
        certificate,
        certificate_raw,
        _poll_identifier,
    ) -> None:
        """run after each successful certificate enrollment/renewal"""
        self.logger.debug("Hook.success_hook() called")

        if not self.report_successes:
            self.logger.debug(
                "Hook.success_hook() disabled because report_successes is False"
            )
            return

        try:
            self.san = self._clean_san(cert_san_get(self.logger, certificate_raw))

            self.envelope["Subject"] = self._format_subject("success", self.san)

            # Create formatted message with header and success details
            message_header = self._format_message_header("success", self.san)
            success_details = (
                f"Certificate issued successfully!\n\nRequest Key: {request_key}"
            )

            # Add certificate details if available
            if certificate:
                try:
                    cert_list = x509.load_pem_x509_certificates(
                        certificate.encode("utf-8")
                    )
                    if cert_list:
                        cert = cert_list[0]
                        success_details += f"\nSerial Number: {cert.serial_number}"
                        success_details += f"\nValid From: {cert.not_valid_before}"
                        success_details += f"\nValid Until: {cert.not_valid_after}"
                except Exception as cert_err:
                    self.logger.debug(
                        f"Could not parse certificate details: {cert_err}"
                    )

            self.msg.append(message_header)
            self.msg.append(success_details)

            self._attach_csr(request_key, csr)
            self._attach_cert(request_key, certificate)

            self._done()

        except Exception as e:
            self.logger.error(f"Error in success_hook: {e}")
            raise RuntimeError(f"success_hook execution failed: {e}") from e
        self.logger.debug("Hooks.success_hook() ended")


# For local testing
if __name__ == "__main__":
    import logging
    from acme_srv.helper import generate_random_string

    log_mode = logging.DEBUG
    logging.basicConfig(level=log_mode)
    logger = logging.getLogger(__name__)

    # Test CSR for something.example.com
    csr = (
        "MIIBTDCB0gIBADAgMR4wHAYDVQQDExVzb21ldGhpbmcuZXhhbXBsZS5jb20wdjAQBgcqhkjOPQIBBgUr"
        "gQQAIgNiAATkHOWijzPd0n/exl3jPVrkPAAJeND6sHiOAecYxsQikE8ImBU1DT6RKBElLkUCF7ButTeq"
        "xkkfRU4Kz3pfSZe75rVqXYfN7xUzXEt2+vpqpA65q8ZGrj9ZgXKxrA89E7agMzAxBgkqhkiG9w0BCQ4x"
        "JDAiMCAGA1UdEQQZMBeCFXNvbWV0aGluZy5leGFtcGxlLmNvbTAKBggqhkjOPQQDAgNpADBmAjEAgirc"
        "tuTr4+SRJh+MsmnScYkrV+yC1qRQwUMZGgQcPy4jxmemdyQ9p6y52dzk0j2sAjEA5+OyAcRqtWeLL1Xi"
        "PoZH0NykBcCmQWMavJubfk0seZyFE0GsFjOPk7qAoJGVYZU8"
    )

    # These are just mkcert certificates for something.example.com and an autogenerated CA
    certificate = (
        "-----BEGIN CERTIFICATE-----\nMIIECjCCAnKgAwIBAgIRALGHaaUUFeRgIrUBibd8K3owDQYJKoZ"
        "IhvcNAQELBQAw\nVTEeMBwGA1UEChMVbWtjZXJ0IGRldmVsb3BtZW50IENBMRUwEwYDVQQLDAxyb290"
        "\nQGJhc3Rpb24xHDAaBgNVBAMME21rY2VydCByb290QGJhc3Rpb24wHhcNMjUxMDAx\nMTQyMjMxWhcN"
        "MjgwMTAxMTQyMjMxWjBAMScwJQYDVQQKEx5ta2NlcnQgZGV2ZWxv\ncG1lbnQgY2VydGlmaWNhdGUxFT"
        "ATBgNVBAsMDHJvb3RAYmFzdGlvbjCCASIwDQYJ\nKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMVJJSx0"
        "7B5xVBF7iT1jwvP9Q7sQHBAa\nOSctCmm8FMgQAn0B1i/M5RORrxmsxe9TGYQN23mgZPrkhfFREbK3jF"
        "1qDyi5aqyv\nRUCY8c6V8gVNHqeFY/Fbo7eVpUmL6cEWCQa4/IyC8HZgWZPvK8DiNEKTS6fa++Wg\ng7"
        "hEl0Du9IENEdnJZ8S63UGUklNaUmn/lsD2SMgtDq0OJUYmU5Zn1Uryh8I4MJCu\nHY/+i4CV+6tirKYN"
        "eQYvX2lxY8AcYnRsg8x18IVO5fu7DoH18uK0YtlTMEYac+AX\nOI/6B0C6NqXse71cQs53UF/O7ew+OC"
        "kZ67CoYobAqeuiOVEEA+qTSUsCAwEAAaNq\nMGgwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsG"
        "AQUFBwMBMB8GA1UdIwQY\nMBaAFEW2GtPZX80jY6cvOq8rMMAfW1hsMCAGA1UdEQQZMBeCFXNvbWV0aG"
        "luZy5l\neGFtcGxlLmNvbTANBgkqhkiG9w0BAQsFAAOCAYEAkDCKBHuqVxcXgx7vhftzDE3M\nj8x7WC"
        "4di+rkIrxyJ3ulGHc7Pl2gyvMoKJxRCqcK4WgLH7AqDkRsQSF+/yvv+c0H\nbUYjauPfDo1yUlLIQpo3"
        "7uwJjsfQt4j/AFLpYHw2myqAsqMw1jwbXRuLyyiHWSay\nljyHhWVnbZcLZNvBwL6bV0RCuRlWCFfjlA"
        "6buXW3a23krjs8k5I4UhKaeX7d0Pvk\nx/3JxjlGlOA8tYBT8+6Aq1xOIC1MuD8h/32Cxa7vDI9VyspY"
        "bsbCBl5m2XD566/P\nRE5rn62kBBHEXiIpFrE0R1d8MFTx9PEC00jVFDWnec3Ayl2TiTpptCF/Cb5S9K"
        "6g\nEdUFUkQj9dTxX8owUbm/tYGIYrwibWzTtscb75KjSzExnZApMfNgngke8r1f6P4Y\nHRQQU7/0Bc"
        "Di2GPzCy83rN3d2DFn6U66TZG0EEEdV1e1A0gsqfgx/b6YAZsZv26H\nZ5IkqXdj3IZRDcwdYgaTrlsl"
        "kPsantdPl+x/kxP5\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\nMIIE"
        "ejCCAuKgAwIBAgIRAI5dQJ4OEZYF5sy28Iw+/zkwDQYJKoZIhvcNAQELBQAw\nVTEeMBwGA1UEChMVbW"
        "tjZXJ0IGRldmVsb3BtZW50IENBMRUwEwYDVQQLDAxyb290\nQGJhc3Rpb24xHDAaBgNVBAMME21rY2Vy"
        "dCByb290QGJhc3Rpb24wHhcNMjUxMDAx\nMTQyMjMwWhcNMzUxMDAxMTQyMjMwWjBVMR4wHAYDVQQKEx"
        "Vta2NlcnQgZGV2ZWxv\ncG1lbnQgQ0ExFTATBgNVBAsMDHJvb3RAYmFzdGlvbjEcMBoGA1UEAwwTbWtj"
        "ZXJ0\nIHJvb3RAYmFzdGlvbjCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAKo5\nMM8/lupi"
        "8cOQqh5igXfGFrunERIiShzhV3EHVpQN+h3SU0BQF50DZHDTL1rHQqAn\nhPK4fgZ37s9HjssysejgYK"
        "61w9YgvoOd6dlsCTSYjpF19T9Dz5SY8yZz3lNLHcbg\nN111PZP4hyN3BtNw4ttENGuKAqHgvFO/xmzM"
        "gJtT62G4qq8VwHa8ktFa3b9Lh14/\njEOjUIkgAgHE869/deebb2ENox7nL+W0VB9o0XCqMDYF0ZF6pw"
        "4gVP2FgNbwjSgM\nci/NCW99biGHOKA5LVG4d6nNxFgOg7GdEFExzzHjjyIYQBC/ZB7ulDyQQ6KcQRn5"
        "\nbvn83SuUZ1cGRSWSndosR3LhEJaxDLbr68X7byL7PNkBM4ILAGpd+oZLCM4Z9cpF\njGW4GxilijEg"
        "Smo7gLZk++oEh3O31Wt5dyGs2BHeUDf0rHG7z+agpzK0H6Ar9Rj5\nurfDJvswioyU7jUxrpOg+4Wk/J"
        "aJWncbU49fZRtAiwYZVVHyvKf5bn+bRJK+bQID\nAQABo0UwQzAOBgNVHQ8BAf8EBAMCAgQwEgYDVR0T"
        "AQH/BAgwBgEB/wIBADAdBgNV\nHQ4EFgQURbYa09lfzSNjpy86ryswwB9bWGwwDQYJKoZIhvcNAQELBQ"
        "ADggGBAF+y\nWudDZVtWEbNpsSz5YvZ3W0BuNwaFo5TFYhzhh4ougs/SUhvPW5dAsVBJBjTgJ4fy\nXm"
        "miptcVzrvZiaB2+muL1PT/vUhFomuyqw46smzBIrUyHHmjqdoVIhmJ4XJq/eLS\n7wMLDpTeH3kQaQWt"
        "cK1EqlPOIMn5m/st663280lB2ICyv1zSQgWIkv4YpmzAuJcm\nwYw899emEsSdf3q1lQoLR0NkBdRPSN"
        "Zcnb9+wR98Iw5Rjca/7P0A1RbbEmbayXzf\n4adhIZaaCBDhADcU6SBC5v8HsIj0tolyf7nTKarKJoKy"
        "eY1i1sXrK28vZyWykLLD\nQ7FHcRDfoAtJ2QUvxbpBXpDg/F79PDjrdjc6n8nn4RG+JIwO8j7t3GMB5c"
        "MWOnKC\nruQ4NuKcsWkcIaQIcxJTx+tOYyGqyAMzxA+VFTQ+HNjcFBnue/XJOya4dpOo1BEG\nAacSqy"
        "ipP2lMM8Xbje7snzwmutRdATxiyGKDzacEJWUMHzlkrX8WsFIUnVNMUA==\n-----END CERTIFICATE"
        "-----"
    )

    # Generate the "certificate_raw" variable from the bundle in certificate since it has all the info no need to duplicate it
    cert, ca = x509.load_pem_x509_certificates(certificate.encode("utf-8"))
    certificate_raw = "".join(
        cert.public_bytes(serialization.Encoding.PEM).decode("utf-8").splitlines()[1:-1]
    )

    # a Failure message
    request_key = generate_random_string(logger, 12)
    h = Hooks(logger)
    h.post_hook(request_key, "", csr, "urn:ietf:params:acme:error:rejectedIdentifier")

    # a Success message
    request_key = generate_random_string(logger, 12)
    h = Hooks(logger)
    h.success_hook(request_key, "", csr, certificate, certificate_raw, "")
