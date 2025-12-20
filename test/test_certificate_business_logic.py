import os
import unittest
from unittest.mock import MagicMock, patch
import sys

# Add the parent directory to sys.path so we can import acme_srv
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acme_srv.certificate_business_logic import CertificateBusinessLogic


class TestCertificateBusinessLogic(unittest.TestCase):
    def setUp(self):
        self.mock_logger = MagicMock()
        self.mock_err_msg_dic = {
            "badcsr": "Invalid CSR",
            "serverinternal": "Internal server error",
        }
        self.config = MagicMock()
        self.config.tnauthlist_support = True
        self.config.cn2san_add = True
        self.config.cert_reusage_timeframe = 10
        self.logic = CertificateBusinessLogic(
            debug=True,
            logger=self.mock_logger,
            err_msg_dic=self.mock_err_msg_dic,
            config=self.config,
        )

    @patch("acme_srv.certificate_business_logic.csr_load")
    def test_001_validate_csr_valid(self, mock_csr_load):
        mock_csr_load.return_value = MagicMock()
        code, error, detail = self.logic.validate_csr("valid_csr")
        self.assertEqual(code, 200)
        self.assertIsNone(error)
        self.assertIsNone(detail)

    @patch("acme_srv.certificate_business_logic.csr_load")
    def test_002_validate_csr_empty(self, mock_csr_load):
        code, error, detail = self.logic.validate_csr("")
        self.assertEqual(code, 400)
        self.assertEqual(error, "Invalid CSR")
        self.assertEqual(detail, "CSR is empty")

    @patch("acme_srv.certificate_business_logic.csr_load")
    def test_003_validate_csr_invalid_format(self, mock_csr_load):
        mock_csr_load.return_value = None
        code, error, detail = self.logic.validate_csr("bad_csr")
        self.assertEqual(code, 400)
        self.assertEqual(error, "Invalid CSR")
        self.assertEqual(detail, "CSR format is invalid")

    @patch("acme_srv.certificate_business_logic.csr_load")
    def test_004_validate_csr_exception(self, mock_csr_load):
        mock_csr_load.side_effect = Exception("fail")
        code, error, detail = self.logic.validate_csr("csr")
        self.assertEqual(code, 500)
        self.assertEqual(error, "Internal server error")
        self.assertEqual(detail, "CSR validation failed")

    @patch("acme_srv.certificate_business_logic.cert_dates_get")
    def test_005_calculate_certificate_dates_valid(self, mock_cert_dates_get):
        mock_cert_dates_get.return_value = (123, 456)
        issue, expire = self.logic.calculate_certificate_dates("cert")
        self.assertEqual(issue, 123)
        self.assertEqual(expire, 456)

    @patch("acme_srv.certificate_business_logic.cert_dates_get")
    def test_006_calculate_certificate_dates_exception(self, mock_cert_dates_get):
        mock_cert_dates_get.side_effect = Exception("fail")
        issue, expire = self.logic.calculate_certificate_dates("cert")
        self.assertEqual(issue, 0)
        self.assertEqual(expire, 0)

    @patch("acme_srv.certificate_business_logic.generate_random_string")
    def test_007_generate_certificate_name(self, mock_generate_random_string):
        mock_generate_random_string.return_value = "randomname"
        name = self.logic.generate_certificate_name()
        self.assertEqual(name, "randomname")

    def test_008_validate_certificate_data_empty(self):
        self.assertTrue(self.logic.validate_certificate_data(""))

    def test_009_validate_certificate_data_pem(self):
        pem = "-----BEGIN CERTIFICATE-----\n..."
        self.assertTrue(self.logic.validate_certificate_data(pem))

    def test_010_validate_certificate_data_other(self):
        self.assertTrue(self.logic.validate_certificate_data("something else"))

    def test_011_validate_certificate_data_exception(self):
        # Ensure a logger object exists to avoid AttributeError
        logic = CertificateBusinessLogic(debug=True, logger=MagicMock())
        # purposely pass an object that could raise internally; method should still return True
        self.assertTrue(logic.validate_certificate_data(object()))

    @patch("acme_srv.certificate_business_logic.cert_serial_get")
    @patch("acme_srv.certificate_business_logic.cert_cn_get")
    @patch("acme_srv.certificate_business_logic.cert_san_get")
    @patch("acme_srv.certificate_business_logic.cert_aki_get")
    @patch.object(CertificateBusinessLogic, "calculate_certificate_dates")
    def test_012_extract_certificate_info(
        self, mock_dates, mock_aki, mock_san, mock_cn, mock_serial
    ):
        mock_serial.return_value = "serial"
        mock_cn.return_value = "cn"
        mock_san.return_value = ["san1", "san2"]
        mock_aki.return_value = "aki"
        mock_dates.return_value = (111, 222)
        info = self.logic.extract_certificate_info("cert")
        self.assertEqual(info["serial"], "serial")
        self.assertEqual(info["cn"], "cn")
        self.assertEqual(info["san"], "['san1', 'san2']")
        self.assertEqual(info["aki"], "aki")
        self.assertEqual(info["issue_date"], 111)
        self.assertEqual(info["expire_date"], 222)

    @patch(
        "acme_srv.certificate_business_logic.cert_serial_get",
        side_effect=Exception("fail"),
    )
    def test_013_extract_certificate_info_exception(self, mock_serial):
        info = self.logic.extract_certificate_info("cert")
        self.assertEqual(info, {})

    @patch("acme_srv.certificate_business_logic.string_sanitize")
    def test_014_sanitize_certificate_name(self, mock_string_sanitize):
        mock_string_sanitize.return_value = "sanitized"
        result = self.logic.sanitize_certificate_name("name")
        self.assertEqual(result, "sanitized")

    @patch(
        "acme_srv.certificate_business_logic.string_sanitize",
        side_effect=Exception("fail"),
    )
    def test_015_sanitize_certificate_name_exception(self, mock_string_sanitize):
        result = self.logic.sanitize_certificate_name("name")
        self.assertEqual(result, "name")

    def test_016_format_certificate_response_with_cert(self):
        result = self.logic.format_certificate_response("cert", 201)
        self.assertEqual(result["code"], 201)
        self.assertEqual(result["data"], "cert")
        self.assertIn("headers", result)
        self.assertEqual(
            result["headers"], {"Content-Type": "application/pem-certificate-chain"}
        )

    def test_017_format_certificate_response_without_cert(self):
        result = self.logic.format_certificate_response("", 404)
        self.assertEqual(result["code"], 404)
        self.assertEqual(result["data"], "")
        self.assertNotIn("headers", result)


if __name__ == "__main__":
    unittest.main()
