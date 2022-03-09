#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for acme2certifier """
# pylint: disable= C0415, W0212
import unittest
import sys
import os
from OpenSSL import crypto
from unittest.mock import patch, Mock, MagicMock
import requests

sys.path.insert(0, '.')
sys.path.insert(1, '..')

class TestACMEHandler(unittest.TestCase):
    """ test class for cgi_handler """

    def setUp(self):
        """ setup unittest """
        import logging
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')
        from examples.ca_handler.mscertsrv_ca_handler import CAhandler, _get_certificates
        self.cahandler = CAhandler(False, self.logger)
        self._get_certificates = _get_certificates
        self.dir_path = os.path.dirname(os.path.realpath(__file__))

    def test_001_default(self):
        """ default test which always passes """
        self.assertEqual('foo', 'foo')

    def test_002_get_certificates(self):
        """ test pkcs7 convrt to pem """
        cert_pem_list = []
        with open(self.dir_path + '/ca/certs.p7b', 'r') as fso:
            pkcs7 = crypto.load_pkcs7_data(crypto.FILETYPE_PEM, fso.read())
            cert_list = self._get_certificates(pkcs7)

            for cert in cert_list:
                cert_pem_list.append(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        result = [b'-----BEGIN CERTIFICATE-----\nMIIFTzCCAzegAwIBAgIIAzHyhSyrXfMwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MTM1\nNDAwWhcNMzAwNTI2MjM1OTAwWjAqMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEP\nMA0GA1UEAxMGc3ViLWNhMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA\nxXHaGZsolXe+PBdUryngHP9VbBC1mehqeTtYI+hqsqGNH7q9a7bSrxMwFuF1kYL8\njqqxkJdtl0L94xcxJg/ZdMx7Nt0vGI+BaAuTpEpUEHeN4tqS6NhB/m/0LGkAELc/\nqkzmoO4B1FDwEEj/3IXtZcupqG80oDt7jWSGXdtF7NTjzcumznMeRXidCdhxRxT/\n/WrsChaytXo0xWZ56oeNwd6x6Dr8/39PBOWtj4fldyDcg+Q+alci2tx9pxmu2bCV\nXcB9ftCLKhDk2WEHE88bgKSp7fV2RCmq9po+Tx8JJ7qecLunUsK/F0XN4kpoQLm9\nhcymqchnMSncSiyin1dQHGHWgXDtBDdq6A2Z6rx26Qk5H9HTYvcNSe1YwFEDoGLB\nZQjbCPWiaqoaH4agBQTclPvrrSCRaVmhUSO+pBtSXDkmN4t3MDZxfgRkp8ixwkB1\n5Y5f0LTpCyAJsdQDw8+Ea0aDqO30eskh4CErnm9+Fejd9Ew2cwpdwfBXzVSbYilM\nGueQihZHvJmVRxAwU69aO2Qs8B0tQ60CfWKVlmWPiakrvYYlPp0FBsM61G6LZEN8\nhH2CKnS8hHv5IWEXZvp0Pk8V3P5h6bWN0Tl+x/V1Prt7Wp8NoiPETE8XyDDxe6dm\nKxztWBH/mTsJyMGb6ZiUoXdPU9TFUKqHxTRLHaxfsPsCAwEAAaN4MHYwEgYDVR0T\nAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQUv96OjgYiIqutQ8jd1E+oq0hBPtUwDgYD\nVR0PAQH/BAQDAgGGMBEGCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYP\neGNhIGNlcnRpZmljYXRlMA0GCSqGSIb3DQEBCwUAA4ICAQBbHLEVyg4f9uEujroc\n31UVyDRLMdPgEPLjOenSBCBmH0N81whDmxNI/7JAAB6J14WMX8OLF0HkZnb7G77W\nvDhy1aFvQFbXHBz3/zUO9Mw9J4L2XEW6ond3Nsh1m2oXeBde3R3ANxuIzHqZDlP9\n6YrRcHjnf4+1/5AKDJAvJD+gFb5YnYUKH2iSvHUvG17xcZx98Rf2eo8LealG4JqH\nJh4sKRy0VjDQD7jXSCbweTHEb8wz+6OfNGrIo+BhTFP5vPcwE4nlJwYBoaOJ5cVa\n7gdQJ7WkLSxvwHxuxzvSVK73u3jl3I9SqTrbMLG/jeJyV0P8EvdljOaGnCtQVRwC\nzM4ptXUvKhKOHy7/nyTF/Bc35ZwwL/2xWvNK1+NibgE/6CFxupwWpdmxQbVVuoQ3\n2tUil9ty0yC6m5GKE8+t1lrZuxyA+b/TBnYNO5xo8UEMbkpxaNYSwmw+f/loxXP/\nM7sIBcLvy2ugHEBxwd9o/kLXeXT2DaRvxPjp4yk8MpJRpNmz3aB5HJwaUnaRLVo5\nZ3XWWXmjMGZ6/m0AAoDbDz/pXtOoJZT8BJdD1DuDdszVsQnLVn4B/LtIXL6FbXsF\nzfv6ERP9a5gpKUZ+4NjgrnlGtdccNZpwyWF0IXcvaq3b8hXIRO4hMjzHeHfzJN4t\njX1vlY35Ofonc4+6dRVamBiF9A==\n-----END CERTIFICATE-----\n', b'-----BEGIN CERTIFICATE-----\nMIIFcDCCA1igAwIBAgIIevLTTxOMoZgwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MDAw\nMDAwWhcNMzAwNTI2MjM1OTU5WjArMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEQ\nMA4GA1UEAxMHcm9vdC1jYTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB\nAJy4UZHdZgYt64k/rFamoC676tYvtabeuiqVw1c6oVZI897cFLG6BYwyr2Eaj7tF\nrqTJDeMN4vZSudLsmLDq6m8KwX/riPzUTIlcjM5aIMANZr9rLEs3NWtcivolB5aQ\n1slhdVitUPLuxsFnYeQTyxFyP7lng9M/Z403KLG8phdmKjM0vJkaj4OuKOXf3UsW\nqWQYyRl/ms07xVj02uq08LkoeO+jtQisvyVXURdaCceZtyK/ZBQ7NFCsbK112cVR\n1e2aJol7NJAA6Wm6iBzAdkAA2l3kh40SLoEbaiaVMixLN2vilIZOOAoDXX4+T6ir\n+KnDVSJ2yu5c/OJMwuXwHrh7Lgg1vsFR5TNehknhjUuWOUO+0TkKPg2A7KTg72OZ\n2mOcLZIbxzr1P5RRvdmLQLPrTF2EJvpQPNmbXqN3ZVWEvfHTjkkTFY/dsOTvFTgS\nri15zYKch8votcU7z+BQhgmMtwO2JhPMmZ6ABd9skI7ijWpwOltAhxtdoBO6T6CB\nCrE2yXc6V/PyyAKcFglNmIght5oXsnE+ub/dtx8f9Iea/xNPdo5aGy8fdaitolDK\n16kd3Kb7OE4HMHIwOxxF1BEAqerxxhbLMRBr8hRSZI5cvLzWLvpAQ5zuhjD6V3b9\nBYFd4ujAu3zl3mbzdbYjFoGOX6aBZaGDxlc4O2W7HxntAgMBAAGjgZcwgZQwDwYD\nVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUDGVvuTFYZtEAkz3af9wRKDDvAswwHwYD\nVR0jBBgwFoAUDGVvuTFYZtEAkz3af9wRKDDvAswwDgYDVR0PAQH/BAQDAgGGMBEG\nCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYPeGNhIGNlcnRpZmljYXRl\nMA0GCSqGSIb3DQEBCwUAA4ICAQAjko7dX+iCgT+m3Iy1Vg6j7MRevPAzq1lqHRRN\nNdt2ct530pIut7Fv5V2xYk35ka+i/G+XyOvTXa9vAUKiBtiRnUPsXu4UcS7CcrCX\nEzHx4eOtHnp5wDhO0Fx5/OUZTaP+L7Pd1GD/j953ibx5bMa/M9Rj+S486nst57tu\nDRmEAavFDiMd6L3jH4YSckjmIH2uSeDIaRa9k6ag077XmWhvVYQ9tuR7RGbSuuV3\nFc6pqcFbbWpoLhNRcFc+hbUKOsKl2cP+QEKP/H2s3WMllqgAKKZeO+1KOsGo1CDs\n475bIXyCBpFbH2HOPatmu3yZRQ9fj9ta9EW46n33DFRNLinFWa4WJs4yLVP1juge\n2TCOyA1t61iy++RRXSG3e7NFYrEZuCht1EdDAdzIUY89m9NCPwoDYS4CahgnfkkO\n7YQe6f6yqK6isyf8ZFcp1uF58eERDiF/FDqS8nLmCdURuI56DDoNvDpig5J/9RNW\nG8vEvt2p7QrjeZ3EAatx5JuYty/NKTHZwJWk51CgzEgzDwzE2JIiqeldtL5d0Sl6\neVuv0G04BEyuXxEWpgVVzBS4qEFIBSnTJzgu1PXmId3yLvg2Nr8NKvwyZmN5xKFp\n0A9BWo15zW1PXDaD+l39oTYD7agjXkzTAjYIcfNJ7ATIYFD0xAvNAOf70s7aNupF\nfvkG2Q==\n-----END CERTIFICATE-----\n']
        self.assertEqual(result, cert_pem_list)

    @patch('OpenSSL.crypto._lib.sk_X509_num')
    def test_003_get_certificates(self, mock_num):
        """ test get_certificates to cover cornercases """
        mock_num.return_value = 0
        input = Mock()
        input.type_is_signed = Mock(return_value=None)
        self.assertFalse(self._get_certificates(input))

    def test_004__pkcs7_to_pem(self):
        """ test pkcs7 to pem default output """
        with open(self.dir_path + '/ca/certs.p7b', 'r') as fso:
            file_content = fso.read()
        with open(self.dir_path + '/ca/certs.pem', 'r') as fso:
            result = fso.read()
        self.assertEqual(result, self.cahandler._pkcs7_to_pem(file_content))

    def test_005__pkcs7_to_pem(self):
        """ test pkcs7 to pem output string """
        with open(self.dir_path + '/ca/certs.p7b', 'r') as fso:
            file_content = fso.read()
        with open(self.dir_path + '/ca/certs.pem', 'r') as fso:
            result = fso.read()
        self.assertEqual(result, self.cahandler._pkcs7_to_pem(file_content, 'string'))

    def test_006__pkcs7_to_pem(self):
        """ test pkcs7 to pem output list """
        with open(self.dir_path + '/ca/certs.p7b', 'r') as fso:
            file_content = fso.read()
        result = ['-----BEGIN CERTIFICATE-----\nMIIFTzCCAzegAwIBAgIIAzHyhSyrXfMwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MTM1\nNDAwWhcNMzAwNTI2MjM1OTAwWjAqMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEP\nMA0GA1UEAxMGc3ViLWNhMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA\nxXHaGZsolXe+PBdUryngHP9VbBC1mehqeTtYI+hqsqGNH7q9a7bSrxMwFuF1kYL8\njqqxkJdtl0L94xcxJg/ZdMx7Nt0vGI+BaAuTpEpUEHeN4tqS6NhB/m/0LGkAELc/\nqkzmoO4B1FDwEEj/3IXtZcupqG80oDt7jWSGXdtF7NTjzcumznMeRXidCdhxRxT/\n/WrsChaytXo0xWZ56oeNwd6x6Dr8/39PBOWtj4fldyDcg+Q+alci2tx9pxmu2bCV\nXcB9ftCLKhDk2WEHE88bgKSp7fV2RCmq9po+Tx8JJ7qecLunUsK/F0XN4kpoQLm9\nhcymqchnMSncSiyin1dQHGHWgXDtBDdq6A2Z6rx26Qk5H9HTYvcNSe1YwFEDoGLB\nZQjbCPWiaqoaH4agBQTclPvrrSCRaVmhUSO+pBtSXDkmN4t3MDZxfgRkp8ixwkB1\n5Y5f0LTpCyAJsdQDw8+Ea0aDqO30eskh4CErnm9+Fejd9Ew2cwpdwfBXzVSbYilM\nGueQihZHvJmVRxAwU69aO2Qs8B0tQ60CfWKVlmWPiakrvYYlPp0FBsM61G6LZEN8\nhH2CKnS8hHv5IWEXZvp0Pk8V3P5h6bWN0Tl+x/V1Prt7Wp8NoiPETE8XyDDxe6dm\nKxztWBH/mTsJyMGb6ZiUoXdPU9TFUKqHxTRLHaxfsPsCAwEAAaN4MHYwEgYDVR0T\nAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQUv96OjgYiIqutQ8jd1E+oq0hBPtUwDgYD\nVR0PAQH/BAQDAgGGMBEGCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYP\neGNhIGNlcnRpZmljYXRlMA0GCSqGSIb3DQEBCwUAA4ICAQBbHLEVyg4f9uEujroc\n31UVyDRLMdPgEPLjOenSBCBmH0N81whDmxNI/7JAAB6J14WMX8OLF0HkZnb7G77W\nvDhy1aFvQFbXHBz3/zUO9Mw9J4L2XEW6ond3Nsh1m2oXeBde3R3ANxuIzHqZDlP9\n6YrRcHjnf4+1/5AKDJAvJD+gFb5YnYUKH2iSvHUvG17xcZx98Rf2eo8LealG4JqH\nJh4sKRy0VjDQD7jXSCbweTHEb8wz+6OfNGrIo+BhTFP5vPcwE4nlJwYBoaOJ5cVa\n7gdQJ7WkLSxvwHxuxzvSVK73u3jl3I9SqTrbMLG/jeJyV0P8EvdljOaGnCtQVRwC\nzM4ptXUvKhKOHy7/nyTF/Bc35ZwwL/2xWvNK1+NibgE/6CFxupwWpdmxQbVVuoQ3\n2tUil9ty0yC6m5GKE8+t1lrZuxyA+b/TBnYNO5xo8UEMbkpxaNYSwmw+f/loxXP/\nM7sIBcLvy2ugHEBxwd9o/kLXeXT2DaRvxPjp4yk8MpJRpNmz3aB5HJwaUnaRLVo5\nZ3XWWXmjMGZ6/m0AAoDbDz/pXtOoJZT8BJdD1DuDdszVsQnLVn4B/LtIXL6FbXsF\nzfv6ERP9a5gpKUZ+4NjgrnlGtdccNZpwyWF0IXcvaq3b8hXIRO4hMjzHeHfzJN4t\njX1vlY35Ofonc4+6dRVamBiF9A==\n-----END CERTIFICATE-----\n', '-----BEGIN CERTIFICATE-----\nMIIFcDCCA1igAwIBAgIIevLTTxOMoZgwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MDAw\nMDAwWhcNMzAwNTI2MjM1OTU5WjArMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEQ\nMA4GA1UEAxMHcm9vdC1jYTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB\nAJy4UZHdZgYt64k/rFamoC676tYvtabeuiqVw1c6oVZI897cFLG6BYwyr2Eaj7tF\nrqTJDeMN4vZSudLsmLDq6m8KwX/riPzUTIlcjM5aIMANZr9rLEs3NWtcivolB5aQ\n1slhdVitUPLuxsFnYeQTyxFyP7lng9M/Z403KLG8phdmKjM0vJkaj4OuKOXf3UsW\nqWQYyRl/ms07xVj02uq08LkoeO+jtQisvyVXURdaCceZtyK/ZBQ7NFCsbK112cVR\n1e2aJol7NJAA6Wm6iBzAdkAA2l3kh40SLoEbaiaVMixLN2vilIZOOAoDXX4+T6ir\n+KnDVSJ2yu5c/OJMwuXwHrh7Lgg1vsFR5TNehknhjUuWOUO+0TkKPg2A7KTg72OZ\n2mOcLZIbxzr1P5RRvdmLQLPrTF2EJvpQPNmbXqN3ZVWEvfHTjkkTFY/dsOTvFTgS\nri15zYKch8votcU7z+BQhgmMtwO2JhPMmZ6ABd9skI7ijWpwOltAhxtdoBO6T6CB\nCrE2yXc6V/PyyAKcFglNmIght5oXsnE+ub/dtx8f9Iea/xNPdo5aGy8fdaitolDK\n16kd3Kb7OE4HMHIwOxxF1BEAqerxxhbLMRBr8hRSZI5cvLzWLvpAQ5zuhjD6V3b9\nBYFd4ujAu3zl3mbzdbYjFoGOX6aBZaGDxlc4O2W7HxntAgMBAAGjgZcwgZQwDwYD\nVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUDGVvuTFYZtEAkz3af9wRKDDvAswwHwYD\nVR0jBBgwFoAUDGVvuTFYZtEAkz3af9wRKDDvAswwDgYDVR0PAQH/BAQDAgGGMBEG\nCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYPeGNhIGNlcnRpZmljYXRl\nMA0GCSqGSIb3DQEBCwUAA4ICAQAjko7dX+iCgT+m3Iy1Vg6j7MRevPAzq1lqHRRN\nNdt2ct530pIut7Fv5V2xYk35ka+i/G+XyOvTXa9vAUKiBtiRnUPsXu4UcS7CcrCX\nEzHx4eOtHnp5wDhO0Fx5/OUZTaP+L7Pd1GD/j953ibx5bMa/M9Rj+S486nst57tu\nDRmEAavFDiMd6L3jH4YSckjmIH2uSeDIaRa9k6ag077XmWhvVYQ9tuR7RGbSuuV3\nFc6pqcFbbWpoLhNRcFc+hbUKOsKl2cP+QEKP/H2s3WMllqgAKKZeO+1KOsGo1CDs\n475bIXyCBpFbH2HOPatmu3yZRQ9fj9ta9EW46n33DFRNLinFWa4WJs4yLVP1juge\n2TCOyA1t61iy++RRXSG3e7NFYrEZuCht1EdDAdzIUY89m9NCPwoDYS4CahgnfkkO\n7YQe6f6yqK6isyf8ZFcp1uF58eERDiF/FDqS8nLmCdURuI56DDoNvDpig5J/9RNW\nG8vEvt2p7QrjeZ3EAatx5JuYty/NKTHZwJWk51CgzEgzDwzE2JIiqeldtL5d0Sl6\neVuv0G04BEyuXxEWpgVVzBS4qEFIBSnTJzgu1PXmId3yLvg2Nr8NKvwyZmN5xKFp\n0A9BWo15zW1PXDaD+l39oTYD7agjXkzTAjYIcfNJ7ATIYFD0xAvNAOf70s7aNupF\nfvkG2Q==\n-----END CERTIFICATE-----\n']
        self.assertEqual(result, self.cahandler._pkcs7_to_pem(file_content, 'list'))

    def test_007__pkcs7_to_pem(self):
        """ test pkcs7 to pem output list """
        with open(self.dir_path + '/ca/certs.p7b', 'r') as fso:
            file_content = fso.read()
        result = None
        self.assertEqual(result, self.cahandler._pkcs7_to_pem(file_content, 'unknown'))

    @patch('OpenSSL.crypto.load_pkcs7_data')
    def test_008__pkcs7_to_pem(self, mock_load):
        """ test pkcs7 to pem output list """
        with open(self.dir_path + '/ca/certs.p7b', 'r') as fso:
            file_content = fso.read()
        # mock_load.side_effects = Exception('exc_load_pkcs7')
        mock_load.return_value = None
        result = None
        self.assertEqual(result, self.cahandler._pkcs7_to_pem(file_content, 'unknown'))

    @patch('OpenSSL.crypto.load_pkcs7_data')
    def test_009__pkcs7_to_pem(self, mock_load):
        """ test pkcs7 to pem exceptin """
        with open(self.dir_path + '/ca/certs.p7b', 'r') as fso:
            file_content = fso.read()
        mock_load.side_effect = Exception('foo')
        result = None
        self.assertEqual(result, self.cahandler._pkcs7_to_pem(file_content, 'unknown'))

    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_010_config_load(self, mock_load_cfg):
        """ test _config_load no cahandler section """
        mock_load_cfg.return_value = {}
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual('basic', self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)

    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_011_config_load(self, mock_load_cfg):
        """ test _config_load cahandler section with unknown values """
        mock_load_cfg.return_value = {'CAhandler': {'foo': 'bar'}}
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual('basic', self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)

    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_012_config_load(self, mock_load_cfg):
        """ test _config_load no cahandler section with host value """
        mock_load_cfg.return_value = {'CAhandler': {'host': 'host'}}
        self.cahandler._config_load()
        self.assertEqual('host', self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual('basic', self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)

    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_013_config_load(self, mock_load_cfg):
        """ test _config_load cahandler section with user values """
        mock_load_cfg.return_value = {'CAhandler': {'user': 'user'}}
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertEqual('user', self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual('basic', self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)

    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_014_config_load(self, mock_load_cfg):
        """ test _config_load cahandler section with password values """
        mock_load_cfg.return_value = {'CAhandler': {'password': 'password'}}
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertEqual('password', self.cahandler.password)
        self.assertEqual('basic', self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)

    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_015_config_load(self, mock_load_cfg):
        """ test _config_load cahandler section with authmethod basic """
        mock_load_cfg.return_value = {'CAhandler': {'auth_method': 'basic'}}
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual('basic', self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)

    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_016_config_load(self, mock_load_cfg):
        """ test _config_load cahandler section with authmethod ntlm """
        mock_load_cfg.return_value = {'CAhandler': {'auth_method': 'ntlm'}}
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual('ntlm', self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)

    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_017_config_load(self, mock_load_cfg):
        """ test _config_load cahandler section with authmethod unknown """
        mock_load_cfg.return_value = {'CAhandler': {'auth_method': 'unknown'}}
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual('basic', self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)

    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_018_config_load(self, mock_load_cfg):
        """ test _config_load cahandler section with ca_bundle value """
        mock_load_cfg.return_value = {'CAhandler': {'ca_bundle': 'ca_bundle'}}
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual('basic', self.cahandler.auth_method)
        self.assertEqual('ca_bundle', self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)

    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_019_config_load(self, mock_load_cfg):
        """ test _config_load cahandler section with template value """
        mock_load_cfg.return_value = {'CAhandler': {'template': 'template'}}
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual('basic', self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertEqual('template', self.cahandler.template)

    @patch.dict('os.environ', {'host_variable': 'host'})
    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_020_config_load(self, mock_load_cfg):
        """ test _config_load - load with host variable """
        mock_load_cfg.return_value = {'CAhandler': {'host_variable': 'host_variable'}}
        self.cahandler._config_load()
        self.assertEqual('host', self.cahandler.host)

    @patch.dict('os.environ', {'host_variable': 'host'})
    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_021_config_load(self, mock_load_cfg):
        """ test _config_load - load with host variable which does not exist """
        mock_load_cfg.return_value = {'CAhandler': {'host_variable': 'doesnotexist'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertIn("ERROR:test_a2c:CAhandler._config_load() could not load host_variable:'doesnotexist'", lcm.output)

    @patch.dict('os.environ', {'host_variable': 'host'})
    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_022_config_load(self, mock_load_cfg):
        """ test _config_load - load with host variable which gets overwritten """
        mock_load_cfg.return_value = {'CAhandler': {'host_variable': 'host_variable', 'host': 'host_local'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertEqual('host_local', self.cahandler.host)
        self.assertIn('INFO:test_a2c:CAhandler._config_load() overwrite host', lcm.output)

    @patch.dict('os.environ', {'user_variable': 'user'})
    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_023_config_load(self, mock_load_cfg):
        """ test _config_load - load with user variable """
        mock_load_cfg.return_value = {'CAhandler': {'user_variable': 'user_variable'}}
        self.cahandler._config_load()
        self.assertEqual('user', self.cahandler.user)

    @patch.dict('os.environ', {'user_variable': 'user'})
    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_024_config_load(self, mock_load_cfg):
        """ test _config_load - load with user variable which does not exist """
        mock_load_cfg.return_value = {'CAhandler': {'user_variable': 'doesnotexist'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.user)
        self.assertIn("ERROR:test_a2c:CAhandler._config_load() could not load user_variable:'doesnotexist'", lcm.output)

    @patch.dict('os.environ', {'user_variable': 'user'})
    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_025_config_load(self, mock_load_cfg):
        """ test _config_load - load with user variable which gets overwritten """
        mock_load_cfg.return_value = {'CAhandler': {'user_variable': 'user_variable', 'user': 'user_local'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertEqual('user_local', self.cahandler.user)
        self.assertIn('INFO:test_a2c:CAhandler._config_load() overwrite user', lcm.output)

    @patch.dict('os.environ', {'password_variable': 'password'})
    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_026_config_load(self, mock_load_cfg):
        """ test _config_load - load with password variable """
        mock_load_cfg.return_value = {'CAhandler': {'password_variable': 'password_variable'}}
        self.cahandler._config_load()
        self.assertEqual('password', self.cahandler.password)

    @patch.dict('os.environ', {'password_variable': 'password'})
    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_027_config_load(self, mock_load_cfg):
        """ test _config_load - load with password variable which does not exist """
        mock_load_cfg.return_value = {'CAhandler': {'password_variable': 'doesnotexist'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.password)
        self.assertIn("ERROR:test_a2c:CAhandler._config_load() could not load password_variable:'doesnotexist'", lcm.output)

    @patch.dict('os.environ', {'password_variable': 'password'})
    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_028_config_load(self, mock_load_cfg):
        """ test _config_load - load with password variable which gets overwritten """
        mock_load_cfg.return_value = {'CAhandler': {'password_variable': 'password_variable', 'password': 'password_local'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertEqual('password_local', self.cahandler.password)
        self.assertIn('INFO:test_a2c:CAhandler._config_load() overwrite password', lcm.output)

    @patch('examples.ca_handler.mscertsrv_ca_handler.proxy_check')
    @patch('json.loads')
    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_029_config_load(self, mock_load_cfg, mock_json, mock_chk):
        """ test _config_load ca_handler configured load proxies """
        mock_load_cfg.return_value = {'DEFAULT': {'proxy_server_list': 'foo'}}
        mock_json.return_value = 'foo.bar.local'
        mock_chk.return_value = 'proxy.bar.local'
        self.cahandler._config_load()
        self.assertTrue(mock_json.called)
        self.assertTrue(mock_chk.called)
        self.assertEqual({'http': 'proxy.bar.local', 'https': 'proxy.bar.local'},self.cahandler.proxy )

    @patch('examples.ca_handler.mscertsrv_ca_handler.proxy_check')
    @patch('json.loads')
    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_030_config_load(self, mock_load_cfg, mock_json, mock_chk):
        """ test _config_load ca_handler configured load proxies failed with exception in json.load """
        mock_load_cfg.return_value = {'DEFAULT': {'proxy_server_list': 'foo'}}
        mock_json.side_effect = Exception('exc_load_config')
        mock_chk.side = 'proxy.bar.local'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertTrue(mock_json.called)
        self.assertFalse(mock_chk.called)
        self.assertFalse(self.cahandler.proxy )
        self.assertIn('WARNING:test_a2c:CAhandler._config_load() proxy_server_list failed with error: exc_load_config', lcm.output)

    def test_031_revoke(self):
        """ test revocation """
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'Revocation is not supported.'), self.cahandler.revoke('cert', 'rev_reason', 'rev_date'))

    def test_032_poll(self):
        """ test polling """
        self.assertEqual(('Method not implemented.', None, None, 'poll_identifier', False), self.cahandler.poll('cert_name', 'poll_identifier', 'csr'))

    def test_033_trigger(self):
        """ test polling """
        self.assertEqual(('Method not implemented.', None, None), self.cahandler.trigger('payload'))

    def test_034_check_credentials(self):
        """ test polling """
        ca_server = Mock()
        ca_server.check_credentials = Mock(return_value=True)
        self.assertTrue(self.cahandler._check_credentials(ca_server))

    def test_035_check_credentials(self):
        """ test polling """
        ca_server = Mock()
        ca_server.check_credentials = Mock(return_value=False)
        self.assertFalse(self.cahandler._check_credentials(ca_server))

    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._config_load')
    def test_036__enter__(self, mock_cfg):
        """ test enter  called """
        mock_cfg.return_value = True
        self.cahandler.__enter__()
        self.assertTrue(mock_cfg.called)

    def test_037_enroll(self):
        """ enroll without having self.host """
        self.assertEqual(('Config incomplete', None, None, None), self.cahandler.enroll('csr'))

    def test_038_enroll(self):
        """ enroll without having self.user """
        self.cahandler.host = 'host'
        self.assertEqual(('Config incomplete', None, None, None), self.cahandler.enroll('csr'))

    def test_039_enroll(self):
        """ enroll without having self.password """
        self.cahandler.host = 'host'
        self.cahandler.user = 'user'
        self.assertEqual(('Config incomplete', None, None, None), self.cahandler.enroll('csr'))

    def test_040_enroll(self):
        """ enroll without having self.template """
        self.cahandler.host = 'host'
        self.cahandler.user = 'user'
        self.cahandler.password = 'password'
        self.assertEqual(('Config incomplete', None, None, None), self.cahandler.enroll('csr'))

    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._check_credentials')
    @patch('certsrv.Certsrv')
    def test_041_enroll(self, mock_certserver, mock_credchk):
        """ enroll credential check failed """
        self.cahandler.host = 'host'
        self.cahandler.user = 'user'
        self.cahandler.password = 'password'
        self.cahandler.template = 'template'
        mock_certserver.return_value = 'foo'
        mock_credchk.return_value = False
        self.assertEqual(('Connection or Credentialcheck failed.', None, None, None), self.cahandler.enroll('csr'))

    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._pkcs7_to_pem')
    @patch('examples.ca_handler.mscertsrv_ca_handler.convert_byte_to_string')
    @patch('textwrap.fill')
    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._check_credentials')
    @patch('examples.ca_handler.mscertsrv_ca_handler.Certsrv')
    def test_042_enroll(self, mock_certserver, mock_credchk, mockwrap, mock_b2s, mock_p2p):
        """ enroll enroll successful """
        self.cahandler.host = 'host'
        self.cahandler.user = 'user'
        self.cahandler.password = 'password'
        self.cahandler.template = 'template'
        mockresponse = MagicMock()
        mockresponse.get_chain.return_value = "get_chain"
        mockresponse.get_cert.return_value = "get_cert"
        mock_certserver = mockresponse
        mock_credchk.return_value = True
        mockwrap.return_value = 'mockwrap'
        mock_b2s.side_effect = ['get_chain', 'get_cert']
        mock_p2p.return_value = 'p2p'
        self.assertEqual((None, 'get_certp2p', 'get_cert', None), self.cahandler.enroll('csr'))

    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._pkcs7_to_pem')
    @patch('examples.ca_handler.mscertsrv_ca_handler.convert_byte_to_string')
    @patch('textwrap.fill')
    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._check_credentials')
    @patch('examples.ca_handler.mscertsrv_ca_handler.Certsrv')
    def test_043_enroll(self, mock_certserver, mock_credchk, mockwrap, mock_b2s, mock_p2p):
        """ enroll exceütption in get chain """
        self.cahandler.host = 'host'
        self.cahandler.user = 'user'
        self.cahandler.password = 'password'
        self.cahandler.template = 'template'
        mockresponse = MagicMock()
        mockresponse.get_chain.return_value = 'get_chain'
        mockresponse.get_cert.return_value = "get_cert"
        mock_certserver = mockresponse
        mock_credchk.return_value = True
        mockwrap.return_value = 'mockwrap'
        mock_b2s.side_effect = [Exception('exc_get_chain'), 'get_cert']
        mock_p2p.return_value = 'p2p'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('cert bundling failed', None, 'get_cert', None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:ca_server.get_chain() failed with error: exc_get_chain', lcm.output)
        self.assertIn('ERROR:test_a2c:cert bundling failed', lcm.output)

    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._pkcs7_to_pem')
    @patch('examples.ca_handler.mscertsrv_ca_handler.convert_byte_to_string')
    @patch('textwrap.fill')
    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._check_credentials')
    @patch('examples.ca_handler.mscertsrv_ca_handler.Certsrv')
    def test_044_enroll(self, mock_certserver, mock_credchk, mockwrap, mock_b2s, mock_p2p):
        """ enroll exceütption in get cert """
        self.cahandler.host = 'host'
        self.cahandler.user = 'user'
        self.cahandler.password = 'password'
        self.cahandler.template = 'template'
        mockresponse = MagicMock()
        mockresponse.get_chain.return_value = 'get_chain'
        mockresponse.get_cert.return_value = "get_cert"
        mock_certserver = mockresponse
        mock_credchk.return_value = True
        mockwrap.return_value = 'mockwrap'
        mock_b2s.side_effect = ['exc_get_chain', Exception('get_cert')]
        mock_p2p.return_value = 'p2p'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('cert bundling failed', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:ca_server.get_cert() failed with error: get_cert', lcm.output)
        self.assertIn('ERROR:test_a2c:cert bundling failed', lcm.output)

if __name__ == '__main__':

    unittest.main()
