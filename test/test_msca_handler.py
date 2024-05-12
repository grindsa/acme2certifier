#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for acme2certifier """
# pylint: disable= C0415, W0212
import unittest
import sys
import os
from unittest.mock import patch, Mock, MagicMock
import base64
import configparser

sys.path.insert(0, '.')
sys.path.insert(1, '..')

class TestACMEHandler(unittest.TestCase):
    """ test class for cgi_handler """

    def setUp(self):
        """ setup unittest """
        import logging
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')
        from examples.ca_handler.mscertsrv_ca_handler import CAhandler
        self.cahandler = CAhandler(False, self.logger)
        self.dir_path = os.path.dirname(os.path.realpath(__file__))

    def test_001_default(self):
        """ default test which always passes """
        self.assertEqual('foo', 'foo')

    def test_002__pkcs7_to_pem(self):
        """ test pkcs7 to pem default output """
        with open(self.dir_path + '/ca/certs.p7b', 'r') as fso:
            file_content = fso.read()
        with open(self.dir_path + '/ca/certs.pem', 'r') as fso:
            result = fso.read()
        self.assertEqual(result, self.cahandler._pkcs7_to_pem(file_content))

    def test_003__pkcs7_to_pem(self):
        """ test pkcs7 to pem output string """
        with open(self.dir_path + '/ca/certs.p7b', 'r') as fso:
            file_content = fso.read()
        with open(self.dir_path + '/ca/certs.pem', 'r') as fso:
            result = fso.read()
        self.assertEqual(result, self.cahandler._pkcs7_to_pem(file_content, 'string'))

    def test_004__pkcs7_to_pem(self):
        """ test pkcs7 to pem output list """
        with open(self.dir_path + '/ca/certs.p7b', 'r') as fso:
            file_content = fso.read()
        result = ['-----BEGIN CERTIFICATE-----\nMIIFTzCCAzegAwIBAgIIAzHyhSyrXfMwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MTM1\nNDAwWhcNMzAwNTI2MjM1OTAwWjAqMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEP\nMA0GA1UEAxMGc3ViLWNhMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA\nxXHaGZsolXe+PBdUryngHP9VbBC1mehqeTtYI+hqsqGNH7q9a7bSrxMwFuF1kYL8\njqqxkJdtl0L94xcxJg/ZdMx7Nt0vGI+BaAuTpEpUEHeN4tqS6NhB/m/0LGkAELc/\nqkzmoO4B1FDwEEj/3IXtZcupqG80oDt7jWSGXdtF7NTjzcumznMeRXidCdhxRxT/\n/WrsChaytXo0xWZ56oeNwd6x6Dr8/39PBOWtj4fldyDcg+Q+alci2tx9pxmu2bCV\nXcB9ftCLKhDk2WEHE88bgKSp7fV2RCmq9po+Tx8JJ7qecLunUsK/F0XN4kpoQLm9\nhcymqchnMSncSiyin1dQHGHWgXDtBDdq6A2Z6rx26Qk5H9HTYvcNSe1YwFEDoGLB\nZQjbCPWiaqoaH4agBQTclPvrrSCRaVmhUSO+pBtSXDkmN4t3MDZxfgRkp8ixwkB1\n5Y5f0LTpCyAJsdQDw8+Ea0aDqO30eskh4CErnm9+Fejd9Ew2cwpdwfBXzVSbYilM\nGueQihZHvJmVRxAwU69aO2Qs8B0tQ60CfWKVlmWPiakrvYYlPp0FBsM61G6LZEN8\nhH2CKnS8hHv5IWEXZvp0Pk8V3P5h6bWN0Tl+x/V1Prt7Wp8NoiPETE8XyDDxe6dm\nKxztWBH/mTsJyMGb6ZiUoXdPU9TFUKqHxTRLHaxfsPsCAwEAAaN4MHYwEgYDVR0T\nAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQUv96OjgYiIqutQ8jd1E+oq0hBPtUwDgYD\nVR0PAQH/BAQDAgGGMBEGCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYP\neGNhIGNlcnRpZmljYXRlMA0GCSqGSIb3DQEBCwUAA4ICAQBbHLEVyg4f9uEujroc\n31UVyDRLMdPgEPLjOenSBCBmH0N81whDmxNI/7JAAB6J14WMX8OLF0HkZnb7G77W\nvDhy1aFvQFbXHBz3/zUO9Mw9J4L2XEW6ond3Nsh1m2oXeBde3R3ANxuIzHqZDlP9\n6YrRcHjnf4+1/5AKDJAvJD+gFb5YnYUKH2iSvHUvG17xcZx98Rf2eo8LealG4JqH\nJh4sKRy0VjDQD7jXSCbweTHEb8wz+6OfNGrIo+BhTFP5vPcwE4nlJwYBoaOJ5cVa\n7gdQJ7WkLSxvwHxuxzvSVK73u3jl3I9SqTrbMLG/jeJyV0P8EvdljOaGnCtQVRwC\nzM4ptXUvKhKOHy7/nyTF/Bc35ZwwL/2xWvNK1+NibgE/6CFxupwWpdmxQbVVuoQ3\n2tUil9ty0yC6m5GKE8+t1lrZuxyA+b/TBnYNO5xo8UEMbkpxaNYSwmw+f/loxXP/\nM7sIBcLvy2ugHEBxwd9o/kLXeXT2DaRvxPjp4yk8MpJRpNmz3aB5HJwaUnaRLVo5\nZ3XWWXmjMGZ6/m0AAoDbDz/pXtOoJZT8BJdD1DuDdszVsQnLVn4B/LtIXL6FbXsF\nzfv6ERP9a5gpKUZ+4NjgrnlGtdccNZpwyWF0IXcvaq3b8hXIRO4hMjzHeHfzJN4t\njX1vlY35Ofonc4+6dRVamBiF9A==\n-----END CERTIFICATE-----\n', '-----BEGIN CERTIFICATE-----\nMIIFcDCCA1igAwIBAgIIevLTTxOMoZgwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MDAw\nMDAwWhcNMzAwNTI2MjM1OTU5WjArMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEQ\nMA4GA1UEAxMHcm9vdC1jYTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB\nAJy4UZHdZgYt64k/rFamoC676tYvtabeuiqVw1c6oVZI897cFLG6BYwyr2Eaj7tF\nrqTJDeMN4vZSudLsmLDq6m8KwX/riPzUTIlcjM5aIMANZr9rLEs3NWtcivolB5aQ\n1slhdVitUPLuxsFnYeQTyxFyP7lng9M/Z403KLG8phdmKjM0vJkaj4OuKOXf3UsW\nqWQYyRl/ms07xVj02uq08LkoeO+jtQisvyVXURdaCceZtyK/ZBQ7NFCsbK112cVR\n1e2aJol7NJAA6Wm6iBzAdkAA2l3kh40SLoEbaiaVMixLN2vilIZOOAoDXX4+T6ir\n+KnDVSJ2yu5c/OJMwuXwHrh7Lgg1vsFR5TNehknhjUuWOUO+0TkKPg2A7KTg72OZ\n2mOcLZIbxzr1P5RRvdmLQLPrTF2EJvpQPNmbXqN3ZVWEvfHTjkkTFY/dsOTvFTgS\nri15zYKch8votcU7z+BQhgmMtwO2JhPMmZ6ABd9skI7ijWpwOltAhxtdoBO6T6CB\nCrE2yXc6V/PyyAKcFglNmIght5oXsnE+ub/dtx8f9Iea/xNPdo5aGy8fdaitolDK\n16kd3Kb7OE4HMHIwOxxF1BEAqerxxhbLMRBr8hRSZI5cvLzWLvpAQ5zuhjD6V3b9\nBYFd4ujAu3zl3mbzdbYjFoGOX6aBZaGDxlc4O2W7HxntAgMBAAGjgZcwgZQwDwYD\nVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUDGVvuTFYZtEAkz3af9wRKDDvAswwHwYD\nVR0jBBgwFoAUDGVvuTFYZtEAkz3af9wRKDDvAswwDgYDVR0PAQH/BAQDAgGGMBEG\nCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYPeGNhIGNlcnRpZmljYXRl\nMA0GCSqGSIb3DQEBCwUAA4ICAQAjko7dX+iCgT+m3Iy1Vg6j7MRevPAzq1lqHRRN\nNdt2ct530pIut7Fv5V2xYk35ka+i/G+XyOvTXa9vAUKiBtiRnUPsXu4UcS7CcrCX\nEzHx4eOtHnp5wDhO0Fx5/OUZTaP+L7Pd1GD/j953ibx5bMa/M9Rj+S486nst57tu\nDRmEAavFDiMd6L3jH4YSckjmIH2uSeDIaRa9k6ag077XmWhvVYQ9tuR7RGbSuuV3\nFc6pqcFbbWpoLhNRcFc+hbUKOsKl2cP+QEKP/H2s3WMllqgAKKZeO+1KOsGo1CDs\n475bIXyCBpFbH2HOPatmu3yZRQ9fj9ta9EW46n33DFRNLinFWa4WJs4yLVP1juge\n2TCOyA1t61iy++RRXSG3e7NFYrEZuCht1EdDAdzIUY89m9NCPwoDYS4CahgnfkkO\n7YQe6f6yqK6isyf8ZFcp1uF58eERDiF/FDqS8nLmCdURuI56DDoNvDpig5J/9RNW\nG8vEvt2p7QrjeZ3EAatx5JuYty/NKTHZwJWk51CgzEgzDwzE2JIiqeldtL5d0Sl6\neVuv0G04BEyuXxEWpgVVzBS4qEFIBSnTJzgu1PXmId3yLvg2Nr8NKvwyZmN5xKFp\n0A9BWo15zW1PXDaD+l39oTYD7agjXkzTAjYIcfNJ7ATIYFD0xAvNAOf70s7aNupF\nfvkG2Q==\n-----END CERTIFICATE-----\n']
        self.assertEqual(result, self.cahandler._pkcs7_to_pem(file_content, 'list'))

    def test_005__pkcs7_to_pem(self):
        """ test pkcs7 to pem output list """
        with open(self.dir_path + '/ca/certs.p7b', 'r') as fso:
            file_content = fso.read()
        result = None
        self.assertEqual(result, self.cahandler._pkcs7_to_pem(file_content, 'unknown'))

    def test_006__pkcs7_to_pem(self):
        """ test pkcs7 to pem output list """

        file_content = base64.b64decode('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')
        result = ['-----BEGIN CERTIFICATE-----\nMIIFTzCCAzegAwIBAgIIAzHyhSyrXfMwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MTM1\nNDAwWhcNMzAwNTI2MjM1OTAwWjAqMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEP\nMA0GA1UEAxMGc3ViLWNhMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA\nxXHaGZsolXe+PBdUryngHP9VbBC1mehqeTtYI+hqsqGNH7q9a7bSrxMwFuF1kYL8\njqqxkJdtl0L94xcxJg/ZdMx7Nt0vGI+BaAuTpEpUEHeN4tqS6NhB/m/0LGkAELc/\nqkzmoO4B1FDwEEj/3IXtZcupqG80oDt7jWSGXdtF7NTjzcumznMeRXidCdhxRxT/\n/WrsChaytXo0xWZ56oeNwd6x6Dr8/39PBOWtj4fldyDcg+Q+alci2tx9pxmu2bCV\nXcB9ftCLKhDk2WEHE88bgKSp7fV2RCmq9po+Tx8JJ7qecLunUsK/F0XN4kpoQLm9\nhcymqchnMSncSiyin1dQHGHWgXDtBDdq6A2Z6rx26Qk5H9HTYvcNSe1YwFEDoGLB\nZQjbCPWiaqoaH4agBQTclPvrrSCRaVmhUSO+pBtSXDkmN4t3MDZxfgRkp8ixwkB1\n5Y5f0LTpCyAJsdQDw8+Ea0aDqO30eskh4CErnm9+Fejd9Ew2cwpdwfBXzVSbYilM\nGueQihZHvJmVRxAwU69aO2Qs8B0tQ60CfWKVlmWPiakrvYYlPp0FBsM61G6LZEN8\nhH2CKnS8hHv5IWEXZvp0Pk8V3P5h6bWN0Tl+x/V1Prt7Wp8NoiPETE8XyDDxe6dm\nKxztWBH/mTsJyMGb6ZiUoXdPU9TFUKqHxTRLHaxfsPsCAwEAAaN4MHYwEgYDVR0T\nAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQUv96OjgYiIqutQ8jd1E+oq0hBPtUwDgYD\nVR0PAQH/BAQDAgGGMBEGCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYP\neGNhIGNlcnRpZmljYXRlMA0GCSqGSIb3DQEBCwUAA4ICAQBbHLEVyg4f9uEujroc\n31UVyDRLMdPgEPLjOenSBCBmH0N81whDmxNI/7JAAB6J14WMX8OLF0HkZnb7G77W\nvDhy1aFvQFbXHBz3/zUO9Mw9J4L2XEW6ond3Nsh1m2oXeBde3R3ANxuIzHqZDlP9\n6YrRcHjnf4+1/5AKDJAvJD+gFb5YnYUKH2iSvHUvG17xcZx98Rf2eo8LealG4JqH\nJh4sKRy0VjDQD7jXSCbweTHEb8wz+6OfNGrIo+BhTFP5vPcwE4nlJwYBoaOJ5cVa\n7gdQJ7WkLSxvwHxuxzvSVK73u3jl3I9SqTrbMLG/jeJyV0P8EvdljOaGnCtQVRwC\nzM4ptXUvKhKOHy7/nyTF/Bc35ZwwL/2xWvNK1+NibgE/6CFxupwWpdmxQbVVuoQ3\n2tUil9ty0yC6m5GKE8+t1lrZuxyA+b/TBnYNO5xo8UEMbkpxaNYSwmw+f/loxXP/\nM7sIBcLvy2ugHEBxwd9o/kLXeXT2DaRvxPjp4yk8MpJRpNmz3aB5HJwaUnaRLVo5\nZ3XWWXmjMGZ6/m0AAoDbDz/pXtOoJZT8BJdD1DuDdszVsQnLVn4B/LtIXL6FbXsF\nzfv6ERP9a5gpKUZ+4NjgrnlGtdccNZpwyWF0IXcvaq3b8hXIRO4hMjzHeHfzJN4t\njX1vlY35Ofonc4+6dRVamBiF9A==\n-----END CERTIFICATE-----\n', '-----BEGIN CERTIFICATE-----\nMIIFcDCCA1igAwIBAgIIevLTTxOMoZgwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MDAw\nMDAwWhcNMzAwNTI2MjM1OTU5WjArMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEQ\nMA4GA1UEAxMHcm9vdC1jYTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB\nAJy4UZHdZgYt64k/rFamoC676tYvtabeuiqVw1c6oVZI897cFLG6BYwyr2Eaj7tF\nrqTJDeMN4vZSudLsmLDq6m8KwX/riPzUTIlcjM5aIMANZr9rLEs3NWtcivolB5aQ\n1slhdVitUPLuxsFnYeQTyxFyP7lng9M/Z403KLG8phdmKjM0vJkaj4OuKOXf3UsW\nqWQYyRl/ms07xVj02uq08LkoeO+jtQisvyVXURdaCceZtyK/ZBQ7NFCsbK112cVR\n1e2aJol7NJAA6Wm6iBzAdkAA2l3kh40SLoEbaiaVMixLN2vilIZOOAoDXX4+T6ir\n+KnDVSJ2yu5c/OJMwuXwHrh7Lgg1vsFR5TNehknhjUuWOUO+0TkKPg2A7KTg72OZ\n2mOcLZIbxzr1P5RRvdmLQLPrTF2EJvpQPNmbXqN3ZVWEvfHTjkkTFY/dsOTvFTgS\nri15zYKch8votcU7z+BQhgmMtwO2JhPMmZ6ABd9skI7ijWpwOltAhxtdoBO6T6CB\nCrE2yXc6V/PyyAKcFglNmIght5oXsnE+ub/dtx8f9Iea/xNPdo5aGy8fdaitolDK\n16kd3Kb7OE4HMHIwOxxF1BEAqerxxhbLMRBr8hRSZI5cvLzWLvpAQ5zuhjD6V3b9\nBYFd4ujAu3zl3mbzdbYjFoGOX6aBZaGDxlc4O2W7HxntAgMBAAGjgZcwgZQwDwYD\nVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUDGVvuTFYZtEAkz3af9wRKDDvAswwHwYD\nVR0jBBgwFoAUDGVvuTFYZtEAkz3af9wRKDDvAswwDgYDVR0PAQH/BAQDAgGGMBEG\nCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYPeGNhIGNlcnRpZmljYXRl\nMA0GCSqGSIb3DQEBCwUAA4ICAQAjko7dX+iCgT+m3Iy1Vg6j7MRevPAzq1lqHRRN\nNdt2ct530pIut7Fv5V2xYk35ka+i/G+XyOvTXa9vAUKiBtiRnUPsXu4UcS7CcrCX\nEzHx4eOtHnp5wDhO0Fx5/OUZTaP+L7Pd1GD/j953ibx5bMa/M9Rj+S486nst57tu\nDRmEAavFDiMd6L3jH4YSckjmIH2uSeDIaRa9k6ag077XmWhvVYQ9tuR7RGbSuuV3\nFc6pqcFbbWpoLhNRcFc+hbUKOsKl2cP+QEKP/H2s3WMllqgAKKZeO+1KOsGo1CDs\n475bIXyCBpFbH2HOPatmu3yZRQ9fj9ta9EW46n33DFRNLinFWa4WJs4yLVP1juge\n2TCOyA1t61iy++RRXSG3e7NFYrEZuCht1EdDAdzIUY89m9NCPwoDYS4CahgnfkkO\n7YQe6f6yqK6isyf8ZFcp1uF58eERDiF/FDqS8nLmCdURuI56DDoNvDpig5J/9RNW\nG8vEvt2p7QrjeZ3EAatx5JuYty/NKTHZwJWk51CgzEgzDwzE2JIiqeldtL5d0Sl6\neVuv0G04BEyuXxEWpgVVzBS4qEFIBSnTJzgu1PXmId3yLvg2Nr8NKvwyZmN5xKFp\n0A9BWo15zW1PXDaD+l39oTYD7agjXkzTAjYIcfNJ7ATIYFD0xAvNAOf70s7aNupF\nfvkG2Q==\n-----END CERTIFICATE-----\n']
        self.assertEqual(result, self.cahandler._pkcs7_to_pem(file_content, 'list'))

    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_007_config_load(self, mock_load_cfg):
        """ test _config_load no cahandler section """
        mock_load_cfg.return_value = {}
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual('basic', self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.krb5_config)
        self.assertFalse,(self.cahandler.allowed_domainlist)

    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_008_config_load(self, mock_load_cfg):
        """ test _config_load cahandler section with unknown values """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual('basic', self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.krb5_config)
        self.assertFalse,(self.cahandler.allowed_domainlist)

    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_009_config_load(self, mock_load_cfg):
        """ test _config_load no cahandler section with host value """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'host': 'host'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual('host', self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual('basic', self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.krb5_config)
        self.assertFalse,(self.cahandler.allowed_domainlist)

    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_010_config_load(self, mock_load_cfg):
        """ test _config_load cahandler section with user values """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'user': 'user'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertEqual('user', self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual('basic', self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.krb5_config)
        self.assertFalse,(self.cahandler.allowed_domainlist)

    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_011_config_load(self, mock_load_cfg):
        """ test _config_load cahandler section with password values """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'password': 'password'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertEqual('password', self.cahandler.password)
        self.assertEqual('basic', self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.krb5_config)
        self.assertFalse,(self.cahandler.allowed_domainlist)

    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_012_config_load(self, mock_load_cfg):
        """ test _config_load cahandler section with authmethod basic """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'auth_method': 'basic'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual('basic', self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.krb5_config)
        self.assertFalse,(self.cahandler.allowed_domainlist)

    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_013_config_load(self, mock_load_cfg):
        """ test _config_load cahandler section with authmethod ntlm """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'auth_method': 'ntlm'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual('ntlm', self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.krb5_config)
        self.assertFalse,(self.cahandler.allowed_domainlist)

    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_014_config_load(self, mock_load_cfg):
        """ test _config_load cahandler section with authmethod unknown """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'auth_method': 'unknown'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual('basic', self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.krb5_config)
        self.assertFalse,(self.cahandler.allowed_domainlist)

    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_015_config_load(self, mock_load_cfg):
        """ test _config_load cahandler section with ca_bundle value """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'ca_bundle': 'ca_bundle'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual('basic', self.cahandler.auth_method)
        self.assertEqual('ca_bundle', self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.krb5_config)
        self.assertFalse,(self.cahandler.allowed_domainlist)

    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_016_config_load(self, mock_load_cfg):
        """ test _config_load cahandler section with template value """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'template': 'template'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual('basic', self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertEqual('template', self.cahandler.template)
        self.assertFalse(self.cahandler.krb5_config)
        self.assertFalse,(self.cahandler.allowed_domainlist)

    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_017_config_load(self, mock_load_cfg):
        """ test _config_load cahandler section with template value """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'krb5_config': 'krb5_config'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual('basic', self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)
        self.assertEqual('krb5_config', self.cahandler.krb5_config)
        self.assertFalse,(self.cahandler.allowed_domainlist)

    @patch.dict('os.environ', {'host_variable': 'host'})
    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_018_config_load(self, mock_load_cfg):
        """ test _config_load - load with host variable """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'host_variable': 'host_variable'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual('host', self.cahandler.host)

    @patch.dict('os.environ', {'host_variable': 'host'})
    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_019_config_load(self, mock_load_cfg):
        """ test _config_load - load with host variable which does not exist """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'host_variable': 'doesnotexist'}
        mock_load_cfg.return_value = parser
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertIn("ERROR:test_a2c:CAhandler._config_load() could not load host_variable:'doesnotexist'", lcm.output)

    @patch.dict('os.environ', {'host_variable': 'host'})
    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_020_config_load(self, mock_load_cfg):
        """ test _config_load - load with host variable which gets overwritten """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'host_variable': 'host_variable', 'host': 'host_local'}
        mock_load_cfg.return_value = parser
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertEqual('host_local', self.cahandler.host)
        self.assertIn('INFO:test_a2c:CAhandler._config_load() overwrite host', lcm.output)

    @patch.dict('os.environ', {'user_variable': 'user'})
    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_021_config_load(self, mock_load_cfg):
        """ test _config_load - load with user variable """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'user_variable': 'user_variable'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual('user', self.cahandler.user)

    @patch.dict('os.environ', {'user_variable': 'user'})
    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_022_config_load(self, mock_load_cfg):
        """ test _config_load - load with user variable which does not exist """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'user_variable': 'doesnotexist'}
        mock_load_cfg.return_value = parser
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.user)
        self.assertIn("ERROR:test_a2c:CAhandler._config_load() could not load user_variable:'doesnotexist'", lcm.output)

    @patch.dict('os.environ', {'user_variable': 'user'})
    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_023_config_load(self, mock_load_cfg):
        """ test _config_load - load with user variable which gets overwritten """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'user_variable': 'user_variable', 'user': 'user_local'}
        mock_load_cfg.return_value = parser
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertEqual('user_local', self.cahandler.user)
        self.assertIn('INFO:test_a2c:CAhandler._config_load() overwrite user', lcm.output)

    @patch.dict('os.environ', {'password_variable': 'password'})
    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_024_config_load(self, mock_load_cfg):
        """ test _config_load - load with password variable """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'password_variable': 'password_variable'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual('password', self.cahandler.password)

    @patch.dict('os.environ', {'password_variable': 'password'})
    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_025_config_load(self, mock_load_cfg):
        """ test _config_load - load with password variable which does not exist """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'password_variable': 'doesnotexist'}
        mock_load_cfg.return_value = parser
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.password)
        self.assertIn("ERROR:test_a2c:CAhandler._config_load() could not load password_variable:'doesnotexist'", lcm.output)
        self.assertFalse,(self.cahandler.allowed_domainlist)

    @patch.dict('os.environ', {'password_variable': 'password'})
    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_026_config_load(self, mock_load_cfg):
        """ test _config_load - load with password variable which gets overwritten """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'password_variable': 'password_variable', 'password': 'password_local'}
        mock_load_cfg.return_value = parser
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertEqual('password_local', self.cahandler.password)
        self.assertIn('INFO:test_a2c:CAhandler._config_load() overwrite password', lcm.output)
        self.assertFalse,(self.cahandler.allowed_domainlist)

    @patch('examples.ca_handler.mscertsrv_ca_handler.proxy_check')
    @patch('json.loads')
    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_027_config_load(self, mock_load_cfg, mock_json, mock_chk):
        """ test _config_load ca_handler configured load proxies """
        parser = configparser.ConfigParser()
        parser['DEFAULT'] = {'proxy_server_list': 'foo'}
        mock_load_cfg.return_value = parser
        mock_json.return_value = 'foo.bar.local'
        mock_chk.return_value = 'proxy.bar.local'
        self.cahandler._config_load()
        self.assertTrue(mock_json.called)
        self.assertTrue(mock_chk.called)
        self.assertEqual({'http': 'proxy.bar.local', 'https': 'proxy.bar.local'},self.cahandler.proxy )
        self.assertFalse,(self.cahandler.allowed_domainlist)

    @patch('examples.ca_handler.mscertsrv_ca_handler.proxy_check')
    @patch('json.loads')
    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_028_config_load(self, mock_load_cfg, mock_json, mock_chk):
        """ test _config_load ca_handler configured load proxies failed with exception in json.load """
        parser = configparser.ConfigParser()
        parser['DEFAULT'] = {'proxy_server_list': 'foo'}
        mock_json.side_effect = Exception('exc_load_config')
        mock_load_cfg.return_value = parser
        mock_chk.side = 'proxy.bar.local'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertTrue(mock_json.called)
        self.assertFalse(mock_chk.called)
        self.assertFalse(self.cahandler.proxy )
        self.assertIn('WARNING:test_a2c:CAhandler._config_load() proxy_server_list failed with error: exc_load_config', lcm.output)
        self.assertFalse,(self.cahandler.allowed_domainlist)

    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_029_config_load(self, mock_load_cfg):
        """ allowd_domain_list """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'allowed_domainlist': '["allowed_domainlist"]'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual('basic', self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.krb5_config)
        self.assertEqual(['allowed_domainlist'], self.cahandler.allowed_domainlist)

    @patch('examples.ca_handler.mscertsrv_ca_handler.load_config')
    def test_030_config_load(self, mock_load_cfg):
        """ allowd_domain_list """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'allowed_domainlist': 'wrongstring'}
        mock_load_cfg.return_value = parser
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual('basic', self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.krb5_config)
        self.assertFalse,(self.cahandler.allowed_domainlist)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): failed to parse allowed_domainlist: Expecting value: line 1 column 1 (char 0)', lcm.output)

    def test_029_revoke(self):
        """ test revocation """
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'Revocation is not supported.'), self.cahandler.revoke('cert', 'rev_reason', 'rev_date'))

    def test_030_poll(self):
        """ test polling """
        self.assertEqual(('Method not implemented.', None, None, 'poll_identifier', False), self.cahandler.poll('cert_name', 'poll_identifier', 'csr'))

    def test_031_trigger(self):
        """ test polling """
        self.assertEqual(('Method not implemented.', None, None), self.cahandler.trigger('payload'))

    def test_032_check_credentials(self):
        """ test polling """
        ca_server = Mock()
        ca_server.check_credentials = Mock(return_value=True)
        self.assertTrue(self.cahandler._check_credentials(ca_server))

    def test_033_check_credentials(self):
        """ test polling """
        ca_server = Mock()
        ca_server.check_credentials = Mock(return_value=False)
        self.assertFalse(self.cahandler._check_credentials(ca_server))

    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._config_load')
    def test_034__enter__(self, mock_cfg):
        """ test enter  called """
        mock_cfg.return_value = True
        self.cahandler.__enter__()
        self.assertTrue(mock_cfg.called)

    def test_035_enroll(self):
        """ enroll without having self.host """
        self.assertEqual(('Config incomplete', None, None, None), self.cahandler.enroll('csr'))

    def test_036_enroll(self):
        """ enroll without having self.user """
        self.cahandler.host = 'host'
        self.assertEqual(('Config incomplete', None, None, None), self.cahandler.enroll('csr'))

    def test_037_enroll(self):
        """ enroll without having self.password """
        self.cahandler.host = 'host'
        self.cahandler.user = 'user'
        self.assertEqual(('Config incomplete', None, None, None), self.cahandler.enroll('csr'))

    def test_038_enroll(self):
        """ enroll without having self.template """
        self.cahandler.host = 'host'
        self.cahandler.user = 'user'
        self.cahandler.password = 'password'
        self.assertEqual(('Config incomplete', None, None, None), self.cahandler.enroll('csr'))

    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._check_credentials')
    @patch('certsrv.Certsrv')
    def test_039_enroll(self, mock_certserver, mock_credchk):
        """ enroll credential check failed """
        self.cahandler.host = 'host'
        self.cahandler.user = 'user'
        self.cahandler.password = 'password'
        self.cahandler.template = 'template'
        mock_certserver.return_value = 'foo'
        mock_credchk.return_value = False
        self.assertEqual(('Connection or Credentialcheck failed.', None, None, None), self.cahandler.enroll('csr'))

    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._template_name_get')
    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._pkcs7_to_pem')
    @patch('examples.ca_handler.mscertsrv_ca_handler.convert_byte_to_string')
    @patch('textwrap.fill')
    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._check_credentials')
    @patch('examples.ca_handler.mscertsrv_ca_handler.Certsrv')
    def test_040_enroll(self, mock_certserver, mock_credchk, mockwrap, mock_b2s, mock_p2p, mock_tmpl):
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
        self.assertFalse(mock_tmpl.called)

    @patch('examples.ca_handler.mscertsrv_ca_handler.allowed_domainlist_check')
    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._template_name_get')
    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._pkcs7_to_pem')
    @patch('examples.ca_handler.mscertsrv_ca_handler.convert_byte_to_string')
    @patch('textwrap.fill')
    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._check_credentials')
    @patch('examples.ca_handler.mscertsrv_ca_handler.Certsrv')
    def test_140_enroll(self, mock_certserver, mock_credchk, mockwrap, mock_b2s, mock_p2p, mock_tmpl, mock_adc):
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
        self.assertFalse(mock_tmpl.called)
        self.assertFalse(mock_adc.called)

    @patch('examples.ca_handler.mscertsrv_ca_handler.allowed_domainlist_check')
    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._template_name_get')
    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._pkcs7_to_pem')
    @patch('examples.ca_handler.mscertsrv_ca_handler.convert_byte_to_string')
    @patch('textwrap.fill')
    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._check_credentials')
    @patch('examples.ca_handler.mscertsrv_ca_handler.Certsrv')
    def test_141_enroll(self, mock_certserver, mock_credchk, mockwrap, mock_b2s, mock_p2p, mock_tmpl, mock_adc):
        """ enroll enroll successful """
        self.cahandler.host = 'host'
        self.cahandler.user = 'user'
        self.cahandler.password = 'password'
        self.cahandler.template = 'template'
        self.cahandler.allowed_domainlist = ['allowed_domainlist']
        mockresponse = MagicMock()
        mockresponse.get_chain.return_value = "get_chain"
        mockresponse.get_cert.return_value = "get_cert"
        mock_adc.return_value = True
        mock_certserver = mockresponse
        mock_credchk.return_value = True
        mockwrap.return_value = 'mockwrap'
        mock_b2s.side_effect = ['get_chain', 'get_cert']
        mock_p2p.return_value = 'p2p'
        self.assertEqual((None, 'get_certp2p', 'get_cert', None), self.cahandler.enroll('csr'))
        self.assertFalse(mock_tmpl.called)
        self.assertTrue(mock_adc.called)

    @patch('examples.ca_handler.mscertsrv_ca_handler.allowed_domainlist_check')
    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._template_name_get')
    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._pkcs7_to_pem')
    @patch('examples.ca_handler.mscertsrv_ca_handler.convert_byte_to_string')
    @patch('textwrap.fill')
    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._check_credentials')
    @patch('examples.ca_handler.mscertsrv_ca_handler.Certsrv')
    def test_142_enroll(self, mock_certserver, mock_credchk, mockwrap, mock_b2s, mock_p2p, mock_tmpl, mock_adc):
        """ enroll enroll successful """
        self.cahandler.host = 'host'
        self.cahandler.user = 'user'
        self.cahandler.password = 'password'
        self.cahandler.template = 'template'
        self.cahandler.allowed_domainlist = ['allowed_domainlist']
        mockresponse = MagicMock()
        mockresponse.get_chain.return_value = "get_chain"
        mockresponse.get_cert.return_value = "get_cert"
        mock_adc.return_value = False
        mock_certserver = mockresponse
        mock_credchk.return_value = True
        mockwrap.return_value = 'mockwrap'
        mock_b2s.side_effect = ['get_chain', 'get_cert']
        mock_p2p.return_value = 'p2p'
        self.assertEqual(('SAN/CN check failed', None, None, None), self.cahandler.enroll('csr'))
        self.assertFalse(mock_tmpl.called)
        self.assertTrue(mock_adc.called)

    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._template_name_get')
    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._pkcs7_to_pem')
    @patch('examples.ca_handler.mscertsrv_ca_handler.convert_byte_to_string')
    @patch('textwrap.fill')
    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._check_credentials')
    @patch('examples.ca_handler.mscertsrv_ca_handler.Certsrv')
    def test_041_enroll(self, mock_certserver, mock_credchk, mockwrap, mock_b2s, mock_p2p, mock_tmpl):
        """ enroll enroll successful """
        self.cahandler.host = 'host'
        self.cahandler.user = 'user'
        self.cahandler.password = 'password'
        self.cahandler.template = 'template'
        self.cahandler.header_info_field = 'header_info'
        mockresponse = MagicMock()
        mockresponse.get_chain.return_value = "get_chain"
        mockresponse.get_cert.return_value = "get_cert"
        mock_tmpl.return_value = 'new_template'
        mock_certserver = mockresponse
        mock_credchk.return_value = True
        mockwrap.return_value = 'mockwrap'
        mock_b2s.side_effect = ['get_chain', 'get_cert']
        mock_p2p.return_value = 'p2p'
        self.assertEqual((None, 'get_certp2p', 'get_cert', None), self.cahandler.enroll('csr'))
        self.assertTrue(mock_tmpl.called)
        self.assertEqual('new_template', self.cahandler.template)

    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._template_name_get')
    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._pkcs7_to_pem')
    @patch('examples.ca_handler.mscertsrv_ca_handler.convert_byte_to_string')
    @patch('textwrap.fill')
    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._check_credentials')
    @patch('examples.ca_handler.mscertsrv_ca_handler.Certsrv')
    def test_042_enroll(self, mock_certserver, mock_credchk, mockwrap, mock_b2s, mock_p2p, mock_tmpl):
        """ enroll enroll successful """
        self.cahandler.host = 'host'
        self.cahandler.user = 'user'
        self.cahandler.password = 'password'
        self.cahandler.template = 'template'
        self.cahandler.header_info_field = 'header_info'
        self.cahandler.krb5_config = 'krb5_config'
        mockresponse = MagicMock()
        mockresponse.get_chain.return_value = "get_chain"
        mockresponse.get_cert.return_value = "get_cert"
        mock_tmpl.return_value = 'new_template'
        mock_certserver = mockresponse
        mock_credchk.return_value = True
        mockwrap.return_value = 'mockwrap'
        mock_b2s.side_effect = ['get_chain', 'get_cert']
        mock_p2p.return_value = 'p2p'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((None, 'get_certp2p', 'get_cert', None), self.cahandler.enroll('csr'))
        self.assertIn('INFO:test_a2c:CAhandler.enroll(): load krb5config from krb5_config', lcm.output)
        self.assertTrue(mock_tmpl.called)
        self.assertEqual('new_template', self.cahandler.template)

    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._template_name_get')
    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._pkcs7_to_pem')
    @patch('examples.ca_handler.mscertsrv_ca_handler.convert_byte_to_string')
    @patch('textwrap.fill')
    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._check_credentials')
    @patch('examples.ca_handler.mscertsrv_ca_handler.Certsrv')
    def test_043_enroll(self, mock_certserver, mock_credchk, mockwrap, mock_b2s, mock_p2p, mock_tmpl):
        """ enroll enroll successful """
        self.cahandler.host = 'host'
        self.cahandler.user = 'user'
        self.cahandler.password = 'password'
        self.cahandler.template = 'template'
        self.cahandler.header_info_field = 'header_info'
        mockresponse = MagicMock()
        mockresponse.get_chain.return_value = "get_chain"
        mockresponse.get_cert.return_value = "get_cert"
        mock_tmpl.return_value = None
        mock_certserver = mockresponse
        mock_credchk.return_value = True
        mockwrap.return_value = 'mockwrap'
        mock_b2s.side_effect = ['get_chain', 'get_cert']
        mock_p2p.return_value = 'p2p'
        self.assertEqual((None, 'get_certp2p', 'get_cert', None), self.cahandler.enroll('csr'))
        self.assertTrue(mock_tmpl.called)
        self.assertEqual('template', self.cahandler.template)

    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._pkcs7_to_pem')
    @patch('examples.ca_handler.mscertsrv_ca_handler.convert_byte_to_string')
    @patch('textwrap.fill')
    @patch('examples.ca_handler.mscertsrv_ca_handler.CAhandler._check_credentials')
    @patch('examples.ca_handler.mscertsrv_ca_handler.Certsrv')
    def test_044_enroll(self, mock_certserver, mock_credchk, mockwrap, mock_b2s, mock_p2p):
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
    def test_045_enroll(self, mock_certserver, mock_credchk, mockwrap, mock_b2s, mock_p2p):
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
        mock_b2s.side_effect = ['get_chain', Exception('get_cert')]
        mock_p2p.return_value = 'p2p'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('get_cert', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:ca_server.get_cert() failed with error: get_cert', lcm.output)

    @patch('examples.ca_handler.mscertsrv_ca_handler.header_info_get')
    def test_046_template_name_get(self, mock_header):
        """ test _template_name_get()"""
        mock_header.return_value = [{'header_info': '{"header_field": "template=foo lego-cli/4.14.2 xenolf-acme/4.14.2 (release; linux; amd64)"}'}]
        self.cahandler.header_info_field = 'header_field'
        self.assertEqual('foo', self.cahandler._template_name_get('csr'))

    @patch('examples.ca_handler.mscertsrv_ca_handler.header_info_get')
    def test_047_template_name_get(self, mock_header):
        """ test _template_name_get()"""
        mock_header.return_value = [{'header_info': '{"header_field": "Template=foo lego-cli/4.14.2 xenolf-acme/4.14.2 (release; linux; amd64)"}'}]
        self.cahandler.header_info_field = 'header_field'
        self.assertEqual('foo', self.cahandler._template_name_get('csr'))

    @patch('examples.ca_handler.mscertsrv_ca_handler.header_info_get')
    def test_048_template_name_get(self, mock_header):
        """ test _template_name_get()"""
        mock_header.return_value = [{'header_info': 'header_info'}]
        self.cahandler.header_info_field = 'header_field'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.cahandler._template_name_get('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler._template_name_get() could not parse template: Expecting value: line 1 column 1 (char 0)', lcm.output)

    def test_049_config_headerinfo_load(self):
        """ test config_headerinfo_load()"""
        config_dic = {'Order': {'header_info_list': '["foo", "bar", "foobar"]'}}
        self.cahandler._config_headerinfo_load(config_dic)
        self.assertEqual( 'foo', self.cahandler.header_info_field)

    def test_050_config_headerinfo_load(self):
        """ test config_headerinfo_load()"""
        config_dic = {'Order': {'header_info_list': '["foo"]'}}
        self.cahandler._config_headerinfo_load(config_dic)
        self.assertEqual( 'foo', self.cahandler.header_info_field)

    def test_051_config_headerinfo_load(self):
        """ test config_headerinfo_load()"""
        config_dic = {'Order': {'header_info_list': 'foo'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_headerinfo_load(config_dic)
        self.assertFalse(self.cahandler.header_info_field)
        self.assertIn('WARNING:test_a2c:Order._config_orderconfig_load() header_info_list failed with error: Expecting value: line 1 column 1 (char 0)', lcm.output)


if __name__ == '__main__':

    unittest.main()
