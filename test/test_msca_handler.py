#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for acme2certifier"""

# pylint: disable= C0415, W0212
import unittest
import sys
import os
import subprocess
from unittest.mock import patch, Mock, MagicMock, mock_open
import base64
import configparser

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestACMEHandler(unittest.TestCase):
    """test class for cgi_handler"""

    def setUp(self):
        """setup unittest"""
        import logging

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        from acme2certifier.cahandlers.mscertsrv_ca_handler import CAhandler

        self.cahandler = CAhandler(False, self.logger)
        self.cahandler._ca_templates_cache.clear()
        self.dir_path = os.path.dirname(os.path.realpath(__file__))

    def test_001_default(self):
        """default test which always passes"""
        self.assertEqual("foo", "foo")

    def test_002__pkcs7_to_pem(self):
        """test pkcs7 to pem default output"""
        with open(self.dir_path + "/ca/certs.p7b", "r") as fso:
            file_content = fso.read()
        with open(self.dir_path + "/ca/certs.pem", "r") as fso:
            result = fso.read()
        self.assertEqual(result, self.cahandler._pkcs7_to_pem(file_content))

    def test_003__pkcs7_to_pem(self):
        """test pkcs7 to pem output string"""
        with open(self.dir_path + "/ca/certs.p7b", "r") as fso:
            file_content = fso.read()
        with open(self.dir_path + "/ca/certs.pem", "r") as fso:
            result = fso.read()
        self.assertEqual(result, self.cahandler._pkcs7_to_pem(file_content, "string"))

    def test_004__pkcs7_to_pem(self):
        """test pkcs7 to pem output list"""
        with open(self.dir_path + "/ca/certs.p7b", "r") as fso:
            file_content = fso.read()
        result = [
            "-----BEGIN CERTIFICATE-----\nMIIFTzCCAzegAwIBAgIIAzHyhSyrXfMwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MTM1\nNDAwWhcNMzAwNTI2MjM1OTAwWjAqMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEP\nMA0GA1UEAxMGc3ViLWNhMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA\nxXHaGZsolXe+PBdUryngHP9VbBC1mehqeTtYI+hqsqGNH7q9a7bSrxMwFuF1kYL8\njqqxkJdtl0L94xcxJg/ZdMx7Nt0vGI+BaAuTpEpUEHeN4tqS6NhB/m/0LGkAELc/\nqkzmoO4B1FDwEEj/3IXtZcupqG80oDt7jWSGXdtF7NTjzcumznMeRXidCdhxRxT/\n/WrsChaytXo0xWZ56oeNwd6x6Dr8/39PBOWtj4fldyDcg+Q+alci2tx9pxmu2bCV\nXcB9ftCLKhDk2WEHE88bgKSp7fV2RCmq9po+Tx8JJ7qecLunUsK/F0XN4kpoQLm9\nhcymqchnMSncSiyin1dQHGHWgXDtBDdq6A2Z6rx26Qk5H9HTYvcNSe1YwFEDoGLB\nZQjbCPWiaqoaH4agBQTclPvrrSCRaVmhUSO+pBtSXDkmN4t3MDZxfgRkp8ixwkB1\n5Y5f0LTpCyAJsdQDw8+Ea0aDqO30eskh4CErnm9+Fejd9Ew2cwpdwfBXzVSbYilM\nGueQihZHvJmVRxAwU69aO2Qs8B0tQ60CfWKVlmWPiakrvYYlPp0FBsM61G6LZEN8\nhH2CKnS8hHv5IWEXZvp0Pk8V3P5h6bWN0Tl+x/V1Prt7Wp8NoiPETE8XyDDxe6dm\nKxztWBH/mTsJyMGb6ZiUoXdPU9TFUKqHxTRLHaxfsPsCAwEAAaN4MHYwEgYDVR0T\nAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQUv96OjgYiIqutQ8jd1E+oq0hBPtUwDgYD\nVR0PAQH/BAQDAgGGMBEGCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYP\neGNhIGNlcnRpZmljYXRlMA0GCSqGSIb3DQEBCwUAA4ICAQBbHLEVyg4f9uEujroc\n31UVyDRLMdPgEPLjOenSBCBmH0N81whDmxNI/7JAAB6J14WMX8OLF0HkZnb7G77W\nvDhy1aFvQFbXHBz3/zUO9Mw9J4L2XEW6ond3Nsh1m2oXeBde3R3ANxuIzHqZDlP9\n6YrRcHjnf4+1/5AKDJAvJD+gFb5YnYUKH2iSvHUvG17xcZx98Rf2eo8LealG4JqH\nJh4sKRy0VjDQD7jXSCbweTHEb8wz+6OfNGrIo+BhTFP5vPcwE4nlJwYBoaOJ5cVa\n7gdQJ7WkLSxvwHxuxzvSVK73u3jl3I9SqTrbMLG/jeJyV0P8EvdljOaGnCtQVRwC\nzM4ptXUvKhKOHy7/nyTF/Bc35ZwwL/2xWvNK1+NibgE/6CFxupwWpdmxQbVVuoQ3\n2tUil9ty0yC6m5GKE8+t1lrZuxyA+b/TBnYNO5xo8UEMbkpxaNYSwmw+f/loxXP/\nM7sIBcLvy2ugHEBxwd9o/kLXeXT2DaRvxPjp4yk8MpJRpNmz3aB5HJwaUnaRLVo5\nZ3XWWXmjMGZ6/m0AAoDbDz/pXtOoJZT8BJdD1DuDdszVsQnLVn4B/LtIXL6FbXsF\nzfv6ERP9a5gpKUZ+4NjgrnlGtdccNZpwyWF0IXcvaq3b8hXIRO4hMjzHeHfzJN4t\njX1vlY35Ofonc4+6dRVamBiF9A==\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nMIIFcDCCA1igAwIBAgIIevLTTxOMoZgwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MDAw\nMDAwWhcNMzAwNTI2MjM1OTU5WjArMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEQ\nMA4GA1UEAxMHcm9vdC1jYTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB\nAJy4UZHdZgYt64k/rFamoC676tYvtabeuiqVw1c6oVZI897cFLG6BYwyr2Eaj7tF\nrqTJDeMN4vZSudLsmLDq6m8KwX/riPzUTIlcjM5aIMANZr9rLEs3NWtcivolB5aQ\n1slhdVitUPLuxsFnYeQTyxFyP7lng9M/Z403KLG8phdmKjM0vJkaj4OuKOXf3UsW\nqWQYyRl/ms07xVj02uq08LkoeO+jtQisvyVXURdaCceZtyK/ZBQ7NFCsbK112cVR\n1e2aJol7NJAA6Wm6iBzAdkAA2l3kh40SLoEbaiaVMixLN2vilIZOOAoDXX4+T6ir\n+KnDVSJ2yu5c/OJMwuXwHrh7Lgg1vsFR5TNehknhjUuWOUO+0TkKPg2A7KTg72OZ\n2mOcLZIbxzr1P5RRvdmLQLPrTF2EJvpQPNmbXqN3ZVWEvfHTjkkTFY/dsOTvFTgS\nri15zYKch8votcU7z+BQhgmMtwO2JhPMmZ6ABd9skI7ijWpwOltAhxtdoBO6T6CB\nCrE2yXc6V/PyyAKcFglNmIght5oXsnE+ub/dtx8f9Iea/xNPdo5aGy8fdaitolDK\n16kd3Kb7OE4HMHIwOxxF1BEAqerxxhbLMRBr8hRSZI5cvLzWLvpAQ5zuhjD6V3b9\nBYFd4ujAu3zl3mbzdbYjFoGOX6aBZaGDxlc4O2W7HxntAgMBAAGjgZcwgZQwDwYD\nVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUDGVvuTFYZtEAkz3af9wRKDDvAswwHwYD\nVR0jBBgwFoAUDGVvuTFYZtEAkz3af9wRKDDvAswwDgYDVR0PAQH/BAQDAgGGMBEG\nCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYPeGNhIGNlcnRpZmljYXRl\nMA0GCSqGSIb3DQEBCwUAA4ICAQAjko7dX+iCgT+m3Iy1Vg6j7MRevPAzq1lqHRRN\nNdt2ct530pIut7Fv5V2xYk35ka+i/G+XyOvTXa9vAUKiBtiRnUPsXu4UcS7CcrCX\nEzHx4eOtHnp5wDhO0Fx5/OUZTaP+L7Pd1GD/j953ibx5bMa/M9Rj+S486nst57tu\nDRmEAavFDiMd6L3jH4YSckjmIH2uSeDIaRa9k6ag077XmWhvVYQ9tuR7RGbSuuV3\nFc6pqcFbbWpoLhNRcFc+hbUKOsKl2cP+QEKP/H2s3WMllqgAKKZeO+1KOsGo1CDs\n475bIXyCBpFbH2HOPatmu3yZRQ9fj9ta9EW46n33DFRNLinFWa4WJs4yLVP1juge\n2TCOyA1t61iy++RRXSG3e7NFYrEZuCht1EdDAdzIUY89m9NCPwoDYS4CahgnfkkO\n7YQe6f6yqK6isyf8ZFcp1uF58eERDiF/FDqS8nLmCdURuI56DDoNvDpig5J/9RNW\nG8vEvt2p7QrjeZ3EAatx5JuYty/NKTHZwJWk51CgzEgzDwzE2JIiqeldtL5d0Sl6\neVuv0G04BEyuXxEWpgVVzBS4qEFIBSnTJzgu1PXmId3yLvg2Nr8NKvwyZmN5xKFp\n0A9BWo15zW1PXDaD+l39oTYD7agjXkzTAjYIcfNJ7ATIYFD0xAvNAOf70s7aNupF\nfvkG2Q==\n-----END CERTIFICATE-----\n",
        ]
        self.assertEqual(result, self.cahandler._pkcs7_to_pem(file_content, "list"))

    def test_005__pkcs7_to_pem(self):
        """test pkcs7 to pem output list"""
        with open(self.dir_path + "/ca/certs.p7b", "r") as fso:
            file_content = fso.read()
        result = None
        self.assertEqual(result, self.cahandler._pkcs7_to_pem(file_content, "unknown"))

    def test_006__pkcs7_to_pem(self):
        """test pkcs7 to pem output list"""

        file_content = base64.b64decode(
            "MIIK9AYJKoZIhvcNAQcCoIIK5TCCCuECAQExADALBgkqhkiG9w0BBwGgggrHMIIFTzCCAzegAwIBAgIIAzHyhSyrXfMwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UECxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MTM1NDAwWhcNMzAwNTI2MjM1OTAwWjAqMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEPMA0GA1UEAxMGc3ViLWNhMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxXHaGZsolXe+PBdUryngHP9VbBC1mehqeTtYI+hqsqGNH7q9a7bSrxMwFuF1kYL8jqqxkJdtl0L94xcxJg/ZdMx7Nt0vGI+BaAuTpEpUEHeN4tqS6NhB/m/0LGkAELc/qkzmoO4B1FDwEEj/3IXtZcupqG80oDt7jWSGXdtF7NTjzcumznMeRXidCdhxRxT//WrsChaytXo0xWZ56oeNwd6x6Dr8/39PBOWtj4fldyDcg+Q+alci2tx9pxmu2bCVXcB9ftCLKhDk2WEHE88bgKSp7fV2RCmq9po+Tx8JJ7qecLunUsK/F0XN4kpoQLm9hcymqchnMSncSiyin1dQHGHWgXDtBDdq6A2Z6rx26Qk5H9HTYvcNSe1YwFEDoGLBZQjbCPWiaqoaH4agBQTclPvrrSCRaVmhUSO+pBtSXDkmN4t3MDZxfgRkp8ixwkB15Y5f0LTpCyAJsdQDw8+Ea0aDqO30eskh4CErnm9+Fejd9Ew2cwpdwfBXzVSbYilMGueQihZHvJmVRxAwU69aO2Qs8B0tQ60CfWKVlmWPiakrvYYlPp0FBsM61G6LZEN8hH2CKnS8hHv5IWEXZvp0Pk8V3P5h6bWN0Tl+x/V1Prt7Wp8NoiPETE8XyDDxe6dmKxztWBH/mTsJyMGb6ZiUoXdPU9TFUKqHxTRLHaxfsPsCAwEAAaN4MHYwEgYDVR0TAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQUv96OjgYiIqutQ8jd1E+oq0hBPtUwDgYDVR0PAQH/BAQDAgGGMBEGCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYPeGNhIGNlcnRpZmljYXRlMA0GCSqGSIb3DQEBCwUAA4ICAQBbHLEVyg4f9uEujroc31UVyDRLMdPgEPLjOenSBCBmH0N81whDmxNI/7JAAB6J14WMX8OLF0HkZnb7G77WvDhy1aFvQFbXHBz3/zUO9Mw9J4L2XEW6ond3Nsh1m2oXeBde3R3ANxuIzHqZDlP96YrRcHjnf4+1/5AKDJAvJD+gFb5YnYUKH2iSvHUvG17xcZx98Rf2eo8LealG4JqHJh4sKRy0VjDQD7jXSCbweTHEb8wz+6OfNGrIo+BhTFP5vPcwE4nlJwYBoaOJ5cVa7gdQJ7WkLSxvwHxuxzvSVK73u3jl3I9SqTrbMLG/jeJyV0P8EvdljOaGnCtQVRwCzM4ptXUvKhKOHy7/nyTF/Bc35ZwwL/2xWvNK1+NibgE/6CFxupwWpdmxQbVVuoQ32tUil9ty0yC6m5GKE8+t1lrZuxyA+b/TBnYNO5xo8UEMbkpxaNYSwmw+f/loxXP/M7sIBcLvy2ugHEBxwd9o/kLXeXT2DaRvxPjp4yk8MpJRpNmz3aB5HJwaUnaRLVo5Z3XWWXmjMGZ6/m0AAoDbDz/pXtOoJZT8BJdD1DuDdszVsQnLVn4B/LtIXL6FbXsFzfv6ERP9a5gpKUZ+4NjgrnlGtdccNZpwyWF0IXcvaq3b8hXIRO4hMjzHeHfzJN4tjX1vlY35Ofonc4+6dRVamBiF9DCCBXAwggNYoAMCAQICCHry008TjKGYMA0GCSqGSIb3DQEBCwUAMCsxFzAVBgNVBAsTDmFjbWUyY2VydGlmaWVyMRAwDgYDVQQDEwdyb290LWNhMB4XDTIwMDUyNzAwMDAwMFoXDTMwMDUyNjIzNTk1OVowKzEXMBUGA1UECxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCcuFGR3WYGLeuJP6xWpqAuu+rWL7Wm3roqlcNXOqFWSPPe3BSxugWMMq9hGo+7Ra6kyQ3jDeL2UrnS7Jiw6upvCsF/64j81EyJXIzOWiDADWa/ayxLNzVrXIr6JQeWkNbJYXVYrVDy7sbBZ2HkE8sRcj+5Z4PTP2eNNyixvKYXZiozNLyZGo+Drijl391LFqlkGMkZf5rNO8VY9NrqtPC5KHjvo7UIrL8lV1EXWgnHmbciv2QUOzRQrGytddnFUdXtmiaJezSQAOlpuogcwHZAANpd5IeNEi6BG2omlTIsSzdr4pSGTjgKA11+Pk+oq/ipw1UidsruXPziTMLl8B64ey4INb7BUeUzXoZJ4Y1LljlDvtE5Cj4NgOyk4O9jmdpjnC2SG8c69T+UUb3Zi0Cz60xdhCb6UDzZm16jd2VVhL3x045JExWP3bDk7xU4Eq4tec2CnIfL6LXFO8/gUIYJjLcDtiYTzJmegAXfbJCO4o1qcDpbQIcbXaATuk+ggQqxNsl3Olfz8sgCnBYJTZiIIbeaF7JxPrm/3bcfH/SHmv8TT3aOWhsvH3WoraJQytepHdym+zhOBzByMDscRdQRAKnq8cYWyzEQa/IUUmSOXLy81i76QEOc7oYw+ld2/QWBXeLowLt85d5m83W2IxaBjl+mgWWhg8ZXODtlux8Z7QIDAQABo4GXMIGUMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFAxlb7kxWGbRAJM92n/cESgw7wLMMB8GA1UdIwQYMBaAFAxlb7kxWGbRAJM92n/cESgw7wLMMA4GA1UdDwEB/wQEAwIBhjARBglghkgBhvhCAQEEBAMCAAcwHgYJYIZIAYb4QgENBBEWD3hjYSBjZXJ0aWZpY2F0ZTANBgkqhkiG9w0BAQsFAAOCAgEAI5KO3V/ogoE/ptyMtVYOo+zEXrzwM6tZah0UTTXbdnLed9KSLrexb+VdsWJN+ZGvovxvl8jr012vbwFCogbYkZ1D7F7uFHEuwnKwlxMx8eHjrR56ecA4TtBcefzlGU2j/i+z3dRg/4/ed4m8eWzGvzPUY/kuPOp7Lee7bg0ZhAGrxQ4jHei94x+GEnJI5iB9rkngyGkWvZOmoNO+15lob1WEPbbke0Rm0rrldxXOqanBW21qaC4TUXBXPoW1CjrCpdnD/kBCj/x9rN1jJZaoACimXjvtSjrBqNQg7OO+WyF8ggaRWx9hzj2rZrt8mUUPX4/bWvRFuOp99wxUTS4pxVmuFibOMi1T9Y7oHtkwjsgNbetYsvvkUV0ht3uzRWKxGbgobdRHQwHcyFGPPZvTQj8KA2EuAmoYJ35JDu2EHun+sqiuorMn/GRXKdbhefHhEQ4hfxQ6kvJy5gnVEbiOegw6Dbw6YoOSf/UTVhvLxL7dqe0K43mdxAGrceSbmLcvzSkx2cCVpOdQoMxIMw8MxNiSIqnpXbS+XdEpenlbr9BtOARMrl8RFqYFVcwUuKhBSAUp0yc4LtT15iHd8i74Nja/DSr8MmZjecShadAPQVqNec1tT1w2g/pd/aE2A+2oI15M0wI2CHHzSewEyGBQ9MQLzQDn+9LO2jbqRX75BtmhADEA"
        )
        result = [
            "-----BEGIN CERTIFICATE-----\nMIIFTzCCAzegAwIBAgIIAzHyhSyrXfMwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MTM1\nNDAwWhcNMzAwNTI2MjM1OTAwWjAqMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEP\nMA0GA1UEAxMGc3ViLWNhMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA\nxXHaGZsolXe+PBdUryngHP9VbBC1mehqeTtYI+hqsqGNH7q9a7bSrxMwFuF1kYL8\njqqxkJdtl0L94xcxJg/ZdMx7Nt0vGI+BaAuTpEpUEHeN4tqS6NhB/m/0LGkAELc/\nqkzmoO4B1FDwEEj/3IXtZcupqG80oDt7jWSGXdtF7NTjzcumznMeRXidCdhxRxT/\n/WrsChaytXo0xWZ56oeNwd6x6Dr8/39PBOWtj4fldyDcg+Q+alci2tx9pxmu2bCV\nXcB9ftCLKhDk2WEHE88bgKSp7fV2RCmq9po+Tx8JJ7qecLunUsK/F0XN4kpoQLm9\nhcymqchnMSncSiyin1dQHGHWgXDtBDdq6A2Z6rx26Qk5H9HTYvcNSe1YwFEDoGLB\nZQjbCPWiaqoaH4agBQTclPvrrSCRaVmhUSO+pBtSXDkmN4t3MDZxfgRkp8ixwkB1\n5Y5f0LTpCyAJsdQDw8+Ea0aDqO30eskh4CErnm9+Fejd9Ew2cwpdwfBXzVSbYilM\nGueQihZHvJmVRxAwU69aO2Qs8B0tQ60CfWKVlmWPiakrvYYlPp0FBsM61G6LZEN8\nhH2CKnS8hHv5IWEXZvp0Pk8V3P5h6bWN0Tl+x/V1Prt7Wp8NoiPETE8XyDDxe6dm\nKxztWBH/mTsJyMGb6ZiUoXdPU9TFUKqHxTRLHaxfsPsCAwEAAaN4MHYwEgYDVR0T\nAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQUv96OjgYiIqutQ8jd1E+oq0hBPtUwDgYD\nVR0PAQH/BAQDAgGGMBEGCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYP\neGNhIGNlcnRpZmljYXRlMA0GCSqGSIb3DQEBCwUAA4ICAQBbHLEVyg4f9uEujroc\n31UVyDRLMdPgEPLjOenSBCBmH0N81whDmxNI/7JAAB6J14WMX8OLF0HkZnb7G77W\nvDhy1aFvQFbXHBz3/zUO9Mw9J4L2XEW6ond3Nsh1m2oXeBde3R3ANxuIzHqZDlP9\n6YrRcHjnf4+1/5AKDJAvJD+gFb5YnYUKH2iSvHUvG17xcZx98Rf2eo8LealG4JqH\nJh4sKRy0VjDQD7jXSCbweTHEb8wz+6OfNGrIo+BhTFP5vPcwE4nlJwYBoaOJ5cVa\n7gdQJ7WkLSxvwHxuxzvSVK73u3jl3I9SqTrbMLG/jeJyV0P8EvdljOaGnCtQVRwC\nzM4ptXUvKhKOHy7/nyTF/Bc35ZwwL/2xWvNK1+NibgE/6CFxupwWpdmxQbVVuoQ3\n2tUil9ty0yC6m5GKE8+t1lrZuxyA+b/TBnYNO5xo8UEMbkpxaNYSwmw+f/loxXP/\nM7sIBcLvy2ugHEBxwd9o/kLXeXT2DaRvxPjp4yk8MpJRpNmz3aB5HJwaUnaRLVo5\nZ3XWWXmjMGZ6/m0AAoDbDz/pXtOoJZT8BJdD1DuDdszVsQnLVn4B/LtIXL6FbXsF\nzfv6ERP9a5gpKUZ+4NjgrnlGtdccNZpwyWF0IXcvaq3b8hXIRO4hMjzHeHfzJN4t\njX1vlY35Ofonc4+6dRVamBiF9A==\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nMIIFcDCCA1igAwIBAgIIevLTTxOMoZgwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MDAw\nMDAwWhcNMzAwNTI2MjM1OTU5WjArMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEQ\nMA4GA1UEAxMHcm9vdC1jYTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB\nAJy4UZHdZgYt64k/rFamoC676tYvtabeuiqVw1c6oVZI897cFLG6BYwyr2Eaj7tF\nrqTJDeMN4vZSudLsmLDq6m8KwX/riPzUTIlcjM5aIMANZr9rLEs3NWtcivolB5aQ\n1slhdVitUPLuxsFnYeQTyxFyP7lng9M/Z403KLG8phdmKjM0vJkaj4OuKOXf3UsW\nqWQYyRl/ms07xVj02uq08LkoeO+jtQisvyVXURdaCceZtyK/ZBQ7NFCsbK112cVR\n1e2aJol7NJAA6Wm6iBzAdkAA2l3kh40SLoEbaiaVMixLN2vilIZOOAoDXX4+T6ir\n+KnDVSJ2yu5c/OJMwuXwHrh7Lgg1vsFR5TNehknhjUuWOUO+0TkKPg2A7KTg72OZ\n2mOcLZIbxzr1P5RRvdmLQLPrTF2EJvpQPNmbXqN3ZVWEvfHTjkkTFY/dsOTvFTgS\nri15zYKch8votcU7z+BQhgmMtwO2JhPMmZ6ABd9skI7ijWpwOltAhxtdoBO6T6CB\nCrE2yXc6V/PyyAKcFglNmIght5oXsnE+ub/dtx8f9Iea/xNPdo5aGy8fdaitolDK\n16kd3Kb7OE4HMHIwOxxF1BEAqerxxhbLMRBr8hRSZI5cvLzWLvpAQ5zuhjD6V3b9\nBYFd4ujAu3zl3mbzdbYjFoGOX6aBZaGDxlc4O2W7HxntAgMBAAGjgZcwgZQwDwYD\nVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUDGVvuTFYZtEAkz3af9wRKDDvAswwHwYD\nVR0jBBgwFoAUDGVvuTFYZtEAkz3af9wRKDDvAswwDgYDVR0PAQH/BAQDAgGGMBEG\nCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYPeGNhIGNlcnRpZmljYXRl\nMA0GCSqGSIb3DQEBCwUAA4ICAQAjko7dX+iCgT+m3Iy1Vg6j7MRevPAzq1lqHRRN\nNdt2ct530pIut7Fv5V2xYk35ka+i/G+XyOvTXa9vAUKiBtiRnUPsXu4UcS7CcrCX\nEzHx4eOtHnp5wDhO0Fx5/OUZTaP+L7Pd1GD/j953ibx5bMa/M9Rj+S486nst57tu\nDRmEAavFDiMd6L3jH4YSckjmIH2uSeDIaRa9k6ag077XmWhvVYQ9tuR7RGbSuuV3\nFc6pqcFbbWpoLhNRcFc+hbUKOsKl2cP+QEKP/H2s3WMllqgAKKZeO+1KOsGo1CDs\n475bIXyCBpFbH2HOPatmu3yZRQ9fj9ta9EW46n33DFRNLinFWa4WJs4yLVP1juge\n2TCOyA1t61iy++RRXSG3e7NFYrEZuCht1EdDAdzIUY89m9NCPwoDYS4CahgnfkkO\n7YQe6f6yqK6isyf8ZFcp1uF58eERDiF/FDqS8nLmCdURuI56DDoNvDpig5J/9RNW\nG8vEvt2p7QrjeZ3EAatx5JuYty/NKTHZwJWk51CgzEgzDwzE2JIiqeldtL5d0Sl6\neVuv0G04BEyuXxEWpgVVzBS4qEFIBSnTJzgu1PXmId3yLvg2Nr8NKvwyZmN5xKFp\n0A9BWo15zW1PXDaD+l39oTYD7agjXkzTAjYIcfNJ7ATIYFD0xAvNAOf70s7aNupF\nfvkG2Q==\n-----END CERTIFICATE-----\n",
        ]
        self.assertEqual(result, self.cahandler._pkcs7_to_pem(file_content, "list"))

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_007_config_load(self, mock_load_cfg):
        """test _config_load no cahandler section"""
        parser = configparser.ConfigParser()
        # parser['CAhandler'] = {'foo': 'bar'}
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual("basic", self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.krb5_config)

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_008_config_load(self, mock_load_cfg):
        """test _config_load cahandler section with unknown values"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"foo": "bar"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual("basic", self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.krb5_config)

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_009_config_load(self, mock_load_cfg):
        """test _config_load no cahandler section with host value"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"host": "host"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual("host", self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual("basic", self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.krb5_config)

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_010_config_load(self, mock_load_cfg):
        """test _config_load cahandler section with user values"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"user": "user"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertEqual("user", self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual("basic", self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.krb5_config)

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_011_config_load(self, mock_load_cfg):
        """test _config_load cahandler section with password values"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"password": "password"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertEqual("password", self.cahandler.password)
        self.assertEqual("basic", self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.krb5_config)

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_012_config_load(self, mock_load_cfg):
        """test _config_load cahandler section with authmethod basic"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"auth_method": "basic"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual("basic", self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.krb5_config)

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_013_config_load(self, mock_load_cfg):
        """test _config_load cahandler section with authmethod ntlm"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"auth_method": "ntlm"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual("ntlm", self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.krb5_config)

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_014_config_load_warn_deprecated_basic(self, mock_load_cfg):
        """test warning when auth_method basic is explicitly configured"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"auth_method": "basic"}
        mock_load_cfg.return_value = parser

        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            self.cahandler._config_load()

        self.assertIn(
            "WARNING:test_a2c:Auth method 'basic' is deprecated and will be removed in a future release. Please migrate to 'gssapi' (Kerberos).",
            lcm.output,
        )

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_015_config_load_warn_deprecated_ntlm(self, mock_load_cfg):
        """test warning when auth_method ntlm is explicitly configured"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"auth_method": "ntlm"}
        mock_load_cfg.return_value = parser

        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            self.cahandler._config_load()

        self.assertIn(
            "WARNING:test_a2c:Auth method 'ntlm' is deprecated and will be removed in a future release. Please migrate to 'gssapi' (Kerberos).",
            lcm.output,
        )

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_015b_config_load_warn_default_basic(self, mock_load_cfg):
        """test warning when auth_method defaults to basic"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"host": "host.example"}
        mock_load_cfg.return_value = parser

        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            self.cahandler._config_load()

        self.assertEqual("basic", self.cahandler.auth_method)
        self.assertIn(
            "WARNING:test_a2c:Auth method 'basic' is deprecated and will be removed in a future release. Please migrate to 'gssapi' (Kerberos).",
            lcm.output,
        )

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_015c_config_load_warn_verify_false(self, mock_load_cfg):
        """test warning when verify is disabled"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"auth_method": "gssapi", "verify": "False"}
        mock_load_cfg.return_value = parser

        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            self.cahandler._config_load()

        self.assertFalse(self.cahandler.verify)
        self.assertIn(
            "WARNING:test_a2c:TLS certificate verification is disabled (verify=False). Enrollment traffic to AD CS is vulnerable to MITM. Prefer ca_bundle / system trust.",
            lcm.output,
        )
        self.assertFalse(
            any("Auth method" in msg and "deprecated" in msg for msg in lcm.output)
        )

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_015d_config_load_gssapi_no_auth_deprecation(self, mock_load_cfg):
        """gssapi auth_method does not emit auth deprecation warning"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"auth_method": "gssapi", "verify": "True"}
        mock_load_cfg.return_value = parser

        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            self.cahandler._config_load()

        self.assertEqual("gssapi", self.cahandler.auth_method)
        self.assertFalse(
            any("Auth method" in msg and "deprecated" in msg for msg in lcm.output)
        )
        self.assertFalse(
            any("verify=False" in msg for msg in lcm.output)
        )

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_016_config_load(self, mock_load_cfg):
        """test _config_load cahandler section with authmethod unknown"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"auth_method": "unknown"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual("basic", self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.krb5_config)

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_017_config_load(self, mock_load_cfg):
        """test _config_load cahandler section with ca_bundle value"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"ca_bundle": "ca_bundle"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual("basic", self.cahandler.auth_method)
        self.assertEqual("ca_bundle", self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.krb5_config)

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_018_config_load(self, mock_load_cfg):
        """test _config_load cahandler section with template value"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"template": "template"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual("basic", self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertEqual("template", self.cahandler.template)
        self.assertFalse(self.cahandler.krb5_config)

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_019_config_load(self, mock_load_cfg):
        """test _config_load cahandler section with template value"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"krb5_config": "krb5_config"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual("basic", self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)
        self.assertEqual("krb5_config", self.cahandler.krb5_config)

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_020_config_load_kerberos_keytab_options(self, mock_load_cfg):
        """test _config_load with kerberos keytab related options"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "auth_method": "gssapi",
            "krb5_principal": "svc-a2c-enroll@EXAMPLE.COM",
            "krb5_keytab": "/tmp/svc.keytab",
            "krb5_cache": "/tmp/krb5cc_svc",
            "krb5_config": "/tmp/krb5.conf",
            "krb5_kinit_path": "/usr/local/bin/kinit",
        }
        mock_load_cfg.return_value = parser

        self.cahandler._config_load()

        self.assertEqual("gssapi", self.cahandler.auth_method)
        self.assertEqual("svc-a2c-enroll@EXAMPLE.COM", self.cahandler.krb5_principal)
        self.assertEqual("/tmp/svc.keytab", self.cahandler.krb5_keytab)
        self.assertEqual("/tmp/krb5cc_svc", self.cahandler.krb5_cache)
        self.assertEqual("/tmp/krb5.conf", self.cahandler.krb5_config)
        self.assertEqual("/usr/local/bin/kinit", self.cahandler.krb5_kinit_path)

    @patch.dict("os.environ", {"host_variable": "host"})
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_021_config_load(self, mock_load_cfg):
        """test _config_load - load with host variable"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"host_variable": "host_variable"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual("host", self.cahandler.host)

    @patch.dict("os.environ", {"host_variable": "host"})
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_022_config_load(self, mock_load_cfg):
        """test _config_load - load with host variable which does not exist"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"host_variable": "doesnotexist"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertIn(
            "ERROR:test_a2c:Could not load host_variable from environment: 'doesnotexist'",
            lcm.output,
        )

    @patch.dict("os.environ", {"host_variable": "host"})
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_023_config_load(self, mock_load_cfg):
        """test _config_load - load with host variable which gets overwritten"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"host_variable": "host_variable", "host": "host_local"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertEqual("host_local", self.cahandler.host)
        self.assertIn("INFO:test_a2c:Overwrite host", lcm.output)

    @patch.dict("os.environ", {"user_variable": "user"})
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_024_config_load(self, mock_load_cfg):
        """test _config_load - load with user variable"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"user_variable": "user_variable"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual("user", self.cahandler.user)

    @patch.dict("os.environ", {"user_variable": "user"})
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_025_config_load(self, mock_load_cfg):
        """test _config_load - load with user variable which does not exist"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"user_variable": "doesnotexist"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.user)
        self.assertIn(
            "ERROR:test_a2c:Could not load user_variable from environment: 'doesnotexist'",
            lcm.output,
        )

    @patch.dict("os.environ", {"user_variable": "user"})
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_026_config_load(self, mock_load_cfg):
        """test _config_load - load with user variable which gets overwritten"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"user_variable": "user_variable", "user": "user_local"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertEqual("user_local", self.cahandler.user)
        self.assertIn("INFO:test_a2c:Overwrite user", lcm.output)

    @patch.dict("os.environ", {"password_variable": "password"})
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_027_config_load(self, mock_load_cfg):
        """test _config_load - load with password variable"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"password_variable": "password_variable"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual("password", self.cahandler.password)

    @patch.dict("os.environ", {"password_variable": "password"})
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_028_config_load(self, mock_load_cfg):
        """test _config_load - load with password variable which does not exist"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"password_variable": "doesnotexist"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.password)
        self.assertIn(
            "ERROR:test_a2c:Could not load password_variable from environment: 'doesnotexist'",
            lcm.output,
        )

    @patch.dict("os.environ", {"password_variable": "password"})
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_029_config_load(self, mock_load_cfg):
        """test _config_load - load with password variable which gets overwritten"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "password_variable": "password_variable",
            "password": "password_local",
        }
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertEqual("password_local", self.cahandler.password)
        self.assertIn("INFO:test_a2c:Overwrite password", lcm.output)

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.proxy_check")
    @patch("json.loads")
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_030_config_load(self, mock_load_cfg, mock_json, mock_chk):
        """test _config_load ca_handler configured load proxies"""
        parser = configparser.ConfigParser()
        parser["DEFAULT"] = {"proxy_server_list": "foo"}
        mock_load_cfg.return_value = parser
        mock_json.return_value = "foo.bar.local"
        mock_chk.return_value = "proxy.bar.local"
        self.cahandler._config_load()
        self.assertTrue(mock_json.called)
        self.assertTrue(mock_chk.called)
        self.assertEqual(
            {"http": "proxy.bar.local", "https": "proxy.bar.local"},
            self.cahandler.proxy,
        )

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.proxy_check")
    @patch("json.loads")
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_031_config_load(self, mock_load_cfg, mock_json, mock_chk):
        """test _config_load ca_handler configured load proxies failed with exception in json.load"""
        parser = configparser.ConfigParser()
        parser["DEFAULT"] = {"proxy_server_list": "foo"}
        mock_json.side_effect = Exception("exc_load_config")
        mock_load_cfg.return_value = parser
        mock_chk.side = "proxy.bar.local"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertTrue(mock_json.called)
        self.assertFalse(mock_chk.called)
        self.assertFalse(self.cahandler.proxy)
        self.assertIn(
            "WARNING:test_a2c:Failed to load proxy_server_list from configuration: exc_load_config",
            lcm.output,
        )

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.config_eab_profile_load")
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_032_config_load(self, mock_load_cfg, mock_eab):
        """allowd_domain_list"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "foo": "bar",
            "eab_handler": "handler",
            "eab_profiling": "eab",
        }
        mock_load_cfg.return_value = parser
        mock_eab.return_value = ["eab", "handler"]
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual("basic", self.cahandler.auth_method)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.krb5_config)
        self.assertEqual("handler", self.cahandler.eab_handler)
        self.assertEqual("eab", self.cahandler.eab_profiling)

    def test_033_revoke(self):
        """test revocation"""
        self.assertEqual(
            (
                500,
                "urn:ietf:params:acme:error:serverInternal",
                "Revocation is not supported.",
            ),
            self.cahandler.revoke("cert", "rev_reason", "rev_date"),
        )

    def test_034_poll(self):
        """test polling"""
        self.assertEqual(
            ("Method not implemented.", None, None, "poll_identifier", False),
            self.cahandler.poll("cert_name", "poll_identifier", "csr"),
        )

    def test_035_trigger(self):
        """test polling"""
        self.assertEqual(
            ("Method not implemented.", None, None), self.cahandler.trigger("payload")
        )

    def test_036_check_credentials(self):
        """test polling"""
        ca_server = Mock()
        ca_server.check_credentials = Mock(return_value=True)
        self.assertTrue(self.cahandler._check_credentials(ca_server))

    def test_037_check_credentials(self):
        """test polling"""
        ca_server = Mock()
        ca_server.check_credentials = Mock(return_value=False)
        self.assertFalse(self.cahandler._check_credentials(ca_server))

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._config_load")
    def test_038__enter__(self, mock_cfg):
        """test enter  called"""
        mock_cfg.return_value = True
        self.cahandler.__enter__()
        self.assertTrue(mock_cfg.called)

    def test_039_enroll(self):
        """enroll without having self.host"""
        self.assertEqual(
            ("Configuration error", None, None, None), self.cahandler.enroll("csr")
        )

    def test_040_enroll(self):
        """enroll without having self.user"""
        self.cahandler.host = "host"
        self.assertEqual(
            ("Configuration error", None, None, None), self.cahandler.enroll("csr")
        )

    def test_041_enroll(self):
        """enroll without having self.password"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.assertEqual(
            ("Configuration error", None, None, None), self.cahandler.enroll("csr")
        )

    def test_042_enroll(self):
        """enroll without having self.template"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.assertEqual(
            ("Configuration error", None, None, None), self.cahandler.enroll("csr")
        )

    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._check_credentials"
    )
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.Certsrv")
    def test_043_enroll(self, mock_certserver, mock_credchk):
        """enroll credential check failed"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        mock_certserver.return_value = "foo"
        mock_credchk.return_value = False
        self.assertEqual(
            ("Connection or Credentialcheck failed.", None, None, None),
            self.cahandler.enroll("csr"),
        )

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._pkcs7_to_pem")
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.convert_byte_to_string")
    @patch("textwrap.fill")
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._check_credentials"
    )
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.Certsrv")
    def test_044_enroll(
        self, mock_certserver, mock_credchk, mockwrap, mock_b2s, mock_p2p
    ):
        """enroll enroll successful"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        mockresponse = MagicMock()
        mockresponse.get_chain.return_value = "get_chain"
        mockresponse.get_cert.return_value = "get_cert"
        mock_certserver = mockresponse
        mock_credchk.return_value = True
        mockwrap.return_value = "mockwrap"
        mock_b2s.side_effect = ["get_chain", "get_cert"]
        mock_p2p.return_value = "p2p"
        self.assertEqual(
            (None, "get_certp2p", "get_cert", None), self.cahandler.enroll("csr")
        )

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._pkcs7_to_pem")
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.convert_byte_to_string")
    @patch("textwrap.fill")
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._check_credentials"
    )
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.Certsrv")
    def test_045_enroll(
        self,
        mock_certserver,
        mock_credchk,
        mockwrap,
        mock_b2s,
        mock_p2p,
    ):
        """enroll enroll successful"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        mockresponse = MagicMock()
        mockresponse.get_chain.return_value = "get_chain"
        mockresponse.get_cert.return_value = "get_cert"
        mock_certserver = mockresponse
        mock_credchk.return_value = True
        mockwrap.return_value = "mockwrap"
        mock_b2s.side_effect = ["get_chain", "get_cert"]
        mock_p2p.return_value = "p2p"
        self.assertEqual(
            (None, "get_certp2p", "get_cert", None), self.cahandler.enroll("csr")
        )

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._pkcs7_to_pem")
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.convert_byte_to_string")
    @patch("textwrap.fill")
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._check_credentials"
    )
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.Certsrv")
    def test_046_enroll(
        self,
        mock_certserver,
        mock_credchk,
        mockwrap,
        mock_b2s,
        mock_p2p,
    ):
        """enroll enroll successful"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        mockresponse = MagicMock()
        mockresponse.get_chain.return_value = "get_chain"
        mockresponse.get_cert.return_value = "get_cert"
        mock_certserver = mockresponse
        mock_credchk.return_value = True
        mockwrap.return_value = "mockwrap"
        mock_b2s.side_effect = ["get_chain", "get_cert"]
        mock_p2p.return_value = "p2p"
        self.assertEqual(
            (None, "get_certp2p", "get_cert", None), self.cahandler.enroll("csr")
        )

    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.eab_profile_header_info_check"
    )
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._pkcs7_to_pem")
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.convert_byte_to_string")
    @patch("textwrap.fill")
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._check_credentials"
    )
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.Certsrv")
    def test_047_enroll(
        self, mock_certserver, mock_credchk, mockwrap, mock_b2s, mock_p2p, mock_eab
    ):
        """enroll enroll successful"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        self.cahandler.header_info_field = "header_info"
        mockresponse = MagicMock()
        mockresponse.get_chain.return_value = "get_chain"
        mockresponse.get_cert.return_value = "get_cert"
        mock_eab.return_value = False
        mock_certserver = mockresponse
        mock_credchk.return_value = True
        mockwrap.return_value = "mockwrap"
        mock_b2s.side_effect = ["get_chain", "get_cert"]
        mock_p2p.return_value = "p2p"
        self.assertEqual(
            (None, "get_certp2p", "get_cert", None), self.cahandler.enroll("csr")
        )
        self.assertTrue(mock_eab.called)
        self.assertEqual("template", self.cahandler.template)

    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.eab_profile_header_info_check"
    )
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._pkcs7_to_pem")
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.convert_byte_to_string")
    @patch("textwrap.fill")
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._check_credentials"
    )
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.Certsrv")
    def test_048_enroll(
        self, mock_certserver, mock_credchk, mockwrap, mock_b2s, mock_p2p, mock_eab
    ):
        """enroll enroll successful"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        self.cahandler.header_info_field = "header_info"
        self.cahandler.krb5_config = "krb5_config"
        mockresponse = MagicMock()
        mockresponse.get_chain.return_value = "get_chain"
        mockresponse.get_cert.return_value = "get_cert"
        mock_eab.return_value = "error"
        mock_certserver = mockresponse
        mock_credchk.return_value = True
        mockwrap.return_value = "mockwrap"
        mock_b2s.side_effect = ["get_chain", "get_cert"]
        mock_p2p.return_value = "p2p"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(("error", None, None, None), self.cahandler.enroll("csr"))
        self.assertIn(
            "INFO:test_a2c:Load krb5config from krb5_config",
            lcm.output,
        )
        self.assertTrue(mock_eab.called)
        self.assertEqual("template", self.cahandler.template)

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.subprocess.run")
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.os.path.isfile")
    def test_049_kerberos_acquire_with_kinit_custom_path(
        self,
        mock_isfile,
        mock_subprocess_run,
    ):
        """test kinit fallback uses custom kinit binary and krb5 config"""
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_principal = "svc-a2c-enroll@EXAMPLE.COM"
        self.cahandler.krb5_config = "/tmp/krb5.conf"
        self.cahandler.krb5_kinit_path = "/usr/local/bin/kinit"

        mock_isfile.return_value = True
        result = self.cahandler._kerberos_acquire_with_kinit("/tmp/krb5cc_svc")

        self.assertTrue(result)
        run_args, run_kwargs = mock_subprocess_run.call_args
        self.assertEqual(os.path.realpath("/usr/local/bin/kinit"), run_args[0][0])
        self.assertEqual("/tmp/krb5cc_svc", run_kwargs["env"]["KRB5CCNAME"])
        self.assertEqual("/tmp/krb5.conf", run_kwargs["env"]["KRB5_CONFIG"])

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.subprocess.run")
    def test_049b_kerberos_acquire_with_kinit_rejects_unsafe_path(
        self, mock_subprocess_run
    ):
        """unsafe krb5_kinit_path is rejected before subprocess"""
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_principal = "svc-a2c-enroll@EXAMPLE.COM"
        self.cahandler.krb5_kinit_path = "/tmp/evil.sh"
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            result = self.cahandler._kerberos_acquire_with_kinit("/tmp/krb5cc_svc")
        self.assertFalse(result)
        self.assertFalse(mock_subprocess_run.called)
        self.assertTrue(any("Rejected krb5_kinit_path" in msg for msg in lcm.output))

    def test_050_credentials_are_configured_gssapi_keytab(self):
        """test gssapi keytab mode does not require user/password"""
        self.cahandler.auth_method = "gssapi"
        self.cahandler.krb5_principal = "svc-a2c-enroll@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"

        self.assertTrue(self.cahandler._credentials_are_configured())

    def test_051_enroll_gssapi_keytab_missing_template(self):
        """test enroll in gssapi keytab mode still needs template"""
        self.cahandler.host = "host"
        self.cahandler.auth_method = "gssapi"
        self.cahandler.krb5_principal = "svc-a2c-enroll@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"

        self.assertEqual(
            ("Configuration error", None, None, None), self.cahandler.enroll("csr")
        )

    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.eab_profile_header_info_check"
    )
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._pkcs7_to_pem")
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.convert_byte_to_string")
    @patch("textwrap.fill")
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._check_credentials"
    )
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.Certsrv")
    def test_052_enroll(
        self, mock_certserver, mock_credchk, mockwrap, mock_b2s, mock_p2p, mock_eab
    ):
        """enroll enroll successful"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        self.cahandler.header_info_field = "header_info"
        mockresponse = MagicMock()
        mockresponse.get_chain.return_value = "get_chain"
        mockresponse.get_cert.return_value = "get_cert"
        mock_eab.return_value = None
        mock_certserver = mockresponse
        mock_credchk.return_value = True
        mockwrap.return_value = "mockwrap"
        mock_b2s.side_effect = ["get_chain", "get_cert"]
        mock_p2p.return_value = "p2p"
        self.assertEqual(
            (None, "get_certp2p", "get_cert", None), self.cahandler.enroll("csr")
        )
        self.assertTrue(mock_eab.called)
        self.assertEqual("template", self.cahandler.template)

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._pkcs7_to_pem")
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.convert_byte_to_string")
    @patch("textwrap.fill")
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._check_credentials"
    )
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.Certsrv")
    def test_053_enroll(
        self, mock_certserver, mock_credchk, mockwrap, mock_b2s, mock_p2p
    ):
        """enroll exceütption in get chain"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        mockresponse = MagicMock()
        mockresponse.get_chain.return_value = "get_chain"
        mockresponse.get_cert.return_value = "get_cert"
        mock_certserver = mockresponse
        mock_credchk.return_value = True
        mockwrap.return_value = "mockwrap"
        mock_b2s.side_effect = [Exception("exc_get_chain"), "get_cert"]
        mock_p2p.return_value = "p2p"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                (
                    "Certificate bundling failed: missing CA certificate or issued certificate.",
                    None,
                    "get_cert",
                    None,
                ),
                self.cahandler.enroll("csr"),
            )
        self.assertIn(
            "ERROR:test_a2c:Failed to get CA certificate chain: exc_get_chain",
            lcm.output,
        )
        self.assertIn(
            "ERROR:test_a2c:Failed to bundle certificates: missing ca_pem or cert_raw.",
            lcm.output,
        )

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._pkcs7_to_pem")
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.convert_byte_to_string")
    @patch("textwrap.fill")
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._check_credentials"
    )
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.Certsrv")
    def test_054_enroll(
        self, mock_certserver, mock_credchk, mockwrap, mock_b2s, mock_p2p
    ):
        """enroll exceütption in get cert"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        mockresponse = MagicMock()
        mockresponse.get_chain.return_value = "get_chain"
        mockresponse.get_cert.return_value = "get_cert"
        mock_certserver = mockresponse
        mock_credchk.return_value = True
        mockwrap.return_value = "mockwrap"
        mock_b2s.side_effect = ["get_chain", Exception("get_cert")]
        mock_p2p.return_value = "p2p"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                (
                    self.cahandler.CERT_FETCH_ERROR,
                    None,
                    None,
                    None,
                ),
                self.cahandler.enroll("csr"),
            )
        self.assertIn(
            "ERROR:test_a2c:Failed to enroll certificate from CA: get_cert",
            lcm.output,
        )

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.enrollment_config_log")
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._check_credentials"
    )
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.Certsrv")
    def test_055_enroll(self, mock_certserver, mock_credchk, mock_ecl):
        """enroll credential check failed"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        mock_certserver.return_value = "foo"
        mock_credchk.return_value = False
        self.assertEqual(
            ("Connection or Credentialcheck failed.", None, None, None),
            self.cahandler.enroll("csr"),
        )
        self.assertFalse(mock_ecl.called)

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.enrollment_config_log")
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._check_credentials"
    )
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.Certsrv")
    def test_056_enroll(self, mock_certserver, mock_credchk, mock_ecl):
        """enroll credential check failed"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        self.cahandler.enrollment_config_log = True
        mock_certserver.return_value = "foo"
        mock_credchk.return_value = False
        self.assertEqual(
            ("Connection or Credentialcheck failed.", None, None, None),
            self.cahandler.enroll("csr"),
        )
        self.assertTrue(mock_ecl.called)
        skiplist = mock_ecl.call_args[0][2]
        for key in (
            "password",
            "krb5_keytab",
            "krb5_cache",
            "krb5_config",
            "krb5_kinit_path",
            "_gssapi_creds",
        ):
            self.assertIn(key, skiplist)

    def test_057_enrollment_url_https_check_ok(self):
        """https enrollment url is accepted"""
        self.cahandler.url = "https://ca.example.com/certsrv"
        self.assertIsNone(self.cahandler._enrollment_url_https_check())

    def test_058_enrollment_url_https_check_rejects_http(self):
        """http enrollment url is rejected"""
        self.cahandler.url = "http://ca.example.com/certsrv"
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            error = self.cahandler._enrollment_url_https_check()
        self.assertIn("must use HTTPS", error)
        self.assertTrue(any("must use HTTPS" in msg for msg in lcm.output))

    def test_059_enroll_rejects_http_url(self):
        """enroll fails fast when url is http"""
        self.cahandler.host = "host"
        self.cahandler.url = "http://ca.example.com/certsrv"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            error, cert_bundle, cert_raw, _poll = self.cahandler.enroll("csr")
        self.assertIn("must use HTTPS", error)
        self.assertIsNone(cert_bundle)
        self.assertIsNone(cert_raw)
        self.assertTrue(any("must use HTTPS" in msg for msg in lcm.output))

    def test_060_config_headerinfo_load(self):
        """test config_headerinfo_load()"""
        config_dic = {"Order": {"header_info_list": '["foo", "bar", "foobar"]'}}
        self.cahandler._config_headerinfo_load(config_dic)
        self.assertEqual("foo", self.cahandler.header_info_field)

    def test_061_config_headerinfo_load(self):
        """test config_headerinfo_load()"""
        config_dic = {"Order": {"header_info_list": '["foo"]'}}
        self.cahandler._config_headerinfo_load(config_dic)
        self.assertEqual("foo", self.cahandler.header_info_field)

    def test_062_config_headerinfo_load(self):
        """test config_headerinfo_load()"""
        config_dic = {"Order": {"header_info_list": "foo"}}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_headerinfo_load(config_dic)
        self.assertFalse(self.cahandler.header_info_field)
        self.assertIn(
            "WARNING:test_a2c:Failed to parse header_info_list from configuration: Expecting value: line 1 column 1 (char 0)",
            lcm.output,
        )

    def test_063__config_url_load(self):
        """test _config_url_load()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"url": "foo"}
        self.cahandler._config_url_load(parser)
        self.assertEqual("foo", self.cahandler.url)

    @patch.dict("os.environ", {"url_variable": "foo1"})
    def test_064__config_url_load(self):
        """test _config_url_load()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"url_variable": "url_variable"}
        self.cahandler._config_url_load(parser)
        self.assertEqual("foo1", self.cahandler.url)

    @patch.dict("os.environ", {"url_variable": "foo1"})
    def test_065__config_url_load(self):
        """test _config_url_load()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"url_variable": "url_variable", "url": "foo"}
        self.cahandler._config_url_load(parser)
        self.assertEqual("foo", self.cahandler.url)

    @patch.dict("os.environ", {"url_variable": "foo1"})
    def test_066__config_url_load(self):
        """test _config_url_load()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"url_variable": "doesnotexist"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_url_load(parser)
        self.assertFalse(self.cahandler.url)
        self.assertIn(
            "ERROR:test_a2c:Could not load url_variable from environment: 'doesnotexist'",
            lcm.output,
        )

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.handler_config_check")
    def test_067_handler_check(self, mock_handler_check):
        """test handler_check"""
        self.cahandler.host = "ca.example.com"
        self.cahandler.template = "template"
        mock_handler_check.return_value = "mock_handler_check"
        self.assertEqual("mock_handler_check", self.cahandler.handler_check())

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.handler_config_check")
    def test_067b_handler_check_accepts_url_without_host(self, mock_handler_check):
        """handler_check allows url-only endpoint config"""
        self.cahandler.url = "https://ca.example.com/certsrv"
        self.cahandler.template = "template"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        mock_handler_check.return_value = None
        self.assertIsNone(self.cahandler.handler_check())
        self.assertTrue(mock_handler_check.called)

    def test_067c_handler_check_rejects_http_url(self):
        """handler_check fails for http enrollment url"""
        self.cahandler.url = "http://ca.example.com/certsrv"
        self.cahandler.template = "template"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            error = self.cahandler.handler_check()
        self.assertIn("must use HTTPS", error)
        self.assertTrue(any("must use HTTPS" in msg for msg in lcm.output))

    def test_067d_handler_check_requires_host_or_url(self):
        """handler_check requires host or url"""
        self.cahandler.template = "template"
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            error = self.cahandler.handler_check()
        self.assertIn("host or url", error)
        self.assertTrue(any("host or url" in msg for msg in lcm.output))

    def test_068_config_kerberos_parameter_item_load_env_error(self):
        """_config_kerberos_parameter_item_load logs missing env variables"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"krb5_principal_variable": "DOES_NOT_EXIST"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            value = self.cahandler._config_kerberos_parameter_item_load(
                parser,
                None,
                "krb5_principal",
                "krb5_principal_variable",
                "Could not load krb5_principal_variable from environment: %s",
            )
        self.assertIsNone(value)
        self.assertTrue(
            any(
                "Could not load krb5_principal_variable from environment" in msg
                for msg in lcm.output
            )
        )

    def test_069_config_kerberos_parameters_load_missing_section(self):
        """_config_kerberos_parameters_load returns early without CAhandler section"""
        self.cahandler._config_kerberos_parameters_load({})
        self.assertFalse(self.cahandler.krb5_principal)

    @patch.dict(
        "os.environ", {"KRB5CCNAME": "old_cc", "KRB5_CONFIG": "old_cfg"}, clear=False
    )
    def test_070_kerberos_runtime_environment_is_noop(self):
        """_kerberos_runtime_environment no longer mutates process env"""
        self.cahandler.krb5_cache = "new_cc"
        self.cahandler.krb5_config = "new_cfg"
        with self.cahandler._kerberos_runtime_environment():
            self.assertEqual("old_cc", os.environ.get("KRB5CCNAME"))
            self.assertEqual("old_cfg", os.environ.get("KRB5_CONFIG"))
        self.assertEqual("old_cc", os.environ.get("KRB5CCNAME"))
        self.assertEqual("old_cfg", os.environ.get("KRB5_CONFIG"))

    @patch.dict("os.environ", {}, clear=True)
    def test_071_kerberos_runtime_environment_leaves_env_unset(self):
        """_kerberos_runtime_environment does not introduce KRB5* vars"""
        self.cahandler.krb5_cache = "new_cc"
        self.cahandler.krb5_config = "new_cfg"
        with self.cahandler._kerberos_runtime_environment():
            self.assertNotIn("KRB5CCNAME", os.environ)
            self.assertNotIn("KRB5_CONFIG", os.environ)
        self.assertNotIn("KRB5CCNAME", os.environ)
        self.assertNotIn("KRB5_CONFIG", os.environ)

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.os.unlink")
    def test_072_kerberos_cleanup_temporary_ccache(self, mock_unlink):
        """cleanup removes temporary ccache and resets state"""
        self.cahandler.krb5_cache = "/tmp/runtime_ccache"
        self.cahandler._krb5_cache_is_temporary = True
        self.cahandler._kerberos_cleanup_temporary_ccache()
        mock_unlink.assert_called_once_with("/tmp/runtime_ccache")
        self.assertFalse(self.cahandler._krb5_cache_is_temporary)
        self.assertIsNone(self.cahandler.krb5_cache)

    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.os.unlink",
        side_effect=FileNotFoundError(),
    )
    def test_073_kerberos_cleanup_temporary_ccache_missing(self, mock_unlink):
        """cleanup handles already-removed temporary ccache"""
        self.cahandler.krb5_cache = "/tmp/runtime_ccache"
        self.cahandler._krb5_cache_is_temporary = True
        self.cahandler._kerberos_cleanup_temporary_ccache()
        mock_unlink.assert_called_once_with("/tmp/runtime_ccache")
        self.assertIsNone(self.cahandler.krb5_cache)

    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.os.unlink",
        side_effect=PermissionError("denied"),
    )
    def test_074_kerberos_cleanup_temporary_ccache_error(self, mock_unlink):
        """cleanup logs warning when unlink fails"""
        self.cahandler.krb5_cache = "/tmp/runtime_ccache"
        self.cahandler._krb5_cache_is_temporary = True
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._kerberos_cleanup_temporary_ccache()
        self.assertIn(
            "WARNING:test_a2c:Failed to remove temporary kerberos ccache file '/tmp/runtime_ccache': denied",
            lcm.output,
        )

    def test_075_kerberos_acquire_with_gssapi_raw_success(self):
        """_kerberos_acquire_with_gssapi_raw succeeds when raw API is available"""
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        gssapi = MagicMock()
        gssapi.raw.acquire_cred_from = MagicMock()
        self.assertTrue(
            self.cahandler._kerberos_acquire_with_gssapi_raw(
                gssapi, MagicMock(), "/tmp/cc"
            )
        )
        gssapi.raw.acquire_cred_from.assert_called_once()

    def test_076_kerberos_acquire_with_gssapi_raw_unavailable(self):
        """_kerberos_acquire_with_gssapi_raw returns False when raw API missing"""
        gssapi = MagicMock()
        gssapi.raw = None
        self.assertFalse(
            self.cahandler._kerberos_acquire_with_gssapi_raw(
                gssapi, MagicMock(), "/tmp/cc"
            )
        )

    def test_077_kerberos_acquire_with_gssapi_raw_error(self):
        """_kerberos_acquire_with_gssapi_raw returns False on exception"""
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        gssapi = MagicMock()
        gssapi.raw.acquire_cred_from.side_effect = Exception("raw fail")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(
                self.cahandler._kerberos_acquire_with_gssapi_raw(
                    gssapi, MagicMock(), "/tmp/cc"
                )
            )
        self.assertTrue(
            any("gssapi.raw.acquire_cred_from" in msg for msg in lcm.output)
        )

    def test_078_kerberos_acquire_with_gssapi_highlevel_success(self):
        """_kerberos_acquire_with_gssapi_highlevel succeeds when API available"""
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        gssapi = MagicMock()
        gssapi.Credentials.acquire = MagicMock()
        self.assertTrue(
            self.cahandler._kerberos_acquire_with_gssapi_highlevel(
                gssapi, MagicMock(), "/tmp/cc"
            )
        )

    def test_079_kerberos_acquire_with_gssapi_highlevel_unavailable(self):
        """_kerberos_acquire_with_gssapi_highlevel returns False when API missing"""
        gssapi = MagicMock()
        gssapi.Credentials = None
        self.assertFalse(
            self.cahandler._kerberos_acquire_with_gssapi_highlevel(
                gssapi, MagicMock(), "/tmp/cc"
            )
        )

    def test_080_kerberos_acquire_with_gssapi_highlevel_error(self):
        """_kerberos_acquire_with_gssapi_highlevel returns False on exception"""
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        gssapi = MagicMock()
        gssapi.Credentials.acquire.side_effect = Exception("high fail")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(
                self.cahandler._kerberos_acquire_with_gssapi_highlevel(
                    gssapi, MagicMock(), "/tmp/cc"
                )
            )
        self.assertTrue(any("gssapi.Credentials.acquire" in msg for msg in lcm.output))

    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="kinit", timeout=1),
    )
    def test_081_kerberos_acquire_with_kinit_timeout(self, _mock_run):
        """_kerberos_acquire_with_kinit handles timeout"""
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_principal = "svc@EXAMPLE.COM"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(self.cahandler._kerberos_acquire_with_kinit("/tmp/cc"))
        self.assertTrue(any("kinit timed out" in msg for msg in lcm.output))

    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.subprocess.run",
        side_effect=FileNotFoundError("missing"),
    )
    def test_082_kerberos_acquire_with_kinit_not_found(self, _mock_run):
        """_kerberos_acquire_with_kinit handles missing binary"""
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_principal = "svc@EXAMPLE.COM"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(self.cahandler._kerberos_acquire_with_kinit("/tmp/cc"))
        self.assertTrue(any("command not found" in msg for msg in lcm.output))

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.subprocess.run")
    def test_083_kerberos_acquire_with_kinit_stderr(self, mock_run):
        """_kerberos_acquire_with_kinit logs stderr from CalledProcessError"""
        err = subprocess.CalledProcessError(1, "kinit", stderr=b"kinit failed")
        mock_run.side_effect = err
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_principal = "svc@EXAMPLE.COM"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(self.cahandler._kerberos_acquire_with_kinit("/tmp/cc"))
        self.assertIn(
            "ERROR:test_a2c:Failed to acquire kerberos credentials via kinit: kinit failed",
            lcm.output,
        )

    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.subprocess.run",
        side_effect=Exception("boom"),
    )
    def test_084_kerberos_acquire_with_kinit_generic_error(self, _mock_run):
        """_kerberos_acquire_with_kinit logs generic exceptions"""
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_principal = "svc@EXAMPLE.COM"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(self.cahandler._kerberos_acquire_with_kinit("/tmp/cc"))
        self.assertIn(
            "ERROR:test_a2c:Failed to acquire kerberos credentials via kinit: boom",
            lcm.output,
        )

    def test_085_kerberos_prepare_gssapi_backend_noop(self):
        """_kerberos_prepare_gssapi_backend returns None when not configured"""
        self.cahandler.auth_method = "basic"
        self.assertIsNone(self.cahandler._kerberos_prepare_gssapi_backend())

    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.os.path.isfile",
        return_value=False,
    )
    def test_086_kerberos_prepare_gssapi_backend_missing_keytab(self, _mock_isfile):
        """_kerberos_prepare_gssapi_backend errors when keytab file missing"""
        self.cahandler.auth_method = "gssapi"
        self.cahandler.krb5_principal = "svc@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/missing.keytab"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                "Kerberos keytab file does not exist.",
                self.cahandler._kerberos_prepare_gssapi_backend(),
            )
        self.assertIn(
            "ERROR:test_a2c:Kerberos keytab file does not exist: /tmp/missing.keytab",
            lcm.output,
        )

    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.importlib.import_module",
        side_effect=ImportError("no gssapi"),
    )
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.os.path.isfile",
        return_value=True,
    )
    def test_087_kerberos_prepare_gssapi_backend_import_error(
        self, _mock_isfile, _mock_import
    ):
        """_kerberos_prepare_gssapi_backend errors when gssapi import fails"""
        self.cahandler.auth_method = "gssapi"
        self.cahandler.krb5_principal = "svc@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.assertEqual(
            "gssapi module is required for gssapi keytab authentication.",
            self.cahandler._kerberos_prepare_gssapi_backend(),
        )

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.importlib.import_module")
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.os.path.exists",
        return_value=False,
    )
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.os.path.isfile",
        return_value=True,
    )
    @patch("builtins.open", new_callable=mock_open)
    def test_088_kerberos_prepare_gssapi_backend_success(
        self,
        _mock_open,
        _mock_isfile,
        _mock_exists,
        mock_import,
    ):
        """_kerberos_prepare_gssapi_backend succeeds via raw acquire"""
        self.cahandler.auth_method = "gssapi"
        self.cahandler.krb5_principal = "svc@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_cache = None
        mock_gssapi = MagicMock()
        mock_import.return_value = mock_gssapi
        self.cahandler._kerberos_acquire_with_gssapi_raw = Mock(return_value=True)
        self.cahandler._kerberos_acquire_with_gssapi_highlevel = Mock(
            return_value=False
        )
        self.cahandler._kerberos_acquire_with_kinit = Mock(return_value=False)
        self.assertIsNone(self.cahandler._kerberos_prepare_gssapi_backend())
        self.assertTrue(self.cahandler._krb5_cache_is_temporary)
        self.assertTrue(self.cahandler.krb5_cache)
        self.assertTrue(self.cahandler._kerberos_acquire_with_gssapi_raw.called)
        self.assertFalse(self.cahandler._kerberos_acquire_with_gssapi_highlevel.called)
        self.assertFalse(self.cahandler._kerberos_acquire_with_kinit.called)

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.importlib.import_module")
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.os.path.exists",
        return_value=True,
    )
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.os.path.isfile",
        return_value=True,
    )
    def test_089_kerberos_prepare_gssapi_backend_all_fail(
        self,
        _mock_isfile,
        _mock_exists,
        mock_import,
    ):
        """_kerberos_prepare_gssapi_backend returns error when all acquire methods fail"""
        self.cahandler.auth_method = "gssapi"
        self.cahandler.krb5_principal = "svc@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_cache = "FILE:/tmp/cc"
        mock_import.return_value = MagicMock()
        self.cahandler._kerberos_acquire_with_gssapi_raw = Mock(return_value=False)
        self.cahandler._kerberos_acquire_with_gssapi_highlevel = Mock(
            return_value=False
        )
        self.cahandler._kerberos_acquire_with_kinit = Mock(return_value=False)
        self.assertEqual(
            "Failed to acquire kerberos credentials via gssapi/keytab.",
            self.cahandler._kerberos_prepare_gssapi_backend(),
        )
        self.assertEqual("/tmp/cc", self.cahandler.krb5_cache)
        self.assertTrue(self.cahandler._kerberos_acquire_with_gssapi_raw.called)
        self.assertTrue(self.cahandler._kerberos_acquire_with_gssapi_highlevel.called)
        self.assertTrue(self.cahandler._kerberos_acquire_with_kinit.called)

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.importlib.import_module")
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.os.path.exists",
        return_value=True,
    )
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.os.path.isfile",
        return_value=True,
    )
    def test_090_kerberos_prepare_gssapi_backend_highlevel_success(
        self, _mock_isfile, _mock_exists, mock_import
    ):
        """_kerberos_prepare_gssapi_backend succeeds via highlevel acquire"""
        self.cahandler.auth_method = "gssapi"
        self.cahandler.krb5_principal = "svc@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_cache = "/tmp/cc"
        mock_import.return_value = MagicMock()
        self.cahandler._kerberos_acquire_with_gssapi_raw = Mock(return_value=False)
        self.cahandler._kerberos_acquire_with_gssapi_highlevel = Mock(return_value=True)
        self.cahandler._kerberos_acquire_with_kinit = Mock(return_value=False)
        self.assertIsNone(self.cahandler._kerberos_prepare_gssapi_backend())
        self.assertTrue(self.cahandler._kerberos_acquire_with_gssapi_highlevel.called)
        self.assertFalse(self.cahandler._kerberos_acquire_with_kinit.called)

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.importlib.import_module")
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.os.path.exists",
        return_value=True,
    )
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.os.path.isfile",
        return_value=True,
    )
    def test_091_kerberos_prepare_gssapi_backend_kinit_success(
        self, _mock_isfile, _mock_exists, mock_import
    ):
        """_kerberos_prepare_gssapi_backend succeeds via kinit fallback"""
        self.cahandler.auth_method = "gssapi"
        self.cahandler.krb5_principal = "svc@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_cache = "/tmp/cc"
        mock_import.return_value = MagicMock()
        self.cahandler._kerberos_acquire_with_gssapi_raw = Mock(return_value=False)
        self.cahandler._kerberos_acquire_with_gssapi_highlevel = Mock(
            return_value=False
        )
        self.cahandler._kerberos_acquire_with_kinit = Mock(return_value=True)
        self.assertIsNone(self.cahandler._kerberos_prepare_gssapi_backend())
        self.assertTrue(self.cahandler._kerberos_acquire_with_kinit.called)

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.importlib.import_module")
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.os.path.isfile",
        return_value=True,
    )
    def test_092_kerberos_prepare_gssapi_backend_principal_error(
        self, _mock_isfile, mock_import
    ):
        """_kerberos_prepare_gssapi_backend errors when principal cannot be built"""
        self.cahandler.auth_method = "gssapi"
        self.cahandler.krb5_principal = "svc@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_cache = "/tmp/cc"
        mock_gssapi = MagicMock()
        mock_gssapi.Name.side_effect = Exception("bad principal")
        mock_import.return_value = mock_gssapi
        self.assertEqual(
            "Failed to build kerberos principal for kerberos keytab authentication.",
            self.cahandler._kerberos_prepare_gssapi_backend(),
        )

    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._kerberos_cleanup_temporary_ccache"
    )
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._kerberos_prepare_gssapi_backend",
        return_value="kerberos failed",
    )
    def test_093_enroll_kerberos_prepare_error(self, mock_prepare, mock_cleanup):
        """enroll returns early when kerberos backend setup fails"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                ("kerberos failed", None, None, None),
                self.cahandler.enroll("csr"),
            )
        self.assertIn(
            "ERROR:test_a2c:Kerberos backend setup failed: kerberos failed",
            lcm.output,
        )
        self.assertTrue(mock_prepare.called)
        self.assertTrue(mock_cleanup.called)

    def test_094_default_gssapi_channel_bindings(self):
        """default gssapi_channel_bindings mode is auto"""
        self.assertEqual("auto", self.cahandler.gssapi_channel_bindings)

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_095_config_load_gssapi_channel_bindings_on(self, mock_load_cfg):
        """test _config_load gssapi_channel_bindings=on"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"gssapi_channel_bindings": "on"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual("on", self.cahandler.gssapi_channel_bindings)

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_096_config_load_gssapi_channel_bindings_off(self, mock_load_cfg):
        """test _config_load gssapi_channel_bindings=off"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"gssapi_channel_bindings": "OFF"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual("off", self.cahandler.gssapi_channel_bindings)

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_097_config_load_gssapi_channel_bindings_invalid(self, mock_load_cfg):
        """test _config_load falls back to auto on invalid value"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"gssapi_channel_bindings": "maybe"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertEqual("auto", self.cahandler.gssapi_channel_bindings)
        self.assertIn(
            "WARNING:test_a2c:Invalid gssapi_channel_bindings 'maybe'; using 'auto'. "
            "Allowed values: auto, on, off.",
            lcm.output,
        )

    def test_098_gssapi_channel_bindings_resolve_off(self):
        """off mode never enables channel bindings"""
        self.cahandler.auth_method = "gssapi"
        self.cahandler.gssapi_channel_bindings = "off"
        self.assertEqual((None, None), self.cahandler._gssapi_channel_bindings_resolve())

    def test_099_gssapi_channel_bindings_resolve_non_gssapi(self):
        """non-gssapi auth skips channel bindings"""
        self.cahandler.auth_method = "basic"
        self.cahandler.gssapi_channel_bindings = "on"
        self.assertEqual((None, None), self.cahandler._gssapi_channel_bindings_resolve())

    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.gssapi_channel_bindings_supported",
        return_value=True,
    )
    def test_100_gssapi_channel_bindings_resolve_auto_supported(self, _mock_supported):
        """auto enables tls-server-end-point when supported"""
        self.cahandler.auth_method = "gssapi"
        self.cahandler.gssapi_channel_bindings = "auto"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            result = self.cahandler._gssapi_channel_bindings_resolve()
        self.assertEqual(("tls-server-end-point", None), result)
        self.assertIn(
            "INFO:test_a2c:Enabling GSSAPI channel bindings (tls-server-end-point)",
            lcm.output,
        )

    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.gssapi_channel_bindings_supported",
        return_value=False,
    )
    def test_101_gssapi_channel_bindings_resolve_auto_unsupported(
        self, _mock_supported
    ):
        """auto continues without channel bindings when unsupported"""
        self.cahandler.auth_method = "gssapi"
        self.cahandler.gssapi_channel_bindings = "auto"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            result = self.cahandler._gssapi_channel_bindings_resolve()
        self.assertEqual((None, None), result)
        self.assertTrue(
            any(
                "does not support channel_bindings; continuing without" in entry
                for entry in lcm.output
            )
        )

    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.gssapi_channel_bindings_supported",
        return_value=False,
    )
    def test_102_gssapi_channel_bindings_resolve_on_unsupported(self, _mock_supported):
        """on mode fails when channel bindings are unsupported"""
        self.cahandler.auth_method = "gssapi"
        self.cahandler.gssapi_channel_bindings = "on"
        value, error = self.cahandler._gssapi_channel_bindings_resolve()
        self.assertIsNone(value)
        self.assertIn("requests-gssapi >= 1.4.0", error)

    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.gssapi_channel_bindings_supported",
        return_value=True,
    )
    def test_103_gssapi_channel_bindings_resolve_on_supported(self, _mock_supported):
        """on mode enables tls-server-end-point when supported"""
        self.cahandler.auth_method = "gssapi"
        self.cahandler.gssapi_channel_bindings = "on"
        self.assertEqual(
            ("tls-server-end-point", None),
            self.cahandler._gssapi_channel_bindings_resolve(),
        )

    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._gssapi_channel_bindings_resolve",
        return_value=(
            None,
            "gssapi_channel_bindings=on requires requests-gssapi >= 1.4.0 "
            "with channel_bindings support.",
        ),
    )
    def test_104_enroll_channel_bindings_error(self, mock_resolve):
        """enroll returns channel bindings resolve error"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        self.cahandler.auth_method = "gssapi"
        self.cahandler.gssapi_channel_bindings = "on"
        self.assertEqual(
            (
                "gssapi_channel_bindings=on requires requests-gssapi >= 1.4.0 "
                "with channel_bindings support.",
                None,
                None,
                None,
            ),
            self.cahandler.enroll("csr"),
        )
        self.assertTrue(mock_resolve.called)

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._check_credentials")
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.Certsrv")
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._gssapi_channel_bindings_resolve",
        return_value=("tls-server-end-point", None),
    )
    def test_105_enroll_passes_channel_bindings(
        self, mock_resolve, mock_certsrv, mock_credchk
    ):
        """enroll passes resolved channel_bindings to Certsrv"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        self.cahandler.auth_method = "gssapi"
        mock_credchk.return_value = False
        self.cahandler.enroll("csr")
        self.assertTrue(mock_resolve.called)
        self.assertTrue(mock_certsrv.called)
        self.assertEqual(
            "tls-server-end-point",
            mock_certsrv.call_args.kwargs.get("channel_bindings"),
        )

    def test_106_kerberos_ccache_path_normalizes_file_prefix(self):
        """_kerberos_ccache_path strips FILE: prefix"""
        self.assertEqual(
            "/tmp/cc",
            self.cahandler._kerberos_ccache_path("FILE:/tmp/cc"),
        )
        self.assertEqual("/tmp/cc", self.cahandler._kerberos_ccache_path("/tmp/cc"))
        self.assertIsNone(self.cahandler._kerberos_ccache_path(None))

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.importlib.import_module")
    def test_107_kerberos_gssapi_creds_from_cache_success(self, mock_import):
        """_kerberos_gssapi_creds_from_cache loads Credentials from store"""
        self.cahandler.auth_method = "gssapi"
        self.cahandler.krb5_principal = "svc@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_cache = "FILE:/tmp/cc"
        mock_creds = MagicMock()
        mock_gssapi = MagicMock()
        mock_gssapi.Credentials.return_value = mock_creds
        mock_import.return_value = mock_gssapi
        creds, error = self.cahandler._kerberos_gssapi_creds_from_cache()
        self.assertIs(mock_creds, creds)
        self.assertIsNone(error)
        mock_gssapi.Credentials.assert_called_once_with(
            usage="initiate", store={"ccache": "/tmp/cc"}
        )

    def test_108_kerberos_gssapi_creds_from_cache_noop_without_cache(self):
        """_kerberos_gssapi_creds_from_cache is a no-op without prepared ccache"""
        self.cahandler.auth_method = "gssapi"
        self.assertEqual((None, None), self.cahandler._kerberos_gssapi_creds_from_cache())

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._check_credentials")
    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.Certsrv")
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._kerberos_gssapi_creds_from_cache",
        return_value=("explicit-creds", None),
    )
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._kerberos_prepare_gssapi_backend",
        return_value=None,
    )
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._gssapi_channel_bindings_resolve",
        return_value=(None, None),
    )
    def test_109_enroll_passes_explicit_gssapi_creds(
        self,
        _mock_resolve,
        mock_prepare,
        mock_creds_load,
        mock_certsrv,
        mock_credchk,
    ):
        """enroll passes explicit gssapi_creds to Certsrv in keytab mode"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        self.cahandler.auth_method = "gssapi"
        self.cahandler.krb5_principal = "svc@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        mock_credchk.return_value = False
        self.cahandler.enroll("csr")
        self.assertTrue(mock_prepare.called)
        self.assertTrue(mock_creds_load.called)
        self.assertEqual(
            "explicit-creds",
            mock_certsrv.call_args.kwargs.get("gssapi_creds"),
        )

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.subprocess.run")
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.os.path.isfile",
        return_value=True,
    )
    def test_109b_kerberos_acquire_with_kinit_password(
        self, _mock_isfile, mock_subprocess_run
    ):
        """password kinit uses user principal and subprocess-local KRB5_CONFIG"""
        self.cahandler.user = "a2c"
        self.cahandler.password = "secret"
        self.cahandler.krb5_config = "/tmp/krb5.conf"
        self.cahandler.krb5_kinit_path = "/usr/bin/kinit"

        result = self.cahandler._kerberos_acquire_with_kinit_password("/tmp/krb5cc_pw")

        self.assertTrue(result)
        run_args, run_kwargs = mock_subprocess_run.call_args
        self.assertEqual(os.path.realpath("/usr/bin/kinit"), run_args[0][0])
        self.assertEqual("a2c", run_args[0][1])
        self.assertEqual("secret\n", run_kwargs["input"])
        self.assertEqual("/tmp/krb5cc_pw", run_kwargs["env"]["KRB5CCNAME"])
        self.assertEqual(
            os.path.abspath("/tmp/krb5.conf"), run_kwargs["env"]["KRB5_CONFIG"]
        )
        self.assertTrue(run_kwargs["text"])

    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._kerberos_acquire_with_kinit_password",
        return_value=True,
    )
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._kerberos_ccache_prepare",
        return_value="/tmp/cc_pw",
    )
    def test_109c_kerberos_prepare_gssapi_password_success(
        self, mock_ccache, mock_kinit_pw
    ):
        """password+GSSAPI prepare succeeds via password kinit"""
        self.cahandler.auth_method = "gssapi"
        self.cahandler.user = "a2c"
        self.cahandler.password = "secret"
        self.cahandler.krb5_config = "/tmp/krb5.conf"
        with patch.object(
            self.cahandler, "_kerberos_config_path_resolve", return_value="/tmp/krb5.conf"
        ):
            self.assertIsNone(self.cahandler._kerberos_prepare_gssapi_backend())
        self.assertTrue(mock_ccache.called)
        self.assertTrue(mock_kinit_pw.called)

    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._kerberos_cleanup_temporary_ccache"
    )
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._kerberos_acquire_with_kinit_password",
        return_value=False,
    )
    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.CAhandler._kerberos_ccache_prepare",
        return_value="/tmp/cc_pw",
    )
    def test_109d_kerberos_prepare_gssapi_password_requires_kinit_with_config(
        self, _mock_ccache, _mock_kinit_pw, mock_cleanup
    ):
        """password+GSSAPI with krb5_config fails closed when kinit fails"""
        self.cahandler.auth_method = "gssapi"
        self.cahandler.user = "a2c"
        self.cahandler.password = "secret"
        self.cahandler.krb5_config = "/tmp/krb5.conf"
        with patch.object(
            self.cahandler, "_kerberos_config_path_resolve", return_value="/tmp/krb5.conf"
        ):
            error = self.cahandler._kerberos_prepare_gssapi_backend()
        self.assertIn("password kinit", error)
        self.assertTrue(mock_cleanup.called)

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_110_config_load_allowed_templates(self, mock_load_cfg):
        """allowed_templates loads from JSON list"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "allowed_templates": '["WebServer", "User"]',
            "ca_templates_check": "on",
        }
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual(["WebServer", "User"], self.cahandler.allowed_templates)
        self.assertEqual("on", self.cahandler.ca_templates_check)

    @patch("acme2certifier.cahandlers.mscertsrv_ca_handler.load_config")
    def test_111_config_load_allowed_templates_invalid(self, mock_load_cfg):
        """invalid allowed_templates falls back to empty list"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"allowed_templates": "not-json"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual([], self.cahandler.allowed_templates)

    def test_112_allowed_templates_check_reject(self):
        """non-empty allowlist rejects unknown template"""
        self.cahandler.template = "Other"
        self.cahandler.allowed_templates = ["WebServer"]
        self.assertEqual(
            "Template 'Other' is not allowed",
            self.cahandler._allowed_templates_check(),
        )

    def test_113_allowed_templates_check_allow(self):
        """non-empty allowlist accepts listed template"""
        self.cahandler.template = "WebServer"
        self.cahandler.allowed_templates = ["WebServer"]
        self.assertIsNone(self.cahandler._allowed_templates_check())

    def test_114_ca_templates_membership_warn(self):
        """ca_templates_check=warn continues when template missing"""
        self.cahandler.host = "ca.example"
        self.cahandler.template = "Missing"
        self.cahandler.ca_templates_check = "warn"
        ca_server = MagicMock()
        ca_server.get_templates.return_value = ["WebServer"]
        self.assertIsNone(self.cahandler._ca_templates_membership_check(ca_server))

    def test_115_ca_templates_membership_on_reject(self):
        """ca_templates_check=on rejects missing template"""
        self.cahandler.host = "ca.example"
        self.cahandler.template = "Missing"
        self.cahandler.ca_templates_check = "on"
        ca_server = MagicMock()
        ca_server.get_templates.return_value = ["WebServer"]
        self.assertIn(
            "Missing",
            self.cahandler._ca_templates_membership_check(ca_server),
        )

    def test_116_ca_templates_cache_thread_safe(self):
        """CA template fetch is cached across calls"""
        self.cahandler.host = "ca.example"
        ca_server = MagicMock()
        ca_server.get_templates.return_value = ["WebServer", "User"]
        first = self.cahandler._ca_templates_get(ca_server)
        second = self.cahandler._ca_templates_get(ca_server)
        self.assertEqual(["WebServer", "User"], first)
        self.assertEqual(first, second)
        self.assertEqual(1, ca_server.get_templates.call_count)

    @patch(
        "acme2certifier.cahandlers.mscertsrv_ca_handler.eab_profile_header_info_check",
        return_value=None,
    )
    def test_117_enroll_rejects_disallowed_template(self, _mock_eab):
        """enroll rejects template not in allowed_templates"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "BadTemplate"
        self.cahandler.allowed_templates = ["WebServer"]
        error, cert_bundle, cert_raw, poll_id = self.cahandler.enroll("csr")
        self.assertEqual("Template 'BadTemplate' is not allowed", error)
        self.assertIsNone(cert_bundle)
        self.assertIsNone(cert_raw)
        self.assertIsNone(poll_id)


if __name__ == "__main__":

    unittest.main()
