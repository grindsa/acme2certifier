# -*- coding: utf-8 -*-
"""Tests for acme_srv.helpers.certificates."""

from __future__ import annotations

import base64
import datetime
import logging
from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from acme2certifier.acme_srv.helpers.certificates import (
    cert_aki_get,
    cert_cn_get,
    cert_dates_get,
    cert_der2pem,
    cert_extensions_get,
    cert_issuer_get,
    cert_pem2der,
    cert_pubkey_get,
    cert_san_get,
    cert_serial_get,
    cert_ski_get,
    certid_asn1_get,
    certid_check,
    certid_hex_get,
    pembundle_to_list as _fn_pembundle_to_list,
    pkcs7_to_pem,
)
from acme2certifier.acme_srv.helpers.encoding import (
    b64_decode,
    b64_encode,
)

pytestmark = pytest.mark.usefixtures("clear_config_cache", "_silence_logging")


def test_049_helper_cert_serial_get(logger: logging.Logger) -> None:
    """test cert_serial_get"""
    cert = "MIIDDTCCAfWgAwIBAgIBCjANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDEw9mb28u\n                ZXhhbXBsZS5jb20wHhcNMTkwMTIwMTY1OTIwWhcNMTkwMjE5MTY1OTIwWjAaMRgw\n                FgYDVQQDEw9mb28uZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n                ggEKAoIBAQCqUeNzDyBVugUKZq597ishYAdMPgus5Nw5pWE/Jw7PP0koeFE2wODq\n                HVb+XNFFEX4IOyiE2Pi4ilzfXYGKchhP3wHgnkxGNIwt/cDNZgyTiUpITV/ciFaC\n                7avkvQS6ScCYUYrhby7QnvcU02mAyhNcSVGI5TW7HhFdtWrEAK3N8H6yhxHLSi2y\n                dpQ3kCJyJylqt/Rv3uKNjCvTv867K6A1QSsXoAxtPK9P0UOTRvgHkFf8T32Bn/Er\n                1bjkX9Ms8rqDQmicCWJk260lUHzN6vxaeiEg7Kz3TA8Ik3DMIcvwJrE168G1APo+\n                FyOIKyx+t78HWOlNINIqZMj5e2DpulV7AgMBAAGjXjBcMB8GA1UdIwQYMBaAFK1Z\n                zuGt0Pe+NLerCXqQBYmVV7suMB0GA1UdDgQWBBStWc7hrdD3vjS3qwl6kAWJlVe7\n                LjAaBgNVHREEEzARgg9mb28uZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEB\n                AANW0DD4Xp7LH/Rzf2jVLwiFlbtR6iazyn9S/pH2Gwqjkscv/27/dqJb7CfPdD02\n                5ItQcYkZPJhDOsj63kvUaD89QU31RnYQrXrbXFqYOIAq6kxfZUoQmpfEBxbB4Wxm\n                TW0OWS+FMqNw/SuGs6EQjTRA+gBOeGzj4H9yOFOg0PpadBayZ7UT4lm1LOiFHh8h\n                bta75ocePrurdNxsxKJhLlXbnKD6lurCb4khRhrmLmpK8JxhuaevEVklSQX0gqlR\n                fxAH4XQsaqcaedPNI+W5OUITMz40ezDCbUqxS9KEMCGPoOTXNRAjbr72sc4Vkw7H\n                t+eRUDECE+0UnjyeCjTn3EU="
    assert 10 == cert_serial_get(logger, cert)


def test_050_helper_cert_serial_get(logger: logging.Logger) -> None:
    """test cert_serial_get"""
    cert = "MIIDDTCCAfWgAwIBAgIBCjANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDEw9mb28u\n                ZXhhbXBsZS5jb20wHhcNMTkwMTIwMTY1OTIwWhcNMTkwMjE5MTY1OTIwWjAaMRgw\n                FgYDVQQDEw9mb28uZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n                ggEKAoIBAQCqUeNzDyBVugUKZq597ishYAdMPgus5Nw5pWE/Jw7PP0koeFE2wODq\n                HVb+XNFFEX4IOyiE2Pi4ilzfXYGKchhP3wHgnkxGNIwt/cDNZgyTiUpITV/ciFaC\n                7avkvQS6ScCYUYrhby7QnvcU02mAyhNcSVGI5TW7HhFdtWrEAK3N8H6yhxHLSi2y\n                dpQ3kCJyJylqt/Rv3uKNjCvTv867K6A1QSsXoAxtPK9P0UOTRvgHkFf8T32Bn/Er\n                1bjkX9Ms8rqDQmicCWJk260lUHzN6vxaeiEg7Kz3TA8Ik3DMIcvwJrE168G1APo+\n                FyOIKyx+t78HWOlNINIqZMj5e2DpulV7AgMBAAGjXjBcMB8GA1UdIwQYMBaAFK1Z\n                zuGt0Pe+NLerCXqQBYmVV7suMB0GA1UdDgQWBBStWc7hrdD3vjS3qwl6kAWJlVe7\n                LjAaBgNVHREEEzARgg9mb28uZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEB\n                AANW0DD4Xp7LH/Rzf2jVLwiFlbtR6iazyn9S/pH2Gwqjkscv/27/dqJb7CfPdD02\n                5ItQcYkZPJhDOsj63kvUaD89QU31RnYQrXrbXFqYOIAq6kxfZUoQmpfEBxbB4Wxm\n                TW0OWS+FMqNw/SuGs6EQjTRA+gBOeGzj4H9yOFOg0PpadBayZ7UT4lm1LOiFHh8h\n                bta75ocePrurdNxsxKJhLlXbnKD6lurCb4khRhrmLmpK8JxhuaevEVklSQX0gqlR\n                fxAH4XQsaqcaedPNI+W5OUITMz40ezDCbUqxS9KEMCGPoOTXNRAjbr72sc4Vkw7H\n                t+eRUDECE+0UnjyeCjTn3EU="
    assert 10 == cert_serial_get(logger, cert, hexformat=False)


def test_051_helper_cert_serial_get(logger: logging.Logger) -> None:
    """test cert_serial_get"""
    cert = "MIIDDTCCAfWgAwIBAgIBCjANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDEw9mb28u\n                ZXhhbXBsZS5jb20wHhcNMTkwMTIwMTY1OTIwWhcNMTkwMjE5MTY1OTIwWjAaMRgw\n                FgYDVQQDEw9mb28uZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n                ggEKAoIBAQCqUeNzDyBVugUKZq597ishYAdMPgus5Nw5pWE/Jw7PP0koeFE2wODq\n                HVb+XNFFEX4IOyiE2Pi4ilzfXYGKchhP3wHgnkxGNIwt/cDNZgyTiUpITV/ciFaC\n                7avkvQS6ScCYUYrhby7QnvcU02mAyhNcSVGI5TW7HhFdtWrEAK3N8H6yhxHLSi2y\n                dpQ3kCJyJylqt/Rv3uKNjCvTv867K6A1QSsXoAxtPK9P0UOTRvgHkFf8T32Bn/Er\n                1bjkX9Ms8rqDQmicCWJk260lUHzN6vxaeiEg7Kz3TA8Ik3DMIcvwJrE168G1APo+\n                FyOIKyx+t78HWOlNINIqZMj5e2DpulV7AgMBAAGjXjBcMB8GA1UdIwQYMBaAFK1Z\n                zuGt0Pe+NLerCXqQBYmVV7suMB0GA1UdDgQWBBStWc7hrdD3vjS3qwl6kAWJlVe7\n                LjAaBgNVHREEEzARgg9mb28uZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEB\n                AANW0DD4Xp7LH/Rzf2jVLwiFlbtR6iazyn9S/pH2Gwqjkscv/27/dqJb7CfPdD02\n                5ItQcYkZPJhDOsj63kvUaD89QU31RnYQrXrbXFqYOIAq6kxfZUoQmpfEBxbB4Wxm\n                TW0OWS+FMqNw/SuGs6EQjTRA+gBOeGzj4H9yOFOg0PpadBayZ7UT4lm1LOiFHh8h\n                bta75ocePrurdNxsxKJhLlXbnKD6lurCb4khRhrmLmpK8JxhuaevEVklSQX0gqlR\n                fxAH4XQsaqcaedPNI+W5OUITMz40ezDCbUqxS9KEMCGPoOTXNRAjbr72sc4Vkw7H\n                t+eRUDECE+0UnjyeCjTn3EU="
    assert "0a" == cert_serial_get(logger, cert, hexformat=True)


def test_052_helper_cert_issuer_get(logger: logging.Logger) -> None:
    """test cert_issuer_get"""
    cert = "MIIDDTCCAfWgAwIBAgIBCjANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDEw9mb28u\n                ZXhhbXBsZS5jb20wHhcNMTkwMTIwMTY1OTIwWhcNMTkwMjE5MTY1OTIwWjAaMRgw\n                FgYDVQQDEw9mb28uZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n                ggEKAoIBAQCqUeNzDyBVugUKZq597ishYAdMPgus5Nw5pWE/Jw7PP0koeFE2wODq\n                HVb+XNFFEX4IOyiE2Pi4ilzfXYGKchhP3wHgnkxGNIwt/cDNZgyTiUpITV/ciFaC\n                7avkvQS6ScCYUYrhby7QnvcU02mAyhNcSVGI5TW7HhFdtWrEAK3N8H6yhxHLSi2y\n                dpQ3kCJyJylqt/Rv3uKNjCvTv867K6A1QSsXoAxtPK9P0UOTRvgHkFf8T32Bn/Er\n                1bjkX9Ms8rqDQmicCWJk260lUHzN6vxaeiEg7Kz3TA8Ik3DMIcvwJrE168G1APo+\n                FyOIKyx+t78HWOlNINIqZMj5e2DpulV7AgMBAAGjXjBcMB8GA1UdIwQYMBaAFK1Z\n                zuGt0Pe+NLerCXqQBYmVV7suMB0GA1UdDgQWBBStWc7hrdD3vjS3qwl6kAWJlVe7\n                LjAaBgNVHREEEzARgg9mb28uZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEB\n                AANW0DD4Xp7LH/Rzf2jVLwiFlbtR6iazyn9S/pH2Gwqjkscv/27/dqJb7CfPdD02\n                5ItQcYkZPJhDOsj63kvUaD89QU31RnYQrXrbXFqYOIAq6kxfZUoQmpfEBxbB4Wxm\n                TW0OWS+FMqNw/SuGs6EQjTRA+gBOeGzj4H9yOFOg0PpadBayZ7UT4lm1LOiFHh8h\n                bta75ocePrurdNxsxKJhLlXbnKD6lurCb4khRhrmLmpK8JxhuaevEVklSQX0gqlR\n                fxAH4XQsaqcaedPNI+W5OUITMz40ezDCbUqxS9KEMCGPoOTXNRAjbr72sc4Vkw7H\n                t+eRUDECE+0UnjyeCjTn3EU="
    assert "CN=foo.example.com" == cert_issuer_get(logger, cert)


def test_053_helper_cert_san_get(logger: logging.Logger) -> None:
    """test cert_san_get for a single SAN"""
    cert = "MIIDDTCCAfWgAwIBAgIBCjANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDEw9mb28u\n                ZXhhbXBsZS5jb20wHhcNMTkwMTIwMTY1OTIwWhcNMTkwMjE5MTY1OTIwWjAaMRgw\n                FgYDVQQDEw9mb28uZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n                ggEKAoIBAQCqUeNzDyBVugUKZq597ishYAdMPgus5Nw5pWE/Jw7PP0koeFE2wODq\n                HVb+XNFFEX4IOyiE2Pi4ilzfXYGKchhP3wHgnkxGNIwt/cDNZgyTiUpITV/ciFaC\n                7avkvQS6ScCYUYrhby7QnvcU02mAyhNcSVGI5TW7HhFdtWrEAK3N8H6yhxHLSi2y\n                dpQ3kCJyJylqt/Rv3uKNjCvTv867K6A1QSsXoAxtPK9P0UOTRvgHkFf8T32Bn/Er\n                1bjkX9Ms8rqDQmicCWJk260lUHzN6vxaeiEg7Kz3TA8Ik3DMIcvwJrE168G1APo+\n                FyOIKyx+t78HWOlNINIqZMj5e2DpulV7AgMBAAGjXjBcMB8GA1UdIwQYMBaAFK1Z\n                zuGt0Pe+NLerCXqQBYmVV7suMB0GA1UdDgQWBBStWc7hrdD3vjS3qwl6kAWJlVe7\n                LjAaBgNVHREEEzARgg9mb28uZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEB\n                AANW0DD4Xp7LH/Rzf2jVLwiFlbtR6iazyn9S/pH2Gwqjkscv/27/dqJb7CfPdD02\n                5ItQcYkZPJhDOsj63kvUaD89QU31RnYQrXrbXFqYOIAq6kxfZUoQmpfEBxbB4Wxm\n                TW0OWS+FMqNw/SuGs6EQjTRA+gBOeGzj4H9yOFOg0PpadBayZ7UT4lm1LOiFHh8h\n                bta75ocePrurdNxsxKJhLlXbnKD6lurCb4khRhrmLmpK8JxhuaevEVklSQX0gqlR\n                fxAH4XQsaqcaedPNI+W5OUITMz40ezDCbUqxS9KEMCGPoOTXNRAjbr72sc4Vkw7H\n                t+eRUDECE+0UnjyeCjTn3EU="
    assert ["DNS:foo.example.com"] == cert_san_get(logger, cert)


def test_054_helper_cert_san_get(logger: logging.Logger) -> None:
    """test cert_san_get for a multiple SAN of type DNS"""
    cert = "MIIDIzCCAgugAwIBAgICBZgwDQYJKoZIhvcNAQELBQAwGjEYMBYGA1UEAxMPZm9v\n                LmV4YW1wbGUuY29tMB4XDTE5MDEyMDE3MDkxMVoXDTE5MDIxOTE3MDkxMVowGjEY\n                MBYGA1UEAxMPZm9vLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n                MIIBCgKCAQEA+EM+gzAyjegQSRbJI+qZJhuAGM9i48xvIfuOQHleXoJPjV+8VZRV\n                KDljZNXdNT5Zi7K6HY9C622NOV7QefB6zTtm6mSY08ypNsaeorhIvJdnpaJ9gAGH\n                YeQqJ04fL099kiRXJAv8gT8wdpiekg2KEU4wlXMIRfSHiiB37yjcqUzXl6XYYKGe\n                2USMpDfliXL3o8TW2KByGUdCzXUdNbMgzRXwYxkX2+xV2f0vn8NyXHiHg9yJRof2\n                HTjyvAcXN5Nr987slq/Ex5lXLtpB861Ov3ZbwxyzREjmreZBlze7KTfP5IY66XuN\n                Mvhi7AAs0cLTd3SNjpppE/yvUi5q5gfhXQIDAQABo3MwcTAfBgNVHSMEGDAWgBSl\n                YnpKQw12MmEMpvsTEeQi17UsnDAdBgNVHQ4EFgQUpWJ6SkMNdjJhDKb7ExHkIte1\n                LJwwLwYDVR0RBCgwJoIRZm9vLTIuZXhhbXBsZS5jb22CEWZvby0xLmV4YW1wbGUu\n                Y29tMA0GCSqGSIb3DQEBCwUAA4IBAQASA20TtMPXIHH10dikLhFuI14EOtZzXvCx\n                kGlJw9/5JuvVKLsL1wd8BC9o/lg8apDqsrDZ/+0Nc8g3Z9HRN99vcLsVDdT27DkM\n                BslfXdN/qBhKAp3m7jw29uijX5fss+Wz9iHfHciUjVyMJ4DoFxHYPbMWQG8XEUKR\n                TP6Gp79DzCiPKFt52Y8yVikIET4fnyRzU8kGKLuPoIt+EQQzpG26qWAjeNHAASEM\n                keiA+tedMWzydX52B+tGg+l2svxg34apIBDjK8pF+8ZxTt5yjVUa10GbpffJuiEh\n                NWQddOR8IHg+v6lWc9BtuuKK5ubsg6XOiEjhhr42AKViKalX1i4+"
    assert ["DNS:foo-2.example.com", "DNS:foo-1.example.com"] == cert_san_get(
        logger, cert
    )


def test_055_helper_cert_san_get(logger: logging.Logger) -> None:
    """test cert_san_get for a multiple SAN of type DNS"""
    cert = "MIIDaDCCAVCgAwIBAgIICwL0UBNcUakwDQYJKoZIhvcNAQELBQAwKjEXMBUGA1UECxMOYWNtZTJjZXJ0aWZpZXIxDzANBgNVBAMTBnN1Yi1jYTAeFw0yMzA3MTkxODU5NDRaFw0yNDA3MTgxODU5NDRaMBkxFzAVBgNVBAMTDjE5Mi4xNjguMTQuMTMxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEN626lPpwBt4SEvdf5Tb0BpP1tl9KiFE/9xCIyYPsi9VXVDq/EcwO3CRp4fy+3bhZj6i43DdnluETcx8ZR2XyE6NuMGwwHQYDVR0OBBYEFBp+ZupvT2BB92sDkxy2GffHXDRLMB8GA1UdIwQYMBaAFL/ejo4GIiKrrUPI3dRPqKtIQT7VMAsGA1UdDwQEAwID6DAMBgNVHRMBAf8EAjAAMA8GA1UdEQQIMAaHBMCoDoMwDQYJKoZIhvcNAQELBQADggIBAFpq5RWGP4kDRnRjq8pte87bGS9LEmSlGOA8HlQZ+kjAoTunNN7/gvDch4F/CIl1N8cbQ/Ty1vx9CznTpQ39c2LNMILnjNHqQpYRIgLSBvCm26pAdlmicy6zdGlRKaePoMXINw4csDZ4REERg/c21ANhFclYyWWUM987bHZuBZJM8zBfR98ZnOzuQMRb5xztRlXSvddW4qEyKihl+5wPduaF8hDui4wbDFW6pUE9DWO/S1m37Tshh1O3NLlAlaMMwLsYaGkW7yzM4OrzmghJCRtdF9lbYYqHoKxLVWyCRF/pXqqQ/y+k4sN0MeZ7Wk4dI18aGHTGEzu6GSynNptyCQNsoTYexDA/rx57ukX7TqrU5JU/VyrKYD+M/rsLMj3vY4YmmH4W12IhAxa6+UmGG9ixHKpTgLVLRJDdzPMLY+IdI9WHdo7nHDOsaKvrFWqmvsCxT214jN0fVkOTMazG4ILg4DZhMWh8QxGULR7ul2oYnlyGUXiag7qLjNu1/RltJg9sp+ZxVC7RWaoCwxp6CIT95wrUAFTt9NBkccafsQKsF2ZtrUNZ8Z7B3y6hzr9d6rWlZCKlcr/ZNSOnrRTwuCz5HL3Gd2/DfyZUmy5U1+URbktMIdddlV5jaeSpwFZI8Xga4cYJAE7xjVq8HN3jbZ6m4PyylfaQfXisozKRECs4"
    assert ["IP:192.168.14.131"] == cert_san_get(logger, cert)


def test_056_helper_cert_san_get(logger: logging.Logger) -> None:
    """test cert_san_get for a multiple SAN of type DNS"""
    cert = "MIIDezCCAWOgAwIBAgIIIAuZLppuFT4wDQYJKoZIhvcNAQELBQAwKjEXMBUGA1UECxMOYWNtZTJjZXJ0aWZpZXIxDzANBgNVBAMTBnN1Yi1jYTAeFw0yMzA3MjAwNDIxMTlaFw0yNDA3MTkwNDIxMTlaMBkxFzAVBgNVBAMTDjE5Mi4xNjguMTQuMTMxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQTs6Bra1zfVSiReD4AYj8HCKdcaMO5WsgB0zhpVu3HuSQSIQHC8CMe8haCywjYisbbWeDzT654tc674/MjScraOBgDB+MB0GA1UdDgQWBBQQa+M+3oTsdKTSB/Rt3Dk7/Vy0YzAfBgNVHSMEGDAWgBS/3o6OBiIiq61DyN3UT6irSEE+1TALBgNVHQ8EBAMCA+gwDAYDVR0TAQH/BAIwADAhBgNVHREEGjAYghBmb29iYXIuYmFyLmxvY2FshwTAqA6DMA0GCSqGSIb3DQEBCwUAA4ICAQCcevAczULbl5Le/xI1LSQ/PSsROjOZHUjlWf5bRs53aTM6wMqDBsFGdLzTN5vzWqVjie1Nzu8XGSEEuF0L/2bltGgYiYQqD4HKJedEEbYxQbg77o9JLp52MltvXGRH5gYGSGPZbuQ8QANvDn6FqBZjskOtED8SZGGt5spgxK7eguoJoQken68TgdZptL6l6eryTgouPbG0j5vTPPxuZpqxM9vQa4ADyqyvOKRMkZC98IbruChlCtFztILJPkvNx8Gbmlzv201uW9/9mNzcV8vVtlcB+Ftb/+sCfYuU/ShwUuOxOLE7+OKjLlalfniNwqx2l6f30nvvsa11vQc/Rwy1Z+vv96EzyF+GthMx2qLIG4eLLbISATwUfpR0UcLMtr83LRzB578rxrtwcgB5s+AWSDsYEKnzXabQdX1cEuiM3iEdlZ7McFzRvwElObhoDDOqOjGALWmdboox6dDskpQEhe6JALsj3mH07017h5T3W3PvqWD2IAsqH+WTuxCTmfjbqqoAz/Zt2ipIAFtSk79WvWwth/K+xtYhmuoe2+ygocqa9tF9AyoihImSEk1EjXvqKqRLPZwg41C3WKvLlg57fpRFZYR1W28ZqAqqVNf8MMHcsHdZ7koMBhIKKnSe/HdLWm7ghVjAEdYVYvOcOZHzxXBmnV/6ZLRQXu2XQnATJw=="
    assert ["DNS:foobar.bar.local", "IP:192.168.14.131"] == cert_san_get(logger, cert)


def test_057_helper_cert_san_get(logger: logging.Logger) -> None:
    """test cert_san_get for a multiple SAN of type DNS"""
    cert = "MIIDezCCAWOgAwIBAgIIIAuZLppuFT4wDQYJKoZIhvcNAQELBQAwKjEXMBUGA1UECxMOYWNtZTJjZXJ0aWZpZXIxDzANBgNVBAMTBnN1Yi1jYTAeFw0yMzA3MjAwNDIxMTlaFw0yNDA3MTkwNDIxMTlaMBkxFzAVBgNVBAMTDjE5Mi4xNjguMTQuMTMxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQTs6Bra1zfVSiReD4AYj8HCKdcaMO5WsgB0zhpVu3HuSQSIQHC8CMe8haCywjYisbbWeDzT654tc674/MjScraOBgDB+MB0GA1UdDgQWBBQQa+M+3oTsdKTSB/Rt3Dk7/Vy0YzAfBgNVHSMEGDAWgBS/3o6OBiIiq61DyN3UT6irSEE+1TALBgNVHQ8EBAMCA+gwDAYDVR0TAQH/BAIwADAhBgNVHREEGjAYghBmb29iYXIuYmFyLmxvY2FshwTAqA6DMA0GCSqGSIb3DQEBCwUAA4ICAQCcevAczULbl5Le/xI1LSQ/PSsROjOZHUjlWf5bRs53aTM6wMqDBsFGdLzTN5vzWqVjie1Nzu8XGSEEuF0L/2bltGgYiYQqD4HKJedEEbYxQbg77o9JLp52MltvXGRH5gYGSGPZbuQ8QANvDn6FqBZjskOtED8SZGGt5spgxK7eguoJoQken68TgdZptL6l6eryTgouPbG0j5vTPPxuZpqxM9vQa4ADyqyvOKRMkZC98IbruChlCtFztILJPkvNx8Gbmlzv201uW9/9mNzcV8vVtlcB+Ftb/+sCfYuU/ShwUuOxOLE7+OKjLlalfniNwqx2l6f30nvvsa11vQc/Rwy1Z+vv96EzyF+GthMx2qLIG4eLLbISATwUfpR0UcLMtr83LRzB578rxrtwcgB5s+AWSDsYEKnzXabQdX1cEuiM3iEdlZ7McFzRvwElObhoDDOqOjGALWmdboox6dDskpQEhe6JALsj3mH07017h5T3W3PvqWD2IAsqH+WTuxCTmfjbqqoAz/Zt2ipIAFtSk79WvWwth/K+xtYhmuoe2+ygocqa9tF9AyoihImSEk1EjXvqKqRLPZwg41C3WKvLlg57fpRFZYR1W28ZqAqqVNf8MMHcsHdZ7koMBhIKKnSe/HdLWm7ghVjAEdYVYvOcOZHzxXBmnV/6ZLRQXu2XQnATJw=="
    assert ["DNS:foobar.bar.local", "IP:192.168.14.131"] == cert_san_get(logger, cert)


def test_058_helper_cert_san_get(logger: logging.Logger) -> None:
    """test cert_san_get for a single SAN"""
    cert = "\n-----BEGIN CERTIFICATE-----\nMIIDDTCCAfWgAwIBAgIBCjANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDEw9mb28u\nZXhhbXBsZS5jb20wHhcNMTkwMTIwMTY1OTIwWhcNMTkwMjE5MTY1OTIwWjAaMRgw\nFgYDVQQDEw9mb28uZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\nggEKAoIBAQCqUeNzDyBVugUKZq597ishYAdMPgus5Nw5pWE/Jw7PP0koeFE2wODq\nHVb+XNFFEX4IOyiE2Pi4ilzfXYGKchhP3wHgnkxGNIwt/cDNZgyTiUpITV/ciFaC\n7avkvQS6ScCYUYrhby7QnvcU02mAyhNcSVGI5TW7HhFdtWrEAK3N8H6yhxHLSi2y\ndpQ3kCJyJylqt/Rv3uKNjCvTv867K6A1QSsXoAxtPK9P0UOTRvgHkFf8T32Bn/Er\n1bjkX9Ms8rqDQmicCWJk260lUHzN6vxaeiEg7Kz3TA8Ik3DMIcvwJrE168G1APo+\nFyOIKyx+t78HWOlNINIqZMj5e2DpulV7AgMBAAGjXjBcMB8GA1UdIwQYMBaAFK1Z\nzuGt0Pe+NLerCXqQBYmVV7suMB0GA1UdDgQWBBStWc7hrdD3vjS3qwl6kAWJlVe7\nLjAaBgNVHREEEzARgg9mb28uZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEB\nAANW0DD4Xp7LH/Rzf2jVLwiFlbtR6iazyn9S/pH2Gwqjkscv/27/dqJb7CfPdD02\n5ItQcYkZPJhDOsj63kvUaD89QU31RnYQrXrbXFqYOIAq6kxfZUoQmpfEBxbB4Wxm\nTW0OWS+FMqNw/SuGs6EQjTRA+gBOeGzj4H9yOFOg0PpadBayZ7UT4lm1LOiFHh8h\nbta75ocePrurdNxsxKJhLlXbnKD6lurCb4khRhrmLmpK8JxhuaevEVklSQX0gqlR\nfxAH4XQsaqcaedPNI+W5OUITMz40ezDCbUqxS9KEMCGPoOTXNRAjbr72sc4Vkw7H\nt+eRUDECE+0UnjyeCjTn3EU=\n-----END CERTIFICATE-----\n                "
    assert ["DNS:foo.example.com"] == cert_san_get(logger, cert, recode=False)


def test_059_helper_cert_san_get(logger: logging.Logger) -> None:
    """test cert_san_get for a single SAN and recode = False"""
    cert = "-----BEGIN X509 CERTIFICATE-----\nMIIE2zCCAsOgAwIBAgIPAXI102H4bCWEkhD2SaLsMA0GCSqGSIb3DQEBDQUAMDIx\nCzAJBgNVBAYTAkRFMQ4wDAYDVQQKEwVOb2tpYTETMBEGA1UEAwwKbmNtX3N1Yl9j\nYTAeFw0yMDA1MjEwNTMyMjVaFw0yMDA2MjAyMzU5NTlaMBkxFzAVBgNVBAMTDmZv\nbzEuYmFyLmxvY2FsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbx+\nz+9wsEewBf1hnk3yAy5TFg+lWVdwk2QRdAMDTExVP823QF/K+t6cxJV/+QuWVbHN\n+lx6nQCXIqCZSN97hN0YTkrw8jnA4FpZzyvYI9rKEO3p4sxqndbu4X+gtyMBbXOL\nhjTlN2f7Z081XWIgkikvuZU2XzMZ+BbRFDfsPdDRwbwvgJU6NxpdIKm2DmYIP1MF\no+tLu0toAc0nm9v8Otme28/kpJxmW3iOMkqN9BE+qAkggFDeNoxPtXRyP2PrRgba\nj94e1uznsyni7CYw/a9O1NPrjKFQmPaCk8k9ICvPoLHXtLabekCmvdxyRlDwD/Xo\naygpd9+UHCREhcOu/wIDAQABo4IBBTCCAQEwHwYDVR0jBBgwFoAUEZ+5Dp2l8KCZ\nzHhwr3965P6xxsswHQYDVR0OBBYEFKsuSjgZZMl9vZeBB0wks4Wbg4PhMAsGA1Ud\nDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDBUBgNVHR8ETTBLMEmg\nR6BFhkNodHRwOi8vc3J2Lm5jbG0tc2FtYmEubG9jYWw6ODA4MC9jcmwtYXMtZGVy\nL2N1cnJlbnRjcmwtODcuY3JsP2lkPTg3MEEGCCsGAQUFBwEBBDUwMzAxBggrBgEF\nBQcwAYYlaHR0cDovL3Nydi5uY2xtLXNhbWJhLmxvY2FsOjgwOTAvY2EyLzANBgkq\nhkiG9w0BAQ0FAAOCAgEAgpfWOM8fWlkwSbWtgnAKnu8GNMteOckWS1gMydOhokhY\nPZdkpL8uoMWRahyjhmAH85TtHdydVaQ9NNBUTsbiOqkN2jPurDdzgfUs2gAwoR05\nMkHVWI1+C3lHAVlqPWYld+6Kl3lnEjy3jFSMugTuq5h79f0KxGle7W568Xg+zI3R\nRy1dRggR6W2G9L+7Ez8Y+H/8P/gjbTO1GGYoXI4ISQl3EinL/X7XpYnQ3o14uDLb\nm/h+YyLfi03m8tLJQPM7soDAZx6qI/1V4H/VT1VEKBCiec8w580rIH6GSrjUkddp\nwd0p74B8xwmt9zA+gBV3Js72PBy9mdcMIvYIO3otmN2jQL8PC1B8VNEmf0l8a5wq\n07qftQEI82vcrLG8Dgy7R9AxrIxd1xnZOTrcOo3dU+blAehAJZWT2B0B8XyoGk2/\nCiMCwOQijMgp97tjnuQ3dkRhu50kUN5LCa9jU2ongXj0+28mEKZ5rAQUBQmAMITR\nhTkTB1OxdpFMxyg83OZdYu/xit9YfVB0AAyarqjTst/y79UkExfEf0sAARBiffkx\nPZwtZpoz736yvIqanX6u2zUHLDzSRZXOZHY6pxANqoH6howxqGkI3FMjeDbDUln7\n/TEtRju77ONV1X+8iPYrnQqTRoR3a3IwT8Cz/HErNM6aNCvPVPqakZXZrcpXILY=\n-----END X509 CERTIFICATE-----"
    assert ["DNS:foo1.bar.local"] == cert_san_get(logger, cert, recode=False)


@patch("acme2certifier.acme_srv.helpers.certificates.cert_load")
def test_060_helper_cert_san_get(
    mock_certload: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """test cert_san_get for a single SAN and recode = False"""
    cert = "cert"
    mock_certload.return_value = "mock_csrload"
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert not cert_san_get(logger, cert, recode=False)
    assert (
        "ERROR:test_a2c:Error while getting SANs from certificate: 'str' object has no attribute 'extensions'"
        in lcm.output
    )


def test_061_helper_cert_san_get_email(logger: logging.Logger) -> None:
    """cert_san_get extracts rfc822Name SANs as EMAIL:"""
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "user@example.com")]
    )
    cert_obj = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.RFC822Name("user@example.com"),
                    x509.DNSName("foo.example.com"),
                    x509.IPAddress(ipaddress.IPv4Address("192.168.14.131")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert = base64.b64encode(cert_obj.public_bytes(serialization.Encoding.DER)).decode()
    assert [
        "DNS:foo.example.com",
        "IP:192.168.14.131",
        "EMAIL:user@example.com",
    ] == cert_san_get(logger, cert)


def test_062_helper_cert_san_get_email_only(logger: logging.Logger) -> None:
    """cert_san_get with only rfc822Name SANs"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "user@example.com")]
    )
    cert_obj = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name("user@example.com")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert = base64.b64encode(cert_obj.public_bytes(serialization.Encoding.DER)).decode()
    assert ["EMAIL:user@example.com"] == cert_san_get(logger, cert)


def test_081_helper_cert_pubkey_get(logger: logging.Logger) -> None:
    """test get public_key from certificate"""
    cert = "\n-----BEGIN X509 CERTIFICATE-----\nMIIE2zCCAsOgAwIBAgIPAXI102H4bCWEkhD2SaLsMA0GCSqGSIb3DQEBDQUAMDIx\nCzAJBgNVBAYTAkRFMQ4wDAYDVQQKEwVOb2tpYTETMBEGA1UEAwwKbmNtX3N1Yl9j\nYTAeFw0yMDA1MjEwNTMyMjVaFw0yMDA2MjAyMzU5NTlaMBkxFzAVBgNVBAMTDmZv\nbzEuYmFyLmxvY2FsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbx+\nz+9wsEewBf1hnk3yAy5TFg+lWVdwk2QRdAMDTExVP823QF/K+t6cxJV/+QuWVbHN\n+lx6nQCXIqCZSN97hN0YTkrw8jnA4FpZzyvYI9rKEO3p4sxqndbu4X+gtyMBbXOL\nhjTlN2f7Z081XWIgkikvuZU2XzMZ+BbRFDfsPdDRwbwvgJU6NxpdIKm2DmYIP1MF\no+tLu0toAc0nm9v8Otme28/kpJxmW3iOMkqN9BE+qAkggFDeNoxPtXRyP2PrRgba\nj94e1uznsyni7CYw/a9O1NPrjKFQmPaCk8k9ICvPoLHXtLabekCmvdxyRlDwD/Xo\naygpd9+UHCREhcOu/wIDAQABo4IBBTCCAQEwHwYDVR0jBBgwFoAUEZ+5Dp2l8KCZ\nzHhwr3965P6xxsswHQYDVR0OBBYEFKsuSjgZZMl9vZeBB0wks4Wbg4PhMAsGA1Ud\nDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDBUBgNVHR8ETTBLMEmg\nR6BFhkNodHRwOi8vc3J2Lm5jbG0tc2FtYmEubG9jYWw6ODA4MC9jcmwtYXMtZGVy\nL2N1cnJlbnRjcmwtODcuY3JsP2lkPTg3MEEGCCsGAQUFBwEBBDUwMzAxBggrBgEF\nBQcwAYYlaHR0cDovL3Nydi5uY2xtLXNhbWJhLmxvY2FsOjgwOTAvY2EyLzANBgkq\nhkiG9w0BAQ0FAAOCAgEAgpfWOM8fWlkwSbWtgnAKnu8GNMteOckWS1gMydOhokhY\nPZdkpL8uoMWRahyjhmAH85TtHdydVaQ9NNBUTsbiOqkN2jPurDdzgfUs2gAwoR05\nMkHVWI1+C3lHAVlqPWYld+6Kl3lnEjy3jFSMugTuq5h79f0KxGle7W568Xg+zI3R\nRy1dRggR6W2G9L+7Ez8Y+H/8P/gjbTO1GGYoXI4ISQl3EinL/X7XpYnQ3o14uDLb\nm/h+YyLfi03m8tLJQPM7soDAZx6qI/1V4H/VT1VEKBCiec8w580rIH6GSrjUkddp\nwd0p74B8xwmt9zA+gBV3Js72PBy9mdcMIvYIO3otmN2jQL8PC1B8VNEmf0l8a5wq\n07qftQEI82vcrLG8Dgy7R9AxrIxd1xnZOTrcOo3dU+blAehAJZWT2B0B8XyoGk2/\nCiMCwOQijMgp97tjnuQ3dkRhu50kUN5LCa9jU2ongXj0+28mEKZ5rAQUBQmAMITR\nhTkTB1OxdpFMxyg83OZdYu/xit9YfVB0AAyarqjTst/y79UkExfEf0sAARBiffkx\nPZwtZpoz736yvIqanX6u2zUHLDzSRZXOZHY6pxANqoH6howxqGkI3FMjeDbDUln7\n/TEtRju77ONV1X+8iPYrnQqTRoR3a3IwT8Cz/HErNM6aNCvPVPqakZXZrcpXILY=\n-----END X509 CERTIFICATE-----"
    pub_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbx+z+9wsEewBf1hnk3y\nAy5TFg+lWVdwk2QRdAMDTExVP823QF/K+t6cxJV/+QuWVbHN+lx6nQCXIqCZSN97\nhN0YTkrw8jnA4FpZzyvYI9rKEO3p4sxqndbu4X+gtyMBbXOLhjTlN2f7Z081XWIg\nkikvuZU2XzMZ+BbRFDfsPdDRwbwvgJU6NxpdIKm2DmYIP1MFo+tLu0toAc0nm9v8\nOtme28/kpJxmW3iOMkqN9BE+qAkggFDeNoxPtXRyP2PrRgbaj94e1uznsyni7CYw\n/a9O1NPrjKFQmPaCk8k9ICvPoLHXtLabekCmvdxyRlDwD/Xoaygpd9+UHCREhcOu\n/wIDAQAB\n-----END PUBLIC KEY-----\n"
    assert pub_key == cert_pubkey_get(logger, cert)


def test_162_helper_cert_dates_get(logger: logging.Logger) -> None:
    """get issuing and expiration date from rsa certificate"""
    cert = "MIIElTCCAn2gAwIBAgIRAKD_ulfqPUn-ggOUHOxjp40wDQYJKoZIhvcNAQELBQAwSDELMAkGA1UEBhMCREUxDzANBgNVBAgMBkJlcmxpbjEXMBUGA1UECgwOQWNtZTJDZXJ0aWZpZXIxDzANBgNVBAMMBnN1Yi1jYTAeFw0yMDA1MjcxMjMwMjNaFw0yMDA2MjYxMjMwMjNaMBkxFzAVBgNVBAMMDmZvbzEuYmFyLmxvY2FsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbx-z-9wsEewBf1hnk3yAy5TFg-lWVdwk2QRdAMDTExVP823QF_K-t6cxJV_-QuWVbHN-lx6nQCXIqCZSN97hN0YTkrw8jnA4FpZzyvYI9rKEO3p4sxqndbu4X-gtyMBbXOLhjTlN2f7Z081XWIgkikvuZU2XzMZ-BbRFDfsPdDRwbwvgJU6NxpdIKm2DmYIP1MFo-tLu0toAc0nm9v8Otme28_kpJxmW3iOMkqN9BE-qAkggFDeNoxPtXRyP2PrRgbaj94e1uznsyni7CYw_a9O1NPrjKFQmPaCk8k9ICvPoLHXtLabekCmvdxyRlDwD_Xoaygpd9-UHCREhcOu_wIDAQABo4GoMIGlMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDAdBgNVHQ4EFgQUqy5KOBlkyX29l4EHTCSzhZuDg-EwDgYDVR0PAQH_BAQDAgWgMB8GA1UdIwQYMBaAFBs0P896R0FUZHfnxMJL52ftKQOkMAwGA1UdEwEB_wQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMA0GCSqGSIb3DQEBCwUAA4ICAQB7pQpILzxqcU2RKlr17rcne6NSJTUJnNXALeUFy5PrnjjJY1_B1cKaWluk3p7AMFvUjBpcucGCfEDudW290AQxYjrvl8_ePkzRzEkAo76L7ZqED5upYBZVn_3lA5Alr8L67UC0bDMhKTsy8WJzhWHQlMb37_YFUvtNPoI_MI09Q842VXeNQz5UDZmW9qhyeDIkf6fwOAO66VnGTLuUm2LGQZ-St2GauxR0ZUcRtMJoc-c7WOdHs8DlUCoFtglrzVH98501Sx749CG4nkJr4QNDpkw2hAhlo4Cxzp6PlljPNSgM9MsqqVdrgqDteDM_n-yrVFGezCik4QexDkWARPutRLQtpbhudExVnoFM68ihZ0y3oeDjgUBLybBQpcBAsBqiJ66Q8HTZRSqO9zlKW5Vm1KwAVDh_qgELxvqd0wIVkyxBKPta2l1fvb5YBiVqo4JyNcCTnoBS1emO4vk8XjroKijwLnU0cEXwHrY4JF1uU_kOtoZMGPul5EuBMcODLs7JJ3_IqJd8quI7Vf5zSsaB6nSzQ8XmiQiVogKflBeLl7AWmYCiL-FLP_q4dSJmvdr6fPMNy4-cfDO4Awc8RNfv-VjF5Mq57X1IXJrWKkat4lCEoPMq5WRJV8uVm6XNdwvUJxgCYR9mfol7T6imODDd7BNV4dKYvyteoS0auC0iww"
    assert (1590582623, 1593174623) == cert_dates_get(logger, cert)


def test_163_helper_cert_dates_get(logger: logging.Logger) -> None:
    """get issuing and expiration date no certificate"""
    cert = None
    assert (0, 0) == cert_dates_get(logger, cert)


def test_164_helper_cert_dates_get(logger: logging.Logger) -> None:
    """get issuing and expiration date damaged certificate"""
    cert = "foo"
    assert (0, 0) == cert_dates_get(logger, cert)


def test_165_helper_cert_dates_get(logger: logging.Logger) -> None:
    """get issuing and expiration date ecc certificate"""
    cert = "MIIDozCCAYugAwIBAgIIMMxkE7mRR+YwDQYJKoZIhvcNAQELBQAwKjEXMBUGA1UECxMOYWNtZTJjZXJ0aWZpZXIxDzANBgNVBAMTBnN1Yi1jYTAeFw0yMDA3MTEwNDUzMTFaFw0yMTA3MTEwNDUzMTFaMBkxFzAVBgNVBAMMDmZvbzEuYmFyLmxvY2FsMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAER/KMoV5+zQgegqYue2ztPK2nZVpK2vxb02UzwyHw4ebhJ2gBobI23lSBRa1so1ug0kej7U+ohm5aGFdNxLM0G6OBqDCBpTALBgNVHQ8EBAMCBeAwGQYDVR0RBBIwEIIOZm9vMS5iYXIubG9jYWwwHQYDVR0OBBYEFCSaU743wU8jMETIO381r13tVLdMMA4GA1UdDwEB/wQEAwIFoDAfBgNVHSMEGDAWgBS/3o6OBiIiq61DyN3UT6irSEE+1TAMBgNVHRMBAf8EAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATANBgkqhkiG9w0BAQsFAAOCAgEAmmhHuBhXNM2Azv53rCKY72yTQIoDVHjYrAvTmS6NsJzYflEOMkI7FCes64dWp54BerSD736Yax67b4XmLXc/+T41d7QAcnhY5xvLJiMpSsW37icHcLZpjlOrYDoRmny2U7n6t1aQ03nwgV+BgdaUQYLkUZuczs4kdqH1c9Ot9CCRTHpqSWlmWzGeRgt2uT4gKhFESP9lzx37YwKBHulBGthv1kcAaz8w8iPXBg01OEDiraXCBZFoYDEpDi2w2Y6ChCr7sNsY7aJ3a+2iHGYlktXEntk78S+g00HW61G9oLoRgeqEH3L6qVIpnswPAU/joub0YhNBIUFenCj8c3HMBgMcczzdZL+qStdymhpVkZetzXtMTKtgmxhkRzAOQUBBcHFc+wM97FqC0S4HJAuoHQ4EJ46MxwZH0jBVqcqCPMSaJ88uV902+VGGXrnxMR8RbGWLoCmsYb1ISmBUt+31PjMCYbXKwLmzvbRpO7XAQimvtOqoufl5yeRUJRLcUS6Let0QzU196/nZ789d7Etep7RjDYQm7/QhiWH197yKZ5/mUxqfyHDQ3hk5iX7S/gbo1jQXElEv5tB8Ozs+zVQmB2bXpN8c+8XUaZnwvYC2y+0LAQN4z7xilReCaasxQSsEOLCrlsannkGV704HYnnaKBS2tI948QotHnADHdfHl3o"
    assert (1594443191, 1625979191) == cert_dates_get(logger, cert)


@patch("acme2certifier.acme_srv.helpers.certificates.date_to_uts_utc")
@patch("acme2certifier.acme_srv.helpers.certificates.cert_load")
def test_166_helper_cert_dates_get(
    mock_cert: MagicMock,
    mock_dates: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """get issuing and expiration date excaption"""
    mock_dates.side_effect = [Exception("not_valid_before_utc"), 123, 456]
    mock_cert = Mock()
    mock_cert.not_valid_before_utc.side_effect = Exception("not_valid_before_utc")
    mock_cert.not_valid_after_utc.side_effect = Exception("not_valid_after_utc")
    with capture_logs("test_a2c", level="DEBUG") as lcm:
        assert (123, 456) == cert_dates_get(logger, "cert")
    assert (
        "DEBUG:test_a2c:Error while getting dates from certificate. Fallback to deprecated method: not_valid_before_utc"
        in lcm.output
    )


@patch("acme2certifier.acme_srv.helpers.certificates.date_to_uts_utc")
@patch("acme2certifier.acme_srv.helpers.certificates.cert_load")
def test_167_helper_cert_dates_get(
    mock_cert: MagicMock,
    mock_dates: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """get issuing and expiration date excaption"""
    mock_dates.side_effect = [Exception("uts")]
    mock_cert = Mock()
    mock_cert.not_valid_before_utc.side_effect = Exception("not_valid_before_utc")
    mock_cert.not_valid_after_utc.side_effect = Exception("not_valid_after_utc")
    with capture_logs("test_a2c", level="DEBUG") as lcm:
        assert (0, 0) == cert_dates_get(logger, "cert")
    assert (
        "DEBUG:test_a2c:Error while getting dates from certificate. Fallback to deprecated method: uts"
        in lcm.output
    )
    assert (
        "ERROR:test_a2c:Error while getting dates from certificate: uts" in lcm.output
    )


def test_211_cert_der2pem(logger: logging.Logger) -> None:
    """test cert_der2pem"""
    b64 = "MIIETjCCAjagAwIBAgIRAIG11e4S8ErJuwCYAKsoU3UwDQYJKoZIhvcNAQELBQAwETEPMA0GA1UEAxMGc3ViLWNhMB4XDTIxMDYxMjA2MjMzOFoXDTIzMDYwMjA2MjMzOFowGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0lk4lyEIa0VL/u5ic01Zo/o+gyYqFpU7xe+nbFgiKA+R1rqrzP/sR6xjHqS0Rkv/BcBXf81sp/+iDmwIQLVlBTkKdimqVHCJMAbTL8ZNpcLDaRUce4liyX1cmczPTSqI/kcyEr8tKpYN+KzvKZZsNx2Pbgu7y7/70P2uSywiW+sqYZ+X28KGFxq6wwENzJtweDVsbWql9LLtw6daF41UQg10auNlRL1nhW0SlWZh1zPPW/0sa6C3xX28jjVh843b4ekkRNLXSEYQMTi0qYR2LomQ5aTlQ/hellf17UknfN2aA2RH5D7Ek+mndj/rH21bxQg26KRmHlaJld9K1IfvJAgMBAAGjgZgwgZUwCwYDVR0PBAQDAgXgMBkGA1UdEQQSMBCCDmZvbzEuYmFyLmxvY2FsMB0GA1UdDgQWBBReDKlEWwro02ljWMCi10HMqhDmbzAfBgNVHSMEGDAWgBSDJ855iatD1k7LCUzmM5yhe4IzeDAMBgNVHRMBAf8EAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATANBgkqhkiG9w0BAQsFAAOCAgEAhv7Jco6VjT25FuyOz/C0N5+q2M8sqjcDDYMwUTKXVkIc7/lSsubL8z64eS4I5iBecNOlPXASMoMe0KbdrvzqItYgeisC08rnWQayuDr/dj2Y/v4WptZdTPc0pWZQ7LUSxcZaydMFsIKxtfO2HR84DqrUbpvDfVSP7/UiN2O0TbSBiEC6Xayu6IudGZ9naHTAXzTau6SejcbH+0jWZsDXd1SbDPd3a+ZcHbDLIZAzsjcurleDPS54PIXjblOgMrsheDq/wzxKtvLOZEe8Gr6THwtX6uS0oQ72BFNGfZVVPFiL/q0Dvj2FveBtv7k14QcBqHutE4pEpYb/kcU7cxCVgGlUw8Q8trYQhBB37X9dOHjC2G8cyCeyVr+xfUE12wTKZDRIXjG3FMpKgeB4oNYPWA5m/1GBOGddhmogIB8GXeenDcAjBdVOFuuOrMInHLnLD9w7iEiopfx+six3Nxpo3thDV4xdiTZsWp9ojZhQzW8haEQleJ3Xyl65UuZKHyrRJ0OWR4LRkNwJitG5F0MYg8bjgik/cHTwzIB0HXgnaVeMBJY3sOkvCpAlTGZe1GL9foWIeFkprPG4cePrjtC3Mn8rHH0pIi1mdkcAIdexYdg/qlroKk2ROLXnX5LHmrM1CDZQphgyzLETdwXQdTBOJvc8FsDPhp5p+iqgT2e16QI="
    result = b"-----BEGIN CERTIFICATE-----\nMIIETjCCAjagAwIBAgIRAIG11e4S8ErJuwCYAKsoU3UwDQYJKoZIhvcNAQELBQAw\nETEPMA0GA1UEAxMGc3ViLWNhMB4XDTIxMDYxMjA2MjMzOFoXDTIzMDYwMjA2MjMz\nOFowGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUA\nA4IBDwAwggEKAoIBAQC0lk4lyEIa0VL/u5ic01Zo/o+gyYqFpU7xe+nbFgiKA+R1\nrqrzP/sR6xjHqS0Rkv/BcBXf81sp/+iDmwIQLVlBTkKdimqVHCJMAbTL8ZNpcLDa\nRUce4liyX1cmczPTSqI/kcyEr8tKpYN+KzvKZZsNx2Pbgu7y7/70P2uSywiW+sqY\nZ+X28KGFxq6wwENzJtweDVsbWql9LLtw6daF41UQg10auNlRL1nhW0SlWZh1zPPW\n/0sa6C3xX28jjVh843b4ekkRNLXSEYQMTi0qYR2LomQ5aTlQ/hellf17UknfN2aA\n2RH5D7Ek+mndj/rH21bxQg26KRmHlaJld9K1IfvJAgMBAAGjgZgwgZUwCwYDVR0P\nBAQDAgXgMBkGA1UdEQQSMBCCDmZvbzEuYmFyLmxvY2FsMB0GA1UdDgQWBBReDKlE\nWwro02ljWMCi10HMqhDmbzAfBgNVHSMEGDAWgBSDJ855iatD1k7LCUzmM5yhe4Iz\neDAMBgNVHRMBAf8EAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAN\nBgkqhkiG9w0BAQsFAAOCAgEAhv7Jco6VjT25FuyOz/C0N5+q2M8sqjcDDYMwUTKX\nVkIc7/lSsubL8z64eS4I5iBecNOlPXASMoMe0KbdrvzqItYgeisC08rnWQayuDr/\ndj2Y/v4WptZdTPc0pWZQ7LUSxcZaydMFsIKxtfO2HR84DqrUbpvDfVSP7/UiN2O0\nTbSBiEC6Xayu6IudGZ9naHTAXzTau6SejcbH+0jWZsDXd1SbDPd3a+ZcHbDLIZAz\nsjcurleDPS54PIXjblOgMrsheDq/wzxKtvLOZEe8Gr6THwtX6uS0oQ72BFNGfZVV\nPFiL/q0Dvj2FveBtv7k14QcBqHutE4pEpYb/kcU7cxCVgGlUw8Q8trYQhBB37X9d\nOHjC2G8cyCeyVr+xfUE12wTKZDRIXjG3FMpKgeB4oNYPWA5m/1GBOGddhmogIB8G\nXeenDcAjBdVOFuuOrMInHLnLD9w7iEiopfx+six3Nxpo3thDV4xdiTZsWp9ojZhQ\nzW8haEQleJ3Xyl65UuZKHyrRJ0OWR4LRkNwJitG5F0MYg8bjgik/cHTwzIB0HXgn\naVeMBJY3sOkvCpAlTGZe1GL9foWIeFkprPG4cePrjtC3Mn8rHH0pIi1mdkcAIdex\nYdg/qlroKk2ROLXnX5LHmrM1CDZQphgyzLETdwXQdTBOJvc8FsDPhp5p+iqgT2e1\n6QI=\n-----END CERTIFICATE-----\n"
    der = b64_decode(logger, b64)
    assert result == cert_der2pem(der)


def test_212_cert_pem2der(logger: logging.Logger) -> None:
    """test cert_der2pem"""
    cert = "-----BEGIN CERTIFICATE-----\nMIIEZDCCAkygAwIBAgIIe941mx0FQtAwDQYJKoZIhvcNAQELBQAwKjEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxDzANBgNVBAMTBnN1Yi1jYTAeFw0yMTA0MDkxNTUy\nMDBaFw0yNjA0MDkxNTUyMDBaMBgxFjAUBgNVBAMTDWVzdGNsaWVudC5lc3QwggEi\nMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAn6IqwTE1RvZUm3gelpu4tmrd\nFj8Ub98J1YeQz7qrew5iA81NeH9tR484edjcY0ieOt3e1MfxJoziWtaeqxpsfytm\nVB/i+850kVZmvRCR1jhW/4AzidkVBMQiCR5erPmmheeCxbKkto0rHb7ziRA+F8/f\nZLKfLNsahEQPxDuMItyQFCOQFHh8Hfuend2NgsQKeZ1r5Czf3n5Q6NFff7HG+MDe\nNDNdPB3ShgcvvNCFUS1z615/GIItfSqcWTAVaJ7436cA7yy5y4+0SvjfXYtHYfyt\nhBj/5UqlUmjni8Irj5K8uEtb1YUujmvlTTbzPkhYqIkSoyr7t21Dz+gcYn49AgMB\nAAGjgZ8wgZwwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUN3Z0iLv1FE17DCDBfpxW\n2P+5+kIwCwYDVR0PBAQDAgO4MBMGA1UdJQQMMAoGCCsGAQUFBwMCMBgGA1UdEQQR\nMA+CDWVzdGNsaWVudC5lc3QwEQYJYIZIAYb4QgEBBAQDAgWgMB4GCWCGSAGG+EIB\nDQQRFg94Y2EgY2VydGlmaWNhdGUwDQYJKoZIhvcNAQELBQADggIBACMAHHH4/0eA\nXbS/uKsIjLN1QPnnzgjxC0xoUon8UVM0PUMH+FMg6rs21Xyl5tn5iItmvKI9c3ak\nAZ00RUQKVdmJVFRUKywmfF7n5epBpXtWJrSH817NT9GOp+PO5VUTDV5VkvpVLoy7\nWzThrheLKz1nC1dWowRz86tcBLAsC1zT17fsNZXQDuv4LiQQXs7QKhUU75r1Ixrd\nBPeBQSP5skGpWxm8sapQSfOALoXu1pSoGIr6tqvNGuEoZGvUuWeQHG/G8c2ufL+6\nlEzZBBCd6e2tErkqD/vqfCRzbLcGgSPX0HVWdkjH09nHWXI5UhNr2YgGF7YvSTKW\nJfbDVlTql1BuSn2yTQtDk4E8k9BLr8WfqFSZvYrivT9Ax1n3BD9jvQL5+QRdioH1\nkqNGMme0Pb43pHciX4hu9L5rGenZRmxeGXZ78uSOR+n2bGxAMw1OY7Rx/lsNSKWD\nSN+7xIrwjjXO5Uthev1ecrLAK2+EpjITa6Y85ms39V4ypCEdujkKEBeVxuN8DdMJ\n2GaFGluSRZeYZ0LAPfYr5sp6G6904WF+PcT0WjGenH4PJLXrAttbhhvQxXU0Q8s2\nCUwUHy5OT/DW3POq7WETc+zmFGwZqiP3W9gmN0hHXsKqkNmz2RYgoH57lPS1PJb0\nklGUNHG98CtsmlhrivhSTJWqSIOfyKGF\n-----END CERTIFICATE-----"
    result = "MIIEZDCCAkygAwIBAgIIe941mx0FQtAwDQYJKoZIhvcNAQELBQAwKjEXMBUGA1UECxMOYWNtZTJjZXJ0aWZpZXIxDzANBgNVBAMTBnN1Yi1jYTAeFw0yMTA0MDkxNTUyMDBaFw0yNjA0MDkxNTUyMDBaMBgxFjAUBgNVBAMTDWVzdGNsaWVudC5lc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAn6IqwTE1RvZUm3gelpu4tmrdFj8Ub98J1YeQz7qrew5iA81NeH9tR484edjcY0ieOt3e1MfxJoziWtaeqxpsfytmVB/i+850kVZmvRCR1jhW/4AzidkVBMQiCR5erPmmheeCxbKkto0rHb7ziRA+F8/fZLKfLNsahEQPxDuMItyQFCOQFHh8Hfuend2NgsQKeZ1r5Czf3n5Q6NFff7HG+MDeNDNdPB3ShgcvvNCFUS1z615/GIItfSqcWTAVaJ7436cA7yy5y4+0SvjfXYtHYfythBj/5UqlUmjni8Irj5K8uEtb1YUujmvlTTbzPkhYqIkSoyr7t21Dz+gcYn49AgMBAAGjgZ8wgZwwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUN3Z0iLv1FE17DCDBfpxW2P+5+kIwCwYDVR0PBAQDAgO4MBMGA1UdJQQMMAoGCCsGAQUFBwMCMBgGA1UdEQQRMA+CDWVzdGNsaWVudC5lc3QwEQYJYIZIAYb4QgEBBAQDAgWgMB4GCWCGSAGG+EIBDQQRFg94Y2EgY2VydGlmaWNhdGUwDQYJKoZIhvcNAQELBQADggIBACMAHHH4/0eAXbS/uKsIjLN1QPnnzgjxC0xoUon8UVM0PUMH+FMg6rs21Xyl5tn5iItmvKI9c3akAZ00RUQKVdmJVFRUKywmfF7n5epBpXtWJrSH817NT9GOp+PO5VUTDV5VkvpVLoy7WzThrheLKz1nC1dWowRz86tcBLAsC1zT17fsNZXQDuv4LiQQXs7QKhUU75r1IxrdBPeBQSP5skGpWxm8sapQSfOALoXu1pSoGIr6tqvNGuEoZGvUuWeQHG/G8c2ufL+6lEzZBBCd6e2tErkqD/vqfCRzbLcGgSPX0HVWdkjH09nHWXI5UhNr2YgGF7YvSTKWJfbDVlTql1BuSn2yTQtDk4E8k9BLr8WfqFSZvYrivT9Ax1n3BD9jvQL5+QRdioH1kqNGMme0Pb43pHciX4hu9L5rGenZRmxeGXZ78uSOR+n2bGxAMw1OY7Rx/lsNSKWDSN+7xIrwjjXO5Uthev1ecrLAK2+EpjITa6Y85ms39V4ypCEdujkKEBeVxuN8DdMJ2GaFGluSRZeYZ0LAPfYr5sp6G6904WF+PcT0WjGenH4PJLXrAttbhhvQxXU0Q8s2CUwUHy5OT/DW3POq7WETc+zmFGwZqiP3W9gmN0hHXsKqkNmz2RYgoH57lPS1PJb0klGUNHG98CtsmlhrivhSTJWqSIOfyKGF"
    assert result == b64_encode(logger, cert_pem2der(cert))


def test_213_helper_cert_extensions_get(logger: logging.Logger) -> None:
    """test cert_san_get for a single SAN and recode = False"""
    cert = "-----BEGIN CERTIFICATE-----\nMIIEZDCCAkygAwIBAgIIe941mx0FQtAwDQYJKoZIhvcNAQELBQAwKjEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxDzANBgNVBAMTBnN1Yi1jYTAeFw0yMTA0MDkxNTUy\nMDBaFw0yNjA0MDkxNTUyMDBaMBgxFjAUBgNVBAMTDWVzdGNsaWVudC5lc3QwggEi\nMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAn6IqwTE1RvZUm3gelpu4tmrd\nFj8Ub98J1YeQz7qrew5iA81NeH9tR484edjcY0ieOt3e1MfxJoziWtaeqxpsfytm\nVB/i+850kVZmvRCR1jhW/4AzidkVBMQiCR5erPmmheeCxbKkto0rHb7ziRA+F8/f\nZLKfLNsahEQPxDuMItyQFCOQFHh8Hfuend2NgsQKeZ1r5Czf3n5Q6NFff7HG+MDe\nNDNdPB3ShgcvvNCFUS1z615/GIItfSqcWTAVaJ7436cA7yy5y4+0SvjfXYtHYfyt\nhBj/5UqlUmjni8Irj5K8uEtb1YUujmvlTTbzPkhYqIkSoyr7t21Dz+gcYn49AgMB\nAAGjgZ8wgZwwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUN3Z0iLv1FE17DCDBfpxW\n2P+5+kIwCwYDVR0PBAQDAgO4MBMGA1UdJQQMMAoGCCsGAQUFBwMCMBgGA1UdEQQR\nMA+CDWVzdGNsaWVudC5lc3QwEQYJYIZIAYb4QgEBBAQDAgWgMB4GCWCGSAGG+EIB\nDQQRFg94Y2EgY2VydGlmaWNhdGUwDQYJKoZIhvcNAQELBQADggIBACMAHHH4/0eA\nXbS/uKsIjLN1QPnnzgjxC0xoUon8UVM0PUMH+FMg6rs21Xyl5tn5iItmvKI9c3ak\nAZ00RUQKVdmJVFRUKywmfF7n5epBpXtWJrSH817NT9GOp+PO5VUTDV5VkvpVLoy7\nWzThrheLKz1nC1dWowRz86tcBLAsC1zT17fsNZXQDuv4LiQQXs7QKhUU75r1Ixrd\nBPeBQSP5skGpWxm8sapQSfOALoXu1pSoGIr6tqvNGuEoZGvUuWeQHG/G8c2ufL+6\nlEzZBBCd6e2tErkqD/vqfCRzbLcGgSPX0HVWdkjH09nHWXI5UhNr2YgGF7YvSTKW\nJfbDVlTql1BuSn2yTQtDk4E8k9BLr8WfqFSZvYrivT9Ax1n3BD9jvQL5+QRdioH1\nkqNGMme0Pb43pHciX4hu9L5rGenZRmxeGXZ78uSOR+n2bGxAMw1OY7Rx/lsNSKWD\nSN+7xIrwjjXO5Uthev1ecrLAK2+EpjITa6Y85ms39V4ypCEdujkKEBeVxuN8DdMJ\n2GaFGluSRZeYZ0LAPfYr5sp6G6904WF+PcT0WjGenH4PJLXrAttbhhvQxXU0Q8s2\nCUwUHy5OT/DW3POq7WETc+zmFGwZqiP3W9gmN0hHXsKqkNmz2RYgoH57lPS1PJb0\nklGUNHG98CtsmlhrivhSTJWqSIOfyKGF\n-----END CERTIFICATE-----"
    assert [
        "MAA=",
        "BBQ3dnSIu/UUTXsMIMF+nFbY/7n6Qg==",
        "AwIDuA==",
        "MAoGCCsGAQUFBwMC",
        "MA+CDWVzdGNsaWVudC5lc3Q=",
        "AwIFoA==",
        "Fg94Y2EgY2VydGlmaWNhdGU=",
    ] == cert_extensions_get(logger, cert, recode=False)


def test_214_helper_cert_extensions_get(logger: logging.Logger) -> None:
    """test cert_san_get for a single SAN and recode = True"""
    cert = "MIIEZDCCAkygAwIBAgIIe941mx0FQtAwDQYJKoZIhvcNAQELBQAwKjEXMBUGA1UECxMOYWNtZTJjZXJ0aWZpZXIxDzANBgNVBAMTBnN1Yi1jYTAeFw0yMTA0MDkxNTUyMDBaFw0yNjA0MDkxNTUyMDBaMBgxFjAUBgNVBAMTDWVzdGNsaWVudC5lc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAn6IqwTE1RvZUm3gelpu4tmrdFj8Ub98J1YeQz7qrew5iA81NeH9tR484edjcY0ieOt3e1MfxJoziWtaeqxpsfytmVB/i+850kVZmvRCR1jhW/4AzidkVBMQiCR5erPmmheeCxbKkto0rHb7ziRA+F8/fZLKfLNsahEQPxDuMItyQFCOQFHh8Hfuend2NgsQKeZ1r5Czf3n5Q6NFff7HG+MDeNDNdPB3ShgcvvNCFUS1z615/GIItfSqcWTAVaJ7436cA7yy5y4+0SvjfXYtHYfythBj/5UqlUmjni8Irj5K8uEtb1YUujmvlTTbzPkhYqIkSoyr7t21Dz+gcYn49AgMBAAGjgZ8wgZwwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUN3Z0iLv1FE17DCDBfpxW2P+5+kIwCwYDVR0PBAQDAgO4MBMGA1UdJQQMMAoGCCsGAQUFBwMCMBgGA1UdEQQRMA+CDWVzdGNsaWVudC5lc3QwEQYJYIZIAYb4QgEBBAQDAgWgMB4GCWCGSAGG+EIBDQQRFg94Y2EgY2VydGlmaWNhdGUwDQYJKoZIhvcNAQELBQADggIBACMAHHH4/0eAXbS/uKsIjLN1QPnnzgjxC0xoUon8UVM0PUMH+FMg6rs21Xyl5tn5iItmvKI9c3akAZ00RUQKVdmJVFRUKywmfF7n5epBpXtWJrSH817NT9GOp+PO5VUTDV5VkvpVLoy7WzThrheLKz1nC1dWowRz86tcBLAsC1zT17fsNZXQDuv4LiQQXs7QKhUU75r1IxrdBPeBQSP5skGpWxm8sapQSfOALoXu1pSoGIr6tqvNGuEoZGvUuWeQHG/G8c2ufL+6lEzZBBCd6e2tErkqD/vqfCRzbLcGgSPX0HVWdkjH09nHWXI5UhNr2YgGF7YvSTKWJfbDVlTql1BuSn2yTQtDk4E8k9BLr8WfqFSZvYrivT9Ax1n3BD9jvQL5+QRdioH1kqNGMme0Pb43pHciX4hu9L5rGenZRmxeGXZ78uSOR+n2bGxAMw1OY7Rx/lsNSKWDSN+7xIrwjjXO5Uthev1ecrLAK2+EpjITa6Y85ms39V4ypCEdujkKEBeVxuN8DdMJ2GaFGluSRZeYZ0LAPfYr5sp6G6904WF+PcT0WjGenH4PJLXrAttbhhvQxXU0Q8s2CUwUHy5OT/DW3POq7WETc+zmFGwZqiP3W9gmN0hHXsKqkNmz2RYgoH57lPS1PJb0klGUNHG98CtsmlhrivhSTJWqSIOfyKGF"
    assert [
        "MAA=",
        "BBQ3dnSIu/UUTXsMIMF+nFbY/7n6Qg==",
        "AwIDuA==",
        "MAoGCCsGAQUFBwMC",
        "MA+CDWVzdGNsaWVudC5lc3Q=",
        "AwIFoA==",
        "Fg94Y2EgY2VydGlmaWNhdGU=",
    ] == cert_extensions_get(logger, cert, recode=True)


def test_336_helper_cert_cn_get(logger: logging.Logger) -> None:
    """get cn of csr"""
    cert = "MIIDDTCCAfWgAwIBAgIBCjANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDEw9mb28u\n                ZXhhbXBsZS5jb20wHhcNMTkwMTIwMTY1OTIwWhcNMTkwMjE5MTY1OTIwWjAaMRgw\n                FgYDVQQDEw9mb28uZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n                ggEKAoIBAQCqUeNzDyBVugUKZq597ishYAdMPgus5Nw5pWE/Jw7PP0koeFE2wODq\n                HVb+XNFFEX4IOyiE2Pi4ilzfXYGKchhP3wHgnkxGNIwt/cDNZgyTiUpITV/ciFaC\n                7avkvQS6ScCYUYrhby7QnvcU02mAyhNcSVGI5TW7HhFdtWrEAK3N8H6yhxHLSi2y\n                dpQ3kCJyJylqt/Rv3uKNjCvTv867K6A1QSsXoAxtPK9P0UOTRvgHkFf8T32Bn/Er\n                1bjkX9Ms8rqDQmicCWJk260lUHzN6vxaeiEg7Kz3TA8Ik3DMIcvwJrE168G1APo+\n                FyOIKyx+t78HWOlNINIqZMj5e2DpulV7AgMBAAGjXjBcMB8GA1UdIwQYMBaAFK1Z\n                zuGt0Pe+NLerCXqQBYmVV7suMB0GA1UdDgQWBBStWc7hrdD3vjS3qwl6kAWJlVe7\n                LjAaBgNVHREEEzARgg9mb28uZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEB\n                AANW0DD4Xp7LH/Rzf2jVLwiFlbtR6iazyn9S/pH2Gwqjkscv/27/dqJb7CfPdD02\n                5ItQcYkZPJhDOsj63kvUaD89QU31RnYQrXrbXFqYOIAq6kxfZUoQmpfEBxbB4Wxm\n                TW0OWS+FMqNw/SuGs6EQjTRA+gBOeGzj4H9yOFOg0PpadBayZ7UT4lm1LOiFHh8h\n                bta75ocePrurdNxsxKJhLlXbnKD6lurCb4khRhrmLmpK8JxhuaevEVklSQX0gqlR\n                fxAH4XQsaqcaedPNI+W5OUITMz40ezDCbUqxS9KEMCGPoOTXNRAjbr72sc4Vkw7H\n                t+eRUDECE+0UnjyeCjTn3EU="
    assert "foo.example.com" == cert_cn_get(logger, cert)


def test_343_pembundle_to_list(logger: logging.Logger) -> None:
    """bundle to list"""
    pembundle_to_list = "foo"
    assert not _fn_pembundle_to_list(logger, pembundle_to_list)


def test_344_pembundle_to_list(logger: logging.Logger) -> None:
    """bundle to list"""
    pembundle_to_list = "-----BEGIN CERTIFICATE-----foo"
    assert ["-----BEGIN CERTIFICATE-----foo\n"] == _fn_pembundle_to_list(
        logger, pembundle_to_list
    )


def test_345_pembundle_to_list(logger: logging.Logger) -> None:
    """bundle to list"""
    pembundle_to_list = (
        "-----BEGIN CERTIFICATE-----foo\n-----BEGIN CERTIFICATE-----foo1"
    )
    assert [
        "-----BEGIN CERTIFICATE-----foo\n",
        "-----BEGIN CERTIFICATE-----foo1\n",
    ] == _fn_pembundle_to_list(logger, pembundle_to_list)


def test_346_certid_check(logger: logging.Logger) -> None:
    """test certid_check"""
    certid = "e181efbe6f7ae3ea71c78fc99e4226d7185715be3d289eaa56801dff4696ca4d0420ae0dcf53345691826b81d093e9c7588c35dd5ec5eacf5b1b2606330515d5faf402082cca85f640d54142"
    renewal_info = "MFswCwYJYIZIAWUDBAIBBCDhge--b3rj6nHHj8meQibXGFcVvj0onqpWgB3_RpbKTQQgrg3PUzRWkYJrgdCT6cdYjDXdXsXqz1sbJgYzBRXV-vQCCCzKhfZA1UFC"
    assert certid_check(logger, renewal_info, certid)


def test_347_certid_check(logger: logging.Logger) -> None:
    """test certid_check"""
    certid = "false"
    renewal_info = "MFswCwYJYIZIAWUDBAIBBCDhge--b3rj6nHHj8meQibXGFcVvj0onqpWgB3_RpbKTQQgrg3PUzRWkYJrgdCT6cdYjDXdXsXqz1sbJgYzBRXV-vQCCCzKhfZA1UFC"
    assert not certid_check(logger, renewal_info, certid)


def test_348_certid_asn1_get(logger: logging.Logger) -> None:
    """test certid_asn1_get()"""
    cert_pem = "-----BEGIN CERTIFICATE-----\nMIIDijCCAXKgAwIBAgIILMqF9kDVQUIwDQYJKoZIhvcNAQELBQAwKjEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxDzANBgNVBAMTBnN1Yi1jYTAeFw0yMzA3MDMwNTA5\nNDVaFw0yNDA3MDIwNTA5NDVaMBsxGTAXBgNVBAMTEGxlZ28tMS5iYXIubG9jYWww\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQDmn49aWZb/mRghkT3rgpkV45c5PbE\nLFgQSh2qT7AHEmOv+8SNSjAbgysgJDqXMte4nUQOtYeKEZiy8xaD5ymho4GNMIGK\nMB0GA1UdDgQWBBS5fAkcGAyo4okkZxEeGgLqmLo3izAfBgNVHSMEGDAWgBS/3o6O\nBiIiq61DyN3UT6irSEE+1TALBgNVHQ8EBAMCA+gwDAYDVR0TAQH/BAIwADAtBgNV\nHREEJjAkghBsZWdvLTEuYmFyLmxvY2FsghBsZWdvLTIuYmFyLmxvY2FsMA0GCSqG\nSIb3DQEBCwUAA4ICAQAAYE1U/IR6XRbjnRT9jzit/biRJDFGT7JMfD14pUpXU7ax\nIfndaWA8y0UQ0ZyIiLke+chHWQ2CrYT7wUMjSp08ztViWXDg0IifW4Hcyqx/oNT0\npCaQeRHJOM17ai9oWZEaJMY/r0/1fCTAK7D0zrJxHCQqEXuosm9LJd0fRMamgGZC\nbXN/HrVOGojOLwzE1mMyW261hI5eU7/DD128iyc0mfeCi2R3lL7oXcwN7MtrKUYq\nqpBEfMlrf07zpAGVe/LOB6SLoPCbjYPC368mwdxgGLLz2+nqPTK2V+2yjylt3de5\nLVp6UG3ZxLNN2RjVXCE7Bh1fT585+NzaaXpf4SWyDxu11yHdfXP5Nw5paELjyNhM\nV9lnEJUiLB4scO1p4XWOQDboLXf0RbI0M/0IxqRZzzKxDRXsnIzdQOswxv8Jfnli\nr0yVc/vzYQeKEkKkRwRw2SVTj9v4lU+ryMrqMCpw/z6vRBLKWAg8cmGE2OTtcL91\nQvJeYpp+9g2GJxs+gEja3BlliLf6EUQkI/P/tCUoe3pEJ0XyPgl5m+5SdAS5Ic0U\nqaUvBXcmU56/h8pzSCF2RDoGEpZyHaG84VJLCV857QD2NFlE/S+tUAggbc5l66OE\nu3dZ8B+BJinV++0slP29NFdZ7m6ta0jZJfOaMXYyDwCYvD7FXygHu3fMwc5k3A==\n-----END CERTIFICATE-----"
    issuer_pem = "-----BEGIN CERTIFICATE-----\nMIIFTzCCAzegAwIBAgIIAzHyhSyrXfMwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MTM1\nNDAwWhcNMzAwNTI2MjM1OTAwWjAqMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEP\nMA0GA1UEAxMGc3ViLWNhMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA\nxXHaGZsolXe+PBdUryngHP9VbBC1mehqeTtYI+hqsqGNH7q9a7bSrxMwFuF1kYL8\njqqxkJdtl0L94xcxJg/ZdMx7Nt0vGI+BaAuTpEpUEHeN4tqS6NhB/m/0LGkAELc/\nqkzmoO4B1FDwEEj/3IXtZcupqG80oDt7jWSGXdtF7NTjzcumznMeRXidCdhxRxT/\n/WrsChaytXo0xWZ56oeNwd6x6Dr8/39PBOWtj4fldyDcg+Q+alci2tx9pxmu2bCV\nXcB9ftCLKhDk2WEHE88bgKSp7fV2RCmq9po+Tx8JJ7qecLunUsK/F0XN4kpoQLm9\nhcymqchnMSncSiyin1dQHGHWgXDtBDdq6A2Z6rx26Qk5H9HTYvcNSe1YwFEDoGLB\nZQjbCPWiaqoaH4agBQTclPvrrSCRaVmhUSO+pBtSXDkmN4t3MDZxfgRkp8ixwkB1\n5Y5f0LTpCyAJsdQDw8+Ea0aDqO30eskh4CErnm9+Fejd9Ew2cwpdwfBXzVSbYilM\nGueQihZHvJmVRxAwU69aO2Qs8B0tQ60CfWKVlmWPiakrvYYlPp0FBsM61G6LZEN8\nhH2CKnS8hHv5IWEXZvp0Pk8V3P5h6bWN0Tl+x/V1Prt7Wp8NoiPETE8XyDDxe6dm\nKxztWBH/mTsJyMGb6ZiUoXdPU9TFUKqHxTRLHaxfsPsCAwEAAaN4MHYwEgYDVR0T\nAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQUv96OjgYiIqutQ8jd1E+oq0hBPtUwDgYD\nVR0PAQH/BAQDAgGGMBEGCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYP\neGNhIGNlcnRpZmljYXRlMA0GCSqGSIb3DQEBCwUAA4ICAQBbHLEVyg4f9uEujroc\n31UVyDRLMdPgEPLjOenSBCBmH0N81whDmxNI/7JAAB6J14WMX8OLF0HkZnb7G77W\nvDhy1aFvQFbXHBz3/zUO9Mw9J4L2XEW6ond3Nsh1m2oXeBde3R3ANxuIzHqZDlP9\n6YrRcHjnf4+1/5AKDJAvJD+gFb5YnYUKH2iSvHUvG17xcZx98Rf2eo8LealG4JqH\nJh4sKRy0VjDQD7jXSCbweTHEb8wz+6OfNGrIo+BhTFP5vPcwE4nlJwYBoaOJ5cVa\n7gdQJ7WkLSxvwHxuxzvSVK73u3jl3I9SqTrbMLG/jeJyV0P8EvdljOaGnCtQVRwC\nzM4ptXUvKhKOHy7/nyTF/Bc35ZwwL/2xWvNK1+NibgE/6CFxupwWpdmxQbVVuoQ3\n2tUil9ty0yC6m5GKE8+t1lrZuxyA+b/TBnYNO5xo8UEMbkpxaNYSwmw+f/loxXP/\nM7sIBcLvy2ugHEBxwd9o/kLXeXT2DaRvxPjp4yk8MpJRpNmz3aB5HJwaUnaRLVo5\nZ3XWWXmjMGZ6/m0AAoDbDz/pXtOoJZT8BJdD1DuDdszVsQnLVn4B/LtIXL6FbXsF\nzfv6ERP9a5gpKUZ+4NjgrnlGtdccNZpwyWF0IXcvaq3b8hXIRO4hMjzHeHfzJN4t\njX1vlY35Ofonc4+6dRVamBiF9A==\n-----END CERTIFICATE-----"
    result = "e181efbe6f7ae3ea71c78fc99e4226d7185715be3d289eaa56801dff4696ca4d0420ae0dcf53345691826b81d093e9c7588c35dd5ec5eacf5b1b2606330515d5faf402082cca85f640d54142"
    assert result == certid_asn1_get(logger, cert_pem, issuer_pem)


def test_349_certid_hex_get(logger: logging.Logger) -> None:
    """test certid_check"""
    certid = "false"
    renewal_info = "MFswCwYJYIZIAWUDBAIBBCDhge--b3rj6nHHj8meQibXGFcVvj0onqpWgB3_RpbKTQQgrg3PUzRWkYJrgdCT6cdYjDXdXsXqz1sbJgYzBRXV-vQCCCzKhfZA1UFC"
    assert (
        "300b0609608648016503040201",
        "e181efbe6f7ae3ea71c78fc99e4226d7185715be3d289eaa56801dff4696ca4d0420ae0dcf53345691826b81d093e9c7588c35dd5ec5eacf5b1b2606330515d5faf402082cca85f640d54142",
    ) == certid_hex_get(logger, renewal_info)


def test_365_cert_ski_get(logger: logging.Logger) -> None:
    """test cert_san_get for a multiple SAN of type DNS"""
    cert = "MIIDIzCCAgugAwIBAgICBZgwDQYJKoZIhvcNAQELBQAwGjEYMBYGA1UEAxMPZm9v\n                LmV4YW1wbGUuY29tMB4XDTE5MDEyMDE3MDkxMVoXDTE5MDIxOTE3MDkxMVowGjEY\n                MBYGA1UEAxMPZm9vLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n                MIIBCgKCAQEA+EM+gzAyjegQSRbJI+qZJhuAGM9i48xvIfuOQHleXoJPjV+8VZRV\n                KDljZNXdNT5Zi7K6HY9C622NOV7QefB6zTtm6mSY08ypNsaeorhIvJdnpaJ9gAGH\n                YeQqJ04fL099kiRXJAv8gT8wdpiekg2KEU4wlXMIRfSHiiB37yjcqUzXl6XYYKGe\n                2USMpDfliXL3o8TW2KByGUdCzXUdNbMgzRXwYxkX2+xV2f0vn8NyXHiHg9yJRof2\n                HTjyvAcXN5Nr987slq/Ex5lXLtpB861Ov3ZbwxyzREjmreZBlze7KTfP5IY66XuN\n                Mvhi7AAs0cLTd3SNjpppE/yvUi5q5gfhXQIDAQABo3MwcTAfBgNVHSMEGDAWgBSl\n                YnpKQw12MmEMpvsTEeQi17UsnDAdBgNVHQ4EFgQUpWJ6SkMNdjJhDKb7ExHkIte1\n                LJwwLwYDVR0RBCgwJoIRZm9vLTIuZXhhbXBsZS5jb22CEWZvby0xLmV4YW1wbGUu\n                Y29tMA0GCSqGSIb3DQEBCwUAA4IBAQASA20TtMPXIHH10dikLhFuI14EOtZzXvCx\n                kGlJw9/5JuvVKLsL1wd8BC9o/lg8apDqsrDZ/+0Nc8g3Z9HRN99vcLsVDdT27DkM\n                BslfXdN/qBhKAp3m7jw29uijX5fss+Wz9iHfHciUjVyMJ4DoFxHYPbMWQG8XEUKR\n                TP6Gp79DzCiPKFt52Y8yVikIET4fnyRzU8kGKLuPoIt+EQQzpG26qWAjeNHAASEM\n                keiA+tedMWzydX52B+tGg+l2svxg34apIBDjK8pF+8ZxTt5yjVUa10GbpffJuiEh\n                NWQddOR8IHg+v6lWc9BtuuKK5ubsg6XOiEjhhr42AKViKalX1i4+"
    assert "a5627a4a430d7632610ca6fb1311e422d7b52c9c" == cert_ski_get(logger, cert)


def test_366_cert_aki_get(logger: logging.Logger) -> None:
    """test cert_san_get aki"""
    cert = "MIIEOzCCAiOgAwIBAgIIKndYX0qdb04wDQYJKoZIhvcNAQELBQAwKjEXMBUGA1UECxMOYWNtZTJjZXJ0aWZpZXIxDzANBgNVBAMTBnN1Yi1jYTAeFw0yNDAxMjkyMDA0NTZaFw0yNTAxMjgyMDA0NTZaMD8xFzAVBgNVBAMTDmxlZ28uYmFyLmxvY2FsMRcwFQYDVQQKDA5hY21lMmNlcnRpZmllcjELMAkGA1UEBhMCREUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQKIqEIxeS0JIN+iqsJ+08IJFFmuvfpjFnH4wFD2OLlmeTvfpDsnD00uw/orLvecDvjt48JvgYR8Wv+9C4ajIDfo4IBGTCCARUwHQYDVR0OBBYEFCka80MPgj45/quHJ9oF8Cc1YlsXMB8GA1UdIwQYMBaAFL/ejo4GIiKrrUPI3dRPqKtIQT7VMAsGA1UdDwQEAwID6DBRBgNVHSUBAf8ERzBFBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMDBggrBgEFBQcDBAYIKwYBBQUHAwgGCCsGAQUFBwMJBgcrBgEFAgMFMEoGA1UdHwRDMEEwHqAcoBqGGFVSSTpodHRwOi8vZm9vLmJhci5sb2NhbDAfoB2gG4YZVVJJOmh0dHA6Ly9mb28xLmJhci5sb2NhbDAMBgNVHRMBAf8EAjAAMBkGA1UdEQQSMBCCDmxlZ28uYmFyLmxvY2FsMA0GCSqGSIb3DQEBCwUAA4ICAQB4FxJwQ/aILMzh7jBSr358RA92mX8srPmzQrjPYoU7T2LxwMf+eb0z5x0PMFH8j5FgRvRGWo6rcco8rL+B+gvrVhQ0TfAFEF77WJfKG2XMlnEN/9Ri73J7+dA45kaw8CZRSfUBpIW6fb4N+6frXyIKwBaZnrT6qiy+Izu+ZH6RkaTFrBn5yOWvVyk7aBHE1eZ+3+eA3qBI4UPaeYFSwr3gY5dxfbPktlFgvpCI22ff4NAb/fzjAQsKRTkXkOVqAvBJcWI5d/g32IVMLq0ub13XLe+yHk0iCxyMaIRdN4+W6RYi3gvtTQh6LaOjncWDYLdsm+vN+YqXEqieY5TC1oC8kG9We9eHzKHdNquJnrju536DPqh4xYEDcb+PGvTr3sqYdSikA9v5FuWUGeiZD/ZEvw/p7F7DevD5NO1JaOtfWDwDwxFHEyn+iwTVq3QDEc4j+oyGnQJs5Spoyz3tJi31VMJk+EAKKUV66aVNynLM7Ce4Oj0M67o4pcnDd0uWBMSAg4lH8KIX0IsmMfLnirIqOOwrZ4UkPKlEjD+oZQf5IBukfdHob/bo4fW8q4eU/I8z9w3BTdV1yNVH/ANHg5AItoPabkr65oBTwY51j3FVq0gK+4xVrevcyIeY3A9XFzA18k/gX7O/kf/IrM0dcZWJnsW39byiWhUd4JetJaGeKg"
    assert "bfde8e8e062222abad43c8ddd44fa8ab48413ed5" == cert_aki_get(logger, cert)


def test_367_cert_aki_get_error_handling(logger: logging.Logger) -> None:
    """test cert_aki_get() error handling when AKI is missing"""
    cert = "MIIEHDCCAgSgAwIBAgIPAZ4wdJfqm1tO+Fh4RIFBMA0GCSqGSIb3DQEBDQUAMBkxFzAVBgNVBAMTDk5ldyBSU0EgU3ViIENBMB4XDTI2MDUxNjEwMzMyN1oXDTI3MDUxNjExMDMyN1owFzEVMBMGA1UEAxMMYWNtZS1zaC5hY21lMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqgZcTr/0DMZILNilvYPCDKMd7IGA6jpFuXvjQiF/tSkk+rR2ulkMee7SBI6dBfGqulthwSVPBYIaOOCCBwoFUotvOqp2VWFeeq/M7hrE/2Ld0oydvN0Bnngtrq0IjM+cZOaupg3vJhsUL/BZqQ4XkEzPf9ydo4fuhkD4rFkaaz6ZTCTjJX4YvD2zsIydfiNVp6+hr6iPdJdYfHJebtIh1tg6fEkZH5heoZTKWm2b2W3ZVeMSzDr/gI0SQA6On1WY56/cXetbcLnGR3UFFUhw6RAT6/tL1lt8NbLjVrpl0ibAgPdealMVuwYE54+DUzIto0PWKJpfz9ThVlashppuUwIDAQABo2MwYTAfBgNVHSMEGDAWgBSryf/9VmQhFktiIG28gA+6hGdlmjAdBgNVHQ4EFgQUzCvWZddDuFyxFbPbv6AzgFu2eYUwDgYDVR0PAQH/BAQDAgQwMA8GA1UdEwEB/wQFMAMBAQAwDQYJKoZIhvcNAQENBQADggIBALUZcRH4Cnz4VxvnINV1Homb9HbtaOp4Iq6ehLf281e8AL9jchRoraMOXWOwxrCjvgYf59GPlYpRh4j9EoiQdJkSdJrHME2h5XdG/y05TgNcYB0IefdccDQTlkbibb5MdbM14oGBjP1EgDa6+UHdybXEIHLTxmxqR3hAPjXzbiijibrIhpUOOdL8cLrxYI87IuQWm3OYWuBqMFVCsH8aSHAfwfcVWFtEPL2f9goyvTlzy2k+lGF1PHokHBRucFeg1qfEhbXU4qI8k6MdOAmgxFk7At+Ah6r8V6eVPu+MR+uQUTd7t0Gkp15A48Iezj09WaCEayKg1gzV5X1Jdgv7q/98TvzrEe9gCFdV2z/UmBaXDfkPqd2x4Fl/Bqsb+Ajprt+5XEcBzlpGjhHGVGvk3kjy/PHbnviwjQrTApA7XJDUF055/HPOfFO7WPnFsOgE2Oi5i7u911IAU1ZVy8WdAgkmGZFWL/cECZaidkDaoSWVfjdavr6UkmEuQOv4FjB+QrFn0ESMuaRJdolsI0UYN+3kxXphBYxTcnzWyzUEaylkMt3a7pGsBcyrGldpMQ4TKok1braRQiL0M6MtpEVRkXJC/nMFeQAub++9GTzLh7Deu9iX0GRZBLLlhwfKpcHuJ8TYbpew3ZRDe6GVNmEZ/n5Bq8118hjzHr1N5FOv2XqU"
    aki = cert_aki_get(logger, cert)
    assert aki == "abc9fffd566421164b62206dbc800fba8467659a"


@patch("acme2certifier.acme_srv.helpers.certificates._cert_ski_asn1_get")
@patch("acme2certifier.acme_srv.helpers.certificates.x509.Certificate.extensions")
def test_368_cert_ski_get_error_handling(
    mock_ext: MagicMock, mock_ski_get: MagicMock, logger: logging.Logger
) -> None:
    """test cert_ski_get() error handling when SKI is missing"""
    cert = "MIIDDTCCAfWgAwIBAgIBCjANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDEw9mb28u\n    ZXhhbXBsZS5jb20wHhcNMTkwMTIwMTY1OTIwWhcNMTkwMjE5MTY1OTIwWjAaMRgw\n    FgYDVQQDEw9mb28uZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n    ggEKAoIBAQCqUeNzDyBVugUKZq597ishYAdMPgus5Nw5pWE/Jw7PP0koeFE2wODq\n    HVb+XNFFEX4IOyiE2Pi4ilzfXYGKchhP3wHgnkxGNIwt/cDNZgyTiUpITV/ciFaC\n    7avkvQS6ScCYUYrhby7QnvcU02mAyhNcSVGI5TW7HhFdtWrEAK3N8H6yhxHLSi2y\n    dpQ3kCJyJylqt/Rv3uKNjCvTv867K6A1QSsXoAxtPK9P0UOTRvgHkFf8T32Bn/Er\n    1bjkX9Ms8rqDQmicCWJk260lUHzN6vxaeiEg7Kz3TA8Ik3DMIcvwJrE168G1APo+\n    FyOIKyx+t78HWOlNINIqZMj5e2DpulV7AgMBAAGjXjBcMB8GA1UdIwQYMBaAFK1Z\n    zuGt0Pe+NLerCXqQBYmVV7suMB0GA1UdDgQWBBStWc7hrdD3vjS3qwl6kAWJlVe7\n    LjAaBgNVHREEEzARgg9mb28uZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEB\n    AANW0DD4Xp7LH/Rzf2jVLwiFlbtR6iazyn9S/pH2Gwqjkscv/27/dqJb7CfPdD02\n    5ItQcYkZPJhDOsj63kvUaD89QU31RnYQrXrbXFqYOIAq6kxfZUoQmpfEBxbB4Wxm\n    TW0OWS+FMqNw/SuGs6EQjTRA+gBOeGzj4H9yOFOg0PpadBayZ7UT4lm1LOiFHh8h\n    bta75ocePrurdNxsxKJhLlXbnKD6lurCb4khRhrmLmpK8JxhuaevEVklSQX0gqlR\n    fxAH4XQsaqcaedPNI+W5OUITMz40ezDCbUqxS9KEMCGPoOTXNRAjbr72sc4Vkw7H\n    t+eRUDECE+0UnjyeCjTn3EU="
    mock_ext.get_extension_for_oid.side_effect = Exception("No SKI")
    mock_ski_get.return_value = "asn1-fallback"
    ski = cert_ski_get(logger, cert)
    assert ski == "asn1-fallback"
    mock_ski_get.assert_called_once()


def test_585_pkcs7_to_pem(logger: logging.Logger, test_dir: str) -> None:
    """test pkcs7 to pem default output"""
    with open(test_dir + "/ca/certs.p7b", "r") as fso:
        file_content = fso.read()
    with open(test_dir + "/ca/certs.pem", "r") as fso:
        result = fso.read()
    assert result == pkcs7_to_pem(logger, file_content)


def test_586_pkcs7_to_pem(logger: logging.Logger, test_dir: str) -> None:
    """test pkcs7 to pem output string"""
    with open(test_dir + "/ca/certs.p7b", "r") as fso:
        file_content = fso.read()
    with open(test_dir + "/ca/certs.pem", "r") as fso:
        result = fso.read()
    assert result == pkcs7_to_pem(logger, file_content, "string")


def test_587_pkcs7_to_pem(logger: logging.Logger, test_dir: str) -> None:
    """test pkcs7 to pem output list"""
    with open(test_dir + "/ca/certs.p7b", "r") as fso:
        file_content = fso.read()
    result = [
        "-----BEGIN CERTIFICATE-----\nMIIFTzCCAzegAwIBAgIIAzHyhSyrXfMwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MTM1\nNDAwWhcNMzAwNTI2MjM1OTAwWjAqMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEP\nMA0GA1UEAxMGc3ViLWNhMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA\nxXHaGZsolXe+PBdUryngHP9VbBC1mehqeTtYI+hqsqGNH7q9a7bSrxMwFuF1kYL8\njqqxkJdtl0L94xcxJg/ZdMx7Nt0vGI+BaAuTpEpUEHeN4tqS6NhB/m/0LGkAELc/\nqkzmoO4B1FDwEEj/3IXtZcupqG80oDt7jWSGXdtF7NTjzcumznMeRXidCdhxRxT/\n/WrsChaytXo0xWZ56oeNwd6x6Dr8/39PBOWtj4fldyDcg+Q+alci2tx9pxmu2bCV\nXcB9ftCLKhDk2WEHE88bgKSp7fV2RCmq9po+Tx8JJ7qecLunUsK/F0XN4kpoQLm9\nhcymqchnMSncSiyin1dQHGHWgXDtBDdq6A2Z6rx26Qk5H9HTYvcNSe1YwFEDoGLB\nZQjbCPWiaqoaH4agBQTclPvrrSCRaVmhUSO+pBtSXDkmN4t3MDZxfgRkp8ixwkB1\n5Y5f0LTpCyAJsdQDw8+Ea0aDqO30eskh4CErnm9+Fejd9Ew2cwpdwfBXzVSbYilM\nGueQihZHvJmVRxAwU69aO2Qs8B0tQ60CfWKVlmWPiakrvYYlPp0FBsM61G6LZEN8\nhH2CKnS8hHv5IWEXZvp0Pk8V3P5h6bWN0Tl+x/V1Prt7Wp8NoiPETE8XyDDxe6dm\nKxztWBH/mTsJyMGb6ZiUoXdPU9TFUKqHxTRLHaxfsPsCAwEAAaN4MHYwEgYDVR0T\nAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQUv96OjgYiIqutQ8jd1E+oq0hBPtUwDgYD\nVR0PAQH/BAQDAgGGMBEGCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYP\neGNhIGNlcnRpZmljYXRlMA0GCSqGSIb3DQEBCwUAA4ICAQBbHLEVyg4f9uEujroc\n31UVyDRLMdPgEPLjOenSBCBmH0N81whDmxNI/7JAAB6J14WMX8OLF0HkZnb7G77W\nvDhy1aFvQFbXHBz3/zUO9Mw9J4L2XEW6ond3Nsh1m2oXeBde3R3ANxuIzHqZDlP9\n6YrRcHjnf4+1/5AKDJAvJD+gFb5YnYUKH2iSvHUvG17xcZx98Rf2eo8LealG4JqH\nJh4sKRy0VjDQD7jXSCbweTHEb8wz+6OfNGrIo+BhTFP5vPcwE4nlJwYBoaOJ5cVa\n7gdQJ7WkLSxvwHxuxzvSVK73u3jl3I9SqTrbMLG/jeJyV0P8EvdljOaGnCtQVRwC\nzM4ptXUvKhKOHy7/nyTF/Bc35ZwwL/2xWvNK1+NibgE/6CFxupwWpdmxQbVVuoQ3\n2tUil9ty0yC6m5GKE8+t1lrZuxyA+b/TBnYNO5xo8UEMbkpxaNYSwmw+f/loxXP/\nM7sIBcLvy2ugHEBxwd9o/kLXeXT2DaRvxPjp4yk8MpJRpNmz3aB5HJwaUnaRLVo5\nZ3XWWXmjMGZ6/m0AAoDbDz/pXtOoJZT8BJdD1DuDdszVsQnLVn4B/LtIXL6FbXsF\nzfv6ERP9a5gpKUZ+4NjgrnlGtdccNZpwyWF0IXcvaq3b8hXIRO4hMjzHeHfzJN4t\njX1vlY35Ofonc4+6dRVamBiF9A==\n-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\nMIIFcDCCA1igAwIBAgIIevLTTxOMoZgwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MDAw\nMDAwWhcNMzAwNTI2MjM1OTU5WjArMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEQ\nMA4GA1UEAxMHcm9vdC1jYTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB\nAJy4UZHdZgYt64k/rFamoC676tYvtabeuiqVw1c6oVZI897cFLG6BYwyr2Eaj7tF\nrqTJDeMN4vZSudLsmLDq6m8KwX/riPzUTIlcjM5aIMANZr9rLEs3NWtcivolB5aQ\n1slhdVitUPLuxsFnYeQTyxFyP7lng9M/Z403KLG8phdmKjM0vJkaj4OuKOXf3UsW\nqWQYyRl/ms07xVj02uq08LkoeO+jtQisvyVXURdaCceZtyK/ZBQ7NFCsbK112cVR\n1e2aJol7NJAA6Wm6iBzAdkAA2l3kh40SLoEbaiaVMixLN2vilIZOOAoDXX4+T6ir\n+KnDVSJ2yu5c/OJMwuXwHrh7Lgg1vsFR5TNehknhjUuWOUO+0TkKPg2A7KTg72OZ\n2mOcLZIbxzr1P5RRvdmLQLPrTF2EJvpQPNmbXqN3ZVWEvfHTjkkTFY/dsOTvFTgS\nri15zYKch8votcU7z+BQhgmMtwO2JhPMmZ6ABd9skI7ijWpwOltAhxtdoBO6T6CB\nCrE2yXc6V/PyyAKcFglNmIght5oXsnE+ub/dtx8f9Iea/xNPdo5aGy8fdaitolDK\n16kd3Kb7OE4HMHIwOxxF1BEAqerxxhbLMRBr8hRSZI5cvLzWLvpAQ5zuhjD6V3b9\nBYFd4ujAu3zl3mbzdbYjFoGOX6aBZaGDxlc4O2W7HxntAgMBAAGjgZcwgZQwDwYD\nVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUDGVvuTFYZtEAkz3af9wRKDDvAswwHwYD\nVR0jBBgwFoAUDGVvuTFYZtEAkz3af9wRKDDvAswwDgYDVR0PAQH/BAQDAgGGMBEG\nCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYPeGNhIGNlcnRpZmljYXRl\nMA0GCSqGSIb3DQEBCwUAA4ICAQAjko7dX+iCgT+m3Iy1Vg6j7MRevPAzq1lqHRRN\nNdt2ct530pIut7Fv5V2xYk35ka+i/G+XyOvTXa9vAUKiBtiRnUPsXu4UcS7CcrCX\nEzHx4eOtHnp5wDhO0Fx5/OUZTaP+L7Pd1GD/j953ibx5bMa/M9Rj+S486nst57tu\nDRmEAavFDiMd6L3jH4YSckjmIH2uSeDIaRa9k6ag077XmWhvVYQ9tuR7RGbSuuV3\nFc6pqcFbbWpoLhNRcFc+hbUKOsKl2cP+QEKP/H2s3WMllqgAKKZeO+1KOsGo1CDs\n475bIXyCBpFbH2HOPatmu3yZRQ9fj9ta9EW46n33DFRNLinFWa4WJs4yLVP1juge\n2TCOyA1t61iy++RRXSG3e7NFYrEZuCht1EdDAdzIUY89m9NCPwoDYS4CahgnfkkO\n7YQe6f6yqK6isyf8ZFcp1uF58eERDiF/FDqS8nLmCdURuI56DDoNvDpig5J/9RNW\nG8vEvt2p7QrjeZ3EAatx5JuYty/NKTHZwJWk51CgzEgzDwzE2JIiqeldtL5d0Sl6\neVuv0G04BEyuXxEWpgVVzBS4qEFIBSnTJzgu1PXmId3yLvg2Nr8NKvwyZmN5xKFp\n0A9BWo15zW1PXDaD+l39oTYD7agjXkzTAjYIcfNJ7ATIYFD0xAvNAOf70s7aNupF\nfvkG2Q==\n-----END CERTIFICATE-----\n",
    ]
    assert result == pkcs7_to_pem(logger, file_content, "list")


def test_588_pkcs7_to_pem(logger: logging.Logger, test_dir: str) -> None:
    """test pkcs7 to pem output list"""
    with open(test_dir + "/ca/certs.p7b", "r") as fso:
        file_content = fso.read()
    result = None
    assert result == pkcs7_to_pem(logger, file_content, "unknown")


def test_589_pkcs7_to_pem(logger: logging.Logger) -> None:
    """test pkcs7 to pem output list"""
    file_content = base64.b64decode(
        "MIIK9AYJKoZIhvcNAQcCoIIK5TCCCuECAQExADALBgkqhkiG9w0BBwGgggrHMIIFTzCCAzegAwIBAgIIAzHyhSyrXfMwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UECxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MTM1NDAwWhcNMzAwNTI2MjM1OTAwWjAqMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEPMA0GA1UEAxMGc3ViLWNhMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxXHaGZsolXe+PBdUryngHP9VbBC1mehqeTtYI+hqsqGNH7q9a7bSrxMwFuF1kYL8jqqxkJdtl0L94xcxJg/ZdMx7Nt0vGI+BaAuTpEpUEHeN4tqS6NhB/m/0LGkAELc/qkzmoO4B1FDwEEj/3IXtZcupqG80oDt7jWSGXdtF7NTjzcumznMeRXidCdhxRxT//WrsChaytXo0xWZ56oeNwd6x6Dr8/39PBOWtj4fldyDcg+Q+alci2tx9pxmu2bCVXcB9ftCLKhDk2WEHE88bgKSp7fV2RCmq9po+Tx8JJ7qecLunUsK/F0XN4kpoQLm9hcymqchnMSncSiyin1dQHGHWgXDtBDdq6A2Z6rx26Qk5H9HTYvcNSe1YwFEDoGLBZQjbCPWiaqoaH4agBQTclPvrrSCRaVmhUSO+pBtSXDkmN4t3MDZxfgRkp8ixwkB15Y5f0LTpCyAJsdQDw8+Ea0aDqO30eskh4CErnm9+Fejd9Ew2cwpdwfBXzVSbYilMGueQihZHvJmVRxAwU69aO2Qs8B0tQ60CfWKVlmWPiakrvYYlPp0FBsM61G6LZEN8hH2CKnS8hHv5IWEXZvp0Pk8V3P5h6bWN0Tl+x/V1Prt7Wp8NoiPETE8XyDDxe6dmKxztWBH/mTsJyMGb6ZiUoXdPU9TFUKqHxTRLHaxfsPsCAwEAAaN4MHYwEgYDVR0TAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQUv96OjgYiIqutQ8jd1E+oq0hBPtUwDgYDVR0PAQH/BAQDAgGGMBEGCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYPeGNhIGNlcnRpZmljYXRlMA0GCSqGSIb3DQEBCwUAA4ICAQBbHLEVyg4f9uEujroc31UVyDRLMdPgEPLjOenSBCBmH0N81whDmxNI/7JAAB6J14WMX8OLF0HkZnb7G77WvDhy1aFvQFbXHBz3/zUO9Mw9J4L2XEW6ond3Nsh1m2oXeBde3R3ANxuIzHqZDlP96YrRcHjnf4+1/5AKDJAvJD+gFb5YnYUKH2iSvHUvG17xcZx98Rf2eo8LealG4JqHJh4sKRy0VjDQD7jXSCbweTHEb8wz+6OfNGrIo+BhTFP5vPcwE4nlJwYBoaOJ5cVa7gdQJ7WkLSxvwHxuxzvSVK73u3jl3I9SqTrbMLG/jeJyV0P8EvdljOaGnCtQVRwCzM4ptXUvKhKOHy7/nyTF/Bc35ZwwL/2xWvNK1+NibgE/6CFxupwWpdmxQbVVuoQ32tUil9ty0yC6m5GKE8+t1lrZuxyA+b/TBnYNO5xo8UEMbkpxaNYSwmw+f/loxXP/M7sIBcLvy2ugHEBxwd9o/kLXeXT2DaRvxPjp4yk8MpJRpNmz3aB5HJwaUnaRLVo5Z3XWWXmjMGZ6/m0AAoDbDz/pXtOoJZT8BJdD1DuDdszVsQnLVn4B/LtIXL6FbXsFzfv6ERP9a5gpKUZ+4NjgrnlGtdccNZpwyWF0IXcvaq3b8hXIRO4hMjzHeHfzJN4tjX1vlY35Ofonc4+6dRVamBiF9DCCBXAwggNYoAMCAQICCHry008TjKGYMA0GCSqGSIb3DQEBCwUAMCsxFzAVBgNVBAsTDmFjbWUyY2VydGlmaWVyMRAwDgYDVQQDEwdyb290LWNhMB4XDTIwMDUyNzAwMDAwMFoXDTMwMDUyNjIzNTk1OVowKzEXMBUGA1UECxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCcuFGR3WYGLeuJP6xWpqAuu+rWL7Wm3roqlcNXOqFWSPPe3BSxugWMMq9hGo+7Ra6kyQ3jDeL2UrnS7Jiw6upvCsF/64j81EyJXIzOWiDADWa/ayxLNzVrXIr6JQeWkNbJYXVYrVDy7sbBZ2HkE8sRcj+5Z4PTP2eNNyixvKYXZiozNLyZGo+Drijl391LFqlkGMkZf5rNO8VY9NrqtPC5KHjvo7UIrL8lV1EXWgnHmbciv2QUOzRQrGytddnFUdXtmiaJezSQAOlpuogcwHZAANpd5IeNEi6BG2omlTIsSzdr4pSGTjgKA11+Pk+oq/ipw1UidsruXPziTMLl8B64ey4INb7BUeUzXoZJ4Y1LljlDvtE5Cj4NgOyk4O9jmdpjnC2SG8c69T+UUb3Zi0Cz60xdhCb6UDzZm16jd2VVhL3x045JExWP3bDk7xU4Eq4tec2CnIfL6LXFO8/gUIYJjLcDtiYTzJmegAXfbJCO4o1qcDpbQIcbXaATuk+ggQqxNsl3Olfz8sgCnBYJTZiIIbeaF7JxPrm/3bcfH/SHmv8TT3aOWhsvH3WoraJQytepHdym+zhOBzByMDscRdQRAKnq8cYWyzEQa/IUUmSOXLy81i76QEOc7oYw+ld2/QWBXeLowLt85d5m83W2IxaBjl+mgWWhg8ZXODtlux8Z7QIDAQABo4GXMIGUMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFAxlb7kxWGbRAJM92n/cESgw7wLMMB8GA1UdIwQYMBaAFAxlb7kxWGbRAJM92n/cESgw7wLMMA4GA1UdDwEB/wQEAwIBhjARBglghkgBhvhCAQEEBAMCAAcwHgYJYIZIAYb4QgENBBEWD3hjYSBjZXJ0aWZpY2F0ZTANBgkqhkiG9w0BAQsFAAOCAgEAI5KO3V/ogoE/ptyMtVYOo+zEXrzwM6tZah0UTTXbdnLed9KSLrexb+VdsWJN+ZGvovxvl8jr012vbwFCogbYkZ1D7F7uFHEuwnKwlxMx8eHjrR56ecA4TtBcefzlGU2j/i+z3dRg/4/ed4m8eWzGvzPUY/kuPOp7Lee7bg0ZhAGrxQ4jHei94x+GEnJI5iB9rkngyGkWvZOmoNO+15lob1WEPbbke0Rm0rrldxXOqanBW21qaC4TUXBXPoW1CjrCpdnD/kBCj/x9rN1jJZaoACimXjvtSjrBqNQg7OO+WyF8ggaRWx9hzj2rZrt8mUUPX4/bWvRFuOp99wxUTS4pxVmuFibOMi1T9Y7oHtkwjsgNbetYsvvkUV0ht3uzRWKxGbgobdRHQwHcyFGPPZvTQj8KA2EuAmoYJ35JDu2EHun+sqiuorMn/GRXKdbhefHhEQ4hfxQ6kvJy5gnVEbiOegw6Dbw6YoOSf/UTVhvLxL7dqe0K43mdxAGrceSbmLcvzSkx2cCVpOdQoMxIMw8MxNiSIqnpXbS+XdEpenlbr9BtOARMrl8RFqYFVcwUuKhBSAUp0yc4LtT15iHd8i74Nja/DSr8MmZjecShadAPQVqNec1tT1w2g/pd/aE2A+2oI15M0wI2CHHzSewEyGBQ9MQLzQDn+9LO2jbqRX75BtmhADEA"
    )
    result = [
        "-----BEGIN CERTIFICATE-----\nMIIFTzCCAzegAwIBAgIIAzHyhSyrXfMwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MTM1\nNDAwWhcNMzAwNTI2MjM1OTAwWjAqMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEP\nMA0GA1UEAxMGc3ViLWNhMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA\nxXHaGZsolXe+PBdUryngHP9VbBC1mehqeTtYI+hqsqGNH7q9a7bSrxMwFuF1kYL8\njqqxkJdtl0L94xcxJg/ZdMx7Nt0vGI+BaAuTpEpUEHeN4tqS6NhB/m/0LGkAELc/\nqkzmoO4B1FDwEEj/3IXtZcupqG80oDt7jWSGXdtF7NTjzcumznMeRXidCdhxRxT/\n/WrsChaytXo0xWZ56oeNwd6x6Dr8/39PBOWtj4fldyDcg+Q+alci2tx9pxmu2bCV\nXcB9ftCLKhDk2WEHE88bgKSp7fV2RCmq9po+Tx8JJ7qecLunUsK/F0XN4kpoQLm9\nhcymqchnMSncSiyin1dQHGHWgXDtBDdq6A2Z6rx26Qk5H9HTYvcNSe1YwFEDoGLB\nZQjbCPWiaqoaH4agBQTclPvrrSCRaVmhUSO+pBtSXDkmN4t3MDZxfgRkp8ixwkB1\n5Y5f0LTpCyAJsdQDw8+Ea0aDqO30eskh4CErnm9+Fejd9Ew2cwpdwfBXzVSbYilM\nGueQihZHvJmVRxAwU69aO2Qs8B0tQ60CfWKVlmWPiakrvYYlPp0FBsM61G6LZEN8\nhH2CKnS8hHv5IWEXZvp0Pk8V3P5h6bWN0Tl+x/V1Prt7Wp8NoiPETE8XyDDxe6dm\nKxztWBH/mTsJyMGb6ZiUoXdPU9TFUKqHxTRLHaxfsPsCAwEAAaN4MHYwEgYDVR0T\nAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQUv96OjgYiIqutQ8jd1E+oq0hBPtUwDgYD\nVR0PAQH/BAQDAgGGMBEGCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYP\neGNhIGNlcnRpZmljYXRlMA0GCSqGSIb3DQEBCwUAA4ICAQBbHLEVyg4f9uEujroc\n31UVyDRLMdPgEPLjOenSBCBmH0N81whDmxNI/7JAAB6J14WMX8OLF0HkZnb7G77W\nvDhy1aFvQFbXHBz3/zUO9Mw9J4L2XEW6ond3Nsh1m2oXeBde3R3ANxuIzHqZDlP9\n6YrRcHjnf4+1/5AKDJAvJD+gFb5YnYUKH2iSvHUvG17xcZx98Rf2eo8LealG4JqH\nJh4sKRy0VjDQD7jXSCbweTHEb8wz+6OfNGrIo+BhTFP5vPcwE4nlJwYBoaOJ5cVa\n7gdQJ7WkLSxvwHxuxzvSVK73u3jl3I9SqTrbMLG/jeJyV0P8EvdljOaGnCtQVRwC\nzM4ptXUvKhKOHy7/nyTF/Bc35ZwwL/2xWvNK1+NibgE/6CFxupwWpdmxQbVVuoQ3\n2tUil9ty0yC6m5GKE8+t1lrZuxyA+b/TBnYNO5xo8UEMbkpxaNYSwmw+f/loxXP/\nM7sIBcLvy2ugHEBxwd9o/kLXeXT2DaRvxPjp4yk8MpJRpNmz3aB5HJwaUnaRLVo5\nZ3XWWXmjMGZ6/m0AAoDbDz/pXtOoJZT8BJdD1DuDdszVsQnLVn4B/LtIXL6FbXsF\nzfv6ERP9a5gpKUZ+4NjgrnlGtdccNZpwyWF0IXcvaq3b8hXIRO4hMjzHeHfzJN4t\njX1vlY35Ofonc4+6dRVamBiF9A==\n-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\nMIIFcDCCA1igAwIBAgIIevLTTxOMoZgwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MDAw\nMDAwWhcNMzAwNTI2MjM1OTU5WjArMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEQ\nMA4GA1UEAxMHcm9vdC1jYTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB\nAJy4UZHdZgYt64k/rFamoC676tYvtabeuiqVw1c6oVZI897cFLG6BYwyr2Eaj7tF\nrqTJDeMN4vZSudLsmLDq6m8KwX/riPzUTIlcjM5aIMANZr9rLEs3NWtcivolB5aQ\n1slhdVitUPLuxsFnYeQTyxFyP7lng9M/Z403KLG8phdmKjM0vJkaj4OuKOXf3UsW\nqWQYyRl/ms07xVj02uq08LkoeO+jtQisvyVXURdaCceZtyK/ZBQ7NFCsbK112cVR\n1e2aJol7NJAA6Wm6iBzAdkAA2l3kh40SLoEbaiaVMixLN2vilIZOOAoDXX4+T6ir\n+KnDVSJ2yu5c/OJMwuXwHrh7Lgg1vsFR5TNehknhjUuWOUO+0TkKPg2A7KTg72OZ\n2mOcLZIbxzr1P5RRvdmLQLPrTF2EJvpQPNmbXqN3ZVWEvfHTjkkTFY/dsOTvFTgS\nri15zYKch8votcU7z+BQhgmMtwO2JhPMmZ6ABd9skI7ijWpwOltAhxtdoBO6T6CB\nCrE2yXc6V/PyyAKcFglNmIght5oXsnE+ub/dtx8f9Iea/xNPdo5aGy8fdaitolDK\n16kd3Kb7OE4HMHIwOxxF1BEAqerxxhbLMRBr8hRSZI5cvLzWLvpAQ5zuhjD6V3b9\nBYFd4ujAu3zl3mbzdbYjFoGOX6aBZaGDxlc4O2W7HxntAgMBAAGjgZcwgZQwDwYD\nVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUDGVvuTFYZtEAkz3af9wRKDDvAswwHwYD\nVR0jBBgwFoAUDGVvuTFYZtEAkz3af9wRKDDvAswwDgYDVR0PAQH/BAQDAgGGMBEG\nCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYPeGNhIGNlcnRpZmljYXRl\nMA0GCSqGSIb3DQEBCwUAA4ICAQAjko7dX+iCgT+m3Iy1Vg6j7MRevPAzq1lqHRRN\nNdt2ct530pIut7Fv5V2xYk35ka+i/G+XyOvTXa9vAUKiBtiRnUPsXu4UcS7CcrCX\nEzHx4eOtHnp5wDhO0Fx5/OUZTaP+L7Pd1GD/j953ibx5bMa/M9Rj+S486nst57tu\nDRmEAavFDiMd6L3jH4YSckjmIH2uSeDIaRa9k6ag077XmWhvVYQ9tuR7RGbSuuV3\nFc6pqcFbbWpoLhNRcFc+hbUKOsKl2cP+QEKP/H2s3WMllqgAKKZeO+1KOsGo1CDs\n475bIXyCBpFbH2HOPatmu3yZRQ9fj9ta9EW46n33DFRNLinFWa4WJs4yLVP1juge\n2TCOyA1t61iy++RRXSG3e7NFYrEZuCht1EdDAdzIUY89m9NCPwoDYS4CahgnfkkO\n7YQe6f6yqK6isyf8ZFcp1uF58eERDiF/FDqS8nLmCdURuI56DDoNvDpig5J/9RNW\nG8vEvt2p7QrjeZ3EAatx5JuYty/NKTHZwJWk51CgzEgzDwzE2JIiqeldtL5d0Sl6\neVuv0G04BEyuXxEWpgVVzBS4qEFIBSnTJzgu1PXmId3yLvg2Nr8NKvwyZmN5xKFp\n0A9BWo15zW1PXDaD+l39oTYD7agjXkzTAjYIcfNJ7ATIYFD0xAvNAOf70s7aNupF\nfvkG2Q==\n-----END CERTIFICATE-----\n",
    ]
    assert result == pkcs7_to_pem(logger, file_content, "list")


def test_590_pkcs7_to_pem_tag_replacement_logs_error() -> None:
    """Test pkcs7_to_pem logs error on tag replacement strategy (line 426)"""
    from acme2certifier.acme_srv.helpers.certificates import pkcs7_to_pem

    logger = Mock()
    with patch(
        "acme2certifier.acme_srv.helpers.certificates.load_pem_pkcs7_certificates",
        side_effect=[Exception("fail1"), [Mock()]],
    ):
        with patch(
            "acme2certifier.acme_srv.helpers.certificates.convert_string_to_byte",
            side_effect=lambda x: x,
        ):
            result = pkcs7_to_pem(logger, "dummy", outform="list")
    logger.error.assert_any_call("PKCS7-TAG not found, updated content successfully")
    assert isinstance(result, list)


def test_591_pkcs7_to_pem_all_strategies_fail() -> None:
    """Test pkcs7_to_pem logs error and raises if all strategies fail (lines 436-437)"""
    from acme2certifier.acme_srv.helpers.certificates import pkcs7_to_pem

    logger = Mock()
    with (
        patch(
            "acme2certifier.acme_srv.helpers.certificates.load_pem_pkcs7_certificates",
            side_effect=Exception("fail1"),
        ),
        patch(
            "acme2certifier.acme_srv.helpers.certificates.convert_string_to_byte",
            side_effect=lambda x: x,
        ),
        patch(
            "acme2certifier.acme_srv.helpers.certificates.load_der_pkcs7_certificates",
            side_effect=Exception("fail2"),
        ),
    ):
        with pytest.raises(Exception) as cm:
            pkcs7_to_pem(logger, "dummy", outform="list")
    logger.error.assert_any_call(
        "All PKCS7 loading strategies failed. Last error: %s", cm.value
    )


def test_619_cert_aki_asn1_get_success_and_missing(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """_cert_aki_asn1_get returns hex or None when AKI absent"""
    from acme2certifier.acme_srv.helpers.certificates import _cert_aki_asn1_get

    cert = "MIIDIzCCAgugAwIBAgICBZgwDQYJKoZIhvcNAQELBQAwGjEYMBYGA1UEAxMPZm9v\n                LmV4YW1wbGUuY29tMB4XDTE5MDEyMDE3MDkxMVoXDTE5MDIxOTE3MDkxMVowGjEY\n                MBYGA1UEAxMPZm9vLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n                MIIBCgKCAQEA+EM+gzAyjegQSRbJI+qZJhuAGM9i48xvIfuOQHleXoJPjV+8VZRV\n                KDljZNXdNT5Zi7K6HY9C622NOV7QefB6zTtm6mSY08ypNsaeorhIvJdnpaJ9gAGH\n                YeQqJ04fL099kiRXJAv8gT8wdpiekg2KEU4wlXMIRfSHiiB37yjcqUzXl6XYYKGe\n                2USMpDfliXL3o8TW2KByGUdCzXUdNbMgzRXwYxkX2+xV2f0vn8NyXHiHg9yJRof2\n                HTjyvAcXN5Nr987slq/Ex5lXLtpB861Ov3ZbwxyzREjmreZBlze7KTfP5IY66XuN\n                Mvhi7AAs0cLTd3SNjpppE/yvUi5q5gfhXQIDAQABo3MwcTAfBgNVHSMEGDAWgBSl\n                YnpKQw12MmEMpvsTEeQi17UsnDAdBgNVHQ4EFgQUpWJ6SkMNdjJhDKb7ExHkIte1\n                LJwwLwYDVR0RBCgwJoIRZm9vLTIuZXhhbXBsZS5jb22CEWZvby0xLmV4YW1wbGUu\n                Y29tMA0GCSqGSIb3DQEBCwUAA4IBAQASA20TtMPXIHH10dikLhFuI14EOtZzXvCx\n                kGlJw9/5JuvVKLsL1wd8BC9o/lg8apDqsrDZ/+0Nc8g3Z9HRN99vcLsVDdT27DkM\n                BslfXdN/qBhKAp3m7jw29uijX5fss+Wz9iHfHciUjVyMJ4DoFxHYPbMWQG8XEUKR\n                TP6Gp79DzCiPKFt52Y8yVikIET4fnyRzU8kGKLuPoIt+EQQzpG26qWAjeNHAASEM\n                keiA+tedMWzydX52B+tGg+l2svxg34apIBDjK8pF+8ZxTt5yjVUa10GbpffJuiEh\n                NWQddOR8IHg+v6lWc9BtuuKK5ubsg6XOiEjhhr42AKViKalX1i4+"
    assert "a5627a4a430d7632610ca6fb1311e422d7b52c9c" == _cert_aki_asn1_get(
        logger, cert
    )
    with (
        patch(
            "acme2certifier.acme_srv.helpers.certificates._cert_extension_raw_get",
            return_value=None,
        ),
        capture_logs("test_a2c", level="WARNING") as lcm,
    ):
        assert _cert_aki_asn1_get(logger, cert) is None
    assert "WARNING:test_a2c:No AKI found in certificate" in lcm.output


def test_620_cert_ski_asn1_get_success_and_missing(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """_cert_ski_asn1_get returns hex or None when SKI absent"""
    from acme2certifier.acme_srv.helpers.certificates import _cert_ski_asn1_get

    cert = "MIIDIzCCAgugAwIBAgICBZgwDQYJKoZIhvcNAQELBQAwGjEYMBYGA1UEAxMPZm9v\n                LmV4YW1wbGUuY29tMB4XDTE5MDEyMDE3MDkxMVoXDTE5MDIxOTE3MDkxMVowGjEY\n                MBYGA1UEAxMPZm9vLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n                MIIBCgKCAQEA+EM+gzAyjegQSRbJI+qZJhuAGM9i48xvIfuOQHleXoJPjV+8VZRV\n                KDljZNXdNT5Zi7K6HY9C622NOV7QefB6zTtm6mSY08ypNsaeorhIvJdnpaJ9gAGH\n                YeQqJ04fL099kiRXJAv8gT8wdpiekg2KEU4wlXMIRfSHiiB37yjcqUzXl6XYYKGe\n                2USMpDfliXL3o8TW2KByGUdCzXUdNbMgzRXwYxkX2+xV2f0vn8NyXHiHg9yJRof2\n                HTjyvAcXN5Nr987slq/Ex5lXLtpB861Ov3ZbwxyzREjmreZBlze7KTfP5IY66XuN\n                Mvhi7AAs0cLTd3SNjpppE/yvUi5q5gfhXQIDAQABo3MwcTAfBgNVHSMEGDAWgBSl\n                YnpKQw12MmEMpvsTEeQi17UsnDAdBgNVHQ4EFgQUpWJ6SkMNdjJhDKb7ExHkIte1\n                LJwwLwYDVR0RBCgwJoIRZm9vLTIuZXhhbXBsZS5jb22CEWZvby0xLmV4YW1wbGUu\n                Y29tMA0GCSqGSIb3DQEBCwUAA4IBAQASA20TtMPXIHH10dikLhFuI14EOtZzXvCx\n                kGlJw9/5JuvVKLsL1wd8BC9o/lg8apDqsrDZ/+0Nc8g3Z9HRN99vcLsVDdT27DkM\n                BslfXdN/qBhKAp3m7jw29uijX5fss+Wz9iHfHciUjVyMJ4DoFxHYPbMWQG8XEUKR\n                TP6Gp79DzCiPKFt52Y8yVikIET4fnyRzU8kGKLuPoIt+EQQzpG26qWAjeNHAASEM\n                keiA+tedMWzydX52B+tGg+l2svxg34apIBDjK8pF+8ZxTt5yjVUa10GbpffJuiEh\n                NWQddOR8IHg+v6lWc9BtuuKK5ubsg6XOiEjhhr42AKViKalX1i4+"
    assert "a5627a4a430d7632610ca6fb1311e422d7b52c9c" == _cert_ski_asn1_get(
        logger, cert
    )
    with (
        patch(
            "acme2certifier.acme_srv.helpers.certificates._cert_extension_raw_get",
            return_value=None,
        ),
        capture_logs("test_a2c", level="WARNING") as lcm,
    ):
        assert _cert_ski_asn1_get(logger, cert) is None
    assert "WARNING:test_a2c:No SKI found in certificate" in lcm.output


def test_621_cert_aki_asn1_get_missing_key_identifier(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """_cert_aki_asn1_get warns when AKI has no keyIdentifier"""
    from acme2certifier.acme_srv.helpers.certificates import _cert_aki_asn1_get

    mock_aki = MagicMock()
    mock_aki.__getitem__.return_value.isValue = False
    with (
        patch(
            "acme2certifier.acme_srv.helpers.certificates._cert_extension_raw_get",
            return_value=b"0\x00",
        ),
        patch(
            "acme2certifier.acme_srv.helpers.certificates.decoder.decode",
            return_value=(mock_aki, None),
        ),
        capture_logs("test_a2c", level="WARNING") as lcm,
    ):
        assert _cert_aki_asn1_get(logger, "cert") is None
    assert (
        "WARNING:test_a2c:AKI extension present but keyIdentifier missing" in lcm.output
    )


def test_622_cert_extension_raw_get_no_extensions(logger: logging.Logger) -> None:
    """_cert_extension_raw_get returns None when extensions absent or OID missing"""
    from acme2certifier.acme_srv.helpers.certificates import (
        _cert_extension_raw_get,
        _OID_SKI,
    )

    cert = "MIIDIzCCAgugAwIBAgICBZgwDQYJKoZIhvcNAQELBQAwGjEYMBYGA1UEAxMPZm9v\n                LmV4YW1wbGUuY29tMB4XDTE5MDEyMDE3MDkxMVoXDTE5MDIxOTE3MDkxMVowGjEY\n                MBYGA1UEAxMPZm9vLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n                MIIBCgKCAQEA+EM+gzAyjegQSRbJI+qZJhuAGM9i48xvIfuOQHleXoJPjV+8VZRV\n                KDljZNXdNT5Zi7K6HY9C622NOV7QefB6zTtm6mSY08ypNsaeorhIvJdnpaJ9gAGH\n                YeQqJ04fL099kiRXJAv8gT8wdpiekg2KEU4wlXMIRfSHiiB37yjcqUzXl6XYYKGe\n                2USMpDfliXL3o8TW2KByGUdCzXUdNbMgzRXwYxkX2+xV2f0vn8NyXHiHg9yJRof2\n                HTjyvAcXN5Nr987slq/Ex5lXLtpB861Ov3ZbwxyzREjmreZBlze7KTfP5IY66XuN\n                Mvhi7AAs0cLTd3SNjpppE/yvUi5q5gfhXQIDAQABo3MwcTAfBgNVHSMEGDAWgBSl\n                YnpKQw12MmEMpvsTEeQi17UsnDAdBgNVHQ4EFgQUpWJ6SkMNdjJhDKb7ExHkIte1\n                LJwwLwYDVR0RBCgwJoIRZm9vLTIuZXhhbXBsZS5jb22CEWZvby0xLmV4YW1wbGUu\n                Y29tMA0GCSqGSIb3DQEBCwUAA4IBAQASA20TtMPXIHH10dikLhFuI14EOtZzXvCx\n                kGlJw9/5JuvVKLsL1wd8BC9o/lg8apDqsrDZ/+0Nc8g3Z9HRN99vcLsVDdT27DkM\n                BslfXdN/qBhKAp3m7jw29uijX5fss+Wz9iHfHciUjVyMJ4DoFxHYPbMWQG8XEUKR\n                TP6Gp79DzCiPKFt52Y8yVikIET4fnyRzU8kGKLuPoIt+EQQzpG26qWAjeNHAASEM\n                keiA+tedMWzydX52B+tGg+l2svxg34apIBDjK8pF+8ZxTt5yjVUa10GbpffJuiEh\n                NWQddOR8IHg+v6lWc9BtuuKK5ubsg6XOiEjhhr42AKViKalX1i4+"
    assert _cert_extension_raw_get(logger, cert, "1.2.3.4.5") is None
    assert _cert_extension_raw_get(logger, cert, _OID_SKI) is not None
    mock_cert_asn1 = MagicMock()
    mock_cert_asn1.__getitem__.return_value.__getitem__.return_value = None
    with patch(
        "acme2certifier.acme_srv.helpers.certificates.decoder.decode",
        return_value=(mock_cert_asn1, None),
    ):
        assert _cert_extension_raw_get(logger, cert, _OID_SKI) is None
    mock_exts = MagicMock()
    mock_exts.hasValue.return_value = False
    mock_cert_asn1 = MagicMock()
    mock_cert_asn1.__getitem__.return_value.__getitem__.return_value = mock_exts
    with patch(
        "acme2certifier.acme_srv.helpers.certificates.decoder.decode",
        return_value=(mock_cert_asn1, None),
    ):
        assert _cert_extension_raw_get(logger, cert, _OID_SKI) is None


@patch("acme2certifier.acme_srv.helpers.certificates._cert_aki_asn1_get")
@patch("acme2certifier.acme_srv.helpers.certificates.x509.Certificate.extensions")
def test_623_cert_aki_get_falls_back_to_asn1(
    mock_ext: MagicMock, mock_aki_get: MagicMock, logger: logging.Logger
) -> None:
    """cert_aki_get falls back to ASN.1 helper on cryptography failure"""
    cert = "MIIDIzCCAgugAwIBAgICBZgwDQYJKoZIhvcNAQELBQAwGjEYMBYGA1UEAxMPZm9v\n                LmV4YW1wbGUuY29tMB4XDTE5MDEyMDE3MDkxMVoXDTE5MDIxOTE3MDkxMVowGjEY\n                MBYGA1UEAxMPZm9vLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n                MIIBCgKCAQEA+EM+gzAyjegQSRbJI+qZJhuAGM9i48xvIfuOQHleXoJPjV+8VZRV\n                KDljZNXdNT5Zi7K6HY9C622NOV7QefB6zTtm6mSY08ypNsaeorhIvJdnpaJ9gAGH\n                YeQqJ04fL099kiRXJAv8gT8wdpiekg2KEU4wlXMIRfSHiiB37yjcqUzXl6XYYKGe\n                2USMpDfliXL3o8TW2KByGUdCzXUdNbMgzRXwYxkX2+xV2f0vn8NyXHiHg9yJRof2\n                HTjyvAcXN5Nr987slq/Ex5lXLtpB861Ov3ZbwxyzREjmreZBlze7KTfP5IY66XuN\n                Mvhi7AAs0cLTd3SNjpppE/yvUi5q5gfhXQIDAQABo3MwcTAfBgNVHSMEGDAWgBSl\n                YnpKQw12MmEMpvsTEeQi17UsnDAdBgNVHQ4EFgQUpWJ6SkMNdjJhDKb7ExHkIte1\n                LJwwLwYDVR0RBCgwJoIRZm9vLTIuZXhhbXBsZS5jb22CEWZvby0xLmV4YW1wbGUu\n                Y29tMA0GCSqGSIb3DQEBCwUAA4IBAQASA20TtMPXIHH10dikLhFuI14EOtZzXvCx\n                kGlJw9/5JuvVKLsL1wd8BC9o/lg8apDqsrDZ/+0Nc8g3Z9HRN99vcLsVDdT27DkM\n                BslfXdN/qBhKAp3m7jw29uijX5fss+Wz9iHfHciUjVyMJ4DoFxHYPbMWQG8XEUKR\n                TP6Gp79DzCiPKFt52Y8yVikIET4fnyRzU8kGKLuPoIt+EQQzpG26qWAjeNHAASEM\n                keiA+tedMWzydX52B+tGg+l2svxg34apIBDjK8pF+8ZxTt5yjVUa10GbpffJuiEh\n                NWQddOR8IHg+v6lWc9BtuuKK5ubsg6XOiEjhhr42AKViKalX1i4+"
    mock_ext.get_extension_for_oid.side_effect = Exception("No AKI")
    mock_aki_get.return_value = "asn1-aki"
    assert "asn1-aki" == cert_aki_get(logger, cert)
    mock_aki_get.assert_called_once()


def test_657_cert_bound_names_get_empty(logger: logging.Logger) -> None:
    """cert_bound_names_get returns empty set for empty certificate"""
    from acme2certifier.acme_srv.helpers.certificates import cert_bound_names_get

    assert set() == cert_bound_names_get(logger, None)
    assert set() == cert_bound_names_get(logger, "")


def test_658_cert_bound_names_get_sans_and_cn(logger: logging.Logger) -> None:
    """cert_bound_names_get unions SAN types and subject CN"""
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from acme2certifier.acme_srv.helpers.certificates import cert_bound_names_get

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "cn.example.com")]
    )
    cert_obj = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("san.example.com"),
                    x509.IPAddress(ipaddress.IPv4Address("192.0.2.1")),
                    x509.RFC822Name("user@example.com"),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert = base64.b64encode(cert_obj.public_bytes(serialization.Encoding.DER)).decode()
    assert {
        ("dns", "san.example.com"),
        ("ip", "192.0.2.1"),
        ("email", "user@example.com"),
        ("dns", "cn.example.com"),
    } == cert_bound_names_get(logger, cert)


def test_659_cert_bound_names_get_malformed_san(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """cert_bound_names_get skips malformed SAN strings and logs error"""
    from acme2certifier.acme_srv.helpers.certificates import cert_bound_names_get

    with (
        patch(
            "acme2certifier.acme_srv.helpers.certificates.cert_san_get",
            return_value=["not-a-san"],
        ),
        patch(
            "acme2certifier.acme_srv.helpers.certificates.cert_cn_get",
            return_value=None,
        ),
    ):
        with capture_logs("test_a2c", level="ERROR") as lcm:
            result = cert_bound_names_get(logger, "dummy")
    assert set() == result
    assert any(("Error while splitting SAN not-a-san" in msg for msg in lcm.output))


def test_660_cert_bound_names_get_email_rewrite(logger: logging.Logger) -> None:
    """cert_bound_names_get rewrites DNS SANs containing @ when enabled"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from acme2certifier.acme_srv.helpers.certificates import cert_bound_names_get

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "ignored.example.com")]
    )
    cert_obj = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("user@mail.example.com")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert = base64.b64encode(cert_obj.public_bytes(serialization.Encoding.DER)).decode()
    assert {
        ("email", "user@mail.example.com"),
        ("dns", "ignored.example.com"),
    } == cert_bound_names_get(logger, cert, email_identifier_rewrite=True)
