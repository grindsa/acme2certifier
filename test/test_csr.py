# -*- coding: utf-8 -*-
"""Tests for acme_srv.helpers.csr."""

from __future__ import annotations

import base64
import logging
from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from acme2certifier.acme_srv.helpers.csr import (
    csr_bound_names_get,
    csr_cn_get,
    csr_cn_lookup,
    csr_dn_get,
    csr_extensions_get,
    csr_pubkey_get,
    csr_san_byte_get,
    csr_san_get,
    csr_subject_get,
)

pytestmark = pytest.mark.usefixtures("clear_config_cache", "_silence_logging")


def test_082_helper_csr_pubkey_get(logger: logging.Logger) -> None:
    """test get public_key from certificate"""
    csr = "MIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBvH7P73CwR7AF/WGeTfIDLlMWD6VZV3CTZBF0AwNMTFU/zbdAX8r63pzElX/5C5ZVsc36XHqdAJcioJlI33uE3RhOSvDyOcDgWlnPK9gj2soQ7enizGqd1u7hf6C3IwFtc4uGNOU3Z/tnTzVdYiCSKS+5lTZfMxn4FtEUN+w90NHBvC+AlTo3Gl0gqbYOZgg/UwWj60u7S2gBzSeb2/w62Z7bz+SknGZbeI4ySo30ET6oCSCAUN42jE+1dHI/Y+tGBtqP3h7W7OezKeLsJjD9r07U0+uMoVCY9oKTyT0gK8+gsde0tpt6QKa93HJGUPAP9ehrKCl335QcJESFw67/AgMBAAGgOTA3BgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEAf4cdGpYHLqX+06BFF7+NqXLmKvc7n66vAfevLN75eu/pCXhhRSdpXvcYm+mAVEXJCPaG2kFGt6wfBvVWoVX/91d+OuAtiUHmhY95Oi7g3RF3ThCrvT2mR4zsNiKgC34jXbl9489iIiFRBQXkq2fLwN5JwBYutUENwkDIeApRRbmUzTDbar1xoBAQ3GjVtOAEjHc/3S1yyKkCpM6Qkg8uWOJAXw9INJqH6x55nMZrvTUuXkURc/mvhV+bp2vdKoigGvfa3VVfoAI0BZLQMohQ9QLKoNQsKxEs3JidvpZrl3o23LMGEPoJs3zIuowTa217PHwdBw4UwtD7KxJK/+344A=="
    pub_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbx+z+9wsEewBf1hnk3y\nAy5TFg+lWVdwk2QRdAMDTExVP823QF/K+t6cxJV/+QuWVbHN+lx6nQCXIqCZSN97\nhN0YTkrw8jnA4FpZzyvYI9rKEO3p4sxqndbu4X+gtyMBbXOLhjTlN2f7Z081XWIg\nkikvuZU2XzMZ+BbRFDfsPdDRwbwvgJU6NxpdIKm2DmYIP1MFo+tLu0toAc0nm9v8\nOtme28/kpJxmW3iOMkqN9BE+qAkggFDeNoxPtXRyP2PrRgbaj94e1uznsyni7CYw\n/a9O1NPrjKFQmPaCk8k9ICvPoLHXtLabekCmvdxyRlDwD/Xoaygpd9+UHCREhcOu\n/wIDAQAB\n-----END PUBLIC KEY-----\n"
    assert pub_key == csr_pubkey_get(logger, csr)


def test_083_helper_csr_pubkey_get(logger: logging.Logger) -> None:
    """test get public_key from certificate"""
    csr = "MIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBvH7P73CwR7AF/WGeTfIDLlMWD6VZV3CTZBF0AwNMTFU/zbdAX8r63pzElX/5C5ZVsc36XHqdAJcioJlI33uE3RhOSvDyOcDgWlnPK9gj2soQ7enizGqd1u7hf6C3IwFtc4uGNOU3Z/tnTzVdYiCSKS+5lTZfMxn4FtEUN+w90NHBvC+AlTo3Gl0gqbYOZgg/UwWj60u7S2gBzSeb2/w62Z7bz+SknGZbeI4ySo30ET6oCSCAUN42jE+1dHI/Y+tGBtqP3h7W7OezKeLsJjD9r07U0+uMoVCY9oKTyT0gK8+gsde0tpt6QKa93HJGUPAP9ehrKCl335QcJESFw67/AgMBAAGgOTA3BgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEAf4cdGpYHLqX+06BFF7+NqXLmKvc7n66vAfevLN75eu/pCXhhRSdpXvcYm+mAVEXJCPaG2kFGt6wfBvVWoVX/91d+OuAtiUHmhY95Oi7g3RF3ThCrvT2mR4zsNiKgC34jXbl9489iIiFRBQXkq2fLwN5JwBYutUENwkDIeApRRbmUzTDbar1xoBAQ3GjVtOAEjHc/3S1yyKkCpM6Qkg8uWOJAXw9INJqH6x55nMZrvTUuXkURc/mvhV+bp2vdKoigGvfa3VVfoAI0BZLQMohQ9QLKoNQsKxEs3JidvpZrl3o23LMGEPoJs3zIuowTa217PHwdBw4UwtD7KxJK/+344A=="
    pub_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbx+z+9wsEewBf1hnk3y\nAy5TFg+lWVdwk2QRdAMDTExVP823QF/K+t6cxJV/+QuWVbHN+lx6nQCXIqCZSN97\nhN0YTkrw8jnA4FpZzyvYI9rKEO3p4sxqndbu4X+gtyMBbXOLhjTlN2f7Z081XWIg\nkikvuZU2XzMZ+BbRFDfsPdDRwbwvgJU6NxpdIKm2DmYIP1MFo+tLu0toAc0nm9v8\nOtme28/kpJxmW3iOMkqN9BE+qAkggFDeNoxPtXRyP2PrRgbaj94e1uznsyni7CYw\n/a9O1NPrjKFQmPaCk8k9ICvPoLHXtLabekCmvdxyRlDwD/Xoaygpd9+UHCREhcOu\n/wIDAQAB\n-----END PUBLIC KEY-----\n"
    assert pub_key == csr_pubkey_get(logger, csr, encoding="pem")


def test_084_helper_csr_pubkey_get(logger: logging.Logger) -> None:
    """test get public_key from certificate"""
    csr = "MIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBvH7P73CwR7AF/WGeTfIDLlMWD6VZV3CTZBF0AwNMTFU/zbdAX8r63pzElX/5C5ZVsc36XHqdAJcioJlI33uE3RhOSvDyOcDgWlnPK9gj2soQ7enizGqd1u7hf6C3IwFtc4uGNOU3Z/tnTzVdYiCSKS+5lTZfMxn4FtEUN+w90NHBvC+AlTo3Gl0gqbYOZgg/UwWj60u7S2gBzSeb2/w62Z7bz+SknGZbeI4ySo30ET6oCSCAUN42jE+1dHI/Y+tGBtqP3h7W7OezKeLsJjD9r07U0+uMoVCY9oKTyT0gK8+gsde0tpt6QKa93HJGUPAP9ehrKCl335QcJESFw67/AgMBAAGgOTA3BgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEAf4cdGpYHLqX+06BFF7+NqXLmKvc7n66vAfevLN75eu/pCXhhRSdpXvcYm+mAVEXJCPaG2kFGt6wfBvVWoVX/91d+OuAtiUHmhY95Oi7g3RF3ThCrvT2mR4zsNiKgC34jXbl9489iIiFRBQXkq2fLwN5JwBYutUENwkDIeApRRbmUzTDbar1xoBAQ3GjVtOAEjHc/3S1yyKkCpM6Qkg8uWOJAXw9INJqH6x55nMZrvTUuXkURc/mvhV+bp2vdKoigGvfa3VVfoAI0BZLQMohQ9QLKoNQsKxEs3JidvpZrl3o23LMGEPoJs3zIuowTa217PHwdBw4UwtD7KxJK/+344A=="
    pub_key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbx+z+9wsEewBf1hnk3yAy5TFg+lWVdwk2QRdAMDTExVP823QF/K+t6cxJV/+QuWVbHN+lx6nQCXIqCZSN97hN0YTkrw8jnA4FpZzyvYI9rKEO3p4sxqndbu4X+gtyMBbXOLhjTlN2f7Z081XWIgkikvuZU2XzMZ+BbRFDfsPdDRwbwvgJU6NxpdIKm2DmYIP1MFo+tLu0toAc0nm9v8Otme28/kpJxmW3iOMkqN9BE+qAkggFDeNoxPtXRyP2PrRgbaj94e1uznsyni7CYw/a9O1NPrjKFQmPaCk8k9ICvPoLHXtLabekCmvdxyRlDwD/Xoaygpd9+UHCREhcOu/wIDAQAB"
    assert pub_key == csr_pubkey_get(logger, csr, encoding="base64der")


def test_085_helper_csr_pubkey_get(logger: logging.Logger) -> None:
    """test get public_key from certificate"""
    csr = "MIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBvH7P73CwR7AF/WGeTfIDLlMWD6VZV3CTZBF0AwNMTFU/zbdAX8r63pzElX/5C5ZVsc36XHqdAJcioJlI33uE3RhOSvDyOcDgWlnPK9gj2soQ7enizGqd1u7hf6C3IwFtc4uGNOU3Z/tnTzVdYiCSKS+5lTZfMxn4FtEUN+w90NHBvC+AlTo3Gl0gqbYOZgg/UwWj60u7S2gBzSeb2/w62Z7bz+SknGZbeI4ySo30ET6oCSCAUN42jE+1dHI/Y+tGBtqP3h7W7OezKeLsJjD9r07U0+uMoVCY9oKTyT0gK8+gsde0tpt6QKa93HJGUPAP9ehrKCl335QcJESFw67/AgMBAAGgOTA3BgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEAf4cdGpYHLqX+06BFF7+NqXLmKvc7n66vAfevLN75eu/pCXhhRSdpXvcYm+mAVEXJCPaG2kFGt6wfBvVWoVX/91d+OuAtiUHmhY95Oi7g3RF3ThCrvT2mR4zsNiKgC34jXbl9489iIiFRBQXkq2fLwN5JwBYutUENwkDIeApRRbmUzTDbar1xoBAQ3GjVtOAEjHc/3S1yyKkCpM6Qkg8uWOJAXw9INJqH6x55nMZrvTUuXkURc/mvhV+bp2vdKoigGvfa3VVfoAI0BZLQMohQ9QLKoNQsKxEs3JidvpZrl3o23LMGEPoJs3zIuowTa217PHwdBw4UwtD7KxJK/+344A=="
    pub_key = b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbx+z+9wsEewBf1hnk3yAy5TFg+lWVdwk2QRdAMDTExVP823QF/K+t6cxJV/+QuWVbHN+lx6nQCXIqCZSN97hN0YTkrw8jnA4FpZzyvYI9rKEO3p4sxqndbu4X+gtyMBbXOLhjTlN2f7Z081XWIgkikvuZU2XzMZ+BbRFDfsPdDRwbwvgJU6NxpdIKm2DmYIP1MFo+tLu0toAc0nm9v8Otme28/kpJxmW3iOMkqN9BE+qAkggFDeNoxPtXRyP2PrRgbaj94e1uznsyni7CYw/a9O1NPrjKFQmPaCk8k9ICvPoLHXtLabekCmvdxyRlDwD/Xoaygpd9+UHCREhcOu/wIDAQAB"
    assert pub_key == base64.b64encode(csr_pubkey_get(logger, csr, encoding="der"))


def test_086_helper_csr_pubkey_get(logger: logging.Logger) -> None:
    """test get public_key from certificate"""
    csr = "MIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBvH7P73CwR7AF/WGeTfIDLlMWD6VZV3CTZBF0AwNMTFU/zbdAX8r63pzElX/5C5ZVsc36XHqdAJcioJlI33uE3RhOSvDyOcDgWlnPK9gj2soQ7enizGqd1u7hf6C3IwFtc4uGNOU3Z/tnTzVdYiCSKS+5lTZfMxn4FtEUN+w90NHBvC+AlTo3Gl0gqbYOZgg/UwWj60u7S2gBzSeb2/w62Z7bz+SknGZbeI4ySo30ET6oCSCAUN42jE+1dHI/Y+tGBtqP3h7W7OezKeLsJjD9r07U0+uMoVCY9oKTyT0gK8+gsde0tpt6QKa93HJGUPAP9ehrKCl335QcJESFw67/AgMBAAGgOTA3BgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEAf4cdGpYHLqX+06BFF7+NqXLmKvc7n66vAfevLN75eu/pCXhhRSdpXvcYm+mAVEXJCPaG2kFGt6wfBvVWoVX/91d+OuAtiUHmhY95Oi7g3RF3ThCrvT2mR4zsNiKgC34jXbl9489iIiFRBQXkq2fLwN5JwBYutUENwkDIeApRRbmUzTDbar1xoBAQ3GjVtOAEjHc/3S1yyKkCpM6Qkg8uWOJAXw9INJqH6x55nMZrvTUuXkURc/mvhV+bp2vdKoigGvfa3VVfoAI0BZLQMohQ9QLKoNQsKxEs3JidvpZrl3o23LMGEPoJs3zIuowTa217PHwdBw4UwtD7KxJK/+344A=="
    pub_key = b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbx+z+9wsEewBf1hnk3yAy5TFg+lWVdwk2QRdAMDTExVP823QF/K+t6cxJV/+QuWVbHN+lx6nQCXIqCZSN97hN0YTkrw8jnA4FpZzyvYI9rKEO3p4sxqndbu4X+gtyMBbXOLhjTlN2f7Z081XWIgkikvuZU2XzMZ+BbRFDfsPdDRwbwvgJU6NxpdIKm2DmYIP1MFo+tLu0toAc0nm9v8Otme28/kpJxmW3iOMkqN9BE+qAkggFDeNoxPtXRyP2PrRgbaj94e1uznsyni7CYw/a9O1NPrjKFQmPaCk8k9ICvPoLHXtLabekCmvdxyRlDwD/Xoaygpd9+UHCREhcOu/wIDAQAB"
    assert not csr_pubkey_get(logger, csr, encoding="unk")


def test_093_helper_csr_cn_get(logger: logging.Logger) -> None:
    """get cn of csr"""
    csr = "MIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0lk4lyEIa0VL/u5ic01Zo/o+gyYqFpU7xe+nbFgiKA+R1rqrzP/sR6xjHqS0Rkv/BcBXf81sp/+iDmwIQLVlBTkKdimqVHCJMAbTL8ZNpcLDaRUce4liyX1cmczPTSqI/kcyEr8tKpYN+KzvKZZsNx2Pbgu7y7/70P2uSywiW+sqYZ+X28KGFxq6wwENzJtweDVsbWql9LLtw6daF41UQg10auNlRL1nhW0SlWZh1zPPW/0sa6C3xX28jjVh843b4ekkRNLXSEYQMTi0qYR2LomQ5aTlQ/hellf17UknfN2aA2RH5D7Ek+mndj/rH21bxQg26KRmHlaJld9K1IfvJAgMBAAGgOTA3BgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEAl3egrkO3I94IpxxfSJmVetd7s9uW3lSBqh9OiypFevQO7ZgUxau+k05NKTUNpSq3W9H/lRr5AG5x3/VX8XZVbcLKXQ0d6e38uXBAUFQQJmjBVYqd8KcMfqLeFFUBsLcG04yek2tNIbhXZfBtw9UYO27Y5ktMgWjAz2VskIXl3E2L0b8tGnSKDoMB07IVpYB9bHfHX4o+ccIgq1HxyYT1d+eVIQuSHHxR7j7Wkgb8RG9bCWpVWaYWKWU0Inh3gMnP06kPBJ9nOB4adgC3Hz37ab/0KpmBuQBEgmMfINwV/OpJVv2Su1FYK+uX7E1qUGae6QDsfg0Yor9uP0Vkv4b1NA=="
    assert "foo1.bar.local" == csr_cn_get(logger, csr)


def test_094_helper_csr_cn_get(logger: logging.Logger) -> None:
    """get cn of csr"""
    csr = b"MIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0lk4lyEIa0VL/u5ic01Zo/o+gyYqFpU7xe+nbFgiKA+R1rqrzP/sR6xjHqS0Rkv/BcBXf81sp/+iDmwIQLVlBTkKdimqVHCJMAbTL8ZNpcLDaRUce4liyX1cmczPTSqI/kcyEr8tKpYN+KzvKZZsNx2Pbgu7y7/70P2uSywiW+sqYZ+X28KGFxq6wwENzJtweDVsbWql9LLtw6daF41UQg10auNlRL1nhW0SlWZh1zPPW/0sa6C3xX28jjVh843b4ekkRNLXSEYQMTi0qYR2LomQ5aTlQ/hellf17UknfN2aA2RH5D7Ek+mndj/rH21bxQg26KRmHlaJld9K1IfvJAgMBAAGgOTA3BgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEAl3egrkO3I94IpxxfSJmVetd7s9uW3lSBqh9OiypFevQO7ZgUxau+k05NKTUNpSq3W9H/lRr5AG5x3/VX8XZVbcLKXQ0d6e38uXBAUFQQJmjBVYqd8KcMfqLeFFUBsLcG04yek2tNIbhXZfBtw9UYO27Y5ktMgWjAz2VskIXl3E2L0b8tGnSKDoMB07IVpYB9bHfHX4o+ccIgq1HxyYT1d+eVIQuSHHxR7j7Wkgb8RG9bCWpVWaYWKWU0Inh3gMnP06kPBJ9nOB4adgC3Hz37ab/0KpmBuQBEgmMfINwV/OpJVv2Su1FYK+uX7E1qUGae6QDsfg0Yor9uP0Vkv4b1NA=="
    assert "foo1.bar.local" == csr_cn_get(logger, csr)


def test_131_helper_csr_san_get(logger: logging.Logger) -> None:
    """get sans but no csr"""
    csr = None
    assert [] == csr_san_get(logger, csr)


def test_132_helper_csr_san_get(logger: logging.Logger) -> None:
    """get sans but one san with =="""
    csr = "MIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMwfxxbCCTsZY8mTFZkoQ5cAJyQZLUiz34sDDRvEpI9ZzdNNm2AEZR7AgKNuBkLwzUzY5iQ182huNzYJYZZEvYX++ocF2ngapTMQgfB+bWS5bpWIdjnAcz1/86jmJgTciwL25dSnEWL17Yn3pAWweoewr730rq/PMyIbviQrasksnSo7abe2mctxkHjHb5sZ+Z1yRTN6ir/bObXmxr+vHeeD2vLRv4Hd5XaA1d+k31J2FVMnrn5OpWbxGHo49zd0xdy2mgTdZ9UraLaQnyGlkjYzV0rqHIAIm8HOUjGN5U75/rlOPF0x62FCICZU/z1AgRvugaA5eO8zTSQJiMiBe3AgMBAAGgOTA3BgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEANAXOIkv0CovmdzyoAv1dsiK0TK2XHBdBTEPFDsrT7MnrIXOFS4FnDrg8zpn7QBzBRTl3HaKN8fnpIHkA/6ZRDqaEJq0AeskjxIg9LKDBBx5TEdgPh1CwruRWLlXtrqU7XXQmk0wLIo/kfaDRcTjyJ3yHTEK06mCAaws0sTKlTw2D4pIiDRp8zbLHeSEUX5UKOSGbLSSUY/F2XwgPB8nC2BCD/gkvHRR+dMQSdOCiS9GLwZdYAAyESw6WhmGPjmVbeTRgSt/9//yx3JKQgkFYmpSMLKR2G525M+l1qfku/4b0iMOa4vQjFRj5AXZH0SBpAKtvnFxUpP6P9mTE7+akOQ=="
    assert ["DNS:foo1.bar.local"] == csr_san_get(logger, csr)


def test_133_helper_csr_san_get(logger: logging.Logger) -> None:
    """get sans but one san without =="""
    csr = "MIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMwfxxbCCTsZY8mTFZkoQ5cAJyQZLUiz34sDDRvEpI9ZzdNNm2AEZR7AgKNuBkLwzUzY5iQ182huNzYJYZZEvYX++ocF2ngapTMQgfB+bWS5bpWIdjnAcz1/86jmJgTciwL25dSnEWL17Yn3pAWweoewr730rq/PMyIbviQrasksnSo7abe2mctxkHjHb5sZ+Z1yRTN6ir/bObXmxr+vHeeD2vLRv4Hd5XaA1d+k31J2FVMnrn5OpWbxGHo49zd0xdy2mgTdZ9UraLaQnyGlkjYzV0rqHIAIm8HOUjGN5U75/rlOPF0x62FCICZU/z1AgRvugaA5eO8zTSQJiMiBe3AgMBAAGgOTA3BgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEANAXOIkv0CovmdzyoAv1dsiK0TK2XHBdBTEPFDsrT7MnrIXOFS4FnDrg8zpn7QBzBRTl3HaKN8fnpIHkA/6ZRDqaEJq0AeskjxIg9LKDBBx5TEdgPh1CwruRWLlXtrqU7XXQmk0wLIo/kfaDRcTjyJ3yHTEK06mCAaws0sTKlTw2D4pIiDRp8zbLHeSEUX5UKOSGbLSSUY/F2XwgPB8nC2BCD/gkvHRR+dMQSdOCiS9GLwZdYAAyESw6WhmGPjmVbeTRgSt/9//yx3JKQgkFYmpSMLKR2G525M+l1qfku/4b0iMOa4vQjFRj5AXZH0SBpAKtvnFxUpP6P9mTE7+akOQ"
    assert ["DNS:foo1.bar.local"] == csr_san_get(logger, csr)


def test_134_helper_csr_san_get(logger: logging.Logger) -> None:
    """get sans but two sans"""
    csr = "MIICpzCCAY8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMwfxxbCCTsZY8mTFZkoQ5cAJyQZLUiz34sDDRvEpI9ZzdNNm2AEZR7AgKNuBkLwzUzY5iQ182huNzYJYZZEvYX++ocF2ngapTMQgfB+bWS5bpWIdjnAcz1/86jmJgTciwL25dSnEWL17Yn3pAWweoewr730rq/PMyIbviQrasksnSo7abe2mctxkHjHb5sZ+Z1yRTN6ir/bObXmxr+vHeeD2vLRv4Hd5XaA1d+k31J2FVMnrn5OpWbxGHo49zd0xdy2mgTdZ9UraLaQnyGlkjYzV0rqHIAIm8HOUjGN5U75/rlOPF0x62FCICZU/z1AgRvugaA5eO8zTSQJiMiBe3AgMBAAGgSTBHBgkqhkiG9w0BCQ4xOjA4MAsGA1UdDwQEAwIF4DApBgNVHREEIjAggg5mb28xLmJhci5sb2NhbIIOZm9vMi5iYXIubG9jYWwwDQYJKoZIhvcNAQELBQADggEBADeuf4J8Xziw2OuvLNnLOSgHQl2HdMFtRdgJoun7zPobsP3L3qyXLvvhJcQsIJggu5ZepnHGrCxroSbtRSO65GtLQA0Rq3DCGcPIC1fe9AYrqoynx8bWt2Hd+PyDrBppHVoQzj6yNCt6XNSDs04BMtjs9Pu4DD6DDHmxFMVNdHXea2Rms7C5nLQvXgw7yOF3Zk1vEu7Kue7d3zZMhN+HwwrNEA7RGAEzHHlCv5LL4Mw+kf6OJ8nf/WDiLDKEQIh6bnOuB42Y2wUMpzui8Uur0VJO+twY46MvjiVMMBZE3aPJU33eNPAQVC7GinStn+zQIJA5AADdcO8Lk1qdtaDiGp8"
    assert ["DNS:foo1.bar.local", "DNS:foo2.bar.local"] == csr_san_get(logger, csr)


def test_135_helper_csr_san_get(logger: logging.Logger) -> None:
    """get sans but three sans"""
    csr = "MIICtzCCAZ8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMwfxxbCCTsZY8mTFZkoQ5cAJyQZLUiz34sDDRvEpI9ZzdNNm2AEZR7AgKNuBkLwzUzY5iQ182huNzYJYZZEvYX++ocF2ngapTMQgfB+bWS5bpWIdjnAcz1/86jmJgTciwL25dSnEWL17Yn3pAWweoewr730rq/PMyIbviQrasksnSo7abe2mctxkHjHb5sZ+Z1yRTN6ir/bObXmxr+vHeeD2vLRv4Hd5XaA1d+k31J2FVMnrn5OpWbxGHo49zd0xdy2mgTdZ9UraLaQnyGlkjYzV0rqHIAIm8HOUjGN5U75/rlOPF0x62FCICZU/z1AgRvugaA5eO8zTSQJiMiBe3AgMBAAGgWTBXBgkqhkiG9w0BCQ4xSjBIMAsGA1UdDwQEAwIF4DA5BgNVHREEMjAwgg5mb28xLmJhci5sb2NhbIIOZm9vMi5iYXIubG9jYWyCDmZvbzMuYmFyLmxvY2FsMA0GCSqGSIb3DQEBCwUAA4IBAQAQRkub6G4uijaXOYpCkoz40I+SVRsbRDgnMNjsooZz1+7DVglFjrr6Pb0PPTOvOxtmbHP2KK0WokDn4LqOD2t0heuI+KPQy7m/ROpOB/YZOzTWEB8yS4vjkf/RFiJ7fnCAc8vA+3K/mBVb+89F8w/KlyPmpg1GK7UNgjEa5bnznTox8q12CocCJVykPEiC8AT/VPWUOPfg6gs+V6LO8R73VRPMVy0ttYKGX80ob+KczDTMUhoxXg8OG+G+bXXU+4Tu4l+nQWf2lFejECi/vNKzUT90IbcGJwyk7rc4Q7BJ/t/5nMo+vuV9f+2HI7qakHcw6u9RGylL4OYDf1CrqF1R"
    assert [
        "DNS:foo1.bar.local",
        "DNS:foo2.bar.local",
        "DNS:foo3.bar.local",
    ] == csr_san_get(logger, csr)


def test_136_helper_csr_san_get(logger: logging.Logger) -> None:
    """get sans but three sans"""
    csr = "MIIBFjCBvQIBADAYMRYwFAYDVQQDEw1mb28uYmFyLmxvY2FsMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETOQukalTTCD8y7zoAsmxeAWlbi9oZtzh7XQc7A7KF4fZLP3pYjoZG6s+sXCp7bUpKhuIejrDRp1cFE5NlEK8jaBDMEEGCSqGSIb3DQEJDjE0MDIwMAYDVR0RBCkwJ4INZm9vLmJhci5sb2NhbIcEwKgOg4cQ/oAAAAAAAAACFV3//sABAjAKBggqhkjOPQQDAgNIADBFAiBKUb5r/8aSN4/utaDoi0vIcaASVZz8p1nSJ1YWSCkIpAIhAI20iVBu5j0tBmTc3uRzKIYTqsnXpH0UV8bcONy4m1Sa"
    assert [
        "DNS:foo.bar.local",
        "IP:192.168.14.131",
        "IP:fe80::215:5dff:fec0:102",
    ] == csr_san_get(logger, csr)


def test_137_helper_csr_san_byte_get(logger: logging.Logger) -> None:
    """get sans but two sans"""
    csr = "MIICpzCCAY8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMwfxxbCCTsZY8mTFZkoQ5cAJyQZLUiz34sDDRvEpI9ZzdNNm2AEZR7AgKNuBkLwzUzY5iQ182huNzYJYZZEvYX++ocF2ngapTMQgfB+bWS5bpWIdjnAcz1/86jmJgTciwL25dSnEWL17Yn3pAWweoewr730rq/PMyIbviQrasksnSo7abe2mctxkHjHb5sZ+Z1yRTN6ir/bObXmxr+vHeeD2vLRv4Hd5XaA1d+k31J2FVMnrn5OpWbxGHo49zd0xdy2mgTdZ9UraLaQnyGlkjYzV0rqHIAIm8HOUjGN5U75/rlOPF0x62FCICZU/z1AgRvugaA5eO8zTSQJiMiBe3AgMBAAGgSTBHBgkqhkiG9w0BCQ4xOjA4MAsGA1UdDwQEAwIF4DApBgNVHREEIjAggg5mb28xLmJhci5sb2NhbIIOZm9vMi5iYXIubG9jYWwwDQYJKoZIhvcNAQELBQADggEBADeuf4J8Xziw2OuvLNnLOSgHQl2HdMFtRdgJoun7zPobsP3L3qyXLvvhJcQsIJggu5ZepnHGrCxroSbtRSO65GtLQA0Rq3DCGcPIC1fe9AYrqoynx8bWt2Hd+PyDrBppHVoQzj6yNCt6XNSDs04BMtjs9Pu4DD6DDHmxFMVNdHXea2Rms7C5nLQvXgw7yOF3Zk1vEu7Kue7d3zZMhN+HwwrNEA7RGAEzHHlCv5LL4Mw+kf6OJ8nf/WDiLDKEQIh6bnOuB42Y2wUMpzui8Uur0VJO+twY46MvjiVMMBZE3aPJU33eNPAQVC7GinStn+zQIJA5AADdcO8Lk1qdtaDiGp8"
    assert "MCCCDmZvbzEuYmFyLmxvY2Fsgg5mb28yLmJhci5sb2NhbA==" == csr_san_byte_get(
        logger, csr
    )


@patch("acme2certifier.acme_srv.helpers.csr.csr_load")
def test_138_helper_csr_san_get(
    mock_csrload: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """get sans but three sans"""
    csr = "csr"
    mock_csrload.return_value = "mock_csrload"
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert [] == csr_san_get(logger, csr)
    assert (
        "ERROR:test_a2c:Error while getting SANs from CSR: 'str' object has no attribute 'extensions'"
        in lcm.output
    )


def test_139_helper_csr_san_get_email(logger: logging.Logger) -> None:
    """csr_san_get extracts rfc822Name SANs as EMAIL:"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr_obj = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "user@example.com")])
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.RFC822Name("user@example.com"),
                    x509.RFC822Name("other@example.org"),
                    x509.DNSName("foo.example.com"),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    csr = base64.b64encode(csr_obj.public_bytes(serialization.Encoding.DER)).decode()
    assert [
        "DNS:foo.example.com",
        "EMAIL:user@example.com",
        "EMAIL:other@example.org",
    ] == csr_san_get(logger, csr)


def test_140_helper_csr_san_get_email_only(logger: logging.Logger) -> None:
    """csr_san_get with only rfc822Name SANs"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr_obj = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "user@example.com")])
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name("user@example.com")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    csr = base64.b64encode(csr_obj.public_bytes(serialization.Encoding.DER)).decode()
    assert ["EMAIL:user@example.com"] == csr_san_get(logger, csr)


def test_141_helper_csr_bound_names_get_dns_and_cn(logger: logging.Logger) -> None:
    """csr_bound_names_get unions DNS SAN and CN (CN may duplicate SAN)"""
    csr = "MIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMwfxxbCCTsZY8mTFZkoQ5cAJyQZLUiz34sDDRvEpI9ZzdNNm2AEZR7AgKNuBkLwzUzY5iQ182huNzYJYZZEvYX++ocF2ngapTMQgfB+bWS5bpWIdjnAcz1/86jmJgTciwL25dSnEWL17Yn3pAWweoewr730rq/PMyIbviQrasksnSo7abe2mctxkHjHb5sZ+Z1yRTN6ir/bObXmxr+vHeeD2vLRv4Hd5XaA1d+k31J2FVMnrn5OpWbxGHo49zd0xdy2mgTdZ9UraLaQnyGlkjYzV0rqHIAIm8HOUjGN5U75/rlOPF0x62FCICZU/z1AgRvugaA5eO8zTSQJiMiBe3AgMBAAGgOTA3BgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEANAXOIkv0CovmdzyoAv1dsiK0TK2XHBdBTEPFDsrT7MnrIXOFS4FnDrg8zpn7QBzBRTl3HaKN8fnpIHkA/6ZRDqaEJq0AeskjxIg9LKDBBx5TEdgPh1CwruRWLlXtrqU7XXQmk0wLIo/kfaDRcTjyJ3yHTEK06mCAaws0sTKlTw2D4pIiDRp8zbLHeSEUX5UKOSGbLSSUY/F2XwgPB8nC2BCD/gkvHRR+dMQSdOCiS9GLwZdYAAyESw6WhmGPjmVbeTRgSt/9//yx3JKQgkFYmpSMLKR2G525M+l1qfku/4b0iMOa4vQjFRj5AXZH0SBpAKtvnFxUpP6P9mTE7+akOQ=="
    assert {("dns", "foo1.bar.local")} == csr_bound_names_get(logger, csr)


def test_142_helper_csr_bound_names_get_cn_only_email(logger: logging.Logger) -> None:
    """CN-only email CSR yields a single email name (no SAN extension)"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr_obj = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "User@Example.COM")])
        )
        .sign(key, hashes.SHA256())
    )
    csr = base64.b64encode(csr_obj.public_bytes(serialization.Encoding.DER)).decode()
    assert {("email", "user@example.com")} == csr_bound_names_get(logger, csr)


def test_143_helper_csr_bound_names_get_email_san_and_cn(
    logger: logging.Logger,
) -> None:
    """email SAN + matching CN deduplicates; extra email SAN retained"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr_obj = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "user@example.com")])
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.RFC822Name("user@example.com"),
                    x509.RFC822Name("other@example.org"),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    csr = base64.b64encode(csr_obj.public_bytes(serialization.Encoding.DER)).decode()
    assert {
        ("email", "user@example.com"),
        ("email", "other@example.org"),
    } == csr_bound_names_get(logger, csr)


def test_144_helper_csr_bound_names_get_ip_normalize(logger: logging.Logger) -> None:
    """IP SANs are normalized (IPv6 compressed form)"""
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr_obj = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ip-csr")]))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.IPAddress(ipaddress.IPv6Address("2001:db8::1")),
                    x509.IPAddress(ipaddress.IPv4Address("192.0.2.1")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    csr = base64.b64encode(csr_obj.public_bytes(serialization.Encoding.DER)).decode()
    assert {
        ("dns", "ip-csr"),
        ("ip", "2001:db8::1"),
        ("ip", "192.0.2.1"),
    } == csr_bound_names_get(logger, csr)


def test_145_helper_csr_bound_names_get_cn_extra_dns(logger: logging.Logger) -> None:
    """CN distinct from SANs is retained as dns"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr_obj = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cn.example.com")])
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("san.example.com")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    csr = base64.b64encode(csr_obj.public_bytes(serialization.Encoding.DER)).decode()
    assert {
        ("dns", "cn.example.com"),
        ("dns", "san.example.com"),
    } == csr_bound_names_get(logger, csr)


def test_146_helper_csr_bound_names_get_empty(logger: logging.Logger) -> None:
    """empty/missing CSR yields empty set"""
    assert set() == csr_bound_names_get(logger, None)
    assert set() == csr_bound_names_get(logger, "")


def test_147_helper_csr_bound_names_get_email_rewrite(logger: logging.Logger) -> None:
    """email_identifier_rewrite collapses DNS+EMAIL SANs with @ to email"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr_obj = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "jum@mailserver.acme")])
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("jum@mailserver.acme"),
                    x509.RFC822Name("jum@mailserver.acme"),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    csr = base64.b64encode(csr_obj.public_bytes(serialization.Encoding.DER)).decode()
    assert {
        ("dns", "jum@mailserver.acme"),
        ("email", "jum@mailserver.acme"),
    } == csr_bound_names_get(logger, csr)
    assert {("email", "jum@mailserver.acme")} == csr_bound_names_get(
        logger, csr, email_identifier_rewrite=True
    )


def test_148_helper_csr_extensions_get(logger: logging.Logger) -> None:
    """get sns in hex"""
    csr = "MIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMwfxxbCCTsZY8mTFZkoQ5cAJyQZLUiz34sDDRvEpI9ZzdNNm2AEZR7AgKNuBkLwzUzY5iQ182huNzYJYZZEvYX++ocF2ngapTMQgfB+bWS5bpWIdjnAcz1/86jmJgTciwL25dSnEWL17Yn3pAWweoewr730rq/PMyIbviQrasksnSo7abe2mctxkHjHb5sZ+Z1yRTN6ir/bObXmxr+vHeeD2vLRv4Hd5XaA1d+k31J2FVMnrn5OpWbxGHo49zd0xdy2mgTdZ9UraLaQnyGlkjYzV0rqHIAIm8HOUjGN5U75/rlOPF0x62FCICZU/z1AgRvugaA5eO8zTSQJiMiBe3AgMBAAGgOTA3BgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEANAXOIkv0CovmdzyoAv1dsiK0TK2XHBdBTEPFDsrT7MnrIXOFS4FnDrg8zpn7QBzBRTl3HaKN8fnpIHkA/6ZRDqaEJq0AeskjxIg9LKDBBx5TEdgPh1CwruRWLlXtrqU7XXQmk0wLIo/kfaDRcTjyJ3yHTEK06mCAaws0sTKlTw2D4pIiDRp8zbLHeSEUX5UKOSGbLSSUY/F2XwgPB8nC2BCD/gkvHRR+dMQSdOCiS9GLwZdYAAyESw6WhmGPjmVbeTRgSt/9//yx3JKQgkFYmpSMLKR2G525M+l1qfku/4b0iMOa4vQjFRj5AXZH0SBpAKtvnFxUpP6P9mTE7+akOQ"
    assert ["AwIF4A==", "MBCCDmZvbzEuYmFyLmxvY2Fs"] == csr_extensions_get(logger, csr)


def test_149_helper_csr_extensions_get(logger: logging.Logger) -> None:
    """get tnauth identifier"""
    csr = "MIICuzCCAaMCAQAwHjEcMBoGA1UEAwwTY2VydC5zdGlyLmJhci5sb2NhbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALsLm4zgkl2lEx2EHy1ENfh3cYB79Xb5sD3ehkY+1pXphIWoM9KYVqHKOurModjsh75YjRBSilRfTFSk6kCUahTJyeCbM6Vzl75CcZy7poUxiK+u80JMU/xymUsrqY4GZlh2/XtFMxXHUSf3bhKZAIjBNugsvR/sHtEvJ6RJiuYqHMWUzZ/Vby5L0ywNl+LPSY7AVTUAZ0lKrnUCP4dHnbjwjf+nPi7vT6G0yrEg0qPOYXtJOXdf7vvjLi8J+ap758NtG2qapLdbToIPr0uOEvMO6zs8z1bIyjOHU3kzlpKHzDsPYy8txxKC/3Rae7sKB9gWm8WUxFBmuA7gaFDGQAECAwEAAaBYMFYGCSqGSIb3DQEJDjFJMEcwCwYDVR0PBAQDAgXgMB4GA1UdEQQXMBWCE2NlcnQuc3Rpci5iYXIubG9jYWwwGAYIKwYBBQUHARoEDDAKoAgWBjEyMzQ1NjANBgkqhkiG9w0BAQsFAAOCAQEAjyhJfgb/zJBMYp6ylRtEXgtBpsX9ePUL/iLgIDMcGtwaFm3pkQOSBr4xiTxftnqN77SlC8UEu7PDR73JX6iqLNJWucPlhAXVrr367ygO8GGLrtGddClZmo0lhRBRErgpagWB/jFkbL8afPGJwgQQXF0KWFMcajAPiIl1l6M0w11KqJ23Pwrmi7VJHzIgh4ys0D2UrX7KuV4PIOOmG0s7jTfBSB+yUH2zwVzOAzbr3wrD1WubD7hRaHDUi4bn4DRbquQOzbqfTI6QhetUcNpq4DwhBRcnZwUMJUIcxLAsFnDgGSW+dmJe6JH8MsS+8ZmOLllyQxWzYEVquQQvxFVTZA"
    assert [
        "AwIF4A==",
        "MBWCE2NlcnQuc3Rpci5iYXIubG9jYWw=",
        "MAqgCBYGMTIzNDU2",
    ] == csr_extensions_get(logger, csr)


def test_215_csr_dn_get(logger: logging.Logger) -> None:
    """ " test csr_dn_get"""
    csr = "MIICjDCCAXQCAQAwFzEVMBMGA1UEAwwMdGVzdF9yZXF1ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy6VRYaXuLS/DPa+pf5IEwycpjPfZ2vTFlvjvhwu9A3yaQQn4kD33Fu4p+zorIVmsjgpkUel2104lxFeSV081YKGzOtsajzaIRZhF7mHG5aVA8cahVPHlnxT06kO8F545ZsxE6T22tCbrLJpZk4hcaQUmGcZDWZqI7CXhbi1LSuIVIAAF0lTGMsanIM97ZEtA9mhtxFd7TsLlJpmls1l8MTavFcBtAZXqAsi4LnzEbozSjaLnuXsTe7tPmOS0uOLX+EcTAH/SxkbIg3whehTzC/sVmz5STbpklq3QuudtUl/509fpSa/UQ+WFOUUC3GhiiMM813ZsbAnt1BJepKtrfQIDAQABoDAwLgYJKoZIhvcNAQkOMSEwHzAdBgNVHREEFjAUghJ0ZXN0X3JlcXVlc3QubG9jYWwwDQYJKoZIhvcNAQELBQADggEBAFcKxjJXHBVjzqF3e6fCkDbF1JnVtNyDxZB+h4b5lI7SIuA9O/+0hcl/njeFB1gJbRODws10kKkiAYLXvS/fsLJg1gdyFPmDiCd2nJhDUCBcGmVYraGhV45x67jcUmoeqSSj5KyUY9zI+v3nANvZMf+g31ORtW8PuspkiiLJiyuGzFS67DGovbcBRrM67IApO7p04VwLA0hssFUa+wF9PUWIyu9TLx+w0rNYcp3d1wkJ905TB8gwOKXeB0RwkporlOF3KEcT+ueKZE04867bjZ/ZpiuIDFnO23MsUKLKU9ebWgwYN/xzxA8sroM69y+Acpt9Zwn3vRjVlT92Ztl218Q="
    assert "CN=test_request" == csr_dn_get(logger, csr)


def test_445_csr_subject_get(logger: logging.Logger) -> None:
    """test csr_subject_get()"""
    csr = "MIICwDCCAagCAQAwVDESMBAGA1UEAwwJbGVnby5hY21lMQ0wCwYDVQQKDARhY21lMQwwCgYDVQQLDANmb28xCzAJBgNVBAYTAlVTMRQwEgYDVQQFEwswMC0xMS0yMi0zMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM5AKMmB3o8LLEEGuHo0Ipl4K8z9m3EyM9teSVocQz39DK8s2dKpx8MrsVkTg6M3fuL4yPlim8v0+unPtB18dFeThkijHetxL5x08pVvMVwa7Cjk/22e5IRgBGSQYCO6KCUsNh2vhH93r7x71wlTV3sYe2t0HaEdGqBxdct76J9kyeCY06Br+4PMR7afRvHv4vFH6Y2+hSD4oOd5cSTZXnNWcWRbjNFY7aytzl4JpJiEK0ealDMSf/ZP0n8Sdx1vCx8amaozrLg5z3eLULiAUUgCtqOWOgNLQFNSqjyhZmMTZGGJcTgb43KAKWsO3bfM6rvNTZRbrM7dAsg/bQsK6mMCAwEAAaAnMCUGCSqGSIb3DQEJDjEYMBYwFAYDVR0RBA0wC4IJbGVnby5hY21lMA0GCSqGSIb3DQEBCwUAA4IBAQA19j8Lge9Vqxc/hvWYcU1Kx3KBx5TN97PK0wQFPIIWX20/JRoodzfrMSqO0EgZWB+czoRi8G+2ezbK13sV02dKovo8ISoSvgSZtt53UKBz+JmQd7Q7G1vONZ7d2PT0nTUN4fTA5YQs5nys3O8/2oOxJiJO6IyhmpiVqUbrlU6Harb4MfjNTb+teSQRSCOAX/8U9TdPwuAi6rXdWjXAUxBDQySWkW/B3pd77Ztt5nDFP2DT+7f7mAoWG4+XY6iXcXs1GsDA4XRTx2rCvhQtQomVGAKFwd8aTpHL/ZwNt1GOw6oMZkKKf+axVA1pvAYGhey/4x3uwKf654VB3e2iOCea"
    result_dic = {
        "commonName": "lego.acme",
        "organizationName": "acme",
        "organizationalUnitName": "foo",
        "countryName": "US",
        "serialNumber": "00-11-22-33",
    }
    assert result_dic == csr_subject_get(logger, csr)


def test_446_csr_subject_get(logger: logging.Logger) -> None:
    """test csr_subject_get()"""
    csr = "MIICtjCCAZ4CAQAwQjELMAkGA1UEBhMCREUxDjAMBgNVBAoMBXRlc3RPMQ8wDQYDVQQLDAZ0ZXN0T1UxEjAQBgNVBGEMCTEyMzQ1NjctODCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALs0a3qYQOIkpuRa34QEb+j9PzkMC8eA8bT9icRnpd1DO5LyQjc0OreV8ed3YeV1IVtcf1qX4AYKdIb1X1qa1pFkcneFZsX6B1i/ofRqEXrsN243V4LTjHFwIqwIecFX/Ml9rhCV+/tRTBrl3XIyI2xhZ4qtxIWkavmrvhNy4gY0YBjw4D67NzDJ9gm9Nx8VFzGZxXP0MgOtLOJ7BMCcqJmBwdItaotFCCkQfXC6S+n9sLP3GYrgyShaXMAebYmkNPZ4YJ0H28VfBGcWF2hpmSBgZ15Bj5P3PNYAnAocCUkwcifk3CZoJwcmC1Fm2mC8zOAEQ+GA/KqM6RHmMMKHexECAwEAAaAvMC0GCSqGSIb3DQEJDjEgMB4wHAYDVR0RBBUwE4IRYWNtZS1jbGllbnQubG9jYWwwDQYJKoZIhvcNAQELBQADggEBAB6HE9CMFKvyM4kwmKKeAoXzLhILTWmjDgI1+wBEq781CqXS3/rhTRYxFCjaU4WUFSHFUOo4+qlehwQzFRBLwEdgIylKXVT7etuto9lHU7xpf+wRth3c/PF/DsibC3S+fzlA7UBgxvhO0FbuqnV4pUUp/Y/jsaB4+IWhnwySh+378A98VkLU/1muSaM5AS9rboYyFPtevWzeSZJtz7CLAK2zWJ95ApOIBXHQdm6wsgJzwTTW1apXofNTX5AM6L0TPdieiPKUHPpH2AJZjzCVX9NuhDhLL5klzYwIrvcD2bxGy+xNWAYxXyLhPkGG8F954FAFa66sqiQBlmU92ndtG3Q="
    result_dic = {
        "organizationIdentifier": "1234567-8",
        "organizationName": "testO",
        "organizationalUnitName": "testOU",
        "countryName": "DE",
    }
    assert result_dic == csr_subject_get(logger, csr)


def test_447_csr_subject_get(logger: logging.Logger) -> None:
    """test csr_subject_get()"""
    csr = "MIICcDCCAVgCAQAwADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANOKk0E61QJ2K/NiGSO0aJyqrLfmHytPr35ptLwNdfKQ/8Vb2uoHYAvxVEO9weNTQVlZ9ApkJquBTRoSdqTy6p87inh8JwzFM/neJAsMg2ZiH3gRRRfmIb/4Kce0BUQ66DFSV8sWThyv13EcL+pZYdqRvONujVn7XVPbmB2ZI8qI4iXswRq45mFBW5Dyt3Rlw+KOBu1ejo0lqB2FGQiBONxQrFDyF4nVWN3R9BlhuybSF4Elhos7pkiEfrE+8EzYy+7yMEiDh1m+TmwZRNEdtSWNORF51CF3bYUz8pvpt66vKGi/F6k2iljelw1kNsswZAciNi2jG7S0M+MWMFi680sCAwEAAaArMCkGCSqGSIb3DQEJDjEcMBowGAYDVR0RBBEwD4INZm9vLmJhci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEAivCrcL+uVzDdykT87073atC4B2DHky5bzL+iI8C+BkPq0jRdcVkExMrUtTdtp8Ot1zQHtYc/c/Tj+aYDZ6SdMYtrtHUgxS5JyFh0p+MEvkgZHcWOVC+VlWA+lC9kdX3WetsGT6xqCG4l+BpgCUERghFJ5/+K0bbCI4jT/5ZCT7+pO0qZtw0eg6tQBLPSXzXN98x3nmuaw9PzO1rVG5IMItyU+TlX3pJRXKpqSOHEbeaGWHizMUlbDKzoIiUf+11I9RwTeLlp/HPG8uvRc/zZ1einZPLQgow5kU15jFQSgQtzFHV4ZxuYmWN7oMIruwBNP1hkoTNL1kJcPeOwtEdOMw=="
    assert not csr_subject_get(logger, csr)


@patch("acme2certifier.acme_srv.helpers.csr.csr_san_get")
@patch("acme2certifier.acme_srv.helpers.csr.csr_cn_get")
def test_459_csr_cn_lookup(
    mock_cnget: MagicMock, mock_san_get: MagicMock, logger: logging.Logger
) -> None:
    """test _csr_cn_lookup()"""
    mock_cnget.return_value = "cn"
    mock_san_get.return_value = ["foo:san1", "foo:san2"]
    assert "cn" == csr_cn_lookup(logger, "csr")


@patch("acme2certifier.acme_srv.helpers.csr.csr_san_get")
@patch("acme2certifier.acme_srv.helpers.csr.csr_cn_get")
def test_460_csr_cn_lookup(
    mock_cnget: MagicMock, mock_san_get: MagicMock, logger: logging.Logger
) -> None:
    """test _csr_cn_lookup()"""
    mock_cnget.return_value = None
    mock_san_get.return_value = ["foo:san1", "foo:san2"]
    assert "san1" == csr_cn_lookup(logger, "csr")


@patch("acme2certifier.acme_srv.helpers.csr.csr_san_get")
@patch("acme2certifier.acme_srv.helpers.csr.csr_cn_get")
def test_461_csr_cn_lookup(
    mock_cnget: MagicMock,
    mock_san_get: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """test _csr_cn_lookup()"""
    mock_cnget.return_value = None
    mock_san_get.return_value = ["foosan1", "foo:san2"]
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert "san2" == csr_cn_lookup(logger, "csr")
    assert "ERROR:test_a2c:SAN split failed: list index out of range" in lcm.output


@patch("acme2certifier.acme_srv.helpers.csr.csr_san_get")
@patch("acme2certifier.acme_srv.helpers.csr.csr_cn_get")
def test_462_csr_cn_lookup(
    mock_cnget: MagicMock,
    mock_san_get: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """test _csr_cn_lookup()"""
    mock_cnget.return_value = None
    mock_san_get.return_value = None
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert not csr_cn_lookup(logger, "csr")
    assert "ERROR:test_a2c:No SANs found in CSR" in lcm.output


def test_661_normalize_bound_name_empty_and_invalid_ip() -> None:
    """_normalize_bound_name handles empty values and invalid IP strings"""
    from acme2certifier.acme_srv.helpers.csr import _normalize_bound_name

    assert _normalize_bound_name("", "value") is None
    assert _normalize_bound_name("dns", None) is None
    assert _normalize_bound_name("dns", "") is None
    assert ("ip", "not-an-ip") == _normalize_bound_name("ip", "not-an-ip")


def test_662_cn_bound_type_ip() -> None:
    """_cn_bound_type returns ip for parseable IP common names"""
    from acme2certifier.acme_srv.helpers.csr import _cn_bound_type

    assert "ip" == _cn_bound_type("192.0.2.1")
    assert "email" == _cn_bound_type("a@b.c")
    assert "dns" == _cn_bound_type("example.com")


def test_663_san_list_to_bound_names(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """san_list_to_bound_names converts and skips malformed entries"""
    from acme2certifier.acme_srv.helpers.csr import san_list_to_bound_names

    with capture_logs("test_a2c", level="ERROR") as lcm:
        result = san_list_to_bound_names(
            logger, ["DNS:foo.example.com", "bad", "IP:192.0.2.1", "EMAIL:a@b.c"]
        )
    assert {
        ("dns", "foo.example.com"),
        ("ip", "192.0.2.1"),
        ("email", "a@b.c"),
    } == result
    assert any(("Error while splitting SAN bad" in msg for msg in lcm.output))


def test_664_csr_bound_names_get_malformed_san(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """csr_bound_names_get skips malformed SAN strings from csr_san_get"""
    with (
        patch(
            "acme2certifier.acme_srv.helpers.csr.csr_san_get",
            return_value=["malformed"],
        ),
        patch("acme2certifier.acme_srv.helpers.csr.csr_cn_get", return_value=None),
    ):
        with capture_logs("test_a2c", level="ERROR") as lcm:
            result = csr_bound_names_get(logger, "dummy-csr")
    assert set() == result
    assert any(("Error while splitting SAN malformed" in msg for msg in lcm.output))
