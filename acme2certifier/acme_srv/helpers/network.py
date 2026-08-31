# -*- coding: utf-8 -*-
"""Network utilities for acme2certifier"""

import html
import ipaddress
import socket
import ssl
import logging
import json
import re
import time
from typing import List, Dict, Tuple, Union, Optional
from urllib.parse import urlparse, quote
from urllib3.util import connection
import socks
import dns.resolver
import requests
from .config import load_config
from .validation import ipv6_chk
from .encoding import convert_string_to_byte, b64_encode
from .global_variables import USER_AGENT

# Backward-compatible alias used by existing tests that patch this symbol.
urllib3_cn = connection


def _caaidentities_parse(logger: logging.Logger, value: str) -> List[str]:
    """Parse caaidentities from JSON list or comma-separated string."""
    if not value:
        return []
    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return [str(item).strip() for item in parsed if str(item).strip()]
    except Exception:
        logger.debug("Error parsing caaidentities as json: %s", value)
    return [item.strip() for item in value.split(",") if item.strip()]


def configured_server_name_get(config_dic) -> Optional[str]:
    """Return configured server_name from DEFAULT or Directory section."""
    server_name = config_dic.get("DEFAULT", "server_name", fallback=None)
    if server_name and str(server_name).strip():
        return str(server_name).strip()
    server_name = config_dic.get("Directory", "server_name", fallback=None)
    if server_name and str(server_name).strip():
        return str(server_name).strip()
    return None


def server_name_configuration_validate(logger: logging.Logger, config_dic) -> None:
    """Emit startup warnings for server_name fallback and CAA alignment."""
    server_name = configured_server_name_get(config_dic)
    if not server_name:
        logger.warning(
            "No [DEFAULT] server_name configured; deriving server URL from request "
            "headers. This is not recommended for production."
        )
        return

    caa_raw = config_dic.get("Directory", "caaidentities", fallback=None)
    caaidentities = _caaidentities_parse(logger, caa_raw) if caa_raw else []
    if caaidentities and server_name not in caaidentities:
        logger.warning(
            "Configured server_name '%s' is not listed in Directory.caaidentities %s",
            server_name,
            caaidentities,
        )


def _handle_dns_exception(
    logger: logging.Logger,
    host: str,
    rrtype: str,
    error: Exception,
    errors_encountered: List[str],
) -> None:
    """Handle DNS resolution exceptions and log them appropriately"""
    error_mappings = {
        dns.resolver.NXDOMAIN: f"NXDOMAIN: {host} does not exist",
        dns.resolver.NoAnswer: f"No {rrtype} record found for {host}",
        dns.resolver.Timeout: f"DNS query timeout for {host}",
    }

    error_detail = error_mappings.get(
        type(error), f"DNS resolution error: {str(error)}"
    )

    logger.debug("Error resolving %s with type %s: %s", host, rrtype, error_detail)
    errors_encountered.append(f"{rrtype}: {error_detail}")


def _process_dns_answers(
    logger: logging.Logger,
    answers: dns.resolver.Answer,
    catch_all: bool,
    result: Union[List[str], None],
) -> Tuple[Union[str, List[str], None], bool]:
    """Process DNS resolution answers and return appropriate result"""
    logger.debug("Helper._fqdn_resolve() got answer: %s", list(answers))
    resolved = [str(rdata) for rdata in answers]

    if not resolved:
        return result, True  # No answers found, keep searching

    if catch_all:
        if isinstance(result, list):
            result.extend(resolved)
        return result, False  # Found answers, mark as valid
    else:
        return resolved[0], False  # Return first answer and mark as valid


def _fqdn_resolve(
    logger: logging.Logger,
    req: dns.resolver.Resolver,
    host: str,
    catch_all: bool = False,
) -> Tuple[Union[str, List[str], None], bool, Optional[str]]:
    """resolve hostname with detailed error reporting"""
    logger.debug("Helper._fqdn_resolve(%s:%s)", host, catch_all)

    result = [] if catch_all else None
    invalid = True
    errors_encountered = []

    for rrtype in ["A", "AAAA"]:
        try:
            answers = req.resolve(host, rrtype)
            temp_result, temp_invalid = _process_dns_answers(
                logger, answers, catch_all, result
            )

            if not temp_invalid:  # Only update if we got valid results
                result = temp_result
                invalid = False
                if not catch_all:
                    break  # Early exit for non-catch-all successful resolution
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.Timeout,
            Exception,
        ) as err:
            _handle_dns_exception(logger, host, rrtype, err, errors_encountered)

    # Combine errors if resolution failed
    error_msg = (
        "; ".join(errors_encountered) if invalid and errors_encountered else None
    )

    logger.debug(
        "Helper._fqdn_resolve(%s) ended with: %s, %s, error: %s",
        host,
        result,
        invalid,
        error_msg,
    )
    return (result, invalid, error_msg)


def fqdn_resolve(
    logger: logging.Logger, host: str, dnssrv: List[str] = None, catch_all: bool = False
) -> Tuple[Union[str, List[str], None], bool, Optional[str]]:
    """dns resolver with error reporting"""
    logger.debug("Helper.fqdn_resolve(%s catch_all: %s)", host, catch_all)
    req = dns.resolver.Resolver()

    if dnssrv:
        # add specific dns server
        req.nameservers = dnssrv
    # resolve hostname (including short/unqualified names)
    result, invalid, error_msg = _fqdn_resolve(logger, req, host, catch_all=catch_all)

    logger.debug(
        "Helper.fqdn_resolve(%s) ended with: %s, %s, error: %s",
        host,
        result,
        invalid,
        error_msg,
    )
    return (result, invalid, error_msg)


def ptr_resolve(
    logger: logging.Logger, ip_address: str, dnssrv: List[str] = None
) -> Tuple[str, bool]:
    """reverse dns resolver"""
    logger.debug("Helper.ptr_resolve(%s)", ip_address)
    req = dns.resolver.Resolver()
    invalid = True

    if dnssrv:
        # add specific dns server
        req.nameservers = dnssrv
    try:
        reversed_dns = dns.reversename.from_address(ip_address)
        answers = req.resolve(reversed_dns, "PTR")
        result = str(answers[0])[:-1]  # remove trailing dot
        invalid = False
    except Exception as err:
        logger.debug("Error while resolving %s: %s", ip_address, err)
        result = None

    logger.debug("Helper.ptr_resolve(%s) ended with: %s", ip_address, result)
    return result, invalid


def dns_server_list_load() -> List[str]:
    """load dns-server from config file"""
    config_dic = load_config()

    # define default dns servers
    default_dns_server_list = ["9.9.9.9", "8.8.8.8"]  # NOSONAR

    if "Challenge" in config_dic:
        if "dns_server_list" in config_dic["Challenge"]:
            try:
                dns_server_list = json.loads(config_dic["Challenge"]["dns_server_list"])
            except Exception:
                dns_server_list = default_dns_server_list
        else:
            dns_server_list = default_dns_server_list
    else:
        dns_server_list = default_dns_server_list

    return dns_server_list


def patched_create_connection(address: List[str], *args, **kwargs):  # pragma: no cover
    """Wrap urllib3's create_connection to resolve the name elsewhere"""
    # load dns-servers from config file
    dns_server_list = dns_server_list_load()
    # resolve hostname to an ip address; use your own resolver
    host, port = address
    hostname, _invalid, _error = fqdn_resolve(host, dns_server_list)
    # pylint: disable=W0212
    return connection._orig_create_connection((hostname, port), *args, **kwargs)


def proxy_check(
    logger: logging.Logger, fqdn: str, proxy_server_list: Dict[str, str]
) -> str:
    """check proxy server"""
    logger.debug("Helper.proxy_check(%s)", fqdn)

    # remove leading *.
    proxy_server_list_new = {
        k.replace("*.", ""): v for k, v in proxy_server_list.items()
    }

    proxy = None
    for regex in sorted(proxy_server_list_new.keys(), reverse=True):
        if regex != "*":
            regex_compiled = re.compile(regex)
            if bool(regex_compiled.search(fqdn)):
                # parameter is in - set flag accordingly and stop loop
                proxy = proxy_server_list_new[regex]
                logger.debug(
                    "Helper.proxy_check() match found: fqdn: %s, regex: %s", fqdn, regex
                )
                break

    if "*" in proxy_server_list_new and not proxy:
        logger.debug("Helper.proxy_check() wildcard match found: fqdn: %s", fqdn)
        proxy = proxy_server_list_new["*"]

    logger.debug("Helper.proxy_check() ended with %s", proxy)
    return proxy


def url_get_with_own_dns(
    logger: logging.Logger, url: str, verify: bool = True
) -> Tuple[Optional[str], int, Optional[str]]:
    """request by using an own dns resolver"""
    logger.debug("Helper.url_get_with_own_dns(%s)", url)
    # patch an own connection handler into URL lib
    # pylint: disable=W0212
    connection._orig_create_connection = connection.create_connection
    connection.create_connection = patched_create_connection
    try:
        req = requests.get(
            url,
            verify=verify,
            headers={
                "Connection": "close",
                "Accept-Encoding": "gzip",
                "User-Agent": USER_AGENT,
            },
            timeout=20,
        )
        result = req.text
        status_code = req.status_code
        if status_code != 200:
            error_msg = f"{url} {req.reason}"
        else:
            error_msg = None
    except Exception as err_:
        result = None
        status_code = 500
        error_msg = (
            f"Could not get URL by using the configured DNS servers: {str(err_)}"
        )
        logger.error(error_msg)
    # cleanup
    connection.create_connection = connection._orig_create_connection
    return result, status_code, error_msg


def allowed_gai_family():
    """set family"""
    family = socket.AF_INET  # force IPv4
    return family


def url_get_with_default_dns(
    logger: logging.Logger,
    url: str,
    proxy_list: Dict[str, str],
    verify: bool,
    timeout: int,
) -> Tuple[Optional[str], int, Optional[str]]:
    """http get with default dns server"""
    logger.debug(
        "Helper.url_get_with_default_dns(%s) vrf=%s, timout:%s", url, verify, timeout
    )

    # we need to tweak headers and url for ipv6 addresse
    headers, url = v6_adjust(logger, url)
    try:
        req = requests.get(
            url, verify=verify, timeout=timeout, headers=headers, proxies=proxy_list
        )
        result = req.text
        status_code = req.status_code
        if status_code != 200:
            error_msg = f"{url} {req.reason}"
        else:
            error_msg = None

    except Exception as err_:
        logger.debug("Helper.url_get_with_default_dns(%s): error", err_)
        # force fallback to ipv4
        logger.debug("Helper.url_get_with_default_dns(%s): fallback to v4", url)
        old_gai_family = urllib3_cn.allowed_gai_family
        try:
            urllib3_cn.allowed_gai_family = allowed_gai_family
            req = requests.get(
                url,
                verify=verify,
                timeout=timeout,
                headers={
                    "Connection": "close",
                    "Accept-Encoding": "gzip",
                    "User-Agent": USER_AGENT,
                },
                proxies=proxy_list,
            )
            result = req.text
            status_code = req.status_code
            if status_code != 200:
                error_msg = f"{url} {req.reason}"
            else:
                error_msg = None
        except requests.exceptions.ReadTimeout as _errex:
            logger.debug("Helper.url_get_with_default_dns(%s): read timeout", url)
            result = None
            status_code = 500
            error_msg = f"Could not fetch URL: {url} - Read timeout."
            logger.error(error_msg)
        except requests.exceptions.ConnectionError as _errex:
            logger.debug("Helper.url_get_with_default_dns(%s): connection error", url)
            result = None
            status_code = 500
            error_msg = f"Could not fetch URL: {url} - Connection error."
            logger.error(error_msg)
        except Exception as err:
            logger.debug("Helper.url_get_with_default_dns(%s): other error", url)
            result = None
            status_code = 500
            error_msg = f"Could not fetch URL: {url}"
            logger.error(err)  # NOSONAR

        urllib3_cn.allowed_gai_family = old_gai_family

    return result, status_code, error_msg


def url_get(
    logger: logging.Logger,
    url: str,
    dns_server_list: List[str] = None,
    proxy_server=None,
    verify=True,
    timeout=20,
) -> Tuple[Optional[str], int, Optional[str]]:
    """http get with enhanced error reporting"""
    logger.debug("Helper.url_get(%s) vrf=%s, timout:%s", url, verify, timeout)
    # pylint: disable=w0621
    # configure proxy servers if specified
    if proxy_server:
        proxy_list = {"http": proxy_server, "https": proxy_server}
    else:
        proxy_list = {}
    if dns_server_list and not proxy_server:
        result, status_code, error_msg = url_get_with_own_dns(logger, url, verify)
    else:
        result, status_code, error_msg = url_get_with_default_dns(
            logger, url, proxy_list, verify, timeout
        )

    logger.debug(
        "Helper.url_get() ended with status: %s, error: %s", status_code, error_msg
    )
    return result, status_code, error_msg


def normalize_resolved_ips(
    resolved: Union[str, List[str], None],
) -> List[str]:
    """Normalize fqdn_resolve output to a list of IP strings."""
    if resolved is None:
        return []
    if isinstance(resolved, str):
        return [resolved] if resolved else []
    return [ip for ip in resolved if ip]


def filter_http01_target_ips(
    logger: logging.Logger,
    ips: List[str],
    block_private: bool = False,
) -> Tuple[List[str], Optional[str]]:
    """Filter candidate IPs for HTTP-01 fetches.

    Default (block_private=False): keep all parseable addresses (enterprise-friendly).
    Strict (block_private=True): keep only global (public) addresses.
    IPv4 addresses are preferred over IPv6 for connection attempts.
    """
    logger.debug(
        "Helper.filter_http01_target_ips(block_private=%s): %s", block_private, ips
    )
    allowed_v4: List[str] = []
    allowed_v6: List[str] = []
    for ip_str in ips:
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            logger.debug(
                "Helper.filter_http01_target_ips(): skipping invalid IP %s", ip_str
            )
            continue
        if block_private and not addr.is_global:
            logger.debug(
                "Helper.filter_http01_target_ips(): rejecting non-global IP %s", ip_str
            )
            continue
        if isinstance(addr, ipaddress.IPv4Address):
            allowed_v4.append(str(addr))
        else:
            allowed_v6.append(str(addr))

    allowed = allowed_v4 + allowed_v6
    if not allowed:
        error_msg = "No allowed address for HTTP-01 validation"
        logger.debug("Helper.filter_http01_target_ips() ended with: %s", error_msg)
        return [], error_msg

    logger.debug("Helper.filter_http01_target_ips() ended with: %s", allowed)
    return allowed, None


def _pinned_create_connection(pinned_ip: str):
    """Return a create_connection that dials ``pinned_ip`` instead of resolving.

    Same monkey-patch style as ``patched_create_connection`` / ``url_get_with_own_dns``.
    """

    def _create_connection(address, *args, **kwargs):
        _hostname, port = address
        # pylint: disable=W0212
        return connection._orig_create_connection((pinned_ip, port), *args, **kwargs)

    return _create_connection


def url_get_dns_pinned(
    logger: logging.Logger,
    host: str,
    path: str,
    pinned_ips: List[str],
    verify: bool = True,
    timeout: int = 20,
) -> Tuple[Optional[str], int, Optional[str]]:
    """HTTP GET using a hostname URL while forcing the TCP peer to a pinned IP.

    Keeps ``http://<host>/...`` in the request (normal Host / ingress behavior)
    and overrides urllib3 ``create_connection`` so the socket connects to a
    pre-resolved address without a second DNS lookup (rebinding mitigation).
    """
    logger.debug(
        "Helper.url_get_dns_pinned(host=%s, path=%s, ips=%s)", host, path, pinned_ips
    )
    if not path.startswith("/"):
        path = f"/{path}"

    try:
        host_addr = ipaddress.ip_address(host)
        url_host = f"[{host}]" if isinstance(host_addr, ipaddress.IPv6Address) else host
    except ValueError:
        url_host = host

    url = f"http://{url_host}{path}"
    headers = {
        "Connection": "close",
        "Accept-Encoding": "gzip",
        "User-Agent": USER_AGENT,
    }

    last_error: Optional[str] = "No pinned IP addresses provided"
    last_status = 500
    for ip_str in pinned_ips:
        try:
            ipaddress.ip_address(ip_str)
        except ValueError:
            last_error = f"Invalid pinned IP: {ip_str}"
            continue

        # pylint: disable=W0212
        connection._orig_create_connection = connection.create_connection
        connection.create_connection = _pinned_create_connection(ip_str)
        try:
            req = requests.get(
                url,
                verify=verify,
                timeout=timeout,
                headers=headers,
                proxies={},
            )
            result = req.text
            status_code = req.status_code
            if status_code != 200:
                error_msg = f"{url} {req.reason}"
            else:
                error_msg = None
            logger.debug(
                "Helper.url_get_dns_pinned() connected via %s status=%s",
                ip_str,
                status_code,
            )
            return result, status_code, error_msg
        except requests.exceptions.ReadTimeout:
            last_status = 500
            last_error = f"Could not fetch URL via pinned IP {ip_str} - Read timeout."
            logger.error(last_error)
        except requests.exceptions.ConnectionError:
            last_status = 500
            last_error = (
                f"Could not fetch URL via pinned IP {ip_str} - Connection error."
            )
            logger.error(last_error)
        except Exception as err:
            last_status = 500
            last_error = f"Could not fetch URL via pinned IP {ip_str}: {err}"
            logger.error(last_error)
        finally:
            connection.create_connection = connection._orig_create_connection

    logger.debug(
        "Helper.url_get_dns_pinned() ended with status: %s, error: %s",
        last_status,
        last_error,
    )
    return None, last_status, last_error


def txt_get(logger: logging.Logger, fqdn: str, dns_srv: List[str] = None) -> List[str]:
    """dns query to get the TXt record"""
    logger.debug("Helper.txt_get(%s: %s)", fqdn, dns_srv)

    # rewrite dns resolver if configured
    if dns_srv:
        logger.debug("Helper.txt_get(): use custom dns servers: %s", dns_srv)
        dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
        dns.resolver.default_resolver.nameservers = dns_srv
    txt_record_list = []
    try:
        response = dns.resolver.resolve(fqdn, "TXT")
        for rrecord in response:
            txt_record_list.append(rrecord.strings[0])
    except Exception as err_:
        logger.error("Could not get TXT record: %s", err_)  # NOSONAR
    logger.debug("Helper.txt_get() ended with: %s", txt_record_list)
    return txt_record_list


def proxystring_convert(
    logger: logging.Logger, proxy_server: str
) -> Tuple[str, str, str]:
    """convert proxy string"""
    logger.debug("Helper.proxystring_convert(%s)", proxy_server)

    proxy_proto_dic = {
        "http": socks.PROXY_TYPE_HTTP,
        "socks4": socks.PROXY_TYPE_SOCKS4,
        "socks5": socks.PROXY_TYPE_SOCKS5,
    }
    try:
        proxy_proto, proxy = proxy_server.split("://")
    except Exception:
        logger.error(
            "Error while splitting proxy_server string: %s",
            proxy_server,
        )
        proxy = None
        proxy_proto = None

    if proxy:
        try:
            proxy_addr, proxy_port = proxy.split(":")
        except Exception:
            logger.error("Error while splitting proxy into host/port: %s", proxy)
            proxy_addr = None
            proxy_port = None
    else:
        proxy_addr = None
        proxy_port = None

    if proxy_proto and proxy_addr and proxy_port:
        try:
            proto_string = proxy_proto_dic[proxy_proto]
        except Exception:
            logger.error("Unknown proxy protocol: %s", proxy_proto)
            proto_string = None
    else:
        logger.error(
            "proxy_proto (%s), proxy_addr (%s) or proxy_port (%s) missing",
            proxy_proto,
            proxy_addr,
            proxy_port,
        )
        proto_string = None

    try:
        proxy_port = int(proxy_port)
    except Exception:
        logger.error("Unknown proxy port: %s", proxy_port)
        proxy_port = None

    logger.debug(
        "Helper.proxystring_convert() ended with %s, %s, %s",
        proto_string,
        proxy_addr,
        proxy_port,
    )
    return (proto_string, proxy_addr, proxy_port)


def servercert_get(
    logger: logging.Logger,
    hostname: str,
    port: int = 443,
    proxy_server: str = None,
    sni: str = None,
) -> str:
    """get server certificate from an ssl connection"""
    logger.debug("Helper.servercert_get(%s:%s)", hostname, port)

    pem_cert = None

    if ipv6_chk(logger, hostname):
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    else:
        sock = socks.socksocket()

    # backup - set sni to hostname
    if not sni:
        sni = hostname

    context = ssl.create_default_context()  # NOSONAR
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # NOSONAR
    context.options |= ssl.PROTOCOL_TLS_CLIENT
    context.set_alpn_protocols(["acme-tls/1"])
    # reject insecure ssl version
    try:
        # this does not work on RH8
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    except Exception:  # pragma: no cover
        logger.error(
            "Error while getting the peer certifiate: minimum tls version not supported"
        )

    context.options |= ssl.PROTOCOL_TLS_SERVER

    if proxy_server:
        proxy_proto, proxy_addr, proxy_port = proxystring_convert(logger, proxy_server)
        if proxy_proto and proxy_addr and proxy_port:
            logger.debug("servercert_get(): configure proxy")
            sock.setproxy(proxy_proto, proxy_addr, port=proxy_port)
    try:
        sock.connect((hostname, port))
        with context.wrap_socket(sock, server_hostname=sni) as sslsock:
            logger.debug(
                "servercert_get(): %s:%s:%s version: %s",
                hostname,
                sni,
                port,
                sslsock.version(),
            )
            der_cert = sslsock.getpeercert(True)
            # from binary DER format to PEM
            if der_cert:
                pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
    except Exception as err_:
        logger.error("Could not get peer certificate. Error: %s", err_)  # NOSONAR
        pem_cert = None

    if pem_cert:
        logger.debug(
            "Helper.servercert_get() ended with: %s",
            b64_encode(logger, convert_string_to_byte(pem_cert)),
        )
    else:
        logger.debug("Helper.servercert_get() ended with: None")
    return pem_cert


def v6_adjust(logger: logging.Logger, url: str) -> Tuple[Dict[str, str], str]:
    """corner case for v6 addresses"""
    logger.debug("Helper.v6_adjust(%s)", url)

    headers = {
        "Connection": "close",
        "Accept-Encoding": "gzip",
        "User-Agent": USER_AGENT,
    }

    url_dic = parse_url(logger, url)

    # adjust headers and url in case we have an ipv6address
    if ipv6_chk(logger, url_dic["host"]):
        headers["Host"] = url_dic["host"]
        url = f"{url_dic['proto']}://[{url_dic['host']}]/{url_dic['path']}"

    logger.debug("Helper.v6_adjust() ended")
    return (headers, url)


def header_info_get(
    logger: logging.Logger,
    csr: str,
    vlist: List[str] = ("id", "name", "header_info"),
    field_name: str = "csr",
) -> List[str]:
    """lookup header information"""
    logger.debug("Helper.header_info_get()")

    try:
        from acme2certifier.acme_srv.db_handler import DBstore  # pylint: disable=c0415

        dbstore = DBstore(logger=logger)
        result = dbstore.certificates_search(field_name, csr, vlist)
    except Exception as err:
        result = []
        logger.error(
            "Error while getting header_info from database: %s", err
        )  # NOSONAR

    return list(result)


def get_url(environ: Dict[str, str], include_path: bool = False) -> str:
    """get url"""
    config_dic = load_config()
    configured_server_name = configured_server_name_get(config_dic)
    if configured_server_name:
        server_name = html.escape(configured_server_name)
    elif "HTTP_HOST" in environ:
        server_name = html.escape(environ["HTTP_HOST"])
    else:
        server_name = "localhost"

    if "SERVER_PORT" in environ:
        port = html.escape(environ["SERVER_PORT"])
    else:
        port = 80

    if "HTTP_X_FORWARDED_PROTO" in environ:
        proto = html.escape(environ["HTTP_X_FORWARDED_PROTO"])
    elif "wsgi.url_scheme" in environ:
        proto = html.escape(environ["wsgi.url_scheme"])
    elif int(port) == 443:
        proto = "https"
    else:
        proto = "http"

    if include_path and "PATH_INFO" in environ:
        result = f'{proto}://{server_name}{html.escape(environ["PATH_INFO"])}'
    else:
        result = f"{proto}://{server_name}"
    return result


def parse_url(logger: logging.Logger, url: str) -> Dict[str, str]:
    """split url into pieces"""
    logger.debug("Helper.parse_url()")

    url_dic = {
        "proto": urlparse(url).scheme,
        "host": urlparse(url).netloc,
        "path": urlparse(url).path,
    }
    return url_dic


def encode_url(logger: logging.Logger, input_string: str) -> str:
    """urlencoding"""
    logger.debug("Helper.encode_url(%s)", input_string)

    return quote(input_string)


RETRYABLE_STATUS_CODES = {500, 502, 503, 504}


def _retry_wait_seconds(retry_backoff: float, attempt: int) -> float:
    """Calculate exponential backoff delay for a retry attempt."""
    return retry_backoff * (2 ** (attempt - 1))


def _request_send_by_method(
    logger: logging.Logger,
    session,
    method: str,
    url: str,
    headers: Dict[str, str],
    proxy: Dict[str, str],
    timeout: int,
    payload: Dict[str, str],
    verify: bool,
) -> Tuple[Optional[requests.Response], Optional[Tuple[int, str]]]:
    """Send request by HTTP method and return either response or error tuple."""
    request_args = {
        "url": url,
        "headers": headers,
        "proxies": proxy,
        "timeout": timeout,
        "verify": verify,
    }
    method_lower = method.lower()

    if method_lower == "get":
        return session.get(**request_args), None

    if method_lower in ("post", "put"):
        request_args["json"] = payload
        request_func = session.post if method_lower == "post" else session.put
        return request_func(**request_args), None

    logger.error("Unknown request method: %s", method)
    return None, (500, "Unknown request method")


def _request_parse_response(
    logger: logging.Logger, api_response: requests.Response
) -> Tuple[int, Optional[Union[Dict, str]]]:
    """Parse HTTP response body as JSON when possible."""
    code = api_response.status_code
    if not api_response.text:
        return code, None

    try:
        content = api_response.json()
    except Exception as err_:
        logger.error(
            "Request_operation returned error during json parsing: %s", err_
        )  # NOSONAR
        content = str(err_)

    return code, content


def _request_should_retry(code: int, attempt: int, attempts: int) -> bool:
    """Return True when request should be retried for this attempt."""
    return code in RETRYABLE_STATUS_CODES and attempt < attempts


def request_operation(
    logger: logging.Logger,
    headers: Dict[str, str] = None,
    proxy: Dict[str, str] = None,
    timeout: int = 20,
    url: str = None,
    session=requests,
    method: str = "GET",
    payload: Dict[str, str] = None,
    verify: bool = True,
    retries: int = 0,
    retry_backoff: float = 1.0,
):
    """Execute an HTTP request with optional retry on transient failures."""
    logger.debug("Helper.api_operation(): method: %s", method)

    attempts = 1 + max(retries, 0)

    for attempt in range(1, attempts + 1):
        try:
            api_response, method_error = _request_send_by_method(
                logger,
                session,
                method,
                url,
                headers,
                proxy,
                timeout,
                payload,
                verify,
            )
            if method_error:
                return method_error

            code, content = _request_parse_response(logger, api_response)

            if _request_should_retry(code, attempt, attempts):
                wait = _retry_wait_seconds(retry_backoff, attempt)
                logger.warning(
                    "Request_operation got %s from %s, retry %s/%s in %.1fs",
                    code,
                    url,
                    attempt,
                    attempts - 1,
                    wait,
                )
                time.sleep(wait)
                continue

            logger.debug("Helper.request_operation() ended with: %s", code)
            return code, content

        except Exception as err_:
            if attempt < attempts:
                wait = _retry_wait_seconds(retry_backoff, attempt)
                logger.warning(
                    "Request_operation error: %s, retry %s/%s in %.1fs",
                    err_,
                    attempt,
                    attempts - 1,
                    wait,
                )
                time.sleep(wait)
            else:
                logger.error("Request_operation returned error: %s", err_)  # NOSONAR
                code = 500
                content = str(err_)
                logger.debug("Helper.request_operation() ended with: %s", code)
                return code, content

    return 500, "Unexpected retry loop exit"
