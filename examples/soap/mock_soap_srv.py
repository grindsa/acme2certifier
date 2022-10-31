# -*- coding: utf-8 -*-
""" soap-server mock providing endpoint for soap ca handler """
# pylint: disable=c0209, c0413, e0401
import os
import sys
import argparse
import tempfile
import json
import subprocess
from http.client import responses
from wsgiref.simple_server import WSGIServer, WSGIRequestHandler
import xmltodict
sys.path.insert(0, '.')
sys.path.insert(0, '..')
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))
from acme_srv.helper import b64_encode, b64_decode, b64_url_encode, logger_setup, convert_string_to_byte, convert_byte_to_string, load_config   # nopep8
# pylint: disable=e0611
from examples.ca_handler.xca_ca_handler import CAhandler  # nopep8


def arg_parse():
    """ simple argparser """
    parser = argparse.ArgumentParser(description='soap server')
    parser.add_argument('-d', '--debug', help='debug mode', action="store_true", default=False)
    parser.add_argument('-c', '--configfile', help='config file', default='soap_srv.cfg')
    parser.add_argument('-e', '--error', help='send soap error message', action="store_true", default=False)
    parser.add_argument('-s', '--httpstatuscode', help='http status code', default=200)
    args = parser.parse_args()

    debug = args.debug
    configfile = args.configfile
    error = args.error
    hsc = args.httpstatuscode

    return debug, configfile, hsc, error


def _csr_get(logger, soap_dic, soapenvelope, soapbody, aurrequestcertificate):
    """ get CSR from dictionary """
    logger.debug('_csr_extract()')
    aurrequest = 'aur:request'
    csr = None
    if aurrequest in soap_dic[soapenvelope][soapbody][aurrequestcertificate]:
        if 'aur:CertificateRequestRaw' in soap_dic[soapenvelope][soapbody][aurrequestcertificate][aurrequest]:
            csr = soap_dic[soapenvelope][soapbody][aurrequestcertificate][aurrequest]['aur:CertificateRequestRaw']
        if 'aur:ProfileName' in soap_dic[soapenvelope][soapbody][aurrequestcertificate][aurrequest]:
            logger.info('got request profilename: {0}'.format(soap_dic[soapenvelope][soapbody][aurrequestcertificate][aurrequest]['aur:ProfileName']))
        if 'aur:Email' in soap_dic[soapenvelope][soapbody][aurrequestcertificate][aurrequest]:
            logger.info('got request email: {0}'.format(soap_dic[soapenvelope][soapbody][aurrequestcertificate][aurrequest]['aur:Email']))

    return csr


def _csr_lookup(logger, soap_dic):
    """ get csr from soap request """
    logger.debug('_csr_lookup()')
    csr = None

    soapenvelope = 'soapenv:Envelope'
    soapbody = 'soapenv:Body'
    aurrequestcertificate = 'aur:RequestCertificate'

    if soapenvelope in soap_dic and soapbody in soap_dic[soapenvelope]:
        if aurrequestcertificate in soap_dic[soapenvelope][soapbody]:
            csr = _csr_get(logger, soap_dic, soapenvelope, soapbody, aurrequestcertificate)

    return csr


def _opensslcmd_pem2pkcs7_convert(logger, tmp_dir, filename_list):
    """ build openssl command """
    logger.debug('_opensslcmd_pem2pkcs7_convert()')
    cmd_list = ['openssl', 'crl2pkcs7', '-nocrl', '-outform', 'DER', '-out', '{0}/cert.p7b'.format(tmp_dir)]

    for filename in filename_list:
        cmd_list.append('-certfile')
        cmd_list.append(filename)

    return cmd_list


def _opensslcmd_csr_extract(logger, pkcs7_file, csr_file):
    """ build openssl command """
    logger.debug('_opensslcmd_csr_extract()')
    cmd_list = ['openssl', 'cms', '-in', pkcs7_file, '-verify', '-inform', 'DER', '-noverify', '-outform', 'PEM', '-out', csr_file]

    return cmd_list


def _file_load_binary(logger, filename):
    """ load file at once """
    logger.debug('file_open({0})'.format(filename))
    with open(filename, 'rb') as _file:
        lines = _file.read()
    return lines


def _file_load(logger, filename):
    """ load file at once """
    logger.debug('file_open({0})'.format(filename))
    with open(filename, 'r', encoding='utf8') as _file:
        lines = _file.read()
    return lines


def _file_dump_binary(logger, filename, data_):
    """ dump content in binary format to file """
    logger.debug('file_dump({0})'.format(filename))
    with open(filename, 'wb') as file_:
        file_.write(data_)  # lgtm [py/clear-text-storage-sensitive-data]


def _file_dump(logger, filename, data_):
    """ dump content to  file """
    logger.debug('file_dump({0})'.format(filename))
    with open(filename, 'w', encoding='utf8') as file_:
        file_.write(data_)  # lgtm [py/clear-text-storage-sensitive-data]


def _pem2pkcs7_convert(logger, tmp_dir, pem):
    """ convert pem bunlde to pkcs#7 by using openssl """
    certificate_list = pem.split('-----END CERTIFICATE-----\n')

    filename_list = []
    for cnt, certificate in enumerate(certificate_list):
        if certificate:
            certificate = '{0}-----END CERTIFICATE-----\n'.format(certificate)
            _file_dump(logger, '{0}/{1}.pem'.format(tmp_dir, cnt), certificate)
            filename_list.append('{0}/{1}.pem'.format(tmp_dir, cnt))

    openssl_cmd = _opensslcmd_pem2pkcs7_convert(logger, tmp_dir, filename_list)

    rcode = subprocess.call(openssl_cmd)

    if not rcode:
        content = b64_encode(logger, _file_load_binary(logger, '{0}/cert.p7b'.format(tmp_dir)))
    else:
        content = None

    return content


def _get_request_body(environ):
    """ get body from request data """
    try:
        request_body_size = int(environ.get('CONTENT_LENGTH', 0))
    except ValueError:
        request_body_size = 0
    if 'wsgi.input' in environ:
        request_body = environ['wsgi.input'].read(request_body_size)
    else:
        request_body = None
    return request_body


def _config_load(logger, config_file):
    """ load config file"""
    config_dic = load_config(logger, None, config_file)

    cfg_dic = {}
    if 'CAhandler' in config_dic:
        if 'xdb_file' in config_dic['CAhandler']:
            cfg_dic['xdb_file'] = config_dic['CAhandler']['xdb_file']
        if 'issuing_ca_name' in config_dic['CAhandler']:
            cfg_dic['issuing_ca_name'] = config_dic['CAhandler']['issuing_ca_name']
        if 'issuing_ca_key' in config_dic['CAhandler']:
            cfg_dic['issuing_ca_key'] = config_dic['CAhandler']['issuing_ca_key']
        if 'template_name' in config_dic['CAhandler']:
            cfg_dic['template_name'] = config_dic['CAhandler']['template_name']
        if 'passphrase' in config_dic['CAhandler']:
            cfg_dic['passphrase'] = config_dic['CAhandler']['passphrase']
        if 'ca_cert_chain_list' in config_dic['CAhandler']:
            cfg_dic['ca_cert_chain_list'] = json.loads(config_dic['CAhandler']['ca_cert_chain_list'])

    return cfg_dic


def _csr_extract(logger, tmp_dir, csr):
    """ extract csr from pkcs7 file """

    if csr:
        # dump csr into a file
        _file_dump_binary(logger, '{0}/file.p7b'.format(tmp_dir), b64_decode(logger, csr))
        openssl_cmd = _opensslcmd_csr_extract(logger, '{0}/file.p7b'.format(tmp_dir), '{0}/csr.der'.format(tmp_dir))
        rcode = subprocess.call(openssl_cmd)

        if not rcode:
            content = convert_byte_to_string(b64_url_encode(logger, _file_load_binary(logger, '{0}/csr.der'.format(tmp_dir))))
        else:
            content = None
    else:
        content = None

    return content


def request_process(logger, csr):
    """ construct soap response """

    tmp_dir = tempfile.mkdtemp()
    config_dic = _config_load(logger, CONFIG_FILE)

    ca_handler = CAhandler(True, logger)
    ca_handler.xdb_file = config_dic['xdb_file']
    ca_handler.issuing_ca_name = config_dic['issuing_ca_name']
    ca_handler.issuing_ca_key = config_dic['issuing_ca_key']
    ca_handler.template_name = config_dic['template_name']
    ca_handler.passphrase = config_dic['passphrase']
    ca_handler.ca_cert_chain_list = config_dic['ca_cert_chain_list']

    # extract csr from pkcs7 construct
    csr = _csr_extract(logger, tmp_dir, csr)
    logger.debug('csr: {0}'.format(csr))

    # enroll certificate
    (error, cert_bundle, _cert_raw, _unused) = ca_handler.enroll(csr)

    if not error:
        pkcs7 = _pem2pkcs7_convert(logger, tmp_dir, cert_bundle)
    else:
        pkcs7 = None

    if not ERROR and pkcs7:
        soap_response = """
    <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <s:Body>
        <RequestCertificateResponse xmlns="http://monetplus.cz/services/kb/aurora">
        <RequestCertificateResult xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
            <IssuedCertificate>{0}</IssuedCertificate>
        </RequestCertificateResult>
        </RequestCertificateResponse>
    </s:Body>
    </s:Envelope>
    """.format(pkcs7)
    else:
        soap_response = """
    <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <s:Body>
    <s:Fault>
      <faultcode>s:Client</faultcode>
      <faultstring>Processing RequestCertificate - Error! by request={ProfileName=fooba,CertificateRequestRaw.Length=2486,Email=foo@test.cz,ReturnCertificateCaChain=True}, profile=SSL 2Y AUTO, pkcs7initials=, ErrorMessage=Cannot parse PKCS7 message!</faultstring>
    </s:Fault>
    </s:Body>
    </s:Envelope>"""

    return convert_string_to_byte(soap_response)


def soap_srv(environ, start_response):
    """ echo application """
    request_body = _get_request_body(environ)
    stack_d = xmltodict.parse(request_body)

    csr = _csr_lookup(LOGGER, stack_d)

    if csr:
        # try:
        status = "{0} {1}".format(HTTP_STATUS_CODE, responses[int(HTTP_STATUS_CODE)])
        # Except Exception as error:
        # status = "500 Internal Server Error"
        headers = [("Content-type", "text/xml")]
        start_response(status, headers)
        response = request_process(LOGGER, csr)
    else:
        status = "400 OK"
        headers = [("Content-type", "text/html")]
        start_response(status, headers)
        response = b'Request malformed'

    return [response]


if __name__ == '__main__':

    (DEBUG, CONFIG_FILE, HTTP_STATUS_CODE, ERROR) = arg_parse()

    # initialize logger
    LOGGER = logger_setup(DEBUG)

    httpd = WSGIServer(('0.0.0.0', 8888), WSGIRequestHandler)
    httpd.set_app(soap_srv)
    httpd.serve_forever()
