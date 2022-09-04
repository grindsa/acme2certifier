# -*- coding: utf-8 -*-
""" soap-server mock providing endpoint for soap ca handler """
# pylint: disable=c0209, c0413
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))
import tempfile
import subprocess
from wsgiref.simple_server import WSGIServer, WSGIRequestHandler
import xmltodict
from acme_srv.helper import b64_encode, logger_setup, convert_string_to_byte
from examples.ca_handler.xca_ca_handler import CAhandler

def _csr_lookup(logger, soap_dic):
    """ get csr from soap request """
    logger.debug('_csr_lookup()')
    csr = None
    if 'soapenv:Envelope' in soap_dic:
        if 'soapenv:Body' in soap_dic['soapenv:Envelope']:
            if 'aur:RequestCertificate' in soap_dic['soapenv:Envelope']['soapenv:Body']:
                if 'aur:request' in soap_dic['soapenv:Envelope']['soapenv:Body']['aur:RequestCertificate']:
                    if 'aur:CertificateRequestRaw'  in soap_dic['soapenv:Envelope']['soapenv:Body']['aur:RequestCertificate']['aur:request']:
                        csr = soap_dic['soapenv:Envelope']['soapenv:Body']['aur:RequestCertificate']['aur:request']['aur:CertificateRequestRaw']
    return csr


def _opensslcmd_build(logger, tmp_dir, filename_list):
    """ build openssl command """
    logger.debug('_opensslcmd_build()')
    cmd_list = ['openssl', 'crl2pkcs7', '-nocrl', '-outform', 'DER', '-out', '{0}/cert.p7b'.format(tmp_dir)]

    for filename in filename_list:
        cmd_list.append('-certfile')
        cmd_list.append(filename)

    return cmd_list

def _file_load_binary(logger, filename):
    """ load file at once """
    logger.debug('file_open({0})'.format(filename))
    with open(filename, 'rb') as _file:
        lines = _file.read()
    return lines

def _file_dump(logger, filename, data_):
    """ dump content to  file """
    logger.debug('file_dump({0})'.format(filename))
    with open(filename, 'w', encoding='utf8') as file_:
        file_.write(data_)  # lgtm [py/clear-text-storage-sensitive-data]

def _pem2pkcs7_convert(logger, pem):
    """ convert pem bunlde to pkcs#7 by using openssl """
    tmp_dir = tempfile.mkdtemp()
    certificate_list = pem.split('-----END CERTIFICATE-----\n')

    filename_list = []
    for cnt, certificate in enumerate(certificate_list):
        if certificate:
            certificate = '{0}-----END CERTIFICATE-----\n'.format(certificate)
            _file_dump(logger, '{0}/{1}.pem'.format(tmp_dir, cnt), certificate)
            filename_list.append('{0}/{1}.pem'.format(tmp_dir, cnt))

    openssl_cmd = _opensslcmd_build(logger, tmp_dir, filename_list)

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


def request_process(logger, csr):
    """ construct soap response """

    ca_handler=CAhandler(True, logger)
    ca_handler.xdb_file = 'acme_srv/xca/acme2certifier.xdb'
    ca_handler.issuing_ca_name = 'sub-ca'
    ca_handler.issuing_ca_key = 'sub-ca'
    ca_handler.template_name = 'acme'
    ca_handler.passphrase = 'test1234'
    ca_handler.ca_cert_chain_list = ['root-ca']

    (error, cert_bundle, _cert_raw, _unused ) = ca_handler.enroll(csr)
    if not error:
        pkcs7 = _pem2pkcs7_convert(logger, cert_bundle)
    else:
        pkcs7 = None

    if pkcs7:
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
    return convert_string_to_byte(soap_response)

def soap_srv(environ, start_response):
    """ echo application """
    request_body = _get_request_body(environ)
    stack_d = xmltodict.parse(request_body)

    csr = _csr_lookup(LOGGER, stack_d)

    if csr:
        status = "200 OK"
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


    DEBUG = True
    # initialize logger
    LOGGER = logger_setup(DEBUG)

    # JUST FOR DEBUGGING
    # PEM
    # csr = 'MIICdjCCAV4CAQIwADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALrjMLZ7TXrssxShCeGMVGN5Gbqhe3BRzycBns/L6Nv70F1A20gkQHGXDaLBZIhkEaFUVlmYqz8XtrvNjJpGGT9Kba0Dh4uYXYkst2dssqKRAezGcjG8dNJuFjvuRCQvRqAmeZcDZZ8WsJEpvJiLKhrkbzVZoJfHJEy0X/WeCiQpnG0tPzjTZcZl3XS+fMxcEOvlsnkm1uav9xljI0dx+O5vDlyf8D9xCPeoT9uy+ZKwP/1AEj/tYchmBMmPIAuAKY2gByyN4t34P20comUO6mHaq1J1RXS1rbmpS1YxwIUSUHIl7Nt9rApdOQ47t65dg2h21aJRLQvcgQLCTmnhZqsCAwEAAaAxMC8GCSqGSIb3DQEJDjEiMCAwHgYDVR0RBBcwFYITYWNtZS5uY2xtLXNhbWJhLm9yZzANBgkqhkiG9w0BAQsFAAOCAQEAaQJeB6d/pNp8N8qgXM09g0SioDFUwD1EzKaTDeHlIwzeHtjrbE4X67mg2KgPCoPZ60dfcg7DOj1LzmMqB7tMHJNx4jPw6r7Vc2p7kFuPHmI0YMeI3kxQfNnERoWG3GV4AfzeS8ERdvfMBrqa+lq1xOJTi1qTrADGa5HuRSp19Kv/gC7vsCJp6Zf6QsbkAGF6gOHfxRGIEZb+Yutn3mhMOJbJJGm8NGq0gt0HFJAPPAtGNmeTHhN96n4t9cQiUTQhJPKPIG7SrLI1qvHhPGpEQahy942eTXayqF+1+Eh44IigOgbNAApHLV8ho+J08cJGOCdmHLDU35726yLWSK7Qqg=='
    # p7b from example
    # csr = 'MIIMhgYJKoZIhvcNAQcCoIIMdzCCDHMCAQMxDzANBglghkgBZQMEAgEFADCCAxIGCSqGSIb3DQEHAaCCAwMEggL/MIIC+zCCAeMCAQAwWDELMAkGA1UEBhMCQ1oxFzAVBgNVBAoMDktvbWVyY25pIGJhbmthMQwwCgYDVQQLDANNV1MxIjAgBgNVBAMMGW9tdS50ZXN0LmF1dG90ZXN0LmtiY2xvdWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDRC7A/wAyb//F20YA+FqCV47tHHG/KNNI0Zjb3cU+z/Tl7XXrvnoUdYWn62YkqyuYlp3FmYDhd8m3rCyDDEkkG7nzaoiEFcXQGfOiS2HTcpK8xAeavDbHBVtuyzdo2DvtqAnplGxQlh8Xzsc1DnQtVqyNDrcCQTKpP+sncEUTENnl4vzGROTY8aNaXu1sNXFwBP/0Fz5wrjKkPlSFyN5JjyZEEogT5x6iucBb9vzgtPvp16kigI9x3Vf2zMnOeMnjumJNdWHii2USvslPe+QDlgPKxkUMi3ZRBJoaAMWsNMUZhchxwPi+FWVVUeo9LgQtvM3PkTbO+0sNOWPIIKL4vAgMBAAGgXjBcBgkqhkiG9w0BCQ4xTzBNMEsGA1UdEQREMEKBEWE1MzIwdG13QGRzLmtiLmN6gRJvbmRyZWpfbXVzaWxAa2IuY3qCGW9tdS50ZXN0LmF1dG90ZXN0LmtiY2xvdWQwDQYJKoZIhvcNAQELBQADggEBABHebeD7DdadkXBRnHgt5534y+uiVWngWApO7ZBoMA3kaXfsjTmc5C8Np0RitoVbWIM5k9Sn9bIAT8y7Lq1sOxWwQ7v0P66A7njhoSIOhy5yk8zckkfR2WInG+SAOkfXbk+HtvejRRqE30fE3lk8WwdWwGNyAzfu3/Pz8nPx0YW96Jf7nFXuBMmEbjeftvt520o9bZ/Bju+ZklsVQVQfhJjAx/1eMeW+tsCT8vRunxsmJHP8YwCWxumFui2whvSgSPmq5k4JSNMOUsNJaq788KfqjMyYp3zXdJIqfVJ/ucKiN4GxUTLNbvP/wI+bmEjjh/uPVI7VOHmXaOajEH9sPuegggeyMIIHrjCCBZagAwIBAgITfQAAACM05HO/2dHFDAAAAAAAIzANBgkqhkiG9w0BAQsFADBNMQswCQYDVQQGEwJDWjEcMBoGA1UEChMTS29tZXJjbmkgYmFua2EgYS5zLjEgMB4GA1UEAxMXS0IgSW50ZXJuaSBDQSBUZWNobmlja2EwHhcNMjExMTI1MTE0NjUwWhcNMjMxMTI1MTE0NjUwWjBiMQswCQYDVQQGEwJDWjEXMBUGA1UEChMOS29tZXJjbmkgYmFua2ExFjAUBgNVBAsTDUFQSVBLSUNFUlRSRVExIjAgBgNVBAMTGU1XUyBDZXJ0IFJlcXVlc3QgRGVsZWdhdGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCVo0wTDvobIwjrws6oH9CdcBYoYsnMb7nXmicieafJ1c8UKKFaaDlDOfRAYKP5CP5Nafoz+C3AIpGYGYQ3cyOPY2EduTNfYV8xWSFnAwmNjQLK1hUf+xlyp0SaAv1Mw8wkC4wVksL+a96J3jAWijjklqjqHStNrI3ysuJ5DQ6wCk53poCX1iUaRYP9vtslSpyuhcxEuF/KPavPb1Z+CKNmmTzuFGvMIt4ghN0UHQSkWjQNUrStjQa/+GtLiJEI2QJo8nDkbtXLDz+DprTiZWLT/Xx4B2LpuziaIklf5fFzorOQ6NkwKmaxGKh0oZ1iikBy22EBB0mG/3RaKfIka34vAgMBAAGjggNwMIIDbDAOBgNVHQ8BAf8EBAMCBsAwHgYDVR0RBBcwFYETamFuX3ZvbmRyYWNla0BrYi5jejAdBgNVHQ4EFgQUAb0a3WUgGGZBDiS61K8pqOvYadUwHwYDVR0jBBgwFoAUL3T7eJJUuhsoXoPDcFCZaTKnBrwwggEBBgNVHR8EgfkwgfYwgfOggfCgge2GgcRsZGFwOi8vL0NOPUtCJTIwSW50ZXJuaSUyMENBJTIwVGVjaG5pY2thLENOPVNNS0IxOTUsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9ZHMsREM9a2IsREM9Y3o/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50hiRodHRwOi8vd3d3LmtiLmN6L3BraS9jYWtiaW50dGVjaC5jcmwwggE6BggrBgEFBQcBAQSCASwwggEoMIG8BggrBgEFBQcwAoaBr2xkYXA6Ly8vQ049S0IlMjBJbnRlcm5pJTIwQ0ElMjBUZWNobmlja2EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9ZHMsREM9a2IsREM9Y3o/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwMAYIKwYBBQUHMAKGJGh0dHA6Ly93d3cua2IuY3ovcGtpL2Nha2JpbnR0ZWNoLmNydDA1BggrBgEFBQcwAYYpaHR0cDovL3BraW9jc3Aua2IuY3ovY2FrYmludHRlY2gvYXBpL29jc3AwPQYJKwYBBAGCNxUHBDAwLgYmKwYBBAGCNxUIgpj9IYen2yiC3Z8agdLLSYOj7nhdguW6LIWZwkwCAWQCAQUwFgYDVR0lBA8wDQYLK4Ealc33PoIsBWUwHgYJKwYBBAGCNxUKBBEwDzANBgsrgRqVzfc+giwFZTBABgNVHSAEOTA3MDUGDiuBGpXN9z6HaAEDAgUBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LmtiLmN6L3BraTANBgkqhkiG9w0BAQsFAAOCAgEATAgykAQarHYrE1R5LUsW6nn7AgVafPcWUVGwk/J58V7wk15XBJrRvCYViGS19tuiNE1/Fo3QZOlrPgNUsgqii1+yh05LBiY7tF1R2T4mWtuVK/zDxNk8Q3KqWLXuSwNQXWlzBvNxigKq9n7VSdfQkRg1JgOx8/7SkqkpHg4qCyOjmO28IXMEuXAXpozcdHqQWdGec5N/dqsgn91NHgxS0Dn7g689UhSc2CXDunPvWzULdBX6rwXlJ69ZcyP+m+KjLGkMCpdWeydU2G2hXqdgt4jooCUhWJ28OWFPy9P6AwyBTdXk6rp/Shd18tI6H2skY7os9BIe0J8yzVuHXdDi7PTYhx+Tr70t495W76BZ4ZAr9dx1tLeZgfkgBVpOLYP9oEYX/XuXfKqiDdjWnoXv3jI/o5/Lf9MsJi1m0iztaVKNMKhOBXlwMvitKFsVWvpSw94rKvZiuKAEBDZ0uHgPHjhEy+2S/bFqAuWkv3plCHDyEi1UFYUQG4FzGGCdR7cljMWDJheS/V7IouGy+Ql1b4xN6BTx0FcVYnIz6W6SVz9uz1rjLOhQlQfFZllanHTdcAjRtUYlj+KxX/j+ox0tG4zXlHsPi05o2yfNyUHVgIaBJVT6TpItGbLKUWFUGMASkD3Gd3Zfc/pSLeC2pORBgFPTPh2rWQr8J1wcHp+CVcwxggGPMIIBiwIBATBkME0xCzAJBgNVBAYTAkNaMRwwGgYDVQQKExNLb21lcmNuaSBiYW5rYSBhLnMuMSAwHgYDVQQDExdLQiBJbnRlcm5pIENBIFRlY2huaWNrYQITfQAAACM05HO/2dHFDAAAAAAAIzANBglghkgBZQMEAgEFADANBgkqhkiG9w0BAQEFAASCAQCAkK6N4Upk4kJeLinC7jNoDkHwSiTB3v14NyjY9WMPSo1BX736h3W2S2Em3Hj4o9Yo9x98xb7itamwrA5ZmpWeBYq30rZQPrLsa7fpWHK9uYEOurkJZSzvsVB7aCPyxKWRzMXNqY+Ru0yyJw4Ge3EJzKp82NB2vygN4zUkvCckM6/cdtGQnFZRPXynAmLAdObQZojafibbLAICwPxaoEZhZ7G1TCkO+xRR9GivEtfrx0qAMHK3qc4bYpSxiqZLRMkvROkffewYXs4YBn2vZOgE4gJMmetV/nVutbo5+diEG5rgZe/71rhxeTK0aPJoB8QQUawd6EitOSscyN0ICJRE'
    # request_process(LOGGER, csr)

    httpd = WSGIServer(('0.0.0.0', 8888), WSGIRequestHandler)
    httpd.set_app(soap_srv)
    httpd.serve_forever()
