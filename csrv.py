#!/usr/bin/python3
import OpenSSL
from certsrv import Certsrv

host = 'win-mmn1f17pjo9.ads.dynamop.de'
usr = 'joern'
passwd = 'Test1234'
template = 'Web Server'

# Generate a key
key = OpenSSL.crypto.PKey()
key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

# Generate a CSR
req = OpenSSL.crypto.X509Req()
req.get_subject().CN="myserver.example.com"
san = b"DNS: myserver.example.com"
san_extension = OpenSSL.crypto.X509Extension(b"subjectAltName", False, san)
req.add_extensions([san_extension])

req.set_pubkey(key)
req.sign(key, "sha256")

# Get the cert from the ADCS server
pem_req = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, req)

ca_server = Certsrv(host, usr, passwd, None, 'msca.pem')
result = ca_server.check_credentials()
print(result)
# pem_cert = ca_server.get_cert(pem_req, template)

# Print the key and the cert
# pem_key = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)

# print("Cert:\n{}".format(pem_cert.decode()))
# print("Key:\n{}".format(pem_key.decode()))