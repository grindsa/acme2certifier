<!-- markdownlint-disable  MD013 -->
<!-- wiki-title SOAP CA handler protopype -->
# SOAP CA handler

This handler is a proof of concept allowing certificate enrollment from a certificate authority providing an SOAP interface. Certificate signing requests from acme-clients will be added to a PKCS#7 structure and digitally signed. The certificate belonging to the key used for signing will also be added.

Parts of the code to create the PKCS#7 message are borrowed from [magnuswatn/pkcs7csr](https://github.com/magnuswatn/pkcs7csr)

## Pre-requisites

- Certificate and key (in PEM format) used to sign the PKCS#7 content.
- CA certificate(s) in pem format allowing to validate the certificate presented by the SOAP server.

## Installation and Configuration

- modify the server configuration (`acme_srv/acme_srv.cfg`) and add the following parameters

```config
[CAhandler]
handler_file: examples/ca_handler/pkcs7_soap_ca_handler.py
soap_srv: http[s]://<ip>:<port>
signing_key: <filename>
signing_cert: <filename>
ca_bundle: <filename>
profilename: <Profile Name>
email: <email address>
```

- soap_srv - URL of the SOAP server
- signing_key - Private key of the certificate used sign the PKCS#7 structure (/path to/key.pem)
- signing_cert - Certificate attached to the PKCS#7 message send to SOAP server (/path to/certificate.pem)
- ca_bundle - CA certificate bundle needed to validate the EST server certificate (/path to/ca_bundle.pem). Setting to False disables the certificate check
- profilename - Name of the certificate profile to be inserted into SOAP request
- email - email address to be inserted into SOAP request

## SOAP messages

### SOAP request send by acme2certifier (NewCertRequest)

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
   <soapenv:Header/>
   <soapenv:Body>
      <aur:RequestCertificate>
         <aur:request>
            <aur:ProfileName>profilename</aur:ProfileName>
            <aur:CertificateRequestRaw>PKCS#7 message encoded in base64</aur:CertificateRequestRaw>
            <aur:Email>email</aur:Email>
            <aur:ReturnCertificateCaChain>true</aur:ReturnCertificateCaChain>
         </aur:request>
      </aur:RequestCertificate>
   </soapenv:Body>
</soapenv:Envelope>
```

### SOAP response send by server in case of successful enrollment (NewCertResponse)

```xml
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <s:Body>
    <RequestCertificateResponse>
      <RequestCertificateResult xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
        <IssuedCertificate>certificate chain in PKCS#7 format</IssuedCertificate>
      </RequestCertificateResult>
    </RequestCertificateResponse>
  </s:Body>
</s:Envelope>
```

### SOAP reponse send by server in case of a failure

```xml
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <s:Body>
    <s:Fault>
      <faultcode>s:Client</faultcode>
      <faultstring>Processing RequestCertificate - Error! by request={ProfileName=profilename,CertificateRequestRaw.Length=<lenght>,Email=email,ReturnCertificateCaChain=True}, profile=profilename, pkcs7initials=, ErrorMessage=Cannot parse PKCS7 message!</faultstring>
    </s:Fault>
  </s:Body>
</s:Envelope>
```
