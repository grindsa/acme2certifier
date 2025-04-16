<!-- markdownlint-disable MD013 -->
<!-- wiki-title SOAP CA Handler Prototype -->
# SOAP CA Handler

This handler is a **proof of concept** that enables certificate enrollment from a certificate authority that provides a SOAP interface. Certificate Signing Requests (CSRs) from ACME clients are encapsulated within a **PKCS#7** structure and digitally signed. The certificate corresponding to the signing key is also included.

Parts of the code used to create the PKCS#7 message are borrowed from [magnuswatn/pkcs7csr](https://github.com/magnuswatn/pkcs7csr).

## Prerequisites

Ensure you have the following:

- A **certificate and private key** (PEM format) used to sign the PKCS#7 content.
- **CA certificates** (PEM format) required to validate the certificate presented by the SOAP server.

## Installation and Configuration

Modify the server configuration (`acme_srv/acme_srv.cfg`) and add the following parameters:

```ini
[CAhandler]
handler_file: examples/ca_handler/pkcs7_soap_ca_handler.py
soap_srv: http[s]://<ip>:<port>
signing_key: <filename>
signing_cert: <filename>
ca_bundle: <filename>
profilename: <Profile Name>
email: <email address>
```

### Parameter Explanations

- **soap_srv** – URL of the SOAP server.
- **signing_key** – Private key of the certificate used to sign the PKCS#7 structure (`/path/to/key.pem`).
- **signing_cert** – Certificate attached to the PKCS#7 message sent to the SOAP server (`/path/to/certificate.pem`).
- **ca_bundle** – CA certificate bundle needed to validate the SOAP server certificate (`/path/to/ca_bundle.pem`). Set to `False` to disable certificate validation.
- **profilename** – Name of the certificate profile to be inserted into the SOAP request.
- **email** – Email address to be included in the SOAP request.

## SOAP Messages

### SOAP Request Sent by acme2certifier (NewCertRequest)

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

### SOAP Response Sent by Server Upon Successful Enrollment (NewCertResponse)

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

### SOAP Response Sent by Server in Case of Failure

```xml
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <s:Body>
    <s:Fault>
      <faultcode>s:Client</faultcode>
      <faultstring>Processing RequestCertificate - Error! by request={ProfileName=profilename,CertificateRequestRaw.Length=<length>,Email=email,ReturnCertificateCaChain=True}, profile=profilename, pkcs7initials=, ErrorMessage=Cannot parse PKCS7 message!</faultstring>
    </s:Fault>
  </s:Body>
</s:Envelope>
```
