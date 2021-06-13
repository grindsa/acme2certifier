#!/bin/bash 
# trigger script for Insta Certifier / NCM
# we expect the path to certificate submitted as $1
# commandline for publishing method "/usr/local/certifier/bin/trigger.sh %cert"
# import certificate format must be changed to PEM to interwork with certifier_ca_handler.py

# URL to acme2certifier 
ACME2CERTIFIER_URL='http://192.168.14.1/trigger'

# thats the relative path to cert
CERT_FILE=$1

# certifier base directory
CERTIFIFER_BASE='/usr/local/certifier'
# absolute path to cert
CERT_PATH="${CERTIFIFER_BASE}/${CERT_FILE}"

# certificate object in base64
STR_BASE64=$(cat $CERT_PATH | base64 -w 0)
PAYLOAD='{"payload": "'$STR_BASE64'", "signature": "foo"}'

# post command
curl -X POST -H "Content-Type: application/json" -d "$PAYLOAD" $ACME2CERTIFIER_URL

exit 0
