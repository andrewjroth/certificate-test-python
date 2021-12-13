#!/bin/sh
# Script to run through the first few sections of commands from the readme to setup the Root CA

# Create directories and files
mkdir private certs crl
touch index.txt
echo 1000 > serial
echo 1000 > crl/crlnumber

# Create Key and Root Certificate
openssl ecparam -genkey -name secp384r1 | openssl ec -out private/ca.key.pem
openssl req -config openssl_root.conf -new -x509 -sha384 -extensions v3_ca -key private/ca.key.pem -out certs/ca.crt.pem

# Generate CRL
openssl ca -config openssl_root.conf -gencrl -out crl/root.crl
