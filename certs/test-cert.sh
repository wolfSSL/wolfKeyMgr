#!/bin/bash

# Script to generated a self-signed TLS server certificate
# test-key.pem password is "wolfssl"

if [ -f ./certs/ecc/./certs/test-key.pem ]; then
    # ECC
    openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -v2 aes-128-cbc -outform pem -out ./certs/test-key.pem
fi

openssl req -new -x509 -nodes -key ./certs/test-key.pem -out ./certs/test-cert.pem -sha256 -days 7300 -batch -subj "/C=US/ST=CA/L=Seattle/O=wolfSSL/OU=Development/CN=www.wolfssl.com/emailAddress=info@wolfssl.com"
