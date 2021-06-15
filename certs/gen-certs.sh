#!/bin/bash

echo "Run from wolfkeymgr root"

# Make sure required CA files exist and are populated
rm -f ./certs/index.*
touch ./certs/index.txt 
if [ ! -f ./certs/serial ]; then
	echo 1000 > ./certs/serial
fi
if [ ! -f ./certs/crlnumber ]; then
	echo 2000 > ./certs/crlnumber
fi

if [ "$1" == "clean" ]; then
	rm -f ./certs/1*.pem
	rm -f ./certs/ca-*.pem
	rm -f ./certs/client-*.pem
	rm -f ./certs/client-*.der
	rm -f ./certs/server-*.pem
	rm -f ./certs/server-*.der
	rm -f ./certs/*.old
	
	exit 0
fi

# Script to generated a TLS server and client certificates

# Keys use ECC and PKCS8 with password "wolfssl"

# Generate ECC 256-bit CA
if [ ! -f ./certs/ca-key.pem ]; then
	echo "Creating CA Key (SECP256R1)"
    openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -v2 aes-128-cbc -outform pem -out ./certs/ca-key.pem
fi
echo "Creating self signed root CA certificate"
openssl req -config ./certs/ca-ecc.cnf -extensions v3_ca -x509 -nodes -key ./certs/ca-key.pem -passin pass:'wolfssl' \
	-out ./certs/ca-cert.pem -sha256 -days 7300 -batch \
	-subj "/C=US/ST=Washington/L=Seattle/O=wolfSSL/OU=Development/CN=www.wolfssl.com/emailAddress=info@wolfssl.com"

# Client Key
if [ ! -f ./certs/client-key.pem ]; then
	echo "Creating Client Key (SECP256R1)"
    openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -v2 aes-128-cbc -outform pem -out ./certs/client-key.pem
fi

# Client Cert
echo "Creating signed Client certificate"
openssl req -config ./certs/ca-ecc.cnf -sha256 -new -key ./certs/client-key.pem -passin pass:'wolfssl' \
	-out ./certs/client-cert.csr \
	-subj "/C=US/ST=Washington/L=Seattle/O=Eliptic/OU=ECC/CN=www.wolfssl.com/emailAddress=info@wolfssl.com/"
openssl ca -config ./certs/ca-ecc.cnf -extensions usr_cert -days 3650 -notext -md sha256 \
	-passin pass:'wolfssl' -in ./certs/client-cert.csr -out ./certs/client-cert.pem -batch
rm ./certs/client-cert.csr

if [ ! -f ./certs/server-key.pem ]; then
	echo "Creating Server Key (SECP256R1)"
    openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -v2 aes-128-cbc -outform pem -out ./certs/server-key.pem
fi

# Server Cert
echo "Creating signed Server certificate"
openssl req -config ./certs/ca-ecc.cnf -sha256 -new -key ./certs/server-key.pem -passin pass:'wolfssl' \
	-out ./certs/server-cert.csr \
	-subj "/C=US/ST=Washington/L=Seattle/O=Eliptic/OU=ECC/CN=www.wolfssl.com/emailAddress=info@wolfssl.com/"
openssl ca -config ./certs/ca-ecc.cnf -extensions server_cert -days 3650 -notext -md sha256 \
	-passin pass:'wolfssl' -in ./certs/server-cert.csr -out ./certs/server-cert.pem -batch
rm ./certs/server-cert.csr


# Script to generate a self-signed TLS server certificate for Apache
# No key password

if [ -f ./certs/test-key.pem ]; then
    # ECC
    openssl ecparam -name prime256v1 -genkey -outform pem -out ./certs/test-key.pem
fi

openssl req -new -x509 -nodes -key ./certs/test-key.pem -out ./certs/test-cert.pem -sha256 -days 7300 -batch \
	-subj "/C=US/ST=CA/L=Seattle/O=wolfSSL/OU=Development/CN=localhost/emailAddress=info@wolfssl.com"
