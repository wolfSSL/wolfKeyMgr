#!/bin/bash

set -euo pipefail
umask 077

echo "Run from wolfkeymgr root"

reject_shipped_key() {
    key_file="$1"
    shipped_fingerprint="$2"
    pub_file="$1.pub.tmp"

    if [ ! -f "$key_file" ]; then
        return 0
    fi

    # Write the public key to a file rather than piping it into "openssl
    # dgst". A pipeline whose reader can exit first lets the writer die of
    # SIGPIPE, which "set -o pipefail" then reports as a fingerprint
    # failure. That made this check intermittently take the wrong branch.
    rm -f "$pub_file"
    if ! openssl pkey -in "$key_file" -passin pass:'wolfssl' -pubout \
            -outform DER -out "$pub_file" 2>/dev/null; then
        rm -f "$pub_file"
        echo "Refusing an existing key that could not be fingerprinted:" \
            "$key_file" >&2
        exit 1
    fi
    if ! key_fingerprint=$(openssl dgst -sha256 -r "$pub_file" \
            | awk '{print $1}'); then
        rm -f "$pub_file"
        echo "Refusing an existing key that could not be fingerprinted:" \
            "$key_file" >&2
        exit 1
    fi
    rm -f "$pub_file"

    if [ -z "$key_fingerprint" ]; then
        echo "Refusing an existing key with an empty fingerprint:" \
            "$key_file" >&2
        exit 1
    fi
    if [ "$key_fingerprint" = "$shipped_fingerprint" ]; then
        echo "Refusing to reuse a credential shipped in an older release:" \
            "$key_file" >&2
        echo "Rotate the demo credentials with: ./certs/gen-certs.sh clean" >&2
        exit 1
    fi
}

# Make sure required CA files exist and are populated
rm -f ./certs/index.*
touch ./certs/index.txt 
if [ ! -f ./certs/serial ]; then
	echo 1000 > ./certs/serial
fi
if [ ! -f ./certs/crlnumber ]; then
	echo 2000 > ./certs/crlnumber
fi

if [ "${1:-}" == "clean" ]; then
	rm -f ./certs/1*.pem
	rm -f ./certs/ca-*.pem
	rm -f ./certs/client-*.pem
	rm -f ./certs/client-*.der
	rm -f ./certs/server-*.pem
	rm -f ./certs/server-*.der
	rm -f ./certs/demo-password.txt
	rm -f ./certs/*.old
	
	exit 0
fi

reject_shipped_key ./certs/ca-key.pem \
    e69c343c84239413663520f8ccf82635b1b8954b9e7a793f2ed3b2b5fd774e5c
reject_shipped_key ./certs/client-key.pem \
    9ccdf5657ad96c0c14657937e012486ee0c8db8f735b1abcd28c875dd71c5d2e
reject_shipped_key ./certs/server-key.pem \
    27dea57285ac6798c1c47ad6da9501da76073d54524760450bc5a6001d521d38
reject_shipped_key ./certs/server-rsa-key.pem \
    637b068c61c194f740b93dc0828de708f5f8efb87e7ee8e7822f6b158c5a7744

printf '%s\n' 'wolfssl' > ./certs/demo-password.txt
chmod 600 ./certs/demo-password.txt

# Script to generated a TLS server and client certificates

# Keys use ECC and PKCS8 with password "wolfssl"

# Generate ECC 256-bit CA
if [ ! -f ./certs/ca-key.pem ]; then
	echo "Creating CA Key (SECP256R1)"
    openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 \
        -topk8 -v2 aes-128-cbc -passout pass:'wolfssl' -outform pem \
        -out ./certs/ca-key.pem
fi
echo "Creating self signed root CA certificate"
openssl req -config ./certs/ca-ecc.cnf -extensions v3_ca -x509 -nodes -key ./certs/ca-key.pem -passin pass:'wolfssl' \
	-out ./certs/ca-cert.pem -sha256 -days 7300 -batch \
	-subj "/C=US/ST=Washington/L=Seattle/O=wolfSSL/OU=Development/CN=www.wolfssl.com/emailAddress=info@wolfssl.com"

# Client Key
if [ ! -f ./certs/client-key.pem ]; then
	echo "Creating Client Key (SECP256R1)"
    openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 \
        -topk8 -v2 aes-128-cbc -passout pass:'wolfssl' -outform pem \
        -out ./certs/client-key.pem
fi

# Client Cert
echo "Creating signed Client certificate"
openssl req -config ./certs/ca-ecc.cnf -sha256 -new -key ./certs/client-key.pem -passin pass:'wolfssl' \
	-out ./certs/client-cert.csr \
	-subj "/C=US/ST=Washington/L=Seattle/O=Eliptic/OU=ECC/CN=www.wolfssl.com/emailAddress=info@wolfssl.com/"
openssl ca -config ./certs/ca-ecc.cnf -extensions usr_cert -days 3650 -notext -md sha256 \
	-passin pass:'wolfssl' -in ./certs/client-cert.csr -out ./certs/client-cert.pem -batch
rm ./certs/client-cert.csr

# Server Key
if [ ! -f ./certs/server-key.pem ]; then
	echo "Creating Server Key (SECP256R1)"
    openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 \
        -topk8 -v2 aes-128-cbc -passout pass:'wolfssl' -outform pem \
        -out ./certs/server-key.pem
fi

# Server Cert
echo "Creating signed Server certificate"
openssl req -config ./certs/ca-ecc.cnf -sha256 -new -key ./certs/server-key.pem -passin pass:'wolfssl' \
	-out ./certs/server-cert.csr \
	-subj "/C=US/ST=Washington/L=Seattle/O=Eliptic/OU=ECC/CN=www.wolfssl.com/emailAddress=info@wolfssl.com/"
openssl ca -config ./certs/ca-ecc.cnf -extensions server_cert -days 3650 -notext -md sha256 \
	-passin pass:'wolfssl' -in ./certs/server-cert.csr -out ./certs/server-cert.pem -batch
rm ./certs/server-cert.csr

# Server RSA Key
if [ ! -f ./certs/server-rsa-key.pem ]; then
	echo "Creating Server Key (RSA2048)"
    openssl genrsa -out ./certs/server-rsa-key.pem -passout pass:'wolfssl' -aes128 2048
fi

# Server RSA Cert
echo "Creating signed RSA Server certificate"
openssl req -config ./certs/ca-ecc.cnf -sha256 -new -key ./certs/server-rsa-key.pem -passin pass:'wolfssl' \
	-out ./certs/server-rsa-cert.csr \
	-subj "/C=US/ST=Washington/L=Seattle/O=Eliptic/OU=RSA/CN=www.wolfssl.com/emailAddress=info@wolfssl.com/"
openssl ca -config ./certs/ca-ecc.cnf -extensions server_cert -days 3650 -notext -md sha256 \
	-passin pass:'wolfssl' -in ./certs/server-rsa-cert.csr -out ./certs/server-rsa-cert.pem -batch
rm ./certs/server-rsa-cert.csr


# Script to generate a self-signed TLS server certificate for Apache
# No key password

if [ -f ./certs/test-key.pem ]; then
    # ECC
    openssl ecparam -name prime256v1 -genkey -outform pem -out ./certs/test-key.pem
fi

openssl req -new -x509 -nodes -key ./certs/test-key.pem -out ./certs/test-cert.pem -sha256 -days 7300 -batch \
	-subj "/C=US/ST=CA/L=Seattle/O=wolfSSL/OU=Development/CN=localhost/emailAddress=info@wolfssl.com"
