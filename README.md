# wolf Key Manager

This is a secure service for Key management using ETSI specification.

For a demo package showing use with Apache httpd and the wolfSSL sniffer please email facts@wolfssl.com.

## Design

Based on:
* ETSI TS 103 523-3 V1.3.1 (2019-08)
* IETF RFC 5958

## Features

* Generation of keys using an asymmetric key package request
* Low level socket handling using libevent, which is a portable framework for handling sockets.
* HTTPS server supports GET/PUT requests using HTTP/1.1.
* The CA key can be local PKCS #8 (simple password/encrypted), PKCS #11 HSM or TPM 2.0.
* TLS v1.3 is used for securing connections to server

## Layout of files

* keymanager.c: The main entry point
* sock_mgr.c: The libevent socket manager
* svc_[]: Services exposed (ETSI)
* mod_[]: Modules for support (HTTP, TLS, Socket, ETSI)
* wkm_[]: Generic wolfKeyManager functions

## ETSI Design

Server Side
1) KeyGen (Gen Key). Currently ECC SECP25R1 only.
2) Formatting the KeyGen (asymmetric key package)
3) Sending Wire format (HTTPS)
4) Key expiration and notification of new key to peers

Client side
1) Generating ETSI HTTP request
2) Parsing HTTP response
3) Unbundling asymmetric key


## Installation

1. Install libevent version 2.0+

```sh
$ ./configure
$ make
$ make check   # (optional, but highly recommended)
$ sudo make install
```

2. Install wolfssl version 3.4.2+

```sh
$ ./configure --enable-certservice --enable-sniffer CFLAGS="-DWOLFSSL_DH_EXTRA"
$ make
$ make check   # (optional, but highly recommended)
$ sudo make install
```

Notes:
* To enable all Intel speedups use `--enable-intelasm --enable-sp --enable-sp-asm`
* To enable all Aarch64 speedups use `--enable-armasm --enable-sp --enable-sp-asm`

3. Building wolfKeyMgr on *nix from git repository

    Run the autogen script to generate configure, you'll need the autoconf tools
    installed, then proceed to the next step.

```sh
$ ./autogen.sh
```

4. Building wolfKeyMgr on *nix from a release

```sh
$ ./configure
$ make
$ make check   # (optional, but highly recommended)
$ sudo make install
```

Note: A custom install location can be specified using: `./configure --prefix=/opt/local`

## Running ETSI Example

```
$ ./src/wolfkeymgr
$ ./examples/etsi_client/etsi_client
```


## ETSI (Enterprise Transport Security)

### ETSI Request Case (HTTPS GET)

`GET /.well-known/enterprise-transport-security/keys?fingerprints=[fingerprints]`, where:

a) `fingerprints` shall be present and its value, `[fingerprints]`, shall be either empty or shall be a comma-separated list of the hexadecimal string representation where each entry in the list is the static Diffie-Hellman public key fingerprint, as defined in clause 4.3.3, for which the corresponding public/private key pairs are being requested.

b) The key manager shall return a key package that contains the corresponding public/private key pair for each fingerprint for which it has a record. In the unlikely case that the key manager has more than one public/private key pair corresponding to a given fingerprint, it shall return all of them in the key package. If `[fingerprints]` is empty, the actions of the implementation are out of scope of the present document.

c) The key manager shall return an appropriate HTTP error code if there is not at least one matching public/private key pair [12].

Example:

```
GET /.well-known/enterprise-transport-security/keys?fingerprints=00010203040506070809,09080706050403020100
Accept: application/pkcs8, application/cms
```

### ETSI Push (HTTPS PUT)

The key consumer shall support receiving a key package via an HTTP PUT request to a request-target, given here in origin-form, of `/enterprise-transport-security/keys`.


### Asymmetric Key Packages (RFC 5958)

When an Enterprise Transport Security static Diffie-Hellman public/private key pair are sent from the key manager to a key consumer, they shall be packaged using the Asymmetric Key Package defined in IETF RFC 5958 [3]. Each Asymmetric Key Package shall contain one or more OneAsymmetricKey elements. Such an element will be one of either:

a) a static Diffie-Hellman key pair, hereafter referred to as Type A elements; or
b) a private signing key and a certificate, hereafter referred to as Type B elements.

First the case is defined where elements are static Diffie-Hellman key pairs, and so the Asymmetric Key Package shall contain fields and attributes pertaining to these key pairs, defined below. Though certificates are not sent in the same OneAsymmetricKey element as a static key pair, each Asymmetric Key Package may contain one or more Type B elements (server certificates and corresponding private signing keys). Where such Type B elements are sent, all certificates in the Asymmetric Key Package shall be bound to all of the static Diffie-Hellman key pairs in the Asymmetric Key Package. The use of multiple certificates is intended for the situation where it is necessary to provide certificates with different signature algorithms.
With reference to clause 2 of IETF RFC 5958 [3], the Type A OneAsymmetricKey element used to store each key pair
in the Asymmetric Key Package shall have the following fields set as follows:

1) Version shall be set to version 2 (integer value of 1).
2) privateKeyAlgorithm shall be set to the key pair algorithm identifier (see below).
3) privateKey shall be set to the Diffie-Hellman private key encoded as an octet string.
4) publicKey shall be set to the Diffie-Hellman public key encoded as a bit string.
5) Attributes shall include a validity period for the key pair using the attribute defined in clause 15 of IETF RFC 7906 [4].

### Server Certificate Visibility

The ETSI specification part 3 section 4.3.3 requires the TLS server to present a "visibility" information field indicating "Enterrpise Transport Security" is being used.

```
VisibilityInformation ::= SEQUENCE {
    fingerprint OCTET STRING (SIZE(10)),
    accessDescription UTF8String }
```

where the SHA-256 digest of the static Diffie-Hellman public key as transmitted in the key_share extension of the ServerHello message shall be represented as the vector of 32-bit words (H0, H1,..., H7) as defined in FIPS 180-4 [11]. The fingerprint field shall be set to H0||H1||(H2>>16), which is the first 80 bits of the digest vector read in big-endian format. The accessDescription field shall be a human-readable text string that identifies, either generally or specifically, the controlling or authorizing entities or roles or domains, or any combination of these, of any middleboxes that may be allowed access to the Enterprise Transport Security static Diffie-Hellman private key.

See Recommendation ITU-T X.509 (10/2016) | ISO/IEC 9594-8: "Information technology - Open Systems Interconnection - The Directory: Public-key and attribute certificate frameworks".

## Outstanding Features

1) Add TLS mutual authentication to ETSI example.
2) Add example for HTTP server "VisibilityInformation" extension.

## Support

For questions or to request an evaluation package please email facts@wolfssl.com
