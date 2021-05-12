# wolf Key Manager

This is a secure service for Key management based on ETSI Enterprise Transport Security specification. Provides middle-box decryption of TLS traffic.

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
* wkm_[]: Generic wolf / KeyManager functions

## ETSI Design

Server Side
1) KeyGen (Gen Key). Currently ECC SECP25R1 only.
2) Formatting the KeyGen (asymmetric key package)
3) Sending Wire format (HTTPS)
4) Key expiration and notification of new key to peers

Client side
1) Encoding ETSI HTTP request
2) Parsing HTTP response
3) Unbundling asymmetric key

## ETSI Security

All communication between consumer and ETSI Key Manager will use TLS v1.3.

The Enterprise Transport Security profile does not provide per-session forward secrecy. Knowledge of a given static private key can be used to decrypt all sessions encrypted with that key, and forward secrecy for all of those sessions begins when all copies of that static private key have been destroyed.

Typically an organization will use standard TLS 1.3 to connect with external clients to the enterprise network or data centre. For connections within its own data center and could deployments the Enterprise Transport Security profile can be used.

An organization can rotate their keys as frequently as they choose.

The use of X.509 Visibility Information in the TLS server certificate should be used, but is not required for private internal use. The visibility information OID 0.4.0.3523.3.1 provides a public way to indicate the ETSI security profile is being used.

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

### ETSI Request with Groups (key type)

`GET /.well-known/enterprise-transport- security/keys?groups=[groups]&certs=[sigalgs]&context=contextstr`, where:

a) groups shall be non-empty and its value, [groups], shall be a comma-separated list where each entry in the list is a NamedGroup value defined in clause 4.2.7 in IETF RFC 8446 [2], represented in hexadecimal notation, for which an associated static Diffie-Hellman key pair is being requested.

b) certs may be included. If certs is included, its value, [sigalgs], shall be a comma-separated list where each entry is a colon-separated pair of SignatureScheme values defined in clause B.3.1.3 in IETF RFC 8446 [2], in hexadecimal notation. The first value in the pair shall indicate the requested algorithm for the certificate issuer to use to sign the certificate. The second value in the pair shall indicate the requested algorithm to be used to generate the certificate subject's signing key pair. If certs is included, then for each entry in the list, the key consumer shall request one additional server certificate using that scheme, which is bound to all returned key pairs. If certs is not included, then no certificates are being requested, and so none shall be provided by the key manager.

c) context may be included. If context is included, its value, contextstr, is a free string that the key manager shall use to determine what key pair and certificate contents to return. The structure of contextstr is not specified in the present document.

d) The key manager shall return a key package containing a static Diffie-Hellman key pair for each group listed in [groups]that the key manager supports. For each static Diffie-Hellman key pair in the key package, the key manager shall also return a corresponding server certificate for each given signature algorithm pair listed in [sigalgs] that it supports.

e) If no group in [groups] is supported by the key manager, the key manager shall return an appropriate HTTP error code as defined in clause 6 of IETF RFC 7231 [12]. If the key manager is unable to use contextstr, the key manager may return an appropriate HTTP error code, as defined in clause 6 of IETF RFC 7231 [12], or it may handle the error itself in a way outside the scope of the present document.

Example:

```
GET /.well-known/enterprise-transport-security/keys?groups=0x0018,0x001d&certs=0x0401:0x0809,0x0503:0x0503
Accept: application/pkcs8
```

### ETSI Push (HTTPS PUT)

The key consumer shall support receiving a key package via an HTTP PUT request to a request-target, given here in origin-form, of:
`/enterprise-transport-security/keys`

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

The ETSI specification part 3 section 4.3.3 requires the TLS server to present a "visibility" information field indicating "Enterprise Transport Security" is being used.

```
VisibilityInformation ::= SEQUENCE {
    fingerprint OCTET STRING (SIZE(10)),
    accessDescription UTF8String }
```

where the SHA-256 digest of the static Diffie-Hellman public key as transmitted in the key_share extension of the ServerHello message shall be represented as the vector of 32-bit words (H0, H1,..., H7) as defined in FIPS 180-4 [11]. The fingerprint field shall be set to H0||H1||(H2>>16), which is the first 80 bits of the digest vector read in big-endian format. The accessDescription field shall be a human-readable text string that identifies, either generally or specifically, the controlling or authorizing entities or roles or domains, or any combination of these, of any middle-boxes that may be allowed access to the Enterprise Transport Security static Diffie-Hellman private key.

See Recommendation ITU-T X.509 (10/2016) | ISO/IEC 9594-8: "Information technology - Open Systems Interconnection - The Directory: Public-key and attribute certificate frameworks".


## Key Manager Installation

1. Install libevent version 2.0+

```sh
$ ./configure
$ make
$ make check   # (optional, but highly recommended)
$ sudo make install
```

2. Install wolfssl version 3.4.2+

Note: Requires at least wolfSSL v4.7.0 with PR https://github.com/wolfSSL/wolfssl/pull/3832

```sh
$ ./autogen.sh
$ git clone https://github.com/wolfssl/wolfssl
$ cd wolfssl
$ ./autogen.sh
$ ./configure --enable-sniffer CFLAGS="-DWOLFSSL_DH_EXTRA -DWOLFSSL_SNIFFER_WATCH"
$ make
$ make check   # (optional, but highly recommended)
$ sudo make install
```

Notes:

* To enable all Intel (AESNI/AVX) speedups use `--enable-intelasm --enable-sp --enable-sp-asm`
* To enable all ARMv8 (aarch64) speedups use `--enable-armasm --enable-sp --enable-sp-asm`

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


## Key Manager and ETSI Client Command Line Help

Help using `-?`:

```sh
$ ./src/wolfkeymgr -?
wolfKeyManager 0.3
-?          Help, print this usage
-i          Don't chdir / in daemon mode
-b          Daemon mode, run in background
-p <str>    Pid File name, default ./wolfkeymgr.pid
-l <num>    Log Level (1=Error to 4=Debug), default 4
-f <str>    Log file name, default None
-o <num>    Max open files, default  1024
-s <num>    Seconds to timeout, default 60
-r <num>    Key renewal timeout, default 3600
-t <num>    Thread pool size, default  48
-d          TLS Disable Mutual Authentication
-k <pem>    TLS Server TLS Key, default ./certs/server-key.pem
-w <pass>   TLS Server Key Password, default wolfssl
-c <pem>    TLS Server Certificate, default ./certs/server-cert.pem
-A <pem>    TLS CA Certificate, default ./certs/ca-cert.pem
```

```sh
$ ./examples/etsi_client/etsi_client -?
etsi_client 0.3
-?          Help, print this usage
-e          Error mode, force error response
-h <str>    Host to connect to, default localhost
-p <num>    Port to connect to, default 8119
-t <num>    Thread pool size (stress test), default  0
-l <num>    Log Level (1=Error to 4=Debug), default 4
-r <num>    Requests per thread, default 100
-f <file>   <file> to store ETSI response
-u          Use ETSI Push (default is get)
-s <sec>    Timeout seconds (default 10)
-k <pem>    TLS Client TLS Key, default certs/client-key.pem
-w <pass>   TLS Client Key Password, default wolfssl
-c <pem>    TLS Client Certificate, default certs/client-cert.pem
-A <pem>    TLS CA Certificate, default ./certs/ca-cert.pem
```


## Running the Key Manager and ETSI client

```sh
# Start Key Manager with Log Level 3 (Info) and two worker threads
$ ./src/wolfkeymgr -l 3 -t 2
Feb 24 16:24:04 2021: [INFO] Starting Key Manager
Feb 24 16:24:04 2021: [INFO] Binding listener :::8119
Feb 24 16:24:04 2021: [WARNING] Generating new ECC key (index 0)
Feb 24 16:24:04 2021: [INFO] loaded CA certificate file ./certs/ca-cert.pem
Feb 24 16:24:04 2021: [INFO] loaded key file ./certs/server-key.pem
Feb 24 16:24:04 2021: [INFO] loaded certificate file ./certs/server-cert.pem
Feb 24 16:24:04 2021: [INFO] Setting up new ETSI conn item pool
Feb 24 16:24:04 2021: [INFO] Growing ETSI service conn pool
Feb 24 16:24:04 2021: [INFO] Growing ETSI service conn pool
Feb 24 16:24:11 2021: [INFO] Accepted a connection, sent to thread 0
Feb 24 16:24:11 2021: [INFO] New ETSI service conn
Feb 24 16:24:11 2021: [INFO] Got ETSI Request (103 bytes)
Feb 24 16:24:11 2021: [INFO] Creating connection context
Feb 24 16:24:11 2021: [INFO] Sent ETSI Response (194 bytes)
Feb 24 16:24:11 2021: [INFO] EventCb what = 17
Feb 24 16:24:11 2021: [INFO] Peer ended connection, closing

^C
Feb 24 16:24:15 2021: [INFO] SIGINT handled.
Feb 24 16:24:15 2021: [INFO] Ending main thread loop
Feb 24 16:24:15 2021: [INFO] Sending cancel to threads
Feb 24 16:24:15 2021: [INFO] Joining threads
Feb 24 16:24:15 2021: [INFO] Worker thread exiting, tid = 140694064588352
Feb 24 16:24:15 2021: [INFO] Worker thread exiting, tid = 140694056195648
Feb 24 16:24:15 2021: [INFO] Done with main thread dispatching
Feb 24 16:24:15 2021: [ERROR] Current stats:
total   connections  =                   1
completed            =                   1
timeouts             =                   0
current connections  =                   0
max     concurrent   =                   1
uptime  in seconds   =                  11
average response(ms) =               0.046
Feb 24 16:24:15 2021: [INFO] Exit Key Manager (ret 0)


# Start ETSI client with single GET request
$ ./examples/etsi_client/etsi_client -l 3
Feb 24 16:24:11 2021: [INFO] Starting client
Feb 24 16:24:11 2021: [INFO] Connected to ETSI service
Feb 24 16:24:11 2021: [INFO] Sent single get request (103 bytes)
Feb 24 16:24:11 2021: [INFO] Got ETSI response (121 bytes)
Feb 24 16:24:11 2021: [INFO] Pub X: 4958C92FCF1D0C51A1969370B2CB2E846F25A3FBB5B9621020B338E7CCA8C53F
Feb 24 16:24:11 2021: [INFO] Pub Y: 3EE0E7AF506A86380D11450A39BF3561917824F3A8BEC44AEF3B83C25F058DF9
```

## Stress Testing ETSI Server / Client

* Use the thread pool "-t" to spin up more threads.
* Use the ETSI client "-r" to make additional requests per thread.


## Support

For questions or to request an evaluation package please email facts@wolfssl.com