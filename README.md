# wolf Key Manager for Enterprise Transport Security (ETS)

This is a secure key management service for providing middle-box decryption of TLS traffic.

The library includes examples to demonstrate full passive decryption of an HTTPS server. We also have a demo package for Apache httpd available by request.

## Design

Based on:
* ETSI TS 103 523-3 V1.3.1 (2019-08)
* IETF RFC 5958

## Features

* Generation of keys using an asymmetric key package request
* Low level socket handling using libevent, which is a portable framework for handling sockets
* HTTPS server supports GET/PUT requests using HTTP/1.1
* The CA key can be local PKCS #8 (simple password/encrypted), PKCS #11 HSM or TPM 2.0
* TLS v1.3 is used for securing connections to server
* Secure key vault protected with RSA and AES GCM

## Layout of files

* keymanager.c: The main entry point
* sock_mgr.c: The libevent socket manager
* svc_[]: Services exposed (ETS)
* mod_[]: Modules for support (HTTP, TLS, Socket, ETS and Vault)
* wkm_[]: Generic wolf / KeyManager functions

## ETS Design

Server Side
1) KeyGen (Gen Key)
2) Formatting the KeyGen (asymmetric key package)
3) Sending Wire format (HTTPS)
4) Key expiration and notification of new key to peers

Client side
1) Encoding ETS HTTP request
2) Parsing HTTP response
3) Unbundling asymmetric key


## Key Manager Build and Install

1. Install wolfssl version v4.8.0+

```sh
$ ./autogen.sh
$ git clone https://github.com/wolfssl/wolfssl
$ cd wolfssl
$ ./autogen.sh
$ ./configure --enable-sniffer --enable-curve25519 --enable-curve448 CFLAGS="-DWOLFSSL_DH_EXTRA"
$ make
$ make check   # (optional, but highly recommended)
$ sudo make install
```

Notes:

* To enable all Intel (AESNI/AVX) speedups use `--enable-intelasm --enable-sp --enable-sp-asm`
* To enable all ARMv8 (aarch64) speedups use `--enable-armasm --enable-sp --enable-sp-asm`

* Requires at least wolfSSL v5.0.0 with PR:
   - https://github.com/wolfSSL/wolfssl/pull/4522 (required for Curve448)

2. Install libevent version 2.0+

Most platforms have a `libevent-dev` package available.
Example: `sudo apt install libevent-dev`.

To build manually:

```sh
$ curl -o libevent-2.1.12-stable.tar.gz -L https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/libevent-2.1.12-stable.tar.gz
$ tar xzvf libevent-2.1.12-stable.tar.gz
$ cd libevent-2.1.12-stable
$ ./configure --disable-openssl
$ make
$ make check   # (optional, but highly recommended)
$ sudo make install
```

3. Install libpcap for middle-box decryption example (or build with `--disable-sniffer`)

* Mac OS/X: `brew install libpcap`
* Debian/Ubuntu: `sudo apt install libpcap-dev`
* RedHat/CentOS: 'sudo yum install libpcap-dev`
* Windows: Download and install `WinPcap`

4. Building wolfKeyMgr on *nix

```sh
$ ./autogen.sh # if cloned from git repository
$ ./configure
$ make
$ make check   # (optional, but highly recommended)
$ sudo make install
```

Notes:
* A custom install location can be specified using: `./configure --prefix=/opt/local`
* `autogen.sh` is script to generate configure, you'll need the autoconf tools
installed, then proceed to the next step.
* `src/wolfkeymgr` is the key manager service / dameon. A make install will typically put it into `/usr/local/bin/wolfkeymgr` or ``/usr/bin/wolfkeymgr`.

## Examples

The wolf Key Manager includes examples for ETS client tests, HTTPS server / client and middle-box decryption.

All test parameters for these examples are in the `examples/test_config.h`.

### Key Manager Service

This application handles secure distribution and optional storage of the generated ephemeral keys.

```sh
$ ./src/wolfkeymgr -?
wolfKeyManager 1.1
-?          Help, print this usage
-i          Do not chdir / in daemon mode
-b          Daemon mode, run in background
-p <str>    Pid File name, default ./wolfkeymgr.pid
-P <port>   Listener port, default 8119
-l <num>    Log Level (1=Error to 4=Debug), default 4
-f <str>    Log file name, default None
-o <num>    Max open files, default  1024
-s <num>    Seconds to timeout non-push connections, default 60
-r <num>    Key renewal timeout, default 3600
-u <num>    Key renewal max use count, default 100
-t <num>    Thread pool size, default  16
-k <pem>    TLS Server TLS Key, default ./certs/server-rsa-key.pem
-w <pass>   TLS Server Key Password, default wolfssl
-c <pem>    TLS Server Certificate, default ./certs/server-rsa-cert.pem
-A <pem>    TLS CA Certificate, default ./certs/ca-cert.pem
-K <keyt>   Key Type: SECP256R1, FFDHE_2048, X25519 or X448 (default SECP256R1)
-v <file>   Vault file for key storage, default ./wolfkeymgr.vault
```

To exit the key manager use ctrl+c.

### ETS Test client

This demonstrates secure interactions with the key manager service using the ETS HTTPS GET/PUT commands for different key types.

```sh
$ ./examples/ets_test/ets_test -?
ets_test 1.1
-?          Help, print this usage
-e          Error mode, force error response
-h <str>    Host to connect to, default localhost
-p <num>    Port to connect to, default 8119
-t <num>    Thread pool size (stress test), default  0
-l <num>    Log Level (1=Error to 4=Debug), default 4
-r <num>    Requests per thread, default 1
-f <file>   <file> to store ETS response
-u          Use ETS Push (default is get)
-s <sec>    Timeout seconds (default 10)
-k <pem>    TLS Client TLS Key, default certs/client-key.pem
-w <pass>   TLS Client Key Password, default wolfssl
-c <pem>    TLS Client Certificate, default certs/client-cert.pem
-A <pem>    TLS CA Certificate, default certs/ca-cert.pem
-K <keyt>   Key Type: SECP256R1, FFDHE_2048, X25519 or X448 (default SECP256R1)
-F <fprint> Fingerprint to find (first 80-bit of pkey hash as hex string)
-C <name>   Unique key name (used for multiple servers)
```

This client also support stress testing options:
* Use the thread pool "-t" to spin up more threads.
* Use the ETS test client "-r" to make additional requests per thread.
* Use the "-F" argument to get key for specific fingerprint (hex string of hash of public key - first 80 bits / 10 bytes)
* Use the "-C" command to include context string (used for multiple servers).

#### ETS Fingerprint

The fingerprint is a SHA-256 hash of the ephemeral public key with the first 80 bits (10 bytes) in big endian format. If the fingerprint is blank the current active key for that TLS group will be returned (assuming it is within the expiration and use count restrictions).

The fingerprint is used to lookup an ephemeral key based on public key using the following scheme:
* ECC: Public X and Y hashed with SHA256 (first 10 bytes)
* DH: Public key hashed with SHA256 (first 10 bytes)

#### ETS Context String

The context string is used to specify additional information to the key manager to distribute keys for multiple servers.

### HTTP Server / Client

We have included a simple HTTPS server to show getting the static ephemeral key using the ETS client and key manager.

```
./examples/https/server

HTTPS Server: Port 443

Jun 15 14:26:54 2021: [INFO] Connected to ETS service
Jun 15 14:26:54 2021: [INFO] Sent get request (117 bytes)
Jun 15 14:26:54 2021: [DEBUG] HTTP HTTP/1.1
Jun 15 14:26:54 2021: [DEBUG] 	Code 200: OK
Jun 15 14:26:54 2021: [DEBUG] 	Headers: 4
Jun 15 14:26:54 2021: [DEBUG] 		Content-Type: : application/pkcs8
Jun 15 14:26:54 2021: [DEBUG] 		Connection: : Keep-Alive
Jun 15 14:26:54 2021: [DEBUG] 		Expires: : Tue, 15 Jun 2021 15:26:46 PDT
Jun 15 14:26:54 2021: [DEBUG] 		Content-Length: : 121
Jun 15 14:26:54 2021: [DEBUG] 	Body Size: 121
Jun 15 14:26:54 2021: [INFO] Got ETS response (121 bytes)
Got ETS static ephemeral key (121 bytes)
Jun 15 14:26:54 2021: [INFO] SECP256R1: E24EF332747DF70CD4E5

TLS Accept 127.0.0.1
Jun 15 14:27:01 2021: [DEBUG] HTTP GET
Jun 15 14:27:01 2021: [DEBUG] 	Version: HTTP/1.1
Jun 15 14:27:01 2021: [DEBUG] 	URI: /
Jun 15 14:27:01 2021: [DEBUG] 	Headers: 6
Jun 15 14:27:01 2021: [DEBUG] 		Host: : localhost
Jun 15 14:27:01 2021: [DEBUG] 		Accept: : text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Jun 15 14:27:01 2021: [DEBUG] 		Accept-Language: : en-us
Jun 15 14:27:01 2021: [DEBUG] 		Connection: : keep-alive
Jun 15 14:27:01 2021: [DEBUG] 		Accept-Encoding: : gzip, deflate, br
Jun 15 14:27:01 2021: [DEBUG] 		User-Agent: : Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1 Safari/605.1.15

ETS Key Cached (valid for 3585 sec)
```

### Middle-Box Decryption of TLS traffic

This is a passive way to decrypt TLS traffic including Perfect Forward Secrecy (PFS) TLS v1.3 where a new ephemeral key is used for each session.

This can be run in a real-time mode capturing ethernet traffic on a port for one or more server interfaces. It can also be run passing a previously captured pcap file.

```sh
$ ./examples/middlebox/decrypt -?
decrypt 1.1
usage: ./decrypt or ./decrypt pcapFile keyServerURL [server] [port] [password]
-?           Help, print this usage
pcapFile     A previously saved pcap file
keyServerURL Key Manager URL or private key as PEM (default https://localhost:8119)
server       The server’s IP address (v4 or v6) (default 127.0.0.1)
port         The server port to sniff (default 443)
password     Private Key Password if required
```


## Demo Usage

1. Start the key manager: `./src/wolfkeymgr`
2. Run the HTTPS server `./examples/https/server`
3. Run the middle-box decryption `./examples/middlebox/decrypt` and use the default parameters.
4. Open a web browser to `https://localhost` or run the HTTP client example `./examples/https/client`.
5. In the middle-box decryption window you will see the decrypted HTTPS traffic.

Notes:

1) Most browsers will show a security warning because the certificate common name for localhost is a security risk. Here is not to bypass this for each browser:
* FireFox: "Warning: Potential Security Risk Ahead". Click "Advanced". Click "Accept the Risk and Continue"
* Chrome: Launch Chrome browser and then visit: `chrome://flags/#allow-insecure-localhost`. Using “Allow invalid certificates for resources loaded from localhost” drop-down change the setting from Disabled to Enabled. Relaunch Chrome browser to enable the feature. Doing this will “Allow insecure connections on localhost in Chrome” and fix the issue.

2) Some browsers behave different with localhost and will not send the SNI extension, which may cause issues. Switching to a physical ethernet interface and IP address (example https://192.168.0.4:443) may work better.

3) To generate a different common name in the self-signed certificate see `wolfKeyMgr/certs/gen-certs.sh` and modify `CN=` then re-run `./certs/gen-certs.sh` or manually run the following command:
`openssl req -new -x509 -nodes -key ./certs/test-key.pem -out ./certs/test-cert.pem -sha256 -days 7300 -batch -subj "/C=US/ST=CA/L=Seattle/O=wolfSSL/OU=Development/CN=localhost/emailAddress=info@wolfssl.com"`. For testing it might be useful to setup a fake domain in `/etc/hosts`.

4) If you get "Permission denied" errors try adding `sudo` to the commands.


### Demo example output

```
% ./src/wolfkeymgr
Aug 03 15:05:21 2021: [INFO] Starting Key Manager
Aug 03 15:05:21 2021: [INFO] 	To exit use ctrl+c
Aug 03 15:05:21 2021: [INFO] loaded CA certificate file ./certs/ca-cert.pem
Aug 03 15:05:21 2021: [INFO] loaded key file ./certs/server-rsa-key.pem
Aug 03 15:05:21 2021: [INFO] loaded certificate file ./certs/server-rsa-cert.pem
Aug 03 15:05:21 2021: [ERRO] Vault open failed, creating new
Aug 03 15:05:21 2021: [INFO] Vault ./wolfkeymgr.vault opened (0 bytes)
Aug 03 15:05:21 2021: [INFO] Version: 1
Aug 03 15:05:21 2021: [INFO] Header Size: 296
Aug 03 15:05:21 2021: [INFO] Item Count: 0
Aug 03 15:05:21 2021: [INFO] Total Size: 0
Aug 03 15:05:21 2021: [WARN] Generating new SECP256R1 key
Aug 03 15:05:21 2021: [INFO] Binding listener :::8119
Aug 03 15:05:21 2021: [INFO] Setting up new ETS conn item pool
Aug 03 15:05:21 2021: [INFO] Growing ETS service conn pool
Aug 03 15:05:21 2021: [INFO] Growing ETS service conn pool
Aug 03 15:05:21 2021: [INFO] SECP256R1: E24EF332747DF70CD4E5
Aug 03 15:05:21 2021: [WARN] Vault Auth: Setting up new encryption key
Aug 03 15:05:21 2021: [INFO] Next key renewal 3600 seconds
```

```
 % ./examples/https/server
HTTPS Server: Port 443
Aug 03 15:09:50 2021: [INFO] Connected to ETS service
```

```
 % ./examples/middlebox/decrypt
1. lo0 (No description available)
2. en0 (No description available)
Enter the interface number (1-2) [default: 1]:
server = 127.0.0.1
server = ::1
server = fe80::1
Enter the port to scan [default: 443]:
Enter the server key [default: https://localhost:8119]:
Aug 03 15:07:33 2021: [INFO] Connected to ETS service
...

Got ETS static ephemeral key (121 bytes)
Aug 03 15:07:33 2021: [INFO] SECP256R1: E24EF332747DF70CD4E5
Loaded key for fe80::1:443
SSL App Data(30:323):GET / HTTP/1.1
Host: localhost
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-us
Connection: keep-alive
Accept-Encoding: gzip, deflate, br
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1 Safari/605.1.15


SSL App Data(32:132):HTTP/1.1 200 OK
Content-Type: text/html
Connection: keep-alive
Content-Length: 44

<html><body><h1>It works!</h1></body></html>
```

## Features Missing

* Find error response message (currently disconnects with socket FIN)
* X509 Visibility support
* TLS v1.2 ephemeral key support


## Support

For questions or to request an evaluation package please email facts@wolfssl.com
