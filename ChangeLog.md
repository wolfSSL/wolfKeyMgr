# wolfKeyMgr v1.1 (Nov 9, 2021)
* Added support for x448 (curve448).
* Added argument support to HTTP server.
* Fixed `ets_test` help messages for fingerprint and context string.
* Fix to use `memmove` for relocation of memory within same buffer. 
* Fixed sanitizer and scan-build reports.
* Fixed support for `HAVE_PUBLIC_FFDHE` not defined.
* Fixed HTTPS example server to send shutdown.
* Renamed "ETSI" API/structs to be "ETS" (Enterprise Transport Security) not ETSI org.
* Improved error reporting when connection to key manager fails.
* Improved help on middlebox/decrypt tool.

# wolfKeyMgr v1.0 (Sep 1, 2021)
* Support for Curve25519 and Curve448 in key manager.
* Support for Curve25519 in middle-box decryption.
* Support for loading all supported ephemeral keys.
* Refactor common ETSI client test code.
* Improved middle-box decryption to better handle concurrent keys of different formats.
* Improved handling for not compiled in cases.
* Fix for ./configure config summary.

# wolfKeyMgr v0.11 (Aug 4, 2021)
* Fix to use fingerprint to find keys.
* Improved the fingerprint calculation code and added hash.
* Added multiple server support using `contextStr`.
* Add unit test to `make check`.
* Improve `src/wolfkeymgr` exit documentation.
* Added example output for demo to `README.md`.

# wolfKeyMgr v0.10 (Jul 30, 2021)
* Added secure vault for key storage using RSA and AES GCM.
* Added support for multiple active key types.
* Added key find support.
* Added middlebox decrypt PCAP replay support.
* Added key max use count to limit uses of an ephemeral key.
* Added computed "name" based on public key for ETSI key.
* Added API unit test framework.
* Added `--enable-vault=clear` option to optionally disable vault encryption.
* Fix to not start listeners until key/cert/vault setup.
* Fixed issue with worker threads generating new keys and not using existing ones.
* Fix for https example server listen error handling.
* Fixed gets with newline.
* Fix for middlebox/decrypt default loopback interface selection. Default to first interface (1).
* Fix for request / response collision. Centralize the max buffer sizes.
* Moved key gen into ETSI module.
* Rename `wolfEtsiKeyGet` to `wolfEtsiKeyGetPtr`.
* Refactor to support multiple active key types.
* Improved printing of public key name in logs.
* Improved error for key generation failure.
* Improve libevent and browser issue documentation.
* Improve middle-box decryption error handling for permissions issue.
* Cleanups to remove `WOLFKM_ETSI_SERVICE` and `disableMutalAuth`.
* Move the ETSI documentation into `docs/README.md`. Remove copies of specs and use links.
* Cleanup ETSI service configuration and defaults.

# wolfKeyMgr v0.9 (Jun 15, 2021)
* Added HTTPS server / client for local testing.
* Added middle-box decryption example (uses the wolfSSL sniffer module).
* Fixes for HTTP engine parsing.
* Improve socket select error reporting for timeout vs. error.
* Added ETSI client push support.
* Added ability to specify default key type for Key Manager.
* Added better debug printing for key used.

# wolfKeyMgr v0.8 (May 24, 2021)
* Added DH key support.
* Added HTTP support for fingerprints, groups and contextstr.
* Added ETSI client key argument (`-K`).
* Fixes for URI encoding.
* Refactor of service to support more key types.
* Refactor of internal structure names to leading upper case.
* Removed the "noTLS" build option.

# wolfKeyMgr v0.7 (May 17, 2021)
* Fix for HTTP header encode/decode conflict with variable `i`.
* Fix for HTTP server response parsing with no null termination issue.
* Added expires data to HTTP response.
* Added ETSI client GET caching.
* Added etsi_client `-r` support for GET (test caching).

# wolfKeyMgr v0.6 (May 12, 2021)
* Fix for ETSI client to properly detect socket error with non-blocking connect.
* Added EtsiKey struct and modified the wolfEtsiClientGet() API.
* Implemented some ETSI key helpers.
* Added stub API's for future push/find with callbacks.
* Progress with handling key expiration data and other key types.

# wolfKeyMgr v0.5 (May 10, 2021)
* Fix for missing "make dist" files.
* Fix possible seg fault if pid creation failed.
* Fixed issue with forcful close of listen socket causing loop.
* Added missing files for cert generation.
* Added fingerprint to push syntax.
* Added TODO item for key expires.
* Remove certservice requirement.
* Cleanup unused `KeyManager_t`.
* Do not track and ignore options.h.
* Spelling fixes.

# wolfKeyMgr v0.4 (Mar 1, 2021)
* Fix for stray `wolfSSL_CTX_free`.
* Added mutex protection on ETSI client.
* Added URL decoding to HTTP module.
* Added SIGPIPE ignore to ETSI client.
* Added test key/certificate for Apache HTTPD.
* Added "-r" argument for key manager for the key update interval.

# wolfKeyMgr v0.3 (Feb 24, 2021)
* Added TLS mutual authentication.
* Improved logging and flushing of logging on SIGINT/SIGTERM.
* Added SIGTERM support.
* Improved README.md example steps.
* Fixes for libwolfkeymgr headers for shared use.
* Fix for missing shared library header files. Stop tracking options.h.

# wolfKeyMgr v0.2 (Feb 19, 2021)
* Fixes for threading.
* Added libwolfkeymgr for general use API's.
* Added ETSI client API's.
* Added full HTTP server/client support.
* Abstraction of all modules to library for generic socket, TLS, HTTP and ETSI functions.
* Added non-blocking support for client.
* Added version header.
* Improvement to performance.

# wolfKeyMgr v0.1 - Initial version (Feb 15, 2021)
* Supports ETSI (Enterprise Transport Security) key manager for Get and Push of TLS static ephemeral keys.
* Supports Certificate Signing (enabled with `--enable-certsvc`) disabled by default.
