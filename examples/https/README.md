# HTTPS (TLS) Examples

These examples demonstrate a basic HTTPS server and client for testing the ETSI middle-box decryption with the wolf Key Manager tool.

## TlS Server

Usage: `./examples/https/server`

```
TLS Server: Port 443
TLS Accept 1c1e:e4ee::
Jun 07 16:25:52 2021: [DEBUG] HTTP GET
Jun 07 16:25:52 2021: [DEBUG] 	Version: HTTP/1.1
Jun 07 16:25:52 2021: [DEBUG] 	URI: /
Jun 07 16:25:52 2021: [DEBUG] 	Headers: 6
Jun 07 16:25:52 2021: [DEBUG] 		Host: : localhost
Jun 07 16:25:52 2021: [DEBUG] 		Accept: : text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Jun 07 16:25:52 2021: [DEBUG] 		Accept-Language: : en-us
Jun 07 16:25:52 2021: [DEBUG] 		Connection: : keep-alive
Jun 07 16:25:52 2021: [DEBUG] 		Accept-Encoding: : gzip, deflate, br
Jun 07 16:25:52 2021: [DEBUG] 		User-Agent: : Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.2 Safari/605.1.15
```

Note: Chrome limits use of self-signed certificates with localhost. You can use `chrome://flags/#allow-insecure-localhost` in chrome to enable support.
