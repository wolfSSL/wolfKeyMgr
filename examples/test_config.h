/* test_config.h
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolf Key Manager.
 *
 * wolfKeyMgr is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfKeyMgr is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef WKM_TEST_CONFIG_G
#define WKM_TEST_CONFIG_G

#ifdef __cplusplus
extern "C" {
#endif

/* ETSI client testing configuration */
#define ETSI_TEST_HOST            "localhost"
#define ETSI_TEST_PORT            8119
#define ETSI_TEST_PORT_STR        "8119"
#define ETSI_TEST_TIMEOUT_MS      2
#define ETSI_TEST_KEY_TYPE        ETSI_KEY_TYPE_SECP256R1

/* example certificate and key for mutual authentication to key manager */
/* see ./certs/test-cert.sh for generation and signing */
#define ETSI_TEST_CLIENT_CA       "certs/ca-cert.pem"
#define ETSI_TEST_CLIENT_KEY      "certs/client-key.pem"
#define ETSI_TEST_CLIENT_PASS     "wolfssl"
#define ETSI_TEST_CLIENT_CERT     "certs/client-cert.pem"

/* HTTPS testing configuration */
#define HTTPS_TEST_HOST           "localhost"
#define HTTPS_TEST_PORT           443
#define HTTPS_TEST_TIMEOUT_SEC    30
#define HTTPS_TEST_MAX_DATA       512

/* see ./certs/test-cert.sh for generation and signing */
/* this is a self signed test cert server presents */
#define HTTPS_TEST_CA             "certs/test-cert.pem"
#define HTTPS_TEST_CERT           "certs/test-cert.pem"
#define HTTPS_TEST_KEY            "certs/test-key.pem"

/* HTTP */
#define HTTPS_TEST_REQUEST       "/index.html"
#define HTTPS_TEST_RESPONSE      "<html><body><h1>It works!</h1></body></html>"


#ifdef __cplusplus
}
#endif

#endif /* WKM_TEST_CONFIG_G */
