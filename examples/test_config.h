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

#include "wolfkeymgr/mod_ets.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ETS client testing configuration */
#define ETS_TEST_HOST             "localhost"
#define ETS_TEST_PORT             8119
#define ETS_TEST_PORT_STR         "8119"
#define ETS_TEST_TIMEOUT_MS       2
#define ETS_TEST_KEY_TYPE         ETS_KEY_TYPE_SECP256R1
#define ETS_TEST_URL              "https://" ETS_TEST_HOST ":" ETS_TEST_PORT_STR

/* Example certificate and key for mutual authentication to key manager.
 * See ./certs/test-cert.sh for generation and signing. */
#define ETS_TEST_CLIENT_CA        "certs/ca-cert.pem"
#define ETS_TEST_CLIENT_KEY       "certs/client-key.pem"
#define ETS_TEST_CLIENT_PASS      "wolfssl"
#define ETS_TEST_CLIENT_CERT      "certs/client-cert.pem"

/* HTTPS testing configuration */
#define HTTPS_TEST_HOST           "localhost"
#define HTTPS_TEST_PORT           443
#define HTTPS_TEST_TIMEOUT_SEC    30
#define HTTPS_TEST_MAX_DATA       512

/* See ./certs/test-cert.sh for generation and signing.
 * This is a self signed test cert the server can present. */
#define HTTPS_TEST_CA             "certs/test-cert.pem"
#define HTTPS_TEST_CERT           "certs/test-cert.pem"
#define HTTPS_TEST_KEY            "certs/test-key.pem"

/* HTTP */
#define HTTPS_TEST_REQUEST        "/index.html"
#define HTTPS_TEST_RESPONSE       "<html><body><h1>It works!</h1></body></html>"

/* ETS Client Helper Functions */
typedef int (*ets_client_key_cb)(EtsKey* key, void* cbCtx);
int  ets_client_connect(const char* urlStr);
int  ets_client_get(const char* urlStr, EtsKey* key, int keyType);
int  ets_client_get_all(const char* urlStr, ets_client_key_cb cb, void* cbCtx);
int  ets_client_find(const char* urlStr, EtsKey* key, int namedGroup, const byte* pub, word32 pubSz);
void ets_client_cleanup(void);


#ifndef EX_USAGE
#define EX_USAGE 2
#endif

#ifndef EXIT_FAILURE
#define EXIT_FAILURE 1
#endif


#ifdef __cplusplus
}
#endif

#endif /* WKM_TEST_CONFIG_G */
