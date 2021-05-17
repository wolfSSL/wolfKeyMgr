/* etsi_client.h
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

#ifndef ETSI_CLIENT_H
#define ETSI_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

/* for client tests only */
#define WOLFKM_DEFAULT_HOST         "localhost"
#define WOLFKM_DEFAULT_ETSISVC_PORT "8119"
#define WOLFKM_DEFAULT_REQUESTS     1       /* per thread */

/* example certificate and key for mutual authentication to key manager */
/* see ./certs/test-cert.sh for generation and signing */
#define WOLFKM_ETSICLIENT_CA        "./certs/ca-cert.pem"
#define WOLFKM_ETSICLIENT_KEY      "certs/client-key.pem"
#define WOLFKM_ETSICLIENT_PASS     "wolfssl"
#define WOLFKM_ETSICLIENT_CERT     "certs/client-cert.pem"


#ifdef __cplusplus
}
#endif

#endif /* ETSI_CLIENT_H */
