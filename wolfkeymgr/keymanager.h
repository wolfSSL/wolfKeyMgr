/* keymanager.h
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

#ifndef KEYMANAGER_H
#define KEYMANAGER_H

/* wolfssl headers */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>


/* Key Manager Headers */
#include "wolfkeymgr/wkm_types.h"
#include "wolfkeymgr/wkm_utils.h"
#include "wolfkeymgr/mod_http.h"
#include "wolfkeymgr/mod_etsi.h"
#include "wolfkeymgr/sock_mgr.h"
#include "wolfkeymgr/svc_etsi.h"


/* wolfssl headers */
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/random.h>


/* default program constants */
#ifndef WOLFKM_DEFAULT_LOG_NAME
#define WOLFKM_DEFAULT_LOG_NAME     NULL
#endif
#ifndef WOLFKM_DEFAULT_PID
#define WOLFKM_DEFAULT_PID          "./wolfkeymgr.pid"
#endif
#ifndef WOLFKM_ETSISVC_PORT
#define WOLFKM_ETSISVC_PORT         "8119"
#endif
#ifndef WOLFKM_ETSISVC_KEY_PASSWORD
#define WOLFKM_ETSISVC_KEY_PASSWORD "wolfssl"
#endif
#ifndef WOLFKM_ETSISVC_CA
#define WOLFKM_ETSISVC_CA           "./certs/ca-cert.pem"
#endif
#ifndef WOLFKM_ETSISVC_KEY
#define WOLFKM_ETSISVC_KEY          "./certs/server-rsa-key.pem"
#endif
#ifndef WOLFKM_ETSISVC_CERT
#define WOLFKM_ETSISVC_CERT         "./certs/server-rsa-cert.pem"
#endif
#ifndef WOLFKM_ETSISVC_VAULT
#define WOLFKM_ETSISVC_VAULT        "./wolfkeymgr.vault"
#endif

#ifndef WOLFKM_DEFAULT_FILES
#define WOLFKM_DEFAULT_FILES        1024      /* default max open files */
#endif
#ifndef WOLFKM_DEFAULT_TIMEOUT
#define WOLFKM_DEFAULT_TIMEOUT      60        /* default timeout in seconds */
#endif
#ifndef WOLFKM_KEY_RENEW_TIMEOUT
#define WOLFKM_KEY_RENEW_TIMEOUT    (60*60)   /* key renewal timeout (1 hour) */
#endif
#ifndef WOLFKM_KEY_RENEW_MAX_USES
#define WOLFKM_KEY_RENEW_MAX_USES   100       /* key renewal max uses */
#endif
#ifndef WOLFKM_CONN_ITEMS
#define WOLFKM_CONN_ITEMS           1024      /* new conn item pool size */
#endif
#ifndef WOLFKM_BACKOFF_TIME
#define WOLFKM_BACKOFF_TIME         10000     /* in microseconds */
#endif

/* Determine default ETSI key type */
#ifndef WOLFKM_ETSISVC_DEF_KEY_TYPE
    #ifdef HAVE_ECC
        #define WOLFKM_ETSISVC_DEF_KEY_TYPE  ETSI_KEY_TYPE_SECP256R1
    #elif !defined(NO_DH) && defined(WOLFSSL_DH_EXTRA)
        #define WOLFKM_ETSISVC_DEF_KEY_TYPE  ETSI_KEY_TYPE_FFDHE_2048
    #elif defined(HAVE_CURVE25519)
        #define WOLFKM_ETSISVC_DEF_KEY_TYPE  ETSI_KEY_TYPE_X25519
    #elif defined(HAVE_CURVE448)
        #define WOLFKM_ETSISVC_DEF_KEY_TYPE  ETSI_KEY_TYPE_X25519
    #endif
#endif

#endif /* KEYMANAGER_H */
