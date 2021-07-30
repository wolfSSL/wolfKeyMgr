/* mod_etsi.h
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

#ifndef WOLFKM_ETSI_H
#define WOLFKM_ETSI_H

#ifdef __cplusplus
extern "C" {
#endif

#include "wolfkeymgr/wkm_types.h"
#include "wolfkeymgr/mod_http.h"
#include "wolfkeymgr/mod_socket.h"
#include "wolfkeymgr/mod_tls.h"


#ifndef ETSI_MAX_REQUEST_SZ
#define ETSI_MAX_REQUEST_SZ  MAX_REQUEST_SIZE
#endif
#ifndef ETSI_MAX_RESPONSE_SZ
#define ETSI_MAX_RESPONSE_SZ MAX_RESPONSE_SIZE
#endif

/* Determine max build-time DH key sizes */
#if !defined(NO_DH) && !defined(MAX_DH_PRIV_SZ) && !defined(MAX_DH_PUB_SZ)
#if defined(HAVE_FFDHE_8192)
    #define MAX_DH_PRIV_SZ 52
    #define MAX_DH_PUB_SZ  1024
#elif defined(HAVE_FFDHE_6144)
    #define MAX_DH_PRIV_SZ 46
    #define MAX_DH_PUB_SZ  768
#elif defined(HAVE_FFDHE_4096)
    #define MAX_DH_PRIV_SZ 39
    #define MAX_DH_PUB_SZ  512
#elif defined(HAVE_FFDHE_3072)
    #define MAX_DH_PRIV_SZ 34
    #define MAX_DH_PUB_SZ  384
#elif defined(HAVE_FFDHE_2048)
    #define MAX_DH_PRIV_SZ 29
    #define MAX_DH_PUB_SZ  256
#else
    #error No DH FFDHE parameters enabled!
#endif
#endif

/* opaque type for EtsiClientCtx (pointer reference only) */
typedef struct EtsiClientCtx EtsiClientCtx;

typedef enum EtsiClientType {
    ETSI_CLIENT_UNKNOWN,
    ETSI_CLIENT_GET,  /* ask for key if current one is expired */
    ETSI_CLIENT_PUSH, /* remain connected and server will push new key */
} EtsiClientType;

typedef enum EtsiKeyType {
    ETSI_KEY_TYPE_UNKNOWN = 0,
    /* Named Groups: defined in clause 4.2.7 in IETF RFC 8446 */
    ETSI_KEY_TYPE_SECP160K1 = 15,
    ETSI_KEY_TYPE_SECP160R1 = 16,
    ETSI_KEY_TYPE_SECP160R2 = 17,
    ETSI_KEY_TYPE_SECP192K1 = 18,
    ETSI_KEY_TYPE_SECP192R1 = 19,
    ETSI_KEY_TYPE_SECP224K1 = 20,
    ETSI_KEY_TYPE_SECP224R1 = 21,
    ETSI_KEY_TYPE_SECP256K1 = 22,
    ETSI_KEY_TYPE_SECP256R1 = 23,
    ETSI_KEY_TYPE_SECP384R1 = 24,
    ETSI_KEY_TYPE_SECP521R1 = 25,
    ETSI_KEY_TYPE_BRAINPOOLP256R1 = 26,
    ETSI_KEY_TYPE_BRAINPOOLP384R1 = 27,
    ETSI_KEY_TYPE_BRAINPOOLP512R1 = 28,
    ETSI_KEY_TYPE_X25519    = 29,
    ETSI_KEY_TYPE_X448      = 30,
    ETSI_KEY_TYPE_FFDHE_2048 = 256,
    ETSI_KEY_TYPE_FFDHE_3072 = 257,
    ETSI_KEY_TYPE_FFDHE_4096 = 258,
    ETSI_KEY_TYPE_FFDHE_6144 = 259,
    ETSI_KEY_TYPE_FFDHE_8192 = 260,

    ETSI_KEY_TYPE_MIN = ETSI_KEY_TYPE_SECP160K1,
    ETSI_KEY_TYPE_MAX = ETSI_KEY_TYPE_FFDHE_8192,
} EtsiKeyType;

/* max key public name (can be adjusted at build-time if desired) */
#ifndef ETSI_MAX_KEY_NAME
#define ETSI_MAX_KEY_NAME 64
#endif
#define ETSI_MAX_KEY_NAME_STR (ETSI_MAX_KEY_NAME*2+1)

#ifndef ETSI_MAX_FINGERPRINT
#define ETSI_MAX_FINGERPRINT 10 /* 80-bits - per ETSI spec */
#endif
#define ETSI_MAX_FINGERPRINT_STR (ETSI_MAX_FINGERPRINT*2+1)

typedef struct EtsiKey {
    enum EtsiKeyType type;
    byte   fingerprint[ETSI_MAX_FINGERPRINT];
    word32 nameSz;
    byte   name[ETSI_MAX_KEY_NAME]; /* public info - first 64-bytes */
    word32 responseSz;
    byte   response[ETSI_MAX_RESPONSE_SZ];
    time_t expires; /* from HTTP HTTP_HDR_EXPIRES */

    /* Internal Variables */
    word32 useCount; /* times this key has been used */
    unsigned char isDynamic:1; /* key is dynamically allocated */
} EtsiKey;

/* Key callback Function */
/* if return code is not zero then socket will be closed */
typedef int (*EtsiKeyCallbackFunc)(EtsiClientCtx* client, EtsiKey* key, void* cbCtx);

/* ETSI Client API's */
/* allocate new ETSI client context */
WOLFKM_API EtsiClientCtx* wolfEtsiClientNew(void);

/* Setup the TLS mutual authentication key/certificate for accessing the ETSI Key Manager */
WOLFKM_API int wolfEtsiClientSetKey(EtsiClientCtx* client,
    const char* keyFile,  const char* keyPassword, const char* certFile,
    int fileType);

/* Setup the trusted CA certificate to verify authentic ETSI Key Manager */
WOLFKM_API int wolfEtsiClientAddCA(EtsiClientCtx* client,
    const char* caFile);

/* Open TLS session to ETSI Key Manager */
WOLFKM_API int wolfEtsiClientConnect(EtsiClientCtx* client, 
    const char* host, word16 port, int timeoutSec);

WOLFKM_API int wolfEtsiClientMakeRequest(EtsiClientType type, const char* fingerprint,
    const char* groups, const char* contextstr, byte* request, word32* requestSz);

/* Get will return current key for provided fingerprint */
/* Fingerprint is a SHA256 hash of public key first 80 bits of digest in big- 
    endian format as HEX string (10 characters max) */
/* keyType can be DHE/ECDHE/X25519/X448 */
/* return:
     - zero response means existing key is used, 
     - negative is error
     - positive means new key retrieved */
WOLFKM_API int wolfEtsiClientGet(EtsiClientCtx* client, EtsiKey* key, 
    EtsiKeyType keyType, const char* fingerprint, const char* contextStr,
    int timeoutSec);

/* this call will be blocking until socket failure or callback non-zero return */
/* when server pushes new keys the callback will trigger with EtsiKey populated */
WOLFKM_API int wolfEtsiClientPush(EtsiClientCtx* client, EtsiKeyType keyType,
    const char* fingerprint, const char* contextStr,
    EtsiKeyCallbackFunc cb, void* cbCtx);

/* Retrieve key data for a fingerprint for replay (expired key is okay) */
WOLFKM_API int wolfEtsiClientFind(EtsiClientCtx* client, EtsiKey* key,
    EtsiKeyType keyType, const char* fingerprint, const char* contextStr,
    int timeoutSec);

/* Disconnect from ETSI Key Manager */
WOLFKM_API int wolfEtsiClientClose(EtsiClientCtx* client);

/* Release ETSI client context resources */
WOLFKM_API void wolfEtsiClientFree(EtsiClientCtx* client);

/* ETSI Key API's */
/* allocate ETSI key dynamically from heap */
/* The EtsiKey can come from stack, but must be memset to zero */
WOLFKM_API EtsiKey* wolfEtsiKeyNew(void);
/* Returns the wolf PK type (enum wc_PkType) */
WOLFKM_API int wolfEtsiKeyGetPkType(EtsiKey* key);
/* Load key to WOLFSSL_CTX directly */
WOLFKM_API int wolfEtsiKeyLoadCTX(EtsiKey* key, WOLFSSL_CTX* ctx);
/* Load key to WOLFSSL session directly */
WOLFKM_API int wolfEtsiKeyLoadSSL(EtsiKey* key, WOLFSSL* ssl);
/* Get pointer to PKCS8 key response */
WOLFKM_API int wolfEtsiKeyGetPtr(EtsiKey* key, byte** response, word32* responseSz);
/* Generate a new key */
WOLFKM_API int wolfEtsiKeyGen(EtsiKey* key, EtsiKeyType keyType, WC_RNG* rng);
/* print ETSI key data - for debugging / testing */
WOLFKM_API void wolfEtsiKeyPrint(EtsiKey* key);
/* release ETSI key resources */
WOLFKM_API void wolfEtsiKeyFree(EtsiKey* key);

WOLFKM_API const char* wolfEtsiKeyNamedGroupStr(EtsiKey* key);
WOLFKM_API const char* wolfEtsiKeyGetTypeStr(EtsiKeyType type);

/* Compute name for public key based on TLS key share */
WOLFKM_API int wolfEtsiGetPubKeyName(EtsiKeyType keyType,
    const byte* pub, word32 pubSz, char* name, word32* nameSz);

/* Build public name for key */
WOLFKM_API int wolfEtsiKeyComputeName(EtsiKey* key);

/* these are required if using multiple threads sharing the wolfSSL library for init mutex protection */
WOLFKM_API int wolfEtsiClientInit(void);
WOLFKM_API void wolfEtsiClientCleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* WOLFKM_ETSI_H */
