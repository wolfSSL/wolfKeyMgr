/* mod_ets.h
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

#ifndef WOLFKM_ETS_H
#define WOLFKM_ETS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "wolfkeymgr/wkm_types.h"
#include "wolfkeymgr/mod_http.h"
#include "wolfkeymgr/mod_socket.h"
#include "wolfkeymgr/mod_tls.h"


#ifndef ETS_MAX_REQUEST_SZ
#define ETS_MAX_REQUEST_SZ  MAX_REQUEST_SIZE
#endif
#ifndef ETS_MAX_RESPONSE_SZ
#define ETS_MAX_RESPONSE_SZ MAX_RESPONSE_SIZE
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

/* opaque type for EtsClientCtx (pointer reference only) */
typedef struct EtsClientCtx EtsClientCtx;

typedef enum EtsClientType {
    ETS_CLIENT_UNKNOWN,
    ETS_CLIENT_GET,  /* ask for key if current one is expired */
    ETS_CLIENT_PUSH, /* remain connected and server will push new key */
} EtsClientType;

typedef enum EtsKeyType {
    ETS_KEY_TYPE_UNKNOWN = 0,
    /* Named Groups: defined in clause 4.2.7 in IETF RFC 8446 */
    ETS_KEY_TYPE_SECP160K1 = 15,
    ETS_KEY_TYPE_SECP160R1 = 16,
    ETS_KEY_TYPE_SECP160R2 = 17,
    ETS_KEY_TYPE_SECP192K1 = 18,
    ETS_KEY_TYPE_SECP192R1 = 19,
    ETS_KEY_TYPE_SECP224K1 = 20,
    ETS_KEY_TYPE_SECP224R1 = 21,
    ETS_KEY_TYPE_SECP256K1 = 22,
    ETS_KEY_TYPE_SECP256R1 = 23,
    ETS_KEY_TYPE_SECP384R1 = 24,
    ETS_KEY_TYPE_SECP521R1 = 25,
    ETS_KEY_TYPE_BRAINPOOLP256R1 = 26,
    ETS_KEY_TYPE_BRAINPOOLP384R1 = 27,
    ETS_KEY_TYPE_BRAINPOOLP512R1 = 28,
    ETS_KEY_TYPE_X25519    = 29,
    ETS_KEY_TYPE_X448      = 30,
    ETS_KEY_TYPE_FFDHE_2048 = 256,
    ETS_KEY_TYPE_FFDHE_3072 = 257,
    ETS_KEY_TYPE_FFDHE_4096 = 258,
    ETS_KEY_TYPE_FFDHE_6144 = 259,
    ETS_KEY_TYPE_FFDHE_8192 = 260,

    ETS_KEY_TYPE_MIN = ETS_KEY_TYPE_SECP160K1,
    ETS_KEY_TYPE_MAX = ETS_KEY_TYPE_FFDHE_8192,
} EtsKeyType;

/* max context string (can be adjusted at build-time if desired) */
#ifndef ETS_MAX_CONTEXT_STR
#define ETS_MAX_CONTEXT_STR 32
#endif

#ifndef ETS_MAX_FINGERPRINT
#define ETS_MAX_FINGERPRINT 10 /* 80-bits - per ETS spec */
#endif
#define ETS_MAX_FINGERPRINT_STR (ETS_MAX_FINGERPRINT*2+1)

typedef struct EtsKey {
    enum EtsKeyType type;
    word32 fingerprintSz;
    byte   fingerprint[ETS_MAX_FINGERPRINT];
    char   contextStr[ETS_MAX_CONTEXT_STR];
    word32 responseSz;
    byte   response[ETS_MAX_RESPONSE_SZ];
    time_t expires; /* from HTTP HTTP_HDR_EXPIRES */

    /* Internal Variables */
    word32 useCount; /* times this key has been used */
    unsigned char isDynamic:1; /* key is dynamically allocated */
} EtsKey;

/* Key callback Function */
/* If return code is not zero then socket will be closed */
typedef int (*EtsKeyCallbackFunc)(EtsClientCtx* client, EtsKey* key, void* cbCtx);

/* ETS Client API's */
/* Allocate new ETS client context */
WOLFKM_API EtsClientCtx* wolfEtsClientNew(void);

/* Setup the TLS mutual authentication key/certificate for accessing the ETS Key Manager */
WOLFKM_API int wolfEtsClientSetKey(EtsClientCtx* client,
    const char* keyFile,  const char* keyPassword, const char* certFile,
    int fileType);

/* Setup the trusted CA certificate to verify authentic ETS Key Manager */
WOLFKM_API int wolfEtsClientAddCA(EtsClientCtx* client,
    const char* caFile);

/* Open TLS session to ETS Key Manager */
WOLFKM_API int wolfEtsClientConnect(EtsClientCtx* client,
    const char* host, word16 port, int timeoutSec);

WOLFKM_API int wolfEtsClientMakeRequest(EtsClientType type, const char* fingerprint,
    const char* groups, const char* contextstr, byte* request, word32* requestSz);

/* Get will return current key for provided fingerprint
 * fingerprint: a SHA256 hash of public key first 80 bits of digest in big-
 *  endian format as HEX string (10 characters max)
 * contextStr: Optional server info (for multiple server system)
 * keyType can be DHE/ECDHE/X25519/X448
 * return:
 *   - zero response means existing key is used,
 *   - negative is error
 *   - positive means new key retrieved */
WOLFKM_API int wolfEtsClientGet(EtsClientCtx* client, EtsKey* key,
    EtsKeyType keyType, const char* fingerprint, const char* contextStr,
    int timeoutSec);

/* This call will be blocking until socket failure or callback non-zero return
 * when server pushes new keys the callback will trigger with EtsKey populated */
WOLFKM_API int wolfEtsClientPush(EtsClientCtx* client, EtsKeyType keyType,
    const char* fingerprint, const char* contextStr,
    EtsKeyCallbackFunc cb, void* cbCtx);

/* Retrieve key data for a fingerprint for replay (expired key is okay) */
WOLFKM_API int wolfEtsClientFind(EtsClientCtx* client, EtsKey* key,
    EtsKeyType keyType, const char* fingerprint, const char* contextStr,
    int timeoutSec);

/* Disconnect from ETS Key Manager */
WOLFKM_API int wolfEtsClientClose(EtsClientCtx* client);

/* Release ETS client context resources */
WOLFKM_API void wolfEtsClientFree(EtsClientCtx* client);

/* ETS Key API's */
/* Allocate ETS key dynamically from heap.
 * The EtsKey can come from stack, but must be memset to zero. */
WOLFKM_API EtsKey* wolfEtsKeyNew(void);
/* Returns the wolf PK type (enum wc_PkType) */
WOLFKM_API int wolfEtsKeyGetPkType(EtsKey* key);
/* Lookup the wolfSSL PK type (enum wc_PkType) from named group */
WOLFKM_API int wolfEtsGetPkType(EtsKeyType type);
/* Load key to WOLFSSL_CTX directly */
WOLFKM_API int wolfEtsKeyLoadCTX(EtsKey* key, WOLFSSL_CTX* ctx);
/* Load key to WOLFSSL session directly */
WOLFKM_API int wolfEtsKeyLoadSSL(EtsKey* key, WOLFSSL* ssl);
/* Get pointer to PKCS8 key response */
WOLFKM_API int wolfEtsKeyGetPtr(EtsKey* key, byte** response, word32* responseSz);
/* Generate a new key */
WOLFKM_API int wolfEtsKeyGen(EtsKey* key, EtsKeyType keyType, WC_RNG* rng);
/* Print ETS key data - for debugging / testing */
WOLFKM_API void wolfEtsKeyPrint(EtsKey* key);
/* Release ETS key resources */
WOLFKM_API void wolfEtsKeyFree(EtsKey* key);

WOLFKM_API const char* wolfEtsKeyNamedGroupStr(EtsKey* key);
WOLFKM_API const char* wolfEtsKeyGetTypeStr(EtsKeyType type);

/* Compute name for public key based on TLS key share */
WOLFKM_API int wolfEtsCalcTlsFingerprint(EtsKeyType keyType,
    const byte* pub, word32 pubSz, char* fpStr, word32* fpStrSz);

/* Build public name for key */
WOLFKM_API int wolfEtsKeyComputeName(EtsKey* key);

/* These are required if using multiple threads sharing the wolfSSL library 
 * for init mutex protection */
WOLFKM_API int wolfEtsClientInit(void);
WOLFKM_API void wolfEtsClientCleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* WOLFKM_ETS_H */
