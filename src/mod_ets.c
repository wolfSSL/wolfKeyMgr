/* mod_ets.c
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

#include "wolfkeymgr/mod_ets.h"
#include <signal.h>

struct EtsClientCtx {
    WOLFSSL_CTX*   sslCtx;
    WOLFSSL*       ssl;
    wolfSSL_Mutex  lock;
};


EtsClientCtx* wolfEtsClientNew(void)
{
    EtsClientCtx* client = (EtsClientCtx*)malloc(sizeof(EtsClientCtx));
    if (client) {
        memset(client, 0, sizeof(EtsClientCtx));
        wc_InitMutex(&client->lock);
        client->sslCtx = wolfTlsClientNew();
        if (client->sslCtx == NULL) {
            XLOG(WOLFKM_LOG_ERROR, "Error creating TLS client!\n");
            free(client);
            return NULL;
        }
    }
    return client;
}

int wolfEtsClientSetKey(EtsClientCtx* client, const char* keyFile,
    const char* keyPassword, const char* certFile, int fileType)
{
    int ret;
    if (client == NULL) {
        return WOLFKM_BAD_ARGS;
    }
    wc_LockMutex(&client->lock);
    ret = wolfTlsSetKey(client->sslCtx, keyFile, keyPassword, certFile, fileType);
    wc_UnLockMutex(&client->lock);
    return ret;
}

int wolfEtsClientAddCA(EtsClientCtx* client, const char* caFile)
{
    int ret;
    if (client == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    wc_LockMutex(&client->lock);
    ret = wolfTlsAddCA(client->sslCtx, caFile);
    wc_UnLockMutex(&client->lock);
    return ret;
}

int wolfEtsClientConnect(EtsClientCtx* client, const char* host,
    word16 port, int timeoutSec)
{
    int ret;

    if (client == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    wc_LockMutex(&client->lock);
    ret = wolfTlsConnect(client->sslCtx, &client->ssl, host, port, timeoutSec);
    if (ret == 0) {
        XLOG(WOLFKM_LOG_INFO, "Connected to ETS service\n");
    }
    else {
        XLOG(WOLFKM_LOG_ERROR, "Failure connecting to ETS service %d\n", ret);
        ret = WOLFKM_BAD_HOST;
    }
    wc_UnLockMutex(&client->lock);

    return ret;
}

const char* wolfEtsKeyNamedGroupStr(EtsKey* key)
{
    if (key == NULL)
        return NULL;
    switch (key->type) {
        case ETS_KEY_TYPE_SECP160K1:  return "0x000F"; /* 15 */
        case ETS_KEY_TYPE_SECP160R1:  return "0x0010"; /* 16 */
        case ETS_KEY_TYPE_SECP160R2:  return "0x0011"; /* 17 */
        case ETS_KEY_TYPE_SECP192K1:  return "0x0012"; /* 18 */
        case ETS_KEY_TYPE_SECP192R1:  return "0x0013"; /* 19 */
        case ETS_KEY_TYPE_SECP224K1:  return "0x0014"; /* 20 */
        case ETS_KEY_TYPE_SECP224R1:  return "0x0015"; /* 21 */
        case ETS_KEY_TYPE_SECP256K1:  return "0x0016"; /* 22 */
        case ETS_KEY_TYPE_SECP256R1:  return "0x0017"; /* 23 */
        case ETS_KEY_TYPE_SECP384R1:  return "0x0018"; /* 24 */
        case ETS_KEY_TYPE_SECP521R1:  return "0x0019"; /* 25 */
        case ETS_KEY_TYPE_BRAINPOOLP256R1: return "0x001A"; /* 26 */
        case ETS_KEY_TYPE_BRAINPOOLP384R1: return "0x001B"; /* 27 */
        case ETS_KEY_TYPE_BRAINPOOLP512R1: return "0x001C"; /* 28 */
        case ETS_KEY_TYPE_X25519:     return "0x001D"; /* 29 */
        case ETS_KEY_TYPE_X448:       return "0x001E"; /* 30 */
        case ETS_KEY_TYPE_FFDHE_2048: return "0x0100"; /* 256 */
        case ETS_KEY_TYPE_FFDHE_3072: return "0x0101"; /* 257 */
        case ETS_KEY_TYPE_FFDHE_4096: return "0x0102"; /* 258 */
        case ETS_KEY_TYPE_FFDHE_6144: return "0x0103"; /* 259 */
        case ETS_KEY_TYPE_FFDHE_8192: return "0x0104"; /* 260 */
        default: break;
    }
    return NULL;
}

int wolfEtsClientMakeRequest(EtsClientType type, const char* fingerprint,
    const char* groups, const char* contextstr, byte* request, word32* requestSz)
{
    int ret;
    char uri[HTTP_MAX_URI*3]; /* fingerprint, groups, contextStr */
    size_t uriLen;
    HttpHeader headers[1];
    HttpMethodType httpType;
    headers[0].type = HTTP_HDR_ACCEPT;
    headers[0].string = "application/pkcs8";

    /* Build HTTP ETS request */
    if (type == ETS_CLIENT_PUSH) {
        /* PUT for distributed push of keys */
        httpType = HTTP_METHOD_PUT;
        snprintf(uri, sizeof(uri), "/enterprise-transport-security/keys");
    }
    else {
        /* use GET with either fingerprint (with optional groups/context) */
        httpType = HTTP_METHOD_GET;
        strncpy(uri,
            "/.well-known/enterprise-transport-security/keys?fingerprints=",
            sizeof(uri));
        uriLen = strlen(uri);
        if (fingerprint != NULL) {
            ret = wolfHttpUriEncode(fingerprint, strlen(fingerprint),
                uri+uriLen, sizeof(uri)-uriLen);
            if (ret < 0)
                return WOLFKM_BAD_ARGS;
            uriLen += ret;
        }
        if (groups != NULL) {
            strncpy(uri+uriLen, "&groups=", sizeof(uri)-uriLen);
            uriLen = strlen(uri);
            ret = wolfHttpUriEncode(groups, strlen(groups),
                uri+uriLen, sizeof(uri)-uriLen);
            if (ret < 0)
                return WOLFKM_BAD_ARGS;
            uriLen += ret;
        }
        if (contextstr != NULL) {
            strncpy(uri+uriLen, "&contextstr=", sizeof(uri)-uriLen);
            uriLen = strlen(uri);
            ret = wolfHttpUriEncode(contextstr, strlen(contextstr),
                uri+uriLen, sizeof(uri)-uriLen);
            if (ret < 0)
                return WOLFKM_BAD_ARGS;
            uriLen += ret;
        }
        uri[uriLen] = '\0'; /* null term */
    }
    ret = wolfHttpClient_EncodeRequest(httpType, uri, request,
            requestSz, headers, sizeof(headers)/sizeof(HttpHeader));
    if (ret > 0)
        ret = 0;
    return ret;
}

static void ParseHttpResponseExpires(HttpRsp* rsp, EtsKey* key, time_t now)
{
    int i;

    /* capture expiration */
    for (i=0; i<(int)rsp->headerCount; i++) {
        if (rsp->headers[i].type == HTTP_HDR_EXPIRES) {
            struct tm tm;
            memset(&tm, 0, sizeof(tm));
            /* Convert string to time_t */
            /* HTTP expires example: "Wed, 21 Oct 2015 07:28:00 GMT" */
            if (strptime(rsp->headers[i].string, HTTP_DATE_FMT,
                                                            &tm) != NULL) {
                key->expires = mktime(&tm);
                /* sanity check time against current time */
                /* if this is past current here then it has already
                    expired or is invalid */
                if (key->expires < now) {
                    XLOG(WOLFKM_LOG_WARN,
                        "Key expires time invalid %lu < %lu\n",
                        key->expires, now);
                    key->expires = 0;
                }
            }
            break;
        }
    }
}

static int EtsClientGet(EtsClientCtx* client, EtsKey* key,
    EtsKeyType keyType, const char* fingerprint, const char* contextStr,
    int timeoutSec, HttpRsp* rsp)
{
    int    ret;
    byte   request[ETS_MAX_REQUEST_SZ];
    word32 requestSz = ETS_MAX_REQUEST_SZ;
    int    pos;
    const char* group;

    if (client == NULL || key == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    /* build GET request for key */
    key->type = keyType;
    group = wolfEtsKeyNamedGroupStr(key);
    ret = wolfEtsClientMakeRequest(ETS_CLIENT_GET, fingerprint, group,
        contextStr, request, &requestSz);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_INFO, "EtsClientMakeRequest failed: %d\n", ret);
        return ret;
    }
    XLOG(WOLFKM_LOG_DEBUG, "HTTP Sending: %s\n", (char*)request);

    /* send GET key request */
    wc_LockMutex(&client->lock);
    pos = 0;
    while (pos < (int)requestSz) {
        ret = wolfTlsWrite(client->ssl, (byte*)request + pos,
            requestSz - pos);
        if (ret < 0) {
            wc_UnLockMutex(&client->lock);
            XLOG(WOLFKM_LOG_INFO, "DoClientSend failed: %d (%s)\n", ret,
                wolfSSL_ERR_reason_error_string(ret));
            return ret;
        }
        pos += ret;
    }
    XLOG(WOLFKM_LOG_INFO, "Sent get request (%d bytes)\n", requestSz);

    /* get key response */
    /* TODO: handle HTTP chunked content type */
    /* TODO: handle multiple packets */
    /* TODO: Integrate HTTP processing with read to handle larger payloads */
    key->responseSz = sizeof(key->response);
    do {
        ret = wolfTlsRead(client->ssl, (byte*)key->response,
            (int*)&key->responseSz, timeoutSec);
        if (ret < 0) {
            XLOG(WOLFKM_LOG_ERROR, "DoClientRead failed: %d\n", ret);
            break;
        }
        /* zero response means try again */
    } while (ret == 0);
    wc_UnLockMutex(&client->lock);

    if (ret > 0) {
        /* parse HTTP server response */
        key->expires = 0;
        ret = wolfHttpClient_ParseResponse(rsp,
            (char*)key->response, key->responseSz);
        if (ret == 0 && rsp->body && rsp->bodySz > 0) {
            wolfHttpResponsePrint(rsp);

            /* move payload (body) to response (same buffer) */
            memmove(key->response, rsp->body, rsp->bodySz);
            key->responseSz = rsp->bodySz;
        }
        else {
            XLOG(WOLFKM_LOG_ERROR, "Error parsing HTTP response! %d\n", ret);
        }
    }

    if (ret == 0) {
        /* asymmetric key package response */
        XLOG(WOLFKM_LOG_INFO, "Got ETS response (%d bytes)\n",
            key->responseSz);
        ret = key->responseSz; /* return key size */
    }

    return ret;
}

int wolfEtsClientGet(EtsClientCtx* client, EtsKey* key,
    EtsKeyType keyType, const char* fingerprint, const char* contextStr,
    int timeoutSec)
{
    int    ret;
    time_t now;
    HttpRsp rsp;

    if (client == NULL || key == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    /* Has current key expired? */
    now = wolfGetCurrentTimeT();
    if (key->type == keyType && key->responseSz > 0 &&
        key->expires > 0 && key->expires >= now) {
        /* key is still valid, use existing */
        /* return zero, indicating no key change */
        return 0;
    }

    ret = EtsClientGet(client, key, keyType, fingerprint, contextStr,
        timeoutSec, &rsp);
    if (ret == 0) {
        ParseHttpResponseExpires(&rsp, key, now);
    }
    return ret;
}

int wolfEtsClientPush(EtsClientCtx* client, EtsKeyType keyType,
    const char* fingerprint, const char* contextStr,
    EtsKeyCallbackFunc cb, void* cbCtx)
{
    int    ret;
    byte   request[ETS_MAX_REQUEST_SZ];
    word32 requestSz = ETS_MAX_REQUEST_SZ;
    int    pos;
    HttpRsp rsp;
    const char* group;
    time_t now;
    EtsKey key;

    if (client == NULL || cb == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    /* Request PUSH for new keys */
    memset(&key, 0, sizeof(key));
    key.type = keyType;
    group = wolfEtsKeyNamedGroupStr(&key);
    ret = wolfEtsClientMakeRequest(ETS_CLIENT_PUSH, fingerprint, group,
        contextStr, request, &requestSz);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_INFO, "EtsClientMakeRequest failed: %d\n", ret);
        return ret;
    }

    /* send PUSH key request */
    wc_LockMutex(&client->lock);
    pos = 0;
    while (pos < (int)requestSz) {
        ret = wolfTlsWrite(client->ssl, (byte*)request + pos,
            requestSz - pos);
        if (ret < 0) {
            wc_UnLockMutex(&client->lock);
            XLOG(WOLFKM_LOG_INFO, "DoClientSend failed: %d (%s)\n", ret,
                wolfSSL_ERR_reason_error_string(ret));
            return ret;
        }
        pos += ret;
    }
    XLOG(WOLFKM_LOG_INFO, "Sent get request (%d bytes)\n", requestSz);

    /* wait for key response */
    do {
        /* 0 = no timeout - blocking */
        key.responseSz = sizeof(key.response);
        ret = wolfTlsRead(client->ssl, (byte*)key.response,
            (int*)&key.responseSz, 0);
        if (ret < 0 && ret != WOLFKM_BAD_TIMEOUT) {
            XLOG(WOLFKM_LOG_ERROR, "DoClientRead failed: %d\n", ret);
            break;
        }
        if (ret > 0) {
            /* asymmetric key package response */
            XLOG(WOLFKM_LOG_INFO, "Got ETS response (%d bytes)\n",
                key.responseSz);

            /* parse HTTP server response */
            key.expires = 0;
            ret = wolfHttpClient_ParseResponse(&rsp,
                (char*)key.response, key.responseSz);
            if (ret == 0 && rsp.body && rsp.bodySz > 0) {
                wolfHttpResponsePrint(&rsp);

                now = wolfGetCurrentTimeT();
                ParseHttpResponseExpires(&rsp, &key, now);

                /* move payload (body) to response (same buffer) */
                memcpy(key.response, rsp.body, rsp.bodySz);
                key.responseSz = rsp.bodySz;

                ret = cb(client, &key, cbCtx);
                if (ret != 0) {
                    /* callback requested exit */
                    XLOG(WOLFKM_LOG_INFO, "Push callback requested exit %d\n", ret);
                    break;
                }
            }
            else {
                XLOG(WOLFKM_LOG_ERROR, "Error parsing HTTP response! %d\n", ret);
                break;
            }
        }

        /* zero response means try again */
    } while (ret == 0 || ret == WOLFKM_BAD_TIMEOUT);
    wc_UnLockMutex(&client->lock);

    return ret;
}

int wolfEtsClientFind(EtsClientCtx* client, EtsKey* key,
    EtsKeyType keyType, const char* fingerprint, const char* contextStr,
    int timeoutSec)
{
    HttpRsp rsp;
    /* fingerprint is previously generated ephemeral public key name */
    return EtsClientGet(client, key, keyType, fingerprint, contextStr,
        timeoutSec, &rsp);
}

int wolfEtsKeyGetPtr(EtsKey* key, byte** response, word32* responseSz)
{
    if (key == NULL)
        return WOLFKM_BAD_ARGS;
    if (response)
        *response = (byte*)key->response;
    if (responseSz)
        *responseSz = key->responseSz;
    return 0;
}

EtsKey* wolfEtsKeyNew(void)
{
    EtsKey* key = (EtsKey*)malloc(sizeof(EtsKey));
    if (key) {
        memset(key, 0, sizeof(EtsKey));
        key->isDynamic = 1;
    }
    return key;
}

int wolfEtsGetPkType(EtsKeyType type)
{
    if (type >= ETS_KEY_TYPE_SECP160K1 &&
        type <= ETS_KEY_TYPE_BRAINPOOLP512R1) {
        return WC_PK_TYPE_ECDH;
    }
    if (type >= ETS_KEY_TYPE_FFDHE_2048 &&
        type <= ETS_KEY_TYPE_FFDHE_8192) {
        return WC_PK_TYPE_DH;
    }
    if (type == ETS_KEY_TYPE_X25519) {
        return WC_PK_TYPE_CURVE25519;
    }
    if (type == ETS_KEY_TYPE_X448) {
        return WC_PK_TYPE_CURVE448;
    }
    return WC_PK_TYPE_NONE;
}

int wolfEtsKeyGetPkType(EtsKey* key)
{
    if (key == NULL)
        return WOLFKM_BAD_ARGS;
    return wolfEtsGetPkType(key->type);
}

const char* wolfEtsKeyGetTypeStr(EtsKeyType type)
{
    switch (type) {
        case ETS_KEY_TYPE_SECP160K1:
            return "SECP160K1";
        case ETS_KEY_TYPE_SECP160R1:
            return "SECP160R1";
        case ETS_KEY_TYPE_SECP160R2:
            return "SECP160R2";
        case ETS_KEY_TYPE_SECP192K1:
            return "SECP192K1";
        case ETS_KEY_TYPE_SECP192R1:
            return "SECP192R1";
        case ETS_KEY_TYPE_SECP224K1:
            return "SECP224K1";
        case ETS_KEY_TYPE_SECP224R1:
            return "SECP224R1";
        case ETS_KEY_TYPE_SECP256K1:
            return "SECP256K1";
        case ETS_KEY_TYPE_SECP256R1:
            return "SECP256R1";
        case ETS_KEY_TYPE_SECP384R1:
            return "SECP384R1";
        case ETS_KEY_TYPE_SECP521R1:
            return "SECP521R1";
        case ETS_KEY_TYPE_BRAINPOOLP256R1:
            return "BRAINPOOLP256R1";
        case ETS_KEY_TYPE_BRAINPOOLP384R1:
            return "BRAINPOOLP384R1";
        case ETS_KEY_TYPE_BRAINPOOLP512R1:
            return "BRAINPOOLP512R1";
        case ETS_KEY_TYPE_X25519:
            return "X25519";
        case ETS_KEY_TYPE_X448:
            return "X448";
        case ETS_KEY_TYPE_FFDHE_2048:
            return "FFDHE_2048";
        case ETS_KEY_TYPE_FFDHE_3072:
            return "FFDHE_3072";
        case ETS_KEY_TYPE_FFDHE_4096:
            return "FFDHE_4096";
        case ETS_KEY_TYPE_FFDHE_6144:
            return "FFDHE_6144";
        case ETS_KEY_TYPE_FFDHE_8192:
            return "FFDHE_8192";
        default:
            break;
    }
    return NULL;
}

int wolfEtsKeyLoadCTX(EtsKey* key, WOLFSSL_CTX* ctx)
{
    int ret;
#ifdef WOLFSSL_STATIC_EPHEMERAL
    int keyAlgo;
#endif

    if (key == NULL || ctx == NULL)
        return WOLFKM_BAD_ARGS;

#ifdef WOLFSSL_STATIC_EPHEMERAL
    /* determine key algo */
    keyAlgo = wolfEtsKeyGetPkType(key);

    ret = wolfSSL_CTX_set_ephemeral_key(ctx, keyAlgo,
        (char*)key->response, key->responseSz, WOLFSSL_FILETYPE_ASN1);
#else
    ret = WOLFKM_NOT_COMPILED_IN;
#endif
    return ret;
}

int wolfEtsKeyLoadSSL(EtsKey* key, WOLFSSL* ssl)
{
    int ret;
#ifdef WOLFSSL_STATIC_EPHEMERAL
    int keyAlgo;
#endif

    if (key == NULL || ssl == NULL)
        return WOLFKM_BAD_ARGS;

#ifdef WOLFSSL_STATIC_EPHEMERAL
    /* determine key algo */
    keyAlgo = wolfEtsKeyGetPkType(key);

    ret = wolfSSL_set_ephemeral_key(ssl, keyAlgo,
        (char*)key->response, key->responseSz, WOLFSSL_FILETYPE_ASN1);
    if (ret == 0) {
        /* TODO: handle return code */
        (void)wolfSSL_UseKeyShare(ssl, key->type);
    }
#else
    ret = WOLFKM_NOT_COMPILED_IN;
#endif
    return ret;
}

#ifdef HAVE_ECC
static int NamedGroupToCurveInfo(EtsKeyType keyType, int* curveId, int* keySize)
{
    int ret = 0;
    switch (keyType) {
        case ETS_KEY_TYPE_SECP160K1:
            *curveId = ECC_SECP160K1; *keySize = 20; break;
        case ETS_KEY_TYPE_SECP160R1:
            *curveId = ECC_SECP160R1; *keySize = 20; break;
        case ETS_KEY_TYPE_SECP160R2:
            *curveId = ECC_SECP160R2; *keySize = 20; break;
        case ETS_KEY_TYPE_SECP192K1:
            *curveId = ECC_SECP192K1; *keySize = 24; break;
        case ETS_KEY_TYPE_SECP192R1:
            *curveId = ECC_SECP192R1; *keySize = 24; break;
        case ETS_KEY_TYPE_SECP224K1:
            *curveId = ECC_SECP224K1; *keySize = 28; break;
        case ETS_KEY_TYPE_SECP224R1:
            *curveId = ECC_SECP224R1; *keySize = 28; break;
        case ETS_KEY_TYPE_SECP256K1:
            *curveId = ECC_SECP256K1; *keySize = 32; break;
        case ETS_KEY_TYPE_SECP256R1:
            *curveId = ECC_SECP256R1; *keySize = 32; break;
        case ETS_KEY_TYPE_SECP384R1:
            *curveId = ECC_SECP384R1; *keySize = 48; break;
        case ETS_KEY_TYPE_SECP521R1:
            *curveId = ECC_SECP521R1; *keySize = 66; break;
        case ETS_KEY_TYPE_BRAINPOOLP256R1:
            *curveId = ECC_BRAINPOOLP256R1; *keySize = 32; break;
        case ETS_KEY_TYPE_BRAINPOOLP384R1:
            *curveId = ECC_BRAINPOOLP384R1; *keySize = 48; break;
        case ETS_KEY_TYPE_BRAINPOOLP512R1:
            *curveId = ECC_BRAINPOOLP512R1; *keySize = 64; break;
        default:
            ret = WOLFKM_BAD_ARGS;
            break;
    }
    return ret;
}
#endif

#if !defined(NO_DH) && defined(WOLFSSL_DH_EXTRA)
static int NamedGroupToDhParams(EtsKeyType keyType,
    const DhParams** pParams, word32* pPrivKeySz, word32* pPubKeySz)
{
    int ret = 0;
    const DhParams* params = NULL;
    word32 privKeySz = 0;
    word32 pubKeySz = 0;
    #ifdef HAVE_PUBLIC_FFDHE
    switch (keyType) {
    #ifdef HAVE_FFDHE_2048
        case ETS_KEY_TYPE_FFDHE_2048:
            params = wc_Dh_ffdhe2048_Get(); privKeySz = 29; break;
    #endif
    #ifdef HAVE_FFDHE_3072
        case ETS_KEY_TYPE_FFDHE_3072:
            params = wc_Dh_ffdhe3072_Get(); privKeySz = 34; break;
    #endif
    #ifdef HAVE_FFDHE_4096
        case ETS_KEY_TYPE_FFDHE_4096:
            params = wc_Dh_ffdhe4096_Get(); privKeySz = 39; break;
    #endif
    #ifdef HAVE_FFDHE_6144
        case ETS_KEY_TYPE_FFDHE_6144:
            params = wc_Dh_ffdhe6144_Get(); privKeySz = 46; break;
    #endif
    #ifdef HAVE_FFDHE_8192
        case ETS_KEY_TYPE_FFDHE_8192:
            params = wc_Dh_ffdhe8192_Get(); privKeySz = 52; break;
    #endif
        default:
            ret = WOLFKM_NOT_COMPILED_IN;
            break;
    }
    if (params)
        pubKeySz = params->p_len;
    #else
        privKeySz = wc_DhGetNamedKeyMinSize((int)keyType);
        ret = wc_DhGetNamedKeyParamSize((int)keyType, &pubKeySz, NULL, NULL);
    #endif
    
    if (pParams)
        *pParams = params;
    if (pPubKeySz)
        *pPubKeySz = pubKeySz;
    if (pPrivKeySz)
        *pPrivKeySz = privKeySz;
    return ret;
}
#endif


static int wolfKeyCalcFingerprint(EtsKeyType keyType, const byte* pub, word32 pubSz,
    byte* fp, word32* fpSz)
{
    int ret = 0;
    byte digest[WC_SHA256_DIGEST_SIZE];
    word32 tmpSz;

    if (pub == NULL || pubSz == 0 || fp == NULL || fpSz == NULL)
        return WOLFKM_BAD_ARGS;

    memset(fp, 0, *fpSz);
    tmpSz = *fpSz;
    *fpSz = 0;

    /* SHA256 Hash Pub Key */
    ret = wc_Sha256Hash(pub, pubSz, digest);
    if (ret == 0) {
        /* Return 10-bytes truncated (big endian) */
        if (tmpSz > WC_SHA256_DIGEST_SIZE)
            tmpSz = WC_SHA256_DIGEST_SIZE;
        memcpy(fp, pub, tmpSz);
        *fpSz = tmpSz;
    }

    (void)keyType;
    return ret;
}

#ifdef HAVE_ECC
static int GenNewKeyEcc(EtsKey* key, EtsKeyType keyType, WC_RNG* rng)
{
    int ret;
    int curveId = ECC_CURVE_DEF, keySize = 32;
    ecc_key ecc;

    /* Determine ECC Key Size and Curve */
    ret = NamedGroupToCurveInfo(keyType, &curveId, &keySize);
    if (ret != 0)
        return ret;

    ret = wc_ecc_init(&ecc);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "ECC Init Failed! %d\n", ret);
        return WOLFKM_BAD_KEY;
    }

    ret = wc_ecc_make_key_ex(rng, keySize, &ecc, curveId);
    if (ret == 0) {
        /* Export as DER IETF RFC 5915 */
        key->responseSz = sizeof(key->response);
        ret = wc_EccKeyToDer(&ecc, (byte*)key->response,
            key->responseSz);
        if (ret >= 0) {
            key->responseSz = ret;
            ret = 0;
        }
    }
    if (ret == 0) {
        /* export public */
        byte pub[MAX_ECC_BYTES*2];
        word32 pubXLen = (word32)sizeof(pub)/2;
        word32 pubYLen = (word32)sizeof(pub)/2;
        ret = wc_ecc_export_ex(&ecc,
            pub,         &pubXLen,
            pub+keySize, &pubYLen,
            NULL, NULL, WC_TYPE_UNSIGNED_BIN);
        if (ret == 0) {
            /* compute fingerprint for key */
            word32 fpSz = (word32)sizeof(key->fingerprint);
            ret = wolfKeyCalcFingerprint(keyType, pub, keySize*2,
                key->fingerprint, &fpSz);
        }
    }
    wc_ecc_free(&ecc);

    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "ECC Key Generation Failed! %d\n", ret);
    }

    return ret;
}
#endif

#ifdef HAVE_CURVE25519
static int GenNewKeyCurve25519(EtsKey* key, EtsKeyType keyType, WC_RNG* rng)
{
    int ret;
    curve25519_key curveKey;

    ret = wc_curve25519_init(&curveKey);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Curve25519 init failed! %d\n", ret);
        return WOLFKM_BAD_KEY;
    }

    ret = wc_curve25519_make_key(rng, CURVE25519_KEYSIZE, &curveKey);
    if (ret == 0) {
        key->responseSz = sizeof(key->response);
        ret = wc_Curve25519PrivateKeyToDer(&curveKey, (byte*)key->response,
            key->responseSz);
        if (ret >= 0) {
            key->responseSz = ret;
            ret = 0;
        }
    }
    if (ret == 0) {
        /* export public */
        byte pub[CURVE25519_KEYSIZE];
        word32 pubLen = (word32)sizeof(pub);
        ret = wc_curve25519_export_public_ex(&curveKey, pub, &pubLen,
            EC25519_LITTLE_ENDIAN);
        if (ret == 0) {
            /* compute fingerprint for key */
            word32 fpSz = (word32)sizeof(key->fingerprint);
            ret = wolfKeyCalcFingerprint(keyType, pub, pubLen,
                key->fingerprint, &fpSz);
        }
    }
    wc_curve25519_free(&curveKey);

    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Curve25519 Key Generation Failed! %d\n", ret);
    }

    return ret;
}
#endif /* HAVE_CURVE25519 */

#ifdef HAVE_CURVE448
static int GenNewKeyCurve448(EtsKey* key, EtsKeyType keyType, WC_RNG* rng)
{
    int ret;
    curve448_key curveKey;

    ret = wc_curve448_init(&curveKey);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Curve448 init failed! %d\n", ret);
        return WOLFKM_BAD_KEY;
    }

    ret = wc_curve448_make_key(rng, CURVE448_KEY_SIZE, &curveKey);
    if (ret == 0) {
        key->responseSz = sizeof(key->response);
        ret = wc_Curve448PrivateKeyToDer(&curveKey, (byte*)key->response,
            key->responseSz);
        if (ret >= 0) {
            key->responseSz = ret;
            ret = 0;
        }
    }
    if (ret == 0) {
        /* export public */
        byte pub[CURVE448_PUB_KEY_SIZE];
        word32 pubLen = (word32)sizeof(pub);
        ret = wc_curve448_export_public_ex(&curveKey, pub, &pubLen,
            EC448_LITTLE_ENDIAN);
        if (ret == 0) {
            /* compute fingerprint for key */
            word32 fpSz = (word32)sizeof(key->fingerprint);
            ret = wolfKeyCalcFingerprint(keyType, pub, pubLen,
                key->fingerprint, &fpSz);
        }
    }
    wc_curve448_free(&curveKey);

    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Curve448 Key Generation Failed! %d\n", ret);
    }

    return ret;
}
#endif /* HAVE_CURVE448 */

#if !defined(NO_DH) && defined(WOLFSSL_DH_EXTRA)
static int GenNewKeyDh(EtsKey* key, EtsKeyType keyType, WC_RNG* rng)
{
    int ret;
    DhKey dh;
    const DhParams* params = NULL;
    word32 privKeySz = 0, pubKeySz = 0, p_len;
    byte privKey[MAX_DH_PRIV_SZ];
    byte pubKey[MAX_DH_PUB_SZ];

    ret = NamedGroupToDhParams(keyType, &params, &privKeySz, &pubKeySz);
    if (ret != 0) {
        return ret;
    }
    p_len = pubKeySz;

    ret = wc_InitDhKey(&dh);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "DH Init Failed! %d\n", ret);
        return WOLFKM_BAD_KEY;
    }

    /* Set key params */
#ifdef HAVE_PUBLIC_FFDHE
    ret = wc_DhSetKey(&dh,
        params->p, params->p_len,
        params->g, params->g_len);
#else
    ret = wc_DhSetNamedKey(&dh, (int)keyType);
#endif
    if (ret == 0) {
        /* Generate a new key pair */
        ret = wc_DhGenerateKeyPair(&dh, rng,
            privKey, &privKeySz,
            pubKey, &pubKeySz);
    }
    if (ret == 0) {
        if (p_len != pubKeySz) {
            /* Zero pad the front of the public key to match prime "p" size */
            memmove(pubKey + p_len - pubKeySz, pubKey, pubKeySz);
            memset(pubKey, 0, p_len - pubKeySz);
        }

        /* load public and private key info into DkKey */
        ret = wc_DhImportKeyPair(&dh,
            privKey, privKeySz,
            pubKey, pubKeySz);
    }
    if (ret == 0) {
        /* compute fingerprint for key */
        word32 fpSz = (word32)sizeof(key->fingerprint);
        ret = wolfKeyCalcFingerprint(keyType, pubKey, pubKeySz,
            key->fingerprint, &fpSz);
    }
    if (ret == 0) {
        /* export DH key as DER */
        /* Note: Proper support for wc_DhPrivKeyToDer was added v4.8.0 or
         *       later (see PR 3832) */
        key->responseSz = sizeof(key->response);
        ret = wc_DhPrivKeyToDer(&dh, (byte*)key->response, &key->responseSz);
        if (ret >= 0)
            ret = 0; /* size is returned in key->responseSz */
    }
    wc_FreeDhKey(&dh);

    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "DH Key Generation Failed! %d\n", ret);
    }

    return ret;
}
#endif /* !NO_DH && WOLFSSL_DH_EXTRA */

int wolfEtsKeyGen(EtsKey* key, EtsKeyType keyType, WC_RNG* rng)
{
    int ret = WOLFKM_NOT_COMPILED_IN;

    if (key == NULL || rng == NULL)
        return WOLFKM_BAD_ARGS;

#ifdef HAVE_ECC
    if (keyType >= ETS_KEY_TYPE_SECP160K1 &&
        keyType <= ETS_KEY_TYPE_BRAINPOOLP512R1) {
        ret = GenNewKeyEcc(key, keyType, rng);
    }
#endif
#if !defined(NO_DH) && defined(WOLFSSL_DH_EXTRA)
    if (keyType >= ETS_KEY_TYPE_FFDHE_2048 &&
        keyType <= ETS_KEY_TYPE_FFDHE_8192) {
        ret = GenNewKeyDh(key, keyType, rng);
    }
#endif
#ifdef HAVE_CURVE25519
    if (keyType == ETS_KEY_TYPE_X25519) {
        ret = GenNewKeyCurve25519(key, keyType, rng);
    }
#endif
#ifdef HAVE_CURVE448
    if (keyType == ETS_KEY_TYPE_X448) {
        ret = GenNewKeyCurve448(key, keyType, rng);
    }
#endif

    if (ret == 0) {
        key->type = keyType;
        key->useCount = 0;
    }

    return ret;
}

/* Public key format is same as over the wire via TLS */
int wolfEtsCalcTlsFingerprint(EtsKeyType keyType,
    const byte* pub, word32 pubSz, char* fpStr, word32* fpStrSz)
{
    int ret = WOLFKM_NOT_COMPILED_IN;
    byte fp[ETS_MAX_FINGERPRINT];
    word32 fpSz = (word32)sizeof(fp);

    if (pub == NULL || pubSz == 0 || fpStr == NULL || fpStrSz == NULL)
        return WOLFKM_BAD_ARGS;

    memset(fp, 0, sizeof(fp));

#ifdef HAVE_ECC
    if (keyType >= ETS_KEY_TYPE_SECP160K1 &&
        keyType <= ETS_KEY_TYPE_BRAINPOOLP512R1)
    {
        /* For ECC it is x963 - 1 byte (point type), pub x, pub y */
        int curveId = ECC_CURVE_DEF, keySize = 32;
        ecc_key key;

        ret = NamedGroupToCurveInfo(keyType, &curveId, &keySize);
        if (ret != 0)
            return ret;

        /* this handles compressed ECC keys if HAVE_COMP_KEY is defined */
        ret = wc_ecc_init_ex(&key, NULL, INVALID_DEVID);
        if (ret == 0) {
            byte pubKey[MAX_ECC_BYTES*2];
            word32 pubXLen = sizeof(pubKey)/2, pubYLen = sizeof(pubKey)/2;
            ret = wc_ecc_import_x963_ex(pub, pubSz, &key, curveId);
            if (ret == 0) {
                /* export public - do not trust length from wc_ecc_export_ex,
                 * some older versions do not return correct length for hex string */
                ret = wc_ecc_export_ex(&key,
                    pubKey,         &pubXLen,
                    pubKey+keySize, &pubYLen,
                    NULL, NULL, WC_TYPE_UNSIGNED_BIN);
            }
            if (ret == 0) {
                /* compute fingerprint for key */
                ret = wolfKeyCalcFingerprint(keyType, pubKey, keySize*2,
                    fp, &fpSz);
            }
        }
        wc_ecc_free(&key);
    }
#endif
#if !defined(NO_DH) && defined(WOLFSSL_DH_EXTRA)
    if (keyType >= ETS_KEY_TYPE_FFDHE_2048 &&
        keyType <= ETS_KEY_TYPE_FFDHE_8192)
    {
        /* For DH it is the DH public key as unsigned bin */
        word32 pubKeySz = 0;
        ret = NamedGroupToDhParams(keyType, NULL, NULL, &pubKeySz);
        if (ret == 0) {
            ret = wolfKeyCalcFingerprint(keyType, pub, pubKeySz, fp, &fpSz);
        }
    }
#endif
#ifdef HAVE_CURVE25519
    if (keyType == ETS_KEY_TYPE_X25519) {
        /* For Curve25519 is 32 bytes as unsigned bin */
        ret = wolfKeyCalcFingerprint(keyType, pub, pubSz, fp, &fpSz);
    }
#endif
#ifdef HAVE_CURVE448
    if (keyType == ETS_KEY_TYPE_X448) {
        /* For Curve448 is 56 bytes as unsigned bin */
        ret = wolfKeyCalcFingerprint(keyType, pub, pubSz, fp, &fpSz);
    }
#endif

    if (ret == 0) {
        /* convert bytes to hex string */
        ret = wolfByteToHexString(fp, fpSz, fpStr, *fpStrSz);
        if (ret > 0) {
            *fpStrSz = ret;
            ret = 0;
        }
    }
    return ret;
}

int wolfEtsKeyComputeName(EtsKey* key)
{
    int ret = WOLFKM_NOT_COMPILED_IN;
    int keyAlgo;
    word32 fpSz;
    byte* fp;

    if (key == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    /* if name is already populated then do not calculate again */
    if (key->fingerprintSz > 0) {
        return 0;
    }

    fp = key->fingerprint;
    fpSz = (int)sizeof(key->fingerprint);
    memset(fp, 0, fpSz);

    keyAlgo = wolfEtsKeyGetPkType(key);
#ifdef HAVE_ECC
    if (keyAlgo == WC_PK_TYPE_ECDH) {
        ecc_key ecKey;
        ret = wc_ecc_init(&ecKey);
        if (ret == 0) {
            word32 idx = 0;
            ret = wc_EccPrivateKeyDecode((byte*)key->response, &idx, &ecKey,
                key->responseSz);
            if (ret == 0) {
                byte pub[MAX_ECC_BYTES*2];
                word32 pubXLen = (word32)sizeof(pub)/2;
                word32 pubYLen = (word32)sizeof(pub)/2;
                word32 keySize = wc_ecc_size(&ecKey);
                ret = wc_ecc_export_ex(&ecKey,
                    pub, &pubXLen,
                    pub + keySize, &pubYLen,
                    NULL, NULL, WC_TYPE_UNSIGNED_BIN);
                if (ret == 0) {
                    /* compute fingerprint for key */
                    ret = wolfKeyCalcFingerprint(key->type, pub, keySize*2,
                        fp, &fpSz);
                }
            }
            wc_ecc_free(&ecKey);
        }
    }
#endif
#if !defined(NO_DH) && defined(WOLFSSL_DH_EXTRA)
    if (keyAlgo == WC_PK_TYPE_DH) {
        DhKey dhKey;
        ret = wc_InitDhKey(&dhKey);
        if (ret == 0) {
            word32 idx = 0;
            ret = wc_DhKeyDecode((byte*)key->response, &idx, &dhKey,
                key->responseSz);
            if (ret == 0) {
                byte pubKey[MAX_DH_PUB_SZ];
                word32 pubKeyLen = (word32)sizeof(pubKey);
                ret = wc_export_int(&dhKey.pub, pubKey, &pubKeyLen,
                    MAX_DH_PUB_SZ, WC_TYPE_UNSIGNED_BIN);
                if (ret == 0) {
                    /* compute fingerprint for key */
                    ret = wolfKeyCalcFingerprint(key->type, pubKey, pubKeyLen,
                        fp, &fpSz);
                }
            }
            wc_FreeDhKey(&dhKey);
        }
    }
#endif
#ifdef HAVE_CURVE25519
    if (keyAlgo == WC_PK_TYPE_CURVE25519) {
        curve25519_key curveKey;
        ret = wc_curve25519_init(&curveKey);
        if (ret == 0) {
            word32 idx = 0;
            ret = wc_Curve25519PrivateKeyDecode((byte*)key->response, &idx,
                &curveKey, key->responseSz);
            if (ret == 0) {
                byte pub[CURVE25519_KEYSIZE];
                word32 pubLen = (word32)sizeof(pub);
                ret = wc_curve25519_export_public_ex(&curveKey, pub, &pubLen,
                    EC25519_LITTLE_ENDIAN);
                if (ret == 0) {
                    /* compute fingerprint for key */
                    ret = wolfKeyCalcFingerprint(key->type, pub, pubLen,
                        fp, &fpSz);
                }
            }
            wc_curve25519_free(&curveKey);
        }
    }
#endif
#ifdef HAVE_CURVE448
    if (keyAlgo == WC_PK_TYPE_CURVE448) {
        curve448_key curveKey;
        ret = wc_curve448_init(&curveKey);
        if (ret == 0) {
            word32 idx = 0;
            ret = wc_Curve448PrivateKeyDecode((byte*)key->response, &idx,
                &curveKey, key->responseSz);
            if (ret == 0) {
                byte pub[CURVE448_PUB_KEY_SIZE];
                word32 pubLen = (word32)sizeof(pub);
                ret = wc_curve448_export_public_ex(&curveKey, pub, &pubLen,
                    EC448_LITTLE_ENDIAN);
                if (ret == 0) {
                    /* compute fingerprint for key */
                    ret = wolfKeyCalcFingerprint(key->type, pub, pubLen,
                        fp, &fpSz);
                }
            }
            wc_curve448_free(&curveKey);
        }
    }
#endif

    key->fingerprintSz = fpSz;

    return ret;
}

void wolfEtsKeyPrint(EtsKey* key)
{
    int ret;
    const char* keyAlgoStr;
    char pubName[ETS_MAX_FINGERPRINT_STR];
    int pubSz = (int)sizeof(pubName);

    if (key == NULL) {
        return;
    }

    keyAlgoStr = wolfEtsKeyGetTypeStr(key->type);
    if (keyAlgoStr == NULL) {
        XLOG(WOLFKM_LOG_INFO, "Unknown key type!\n");
        return;
    }

    /* make sure public name is calculated */
    ret = wolfEtsKeyComputeName(key);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Error %d computing key name\n", ret);
    }

    /* convert to hex string (function handles null termination) */
    pubSz = wolfByteToHexString(key->fingerprint, key->fingerprintSz,
        pubName, sizeof(pubName));

    XLOG(WOLFKM_LOG_INFO, "%s: %s\n", keyAlgoStr, pubName);
    (void)pubSz;
}

void wolfEtsKeyFree(EtsKey* key)
{
    if (key) {
        if (key->isDynamic) {
            free(key);
        }
    }
}

int wolfEtsClientClose(EtsClientCtx* client)
{
    int ret = 0;
    if (client && client->ssl) {
        /* send shutdown */
        wc_LockMutex(&client->lock);
        ret = wolfTlsClose(client->ssl, 1);
        client->ssl = NULL;
        wc_UnLockMutex(&client->lock);
    }
    return ret;
}

void wolfEtsClientFree(EtsClientCtx* client)
{
    if (client) {
        wc_LockMutex(&client->lock);
        if (client->ssl) {
            wolfTlsClose(client->ssl, 0);
            client->ssl = NULL;
        }
        if (client->sslCtx) {
            wolfTlsFree(client->sslCtx);
            client->sslCtx = NULL;
        }
        wc_UnLockMutex(&client->lock);
        wc_FreeMutex(&client->lock);
        free(client);
    }
}

int wolfEtsClientInit(void)
{
    /* Ignore SIGPIPE */
    wolfSigIgnore(SIGPIPE);

#if 0
    wolfSSL_Debugging_ON();
#endif
    return wolfSSL_Init();
}

void wolfEtsClientCleanup(void)
{
    wolfSSL_Cleanup();
}
