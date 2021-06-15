/* mod_etsi.c
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

#ifdef WOLFKM_ETSI_SERVICE

#include "wolfkeymgr/mod_etsi.h"
#include <signal.h>

struct EtsiClientCtx {
    WOLFSSL_CTX*   sslCtx;
    WOLFSSL*       ssl;
    wolfSSL_Mutex  lock;
};


EtsiClientCtx* wolfEtsiClientNew(void)
{
    EtsiClientCtx* client = (EtsiClientCtx*)malloc(sizeof(EtsiClientCtx));
    if (client) {
        memset(client, 0, sizeof(EtsiClientCtx));
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

int wolfEtsiClientSetKey(EtsiClientCtx* client, const char* keyFile, 
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

int wolfEtsiClientAddCA(EtsiClientCtx* client, const char* caFile)
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

int wolfEtsiClientConnect(EtsiClientCtx* client, const char* host,
    word16 port, int timeoutSec)
{
    int ret;

    if (client == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    wc_LockMutex(&client->lock);
    ret = wolfTlsConnect(client->sslCtx, &client->ssl, host, port, timeoutSec);
    if (ret == 0) {
        XLOG(WOLFKM_LOG_INFO, "Connected to ETSI service\n");
    }
    else {
        XLOG(WOLFKM_LOG_ERROR, "Failure connecting to ETSI service %d\n", ret);   
    }
    wc_UnLockMutex(&client->lock);

    return ret;
}

const char* wolfEtsiKeyNamedGroupStr(EtsiKey* key)
{
    if (key == NULL)
        return NULL;
    switch (key->type) {
        case ETSI_KEY_TYPE_SECP160K1:  return "0x000F"; /* 15 */
        case ETSI_KEY_TYPE_SECP160R1:  return "0x0010"; /* 16 */
        case ETSI_KEY_TYPE_SECP160R2:  return "0x0011"; /* 17 */
        case ETSI_KEY_TYPE_SECP192K1:  return "0x0012"; /* 18 */
        case ETSI_KEY_TYPE_SECP192R1:  return "0x0013"; /* 19 */
        case ETSI_KEY_TYPE_SECP224K1:  return "0x0014"; /* 20 */
        case ETSI_KEY_TYPE_SECP224R1:  return "0x0015"; /* 21 */
        case ETSI_KEY_TYPE_SECP256K1:  return "0x0016"; /* 22 */
        case ETSI_KEY_TYPE_SECP256R1:  return "0x0017"; /* 23 */
        case ETSI_KEY_TYPE_SECP384R1:  return "0x0018"; /* 24 */
        case ETSI_KEY_TYPE_SECP521R1:  return "0x0019"; /* 25 */
        case ETSI_KEY_TYPE_BRAINPOOLP256R1: return "0x001A"; /* 26 */
        case ETSI_KEY_TYPE_BRAINPOOLP384R1: return "0x001B"; /* 27 */
        case ETSI_KEY_TYPE_BRAINPOOLP512R1: return "0x001C"; /* 28 */
        case ETSI_KEY_TYPE_X25519:     return "0x001D"; /* 29 */
        case ETSI_KEY_TYPE_X448:       return "0x001E"; /* 30 */
        case ETSI_KEY_TYPE_FFDHE_2048: return "0x0100"; /* 256 */
        case ETSI_KEY_TYPE_FFDHE_3072: return "0x0101"; /* 257 */
        case ETSI_KEY_TYPE_FFDHE_4096: return "0x0102"; /* 258 */
        case ETSI_KEY_TYPE_FFDHE_6144: return "0x0103"; /* 259 */
        case ETSI_KEY_TYPE_FFDHE_8192: return "0x0104"; /* 260 */
        default: break;
    }
    return NULL;
}

int wolfEtsiClientMakeRequest(EtsiClientType type, const char* fingerprint,
    const char* groups, const char* contextstr, byte* request, word32* requestSz)
{
    int ret;
    char uri[HTTP_MAX_URI*3]; /* fingerprint, groups, contextStr */
    size_t uriLen;
    HttpHeader headers[1];
    HttpMethodType httpType;
    headers[0].type = HTTP_HDR_ACCEPT;
    headers[0].string = "application/pkcs8";
 
    /* Build HTTP ETSI request */
    if (type == ETSI_CLIENT_PUSH) {
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

static void ParseHttpResponseExpires(HttpRsp* rsp, EtsiKey* key, time_t now)
{
    int i;

    /* capture expiration */
    for (i=0; i<rsp->headerCount; i++) {
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

int wolfEtsiClientGet(EtsiClientCtx* client, EtsiKey* key, 
    EtsiKeyType keyType, const char* fingerprint, const char* contextStr,
    int timeoutSec)
{
    int    ret;
    byte   request[ETSI_MAX_REQUEST_SZ];
    word32 requestSz = ETSI_MAX_REQUEST_SZ;
    int    pos;
    HttpRsp rsp;
    const char* group;
    time_t now;

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

    /* build GET request for current key */
    key->type = keyType;
    group = wolfEtsiKeyNamedGroupStr(key);
    ret = wolfEtsiClientMakeRequest(ETSI_CLIENT_GET, fingerprint, group,
        contextStr, request, &requestSz);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_INFO, "EtsiClientMakeRequest failed: %d\n", ret);
        return ret;
    }

    /* send GET key request */
    wc_LockMutex(&client->lock);
    pos = 0;
    while (pos < requestSz) {
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
        ret = wolfTlsRead(client->ssl, (byte*)key->response, (int*)&key->responseSz,
            timeoutSec);
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
        ret = wolfHttpClient_ParseResponse(&rsp,
            key->response, key->responseSz);
        if (ret == 0 && rsp.body && rsp.bodySz > 0) {
            wolfHttpResponsePrint(&rsp);
            ParseHttpResponseExpires(&rsp, key, now);

            /* move payload (body) to response (same buffer) */
            memcpy(key->response, rsp.body, rsp.bodySz);
            key->responseSz = rsp.bodySz;
        }
        else {
            XLOG(WOLFKM_LOG_ERROR, "Error parsing HTTP response! %d\n", ret);
        }
    }

    if (ret == 0) {
        /* asymmetric key package response */
        XLOG(WOLFKM_LOG_INFO, "Got ETSI response (%d bytes)\n",
            key->responseSz);
        ret = key->responseSz; /* return key size */
    }

    return ret;
}

int wolfEtsiClientPush(EtsiClientCtx* client, EtsiKeyType keyType,
    const char* fingerprint, const char* contextStr,
    EtsiKeyCallbackFunc cb, void* cbCtx)
{
    int    ret;
    byte   request[ETSI_MAX_REQUEST_SZ];
    word32 requestSz = ETSI_MAX_REQUEST_SZ;
    int    pos;
    HttpRsp rsp;
    const char* group;
    time_t now;
    EtsiKey key;

    if (client == NULL || cb == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    /* Request PUSH for new keys */
    memset(&key, 0, sizeof(key));
    key.type = keyType;
    group = wolfEtsiKeyNamedGroupStr(&key);
    ret = wolfEtsiClientMakeRequest(ETSI_CLIENT_PUSH, fingerprint, group,
        contextStr, request, &requestSz);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_INFO, "EtsiClientMakeRequest failed: %d\n", ret);
        return ret;
    }

    /* send PUSH key request */
    wc_LockMutex(&client->lock);
    pos = 0;
    while (pos < requestSz) {
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
            XLOG(WOLFKM_LOG_INFO, "Got ETSI response (%d bytes)\n",
                key.responseSz);

            /* parse HTTP server response */
            key.expires = 0;
            ret = wolfHttpClient_ParseResponse(&rsp,
                key.response, key.responseSz);
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


int wolfEtsiClientFind(EtsiClientCtx* client, EtsiKeyType keyType,
    const char* fingerprint, const char* contextStr, time_t begin, time_t end,
    EtsiKeyCallbackFunc cb, void* cbCtx)
{
    /* TODO: Add find ability for replay */
    (void)client;
    (void)keyType;
    (void)fingerprint;
    (void)contextStr;
    (void)begin;
    (void)end;
    (void)cb;
    (void)cbCtx;
    return WOLFKM_NOT_COMPILED_IN;
}

int wolfEtsiKeyGet(EtsiKey* key, byte** response, word32* responseSz)
{
    if (key == NULL)
        return WOLFKM_BAD_ARGS;
    if (response)
        *response = (byte*)key->response;
    if (responseSz)
        *responseSz = key->responseSz;
    return 0;
}

EtsiKey* wolfEtsiKeyNew(void)
{
    EtsiKey* key = (EtsiKey*)malloc(sizeof(EtsiKey));
    if (key) {
        memset(key, 0, sizeof(EtsiKey));
        key->isDynamic = 1;
    }
    return key;
}

int wolfEtsiKeyGetPkType(EtsiKey* key)
{
    if (key == NULL)
        return WOLFKM_BAD_ARGS;

    if (key->type >= ETSI_KEY_TYPE_SECP160K1 && 
        key->type <= ETSI_KEY_TYPE_BRAINPOOLP512R1) {
        return WC_PK_TYPE_ECDH;
    }
    if (key->type >= ETSI_KEY_TYPE_FFDHE_2048 && 
        key->type <= ETSI_KEY_TYPE_FFDHE_8192) {
        return WC_PK_TYPE_DH;
    }
    if (key->type == ETSI_KEY_TYPE_X25519) {
        return WC_PK_TYPE_CURVE25519;
    }
#ifdef HAVE_CURVE448
    if (key->type == ETSI_KEY_TYPE_X448) {
        return WC_PK_TYPE_CURVE448
    }
#endif
    return WC_PK_TYPE_NONE;
}

const char* wolfEtsiKeyGetTypeStr(EtsiKeyType type)
{
    switch (type) {
        case ETSI_KEY_TYPE_SECP160K1:
            return "SECP160K1";
        case ETSI_KEY_TYPE_SECP160R1:
            return "SECP160R1";
        case ETSI_KEY_TYPE_SECP160R2:
            return "SECP160R2";
        case ETSI_KEY_TYPE_SECP192K1:
            return "SECP192K1";
        case ETSI_KEY_TYPE_SECP192R1:
            return "SECP192R1";
        case ETSI_KEY_TYPE_SECP224K1:
            return "SECP224K1";
        case ETSI_KEY_TYPE_SECP224R1:
            return "SECP224R1";
        case ETSI_KEY_TYPE_SECP256K1:
            return "SECP256K1";
        case ETSI_KEY_TYPE_SECP256R1:
            return "SECP256R1";
        case ETSI_KEY_TYPE_SECP384R1:
            return "SECP384R1";
        case ETSI_KEY_TYPE_SECP521R1:
            return "SECP521R1";
        case ETSI_KEY_TYPE_BRAINPOOLP256R1:
            return "BRAINPOOLP256R1";
        case ETSI_KEY_TYPE_BRAINPOOLP384R1:
            return "BRAINPOOLP384R1";
        case ETSI_KEY_TYPE_BRAINPOOLP512R1:
            return "BRAINPOOLP512R1";
        case ETSI_KEY_TYPE_X25519:
            return "X25519";
        case ETSI_KEY_TYPE_X448:
            return "X448";
        case ETSI_KEY_TYPE_FFDHE_2048:
            return "FFDHE_2048";
        case ETSI_KEY_TYPE_FFDHE_3072:
            return "FFDHE_3072";
        case ETSI_KEY_TYPE_FFDHE_4096:
            return "FFDHE_4096";
        case ETSI_KEY_TYPE_FFDHE_6144:
            return "FFDHE_6144";
        case ETSI_KEY_TYPE_FFDHE_8192:
            return "FFDHE_8192";
        default:
            break;
    }
    return NULL;
}

int wolfEtsiKeyLoadCTX(EtsiKey* key, WOLFSSL_CTX* ctx)
{
    int keyAlgo;

    if (key == NULL || ctx == NULL)
        return WOLFKM_BAD_ARGS;

    /* determine key algo */
    keyAlgo = wolfEtsiKeyGetPkType(key);

    return wolfSSL_CTX_set_ephemeral_key(ctx, keyAlgo, 
        key->response, key->responseSz, WOLFSSL_FILETYPE_ASN1);
}

int wolfEtsiKeyLoadSSL(EtsiKey* key, WOLFSSL* ssl)
{
    int ret;
    int keyAlgo;

    if (key == NULL || ssl == NULL)
        return WOLFKM_BAD_ARGS;

    /* determine key algo */
    keyAlgo = wolfEtsiKeyGetPkType(key);

    ret = wolfSSL_set_ephemeral_key(ssl, keyAlgo, 
        key->response, key->responseSz, WOLFSSL_FILETYPE_ASN1);
    if (ret == 0) {
        /* TODO: handle return code */
        (void)wolfSSL_UseKeyShare(ssl, key->type);
    }
    return ret;
}

int wolfEtsiKeyPrint(EtsiKey* key)
{
    int ret = WOLFKM_NOT_COMPILED_IN;
    int keyAlgo;

    if (key == NULL) {
        return WOLFKM_BAD_ARGS;
    }
    if (key->responseSz == 0) {
        XLOG(WOLFKM_LOG_INFO, "Empty Key\n");
        return 0;
    }

    keyAlgo = wolfEtsiKeyGetPkType(key);

#ifdef HAVE_ECC
    if (keyAlgo == WC_PK_TYPE_ECDH) {
        /* example for loading ECC key */
        ecc_key ecKey;
        ret = wc_ecc_init(&ecKey);
        if (ret == 0) {
            word32 idx = 0;
            ret = wc_EccPrivateKeyDecode((byte*)key->response, &idx, &ecKey,
                key->responseSz);
            if (ret == 0) {
                byte pubX[MAX_ECC_BYTES*2+1];
                byte pubY[MAX_ECC_BYTES*2+1];
                word32 pubXLen = sizeof(pubX), pubYLen = sizeof(pubY);
                ret = wc_ecc_export_ex(&ecKey,
                    pubX, &pubXLen,
                    pubY, &pubYLen, 
                    NULL, NULL, WC_TYPE_HEX_STR);
                if (ret == 0) {
                    XLOG(WOLFKM_LOG_INFO, "ECC Pub X: %s\n", pubX);
                    XLOG(WOLFKM_LOG_INFO, "ECC Pub Y: %s\n", pubY);
                }
            }
            wc_ecc_free(&ecKey);
        }
    }
#endif
#ifndef NO_DH
    if (keyAlgo == WC_PK_TYPE_DH) {
        /* example for loading DHE key */
        DhKey dhKey;
        ret = wc_InitDhKey(&dhKey);
        if (ret == 0) {
            word32 idx = 0;
            ret = wc_DhKeyDecode((byte*)key->response, &idx, &dhKey, key->responseSz);
            if (ret == 0) {
                byte pubKey[MAX_DH_PUB_SZ];
                word32 pubKeyLen = sizeof(pubKey);
                ret = wc_DhExportKeyPair(&dhKey, NULL, NULL, pubKey, &pubKeyLen);
                if (ret == 0) {
                    XLOG(WOLFKM_LOG_INFO, "DH Pub: %d\n", pubKeyLen);
                }
            }
            wc_FreeDhKey(&dhKey);
        }
    }
#endif
#ifdef HAVE_CURVE25519
    if (keyAlgo == WC_PK_TYPE_CURVE25519) {
        /* TODO: add example for loading X25519 key and print */
        //curve25519_key x25519;
        XLOG(WOLFKM_LOG_INFO, "X25519 Pub: TODO\n");
    }
#endif
#ifdef HAVE_CURVE448
    if (keyAlgo == WC_PK_TYPE_CURVE448) {
        /* TODO: add example for loading X448 key and print */
        //curve448_key x448;
        XLOG(WOLFKM_LOG_INFO, "X448 Pub: TODO\n");
    }
#endif
    return ret;
}

void wolfEtsiKeyFree(EtsiKey* key)
{
    if (key) {
        if (key->isDynamic) {
            free(key);
        }
    }
}

int wolfEtsiClientClose(EtsiClientCtx* client)
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

void wolfEtsiClientFree(EtsiClientCtx* client)
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

int wolfEtsiClientInit(void)
{
    /* Ignore SIGPIPE */
    wolfSigIgnore(SIGPIPE);

#if 0
    wolfSSL_Debugging_ON();
#endif
    return wolfSSL_Init();
}

void wolfEtsiClientCleanup(void)
{
    wolfSSL_Cleanup();
}

#endif /* WOLFKM_ETSI_SERVICE */
