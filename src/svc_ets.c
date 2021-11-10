/* svc_ets.c
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

#include "wolfkeymgr/keymanager.h"
#include "wolfkeymgr/mod_http.h"
#include "wolfkeymgr/mod_ets.h"
#include "wolfkeymgr/mod_vault.h"
#include <wolfssl/wolfcrypt/rsa.h>

/* determine maximum concurrent server's (based on fingerprint) */
#ifndef ETS_SVC_MAX_SERVERS
#define ETS_SVC_MAX_SERVERS     4
#endif
/* determine maximum number of active keys */
#ifndef ETS_SVC_MAX_ACTIVE_KEYS
#define ETS_SVC_MAX_ACTIVE_KEYS (ETS_SVC_MAX_SERVERS * 4)
#endif

/* shared context for worker threads */
typedef struct EtsSvcCtx {
    /* latest shared key data */
    EtsKey         keys[ETS_SVC_MAX_ACTIVE_KEYS];
    EtsSvcConfig   config;

    WC_RNG          rng;
    pthread_mutex_t lock;   /* shared lock */

    /* key gen worker */
    pthread_t       kgThread;
    pthread_mutex_t kgMutex;
    pthread_cond_t  kgCond;

#ifdef WOLFKM_VAULT
    wolfVaultCtx*   vault; /* key vault */
#endif

    byte shutdown:1; /* signal to shutdown workers */
} EtsSvcCtx;
static EtsSvcCtx gSvcCtx;

/* The top level service */
static SvcInfo gEtsService = {
    .desc = "ETS",

    /* Callbacks */
    .requestCb = wolfEtsSvc_DoRequest,
    .timeoutCb = wolfEtsSvc_HandleTimeout,
    .notifyCb = wolfEtsSvc_DoNotify,
    .closeCb = wolfEtsSvc_ConnClose,

    /* TLS Certificate and Buffer */
    .certBuffer = NULL,
    .certBufferSz = 0,
    .keyBuffer = NULL,
    .keyBufferSz = 0,
    .caBuffer = NULL,
    .caBufferSz = 0,

    .svcCtx = &gSvcCtx,
};

/* connection object */
typedef struct EtsSvcConn {
    HttpReq req;
    char    fingerprint[ETS_MAX_FINGERPRINT_STR];
    char    contextStr[ETS_MAX_CONTEXT_STR];
    word32  groupNum; /* same as enum EtsKeyType */
} EtsSvcConn;

#ifdef WOLFKM_VAULT
static int AddKeyToVault(EtsSvcCtx* svcCtx, EtsKey* key)
{
    if (svcCtx->vault == NULL) {
        XLOG(WOLFKM_LOG_WARN, "AddKey: vault not open\n");
        return 0; /* don't fail, just log warning */
    }

    return wolfVaultAdd(svcCtx->vault, key->type,
        key->fingerprint, key->fingerprintSz,
        key->response, key->responseSz);
}
#endif

static int EtsSvcGenNewKey(EtsSvcCtx* svcCtx, EtsKeyType keyType, EtsKey* key)
{
    int ret = WOLFKM_NOT_COMPILED_IN;
    const char* keyTypeStr = wolfEtsKeyGetTypeStr(keyType);

    if (svcCtx == NULL || key == NULL || keyTypeStr == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    XLOG(WOLFKM_LOG_WARN, "Generating new %s key\n", keyTypeStr);

    ret = wolfEtsKeyGen(key, keyType, &svcCtx->rng);
    if (ret == 0) {
        key->expires = wolfGetCurrentTimeT() + svcCtx->config.renewSec;

        wolfEtsKeyPrint(key);

    #ifdef WOLFKM_VAULT
        ret = AddKeyToVault(svcCtx, key);
        if (ret != 0) {
            XLOG(WOLFKM_LOG_ERROR, "Failed adding %s key to vault! %d\n",
                keyTypeStr, ret);
        }
    #endif
    }
    else {
        XLOG(WOLFKM_LOG_ERROR, "Failed generating %s key! %s (%d)\n",
            keyTypeStr, wolfKeyMgr_GetError(ret), ret);
    }

    return ret;
}

static void WakeKeyGenWorker(EtsSvcCtx* svcCtx)
{
    /* signal key generation thread to wake */
    pthread_mutex_lock(&svcCtx->kgMutex);
    pthread_cond_signal(&svcCtx->kgCond);
    pthread_mutex_unlock(&svcCtx->kgMutex);
}

static int SetupKeyPackage(SvcConn* conn, EtsSvcCtx* svcCtx)
{
    int ret = 0, i;
    EtsSvcConn* etsConn;
    HttpHeader headers[3];
    struct tm tm;
    char expiresStr[100];
    EtsKey* key = NULL;
    int wakeKg = 0;

    if (conn == NULL || conn->svcConnCtx == NULL || svcCtx == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    etsConn = (EtsSvcConn*)conn->svcConnCtx;

    headers[0].type = HTTP_HDR_CONTENT_TYPE;
    headers[0].string = "application/pkcs8";
    headers[1].type = HTTP_HDR_CONNECTION;
    headers[1].string = "Keep-Alive";
    headers[2].type = HTTP_HDR_EXPIRES;
    headers[2].string = expiresStr;
    memset(expiresStr, 0, sizeof(expiresStr));

    /* find key based on group and optional contextStr */
    pthread_mutex_lock(&svcCtx->lock);
    for (i=0; i<ETS_SVC_MAX_ACTIVE_KEYS; i++) {
        if ((word32)svcCtx->keys[i].type == etsConn->groupNum) {
            word32 ctxStrSz = (word32)strlen(etsConn->contextStr);
            if (ctxStrSz == 0 || (ctxStrSz == (word32)strlen(svcCtx->keys[i].contextStr) &&
                    strncmp(svcCtx->keys[i].contextStr, etsConn->contextStr, ctxStrSz) == 0)) {
                key = &svcCtx->keys[i];
                break;
            }
        }
    }
    /* if one doesn't exist for this group then trigger generation */
    if (key == NULL) {
        /* assign free slot */
        for (i=0; i<ETS_SVC_MAX_ACTIVE_KEYS; i++) {
            if ((word32)svcCtx->keys[i].type == 0) {
                key = &svcCtx->keys[i];
                break;
            }
        }
        /* if no free slots then find oldest key */
        if (key == NULL) {
            time_t oldestTime = 0;
            for (i=0; i<ETS_SVC_MAX_ACTIVE_KEYS; i++) {
                if (oldestTime == 0 || oldestTime > svcCtx->keys[i].expires)
                    oldestTime = svcCtx->keys[i].expires;
            }
            for (i=0; i<ETS_SVC_MAX_ACTIVE_KEYS; i++) {
                if (oldestTime == svcCtx->keys[i].expires) {
                    key = &svcCtx->keys[i];
                    break;
                }
            }
        }
        ret = EtsSvcGenNewKey(svcCtx, etsConn->groupNum, key);
    }

    if (ret == 0) {
        /* Format Expires Time */
        localtime_r(&key->expires, &tm);
        strftime(expiresStr, sizeof(expiresStr), HTTP_DATE_FMT, &tm);

        /* set contextStr */
        strncpy(key->contextStr, etsConn->contextStr, sizeof(key->contextStr));

        /* increment use count */
        key->useCount++;

        /* Wrap key in HTTP server response */
        conn->responseSz = sizeof(conn->response);
        ret = wolfHttpServer_EncodeResponse(0, NULL,
            conn->response, &conn->responseSz, headers,
            sizeof(headers)/sizeof(HttpHeader), (byte*)key->response,
            key->responseSz);

        XLOG(WOLFKM_LOG_INFO, "Setup Key (idx %d, uses %d)\n",
            i, key->useCount);
    }

    if (key && key->useCount >= svcCtx->config.maxUseCount) {
        /* wake key generation thread */
        wakeKg = 1;
    }
    pthread_mutex_unlock(&svcCtx->lock);

    if (wakeKg) {
        /* signal key generation thread to wake */
        WakeKeyGenWorker(svcCtx);
    }

    return ret;
}

#ifdef WOLFKM_VAULT
static int SetupKeyFindResponse(SvcConn* conn, wolfVaultItem* item)
{
    int ret = 0;
    HttpHeader headers[2];
    headers[0].type = HTTP_HDR_CONTENT_TYPE;
    headers[0].string = "application/pkcs8";
    headers[1].type = HTTP_HDR_CONNECTION;
    headers[1].string = "Keep-Alive";

    /* Wrap key in HTTP server response */
    conn->responseSz = sizeof(conn->response);
    ret = wolfHttpServer_EncodeResponse(0, NULL,
        conn->response, &conn->responseSz, headers,
        sizeof(headers)/sizeof(HttpHeader), (byte*)item->data,
        item->dataSz);

    return ret;
}
#endif

static void* KeyPushWorker(void* arg)
{
    int ret, i;
    SvcInfo* svc = (SvcInfo*)arg;
    EtsSvcCtx* svcCtx = (EtsSvcCtx*)svc->svcCtx;
    EtsKey* key;
    time_t now, nextExpires;
    int renewSec, keyGenCount;
    struct timespec max_wait = {0, 0};

    /* generate default key */
    pthread_mutex_lock(&svcCtx->lock);
    key = &svcCtx->keys[0];
    (void)EtsSvcGenNewKey(svcCtx, svcCtx->config.keyTypeDef, key);
    pthread_mutex_unlock(&svcCtx->lock);

    do {
        keyGenCount = 0;
        nextExpires = 0;

        /* renew any expired keys */
        pthread_mutex_lock(&svcCtx->lock);
        now = wolfGetCurrentTimeT();
        for (i=0; i<ETS_SVC_MAX_ACTIVE_KEYS; i++) {
            if (svcCtx->keys[i].type != ETS_KEY_TYPE_UNKNOWN) {
                int expired, maxUses;
                expired = (svcCtx->keys[i].expires > 0 &&
                                                now >= svcCtx->keys[i].expires);
                maxUses = (svcCtx->keys[i].useCount >=
                                                    svcCtx->config.maxUseCount);
                /* check if expired or use count exceeded */
                if (expired || maxUses) {
                    ret = EtsSvcGenNewKey(svcCtx, svcCtx->keys[i].type,
                        &svcCtx->keys[i]);
                    (void)ret; /* ignore error, logged in EtsSvcGenNewKey */

                    keyGenCount++;
                    now = wolfGetCurrentTimeT(); /* refresh time after key gen */
                }
                if (nextExpires == 0 || nextExpires > svcCtx->keys[i].expires) {
                    nextExpires = svcCtx->keys[i].expires;
                }
            }
        }
        renewSec = (nextExpires > now) ?
            nextExpires - now :
            svcCtx->config.renewSec;
        pthread_mutex_unlock(&svcCtx->lock);

        if (keyGenCount > 0) {
            /* push to any connected clients */
            wolfKeyMgr_NotifyAllClients(svc);
        }

        /* wait seconds */
        XLOG(WOLFKM_LOG_INFO, "Next key renewal %d seconds\n", renewSec);

        clock_gettime(CLOCK_REALTIME, &max_wait);
        max_wait.tv_sec += renewSec;

        /* wait for wake signal or timeout */
        pthread_mutex_lock(&svcCtx->kgMutex);
        ret = pthread_cond_timedwait(&svcCtx->kgCond, &svcCtx->kgMutex,
                                                                     &max_wait);
        pthread_mutex_unlock(&svcCtx->kgMutex);

        XLOG(WOLFKM_LOG_DEBUG, "Key Generation Worker Wake %d sec\n", ret);
    } while (!svcCtx->shutdown);

    return NULL;
}

static int wolfEtsSvc_DoResponse(SvcConn* conn)
{
    int ret;

    if (conn == NULL || conn->stream == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ETS response pointers\n");
        return WOLFKM_BAD_ARGS;
    }
    if (conn->responseSz == 0) {
        XLOG(WOLFKM_LOG_ERROR, "ETS HTTP Response / Key not found!\n");
        return WOLFKM_BAD_KEY;
    }

    /* send response, which is in the reused request buffer */
    ret = wolfKeyMgr_DoSend(conn, (byte*)conn->response, conn->responseSz);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "ETS DoSend failed: %d\n", ret);
        return WOLFKM_BAD_SEND;
    }
    XLOG(WOLFKM_LOG_INFO, "Sent ETS Response (%d bytes)\n", conn->responseSz);

    return ret;
}

/* The key request handler */
int wolfEtsSvc_DoRequest(SvcConn* conn)
{
    int ret = 0;
    SvcInfo* svc;
    EtsSvcCtx* svcCtx;
    EtsSvcConn* etsConn;;

    if (conn == NULL || conn->svc == NULL || conn->stream == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ETS Request pointers\n");
        return WOLFKM_BAD_ARGS;
    }

    XLOG(WOLFKM_LOG_INFO, "Got ETS Request (%d bytes)\n", conn->requestSz);

    if (conn->svcConnCtx == NULL) {
        /* Creating connection context */
        XLOG(WOLFKM_LOG_INFO, "Creating connection context\n");
        conn->svcConnCtx = malloc(sizeof(EtsSvcConn));
        if (conn->svcConnCtx == NULL) {
            return WOLFKM_BAD_MEMORY;
        }
        memset(conn->svcConnCtx, 0, sizeof(EtsSvcConn));
    }
    svc = conn->svc;
    svcCtx = (EtsSvcCtx*)svc->svcCtx;
    etsConn = (EtsSvcConn*)conn->svcConnCtx;

    ret = wolfHttpServer_ParseRequest(&etsConn->req, conn->request,
        conn->requestSz);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "ETS HTTP Server Parse failed: %d\n", ret);
        return WOLFKM_BAD_REQUEST_TYPE;
    }
    wolfHttpRequestPrint(&etsConn->req);

    /* Get fingerprint */
    if (wolfHttpUriGetItem(etsConn->req.uri, "fingerprints=",
        etsConn->fingerprint, sizeof(etsConn->fingerprint)) > 0) {
        XLOG(WOLFKM_LOG_DEBUG, "Fingerprint: %s\n", etsConn->fingerprint);
    }

    /* Get groups - borrow contextStr variable */
    if (wolfHttpUriGetItem(etsConn->req.uri, "groups=",
        etsConn->contextStr, sizeof(etsConn->contextStr)) > 0) {
        const char* groupName;
        etsConn->groupNum = (word32)strtol(etsConn->contextStr, NULL, 16);
        groupName = wolfEtsKeyGetTypeStr((EtsKeyType)etsConn->groupNum);
        XLOG(WOLFKM_LOG_DEBUG, "Group: %s (%d)\n",
            groupName, etsConn->groupNum);
        if (groupName == NULL) {
            etsConn->groupNum = 0;
        }
        /* clear borrowed contextStr */
        memset(etsConn->contextStr, 0, sizeof(etsConn->contextStr));
    }

    /* Get context string */
    if (wolfHttpUriGetItem(etsConn->req.uri, "contextstr=",
        etsConn->contextStr, sizeof(etsConn->contextStr)) > 0) {
        XLOG(WOLFKM_LOG_DEBUG, "Context: %s\n", etsConn->contextStr);
    }

#ifdef WOLFKM_VAULT
    /* find uses fingerprint only */
    if (etsConn->groupNum > 0 && strlen(etsConn->fingerprint) > 0) {
        wolfVaultItem item;
        byte name[WOLFKM_VAULT_NAME_MAX_SZ];
        word32 nameSz = (word32)sizeof(name);
        memset(&item, 0, sizeof(item));
        ret = wolfHexStringToByte(etsConn->fingerprint,
            strlen(etsConn->fingerprint), name, nameSz);
        if (ret > 0) {
            nameSz = ret;
            ret = 0;
        }
        if (ret == 0) {
            ret = wolfVaultGet(svcCtx->vault, &item, etsConn->groupNum,
                name, nameSz);
            if (ret == 0) {
                ret = SetupKeyFindResponse(conn, &item);
            }
            wolfVaultFreeItem(&item);
        }
    }
    else
#endif
    if (etsConn->groupNum > 0) {
        ret = SetupKeyPackage(conn, svcCtx);
    }

    if (ret != 0) {
        /* TODO: Setup error response */
    }

    /* Send Response */
    if (ret == 0) {
        ret = wolfEtsSvc_DoResponse(conn);
    }

    return ret;
}

void wolfEtsSvc_ConnClose(SvcConn* conn)
{
    if (conn && conn->svcConnCtx) {
        free(conn->svcConnCtx);
        conn->svcConnCtx = NULL;
    }
}

int wolfEtsSvc_DoNotify(SvcConn* conn)
{
    int ret = 0;
    SvcInfo* svc;
    EtsSvcCtx* svcCtx;
    EtsSvcConn* etsConn;

    if (conn == NULL || conn->svc == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ETS notify pointers\n");
        return WOLFKM_BAD_ARGS;
    }

    svc = conn->svc;
    svcCtx = (EtsSvcCtx*)svc->svcCtx;
    etsConn = (EtsSvcConn*)conn->svcConnCtx;

    if (etsConn != NULL && etsConn->req.type == HTTP_METHOD_PUT) {
        /* update key */
        ret = SetupKeyPackage(conn, svcCtx);

        /* push key to active push threads */
        if (ret == 0)  {
            /* send updated key */
            ret = wolfEtsSvc_DoResponse(conn);
        }
    }

    return ret;
}

int wolfEtsSvc_HandleTimeout(SvcConn* conn)
{
    EtsSvcConn* etsConn;

    if (conn == NULL || conn->svcConnCtx == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ETS timeout pointers\n");
        return WOLFKM_BAD_ARGS;
    }

    etsConn = (EtsSvcConn*)conn->svcConnCtx;

    /* if we received an HTTP request then keep open */
    if (etsConn->req.type != HTTP_METHOD_UNKNOWN) {
        return 0; /* keep open (return non-zero value to close connection) */
    }
    return 1; /* close connection */
}

SvcInfo* wolfEtsSvc_Init(const EtsSvcConfig* config)

{
    int ret;
    SvcInfo* svc = &gEtsService;
    EtsSvcCtx* svcCtx = (EtsSvcCtx*)svc->svcCtx;

    /* capture configuration */
    memcpy(&svcCtx->config, config, sizeof(*config));

    ret = wc_InitRng(&svcCtx->rng);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Error initializing RNG %d\n", ret);
        return NULL;
    }

    pthread_mutex_init(&svcCtx->lock, NULL);

    return svc;
}

int wolfEtsSvc_Start(SvcInfo* svc, struct event_base* mainBase,
    const char* listenPort)
{
    int ret;
    EtsSvcCtx* svcCtx;

    if (svc == NULL)
        return WOLFKM_BAD_ARGS;

    svcCtx = (EtsSvcCtx*)svc->svcCtx;

    /* setup key gen cond signal */
    pthread_mutex_init(&svcCtx->kgMutex, NULL);
    pthread_cond_init(&svcCtx->kgCond, NULL);

    /* start key generation thread */
    if (pthread_create(&svcCtx->kgThread, NULL, KeyPushWorker, svc) != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Error creating keygen worker\n");
        return WOLFKM_BAD_MEMORY;
    }

    /* setup listening events - IPv6 may contain a IPv4 */
    ret = wolfKeyMgr_AddListeners(svc, AF_INET6, listenPort, mainBase);
    if (ret < 0)
        ret = wolfKeyMgr_AddListeners(svc, AF_INET, listenPort, mainBase);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "Failed to bind at least one %s listener,"
                               "already running?\n", svc->desc);
    }

    return ret;
}

void wolfEtsSvc_Cleanup(SvcInfo* svc)
{
    if (svc) {
        EtsSvcCtx* svcCtx = (EtsSvcCtx*)svc->svcCtx;

        if (svc->keyBuffer) {
            free(svc->keyBuffer);
            svc->keyBuffer = NULL;
        }
        if (svc->certBuffer) {
            free(svc->certBuffer);
            svc->certBuffer = NULL;
        }
    #ifdef WOLFKM_VAULT
        if (svcCtx->vault) {
            wolfVaultClose(svcCtx->vault);
        }
    #endif

        wc_FreeRng(&svcCtx->rng);

        /* signal shutdown and wake worker */
        svcCtx->shutdown =  1;
        WakeKeyGenWorker(svcCtx);

        pthread_mutex_destroy(&svcCtx->kgMutex);
        pthread_cond_destroy(&svcCtx->kgCond);

        pthread_mutex_destroy(&svcCtx->lock);
    }
}

#if defined(WOLFKM_VAULT) && defined(WOLFKM_VAULT_ENC)
/* key: returned AES key */
/* keyEnc: key information stored in vault header */
static int wolfEtsSvcVaultAuthCb(wolfVaultCtx* ctx, byte* key, word32 keySz,
    byte* keyEnc, word32 keyEncSz, void* cbCtx)
{
    int ret;
    SvcInfo* svc = (SvcInfo*)cbCtx;
    WC_RNG rng;
    int newKey = 0;
    static byte zeroBuffer[WOLFKM_VAULT_ENC_KEYSZ];
#ifndef NO_RSA
    RsaKey rsa;
    word32 idx = 0, privKeySz = WOLFKM_VAULT_ENC_KEYSZ;
#endif

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        return ret;
    }

    /* Setup encryption key (if needed) */
    if (memcmp(keyEnc, zeroBuffer, keyEncSz) == 0) {
        /* Generate key for encryption */
        ret = wc_RNG_GenerateBlock(&rng, key, keySz);
        if (ret != 0) {
            XLOG(WOLFKM_LOG_ERROR, "Error %s (%d) generating key\n",
                wolfKeyMgr_GetError(ret), ret);
            wc_FreeRng(&rng);
            return ret;
        }
        newKey = 1;
    }

#ifndef NO_RSA
    /* use long term private RSA key to encrypt key */
    ret = wc_InitRsaKey(&rsa, NULL);
    if (ret != 0) {
        wc_FreeRng(&rng);
        return ret;
    }

    /* Decode the RSA long term private key */
    ret = wc_RsaPrivateKeyDecode(svc->keyBuffer, &idx, &rsa, svc->keyBufferSz);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Error %s (%d) decoding RSA key buffer\n",
            wolfKeyMgr_GetError(ret), ret);
    }

    if (ret == 0) {
        privKeySz = wc_RsaEncryptSize(&rsa);
        if (privKeySz > keyEncSz) {
            XLOG(WOLFKM_LOG_ERROR, "Vault Auth: Invalid key size %d!\n",
                keyEncSz);
            ret = WOLFKM_BAD_ARGS;
        }
    }

#ifdef WC_RSA_BLINDING
    if (ret == 0) {
        ret = wc_RsaSetRNG(&rsa, &rng);
    }
#endif

    if (ret == 0 && !newKey) {
        /* use long term private RSA key to decrypt key */
        ret = wc_RsaPrivateDecrypt(keyEnc, privKeySz, key, keySz, &rsa);
        if (ret > 0) {
            if (ret != (int)keySz) {
                XLOG(WOLFKM_LOG_WARN, "Vault Auth: "
                    "Decrypted key size %d not expected %d\n", ret, keySz);
            }
            ret = 0; /* success */
        }
        else {
            XLOG(WOLFKM_LOG_ERROR, "Vault Auth: decrypt key error %s (%d)\n",
                wolfKeyMgr_GetError(ret), ret);
        }
    }

    if (newKey || ret != 0) {
        XLOG(WOLFKM_LOG_WARN, "Vault Auth: Setting up new encryption key\n");
        ret = 0; /* reset error code */
        if (!newKey) {
            /* Generate key for encryption */
            ret = wc_RNG_GenerateBlock(&rng, key, keySz);
        }
        if (ret == 0) {
            /* use long term private RSA key to encrypt key */
            ret = wc_RsaPublicEncrypt(key, keySz, keyEnc, privKeySz, &rsa,
                &rng);
            if (ret > 0) {
                if (ret != (int)privKeySz) {
                    XLOG(WOLFKM_LOG_WARN, "Vault Auth: "
                        "Encrypted key size %d not expected %d\n", ret, privKeySz);
                }
                ret = 0; /* success */
            }
        }
        if (ret != 0) {
            XLOG(WOLFKM_LOG_ERROR, "Vault Auth: encrypt key error %s (%d)\n",
                wolfKeyMgr_GetError(ret), ret);
        }
    }

    wc_FreeRsaKey(&rsa);

#else
    #error Vault encryption not supported!
#endif

    wc_FreeRng(&rng);

    (void)ctx;
    (void)key;
    (void)keySz;
    (void)keyEnc;
    (void)keyEncSz;
    (void)svc;
    return ret;
}
#endif

int wolfEtsSvc_SetVaultFile(SvcInfo* svc, const char* vaultFile)
{
    int ret = 0;
    EtsSvcCtx* svcCtx;

    if (svc == NULL || vaultFile == NULL)
        return WOLFKM_BAD_ARGS;


    svcCtx = (EtsSvcCtx*)svc->svcCtx;
#ifdef WOLFKM_VAULT
    ret = wolfVaultOpen(&svcCtx->vault, vaultFile);
    if (ret == 0) {
        wolfVaultPrintInfo(svcCtx->vault);

    #ifdef WOLFKM_VAULT_ENC
        ret = wolfVaultAuth(svcCtx->vault, wolfEtsSvcVaultAuthCb, svc);
    #endif
    }
#endif
    (void)svcCtx;
    return ret;
}
