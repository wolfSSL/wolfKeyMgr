/* svc_etsi.c
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
#include "wolfkeymgr/mod_etsi.h"
#include "wolfkeymgr/mod_vault.h"
#include <wolfssl/wolfcrypt/rsa.h>

/* determine maximum concurrent server's (based on fingerprint) */
#ifndef ETSI_SVC_MAX_SERVERS
#define ETSI_SVC_MAX_SERVERS     4
#endif
/* determine maximum number of active keys */
#ifndef ETSI_SVC_MAX_ACTIVE_KEYS
#define ETSI_SVC_MAX_ACTIVE_KEYS (ETSI_SVC_MAX_SERVERS * 4)
#endif

/* shared context for worker threads */
typedef struct EtsiSvcCtx {
    /* latest shared key data */
    EtsiKey         keys[ETSI_SVC_MAX_ACTIVE_KEYS];
    EtsiSvcConfig   config;

    WC_RNG          rng;
    pthread_mutex_t lock;   /* shared lock */

    /* key gen worker */
    pthread_t       kgThread;
    pthread_mutex_t kgMutex;
    pthread_cond_t  kgCond;

#ifdef WOLFKM_VAULT
    wolfVaultCtx*   vault; /* key vault */
#endif
} EtsiSvcCtx;
static EtsiSvcCtx gSvcCtx;

/* the top level service */
static SvcInfo gEtsiService = {
    .desc = "ETSI",

    /* Callbacks */
    .requestCb = wolfEtsiSvc_DoRequest,
    .timeoutCb = wolfEtsiSvc_HandleTimeout,
    .notifyCb = wolfEtsiSvc_DoNotify,
    .closeCb = wolfEtsiSvc_ConnClose,

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
typedef struct EtsiSvcConn {
    HttpReq req;
    char    fingerprint[ETSI_MAX_FINGERPRINT_STR];
    char    contextStr[ETSI_MAX_CONTEXT_STR];
    word32  groupNum; /* same as enum EtsiKeyType */
} EtsiSvcConn;

#ifdef WOLFKM_VAULT
static int AddKeyToVault(EtsiSvcCtx* svcCtx, EtsiKey* key)
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

static int EtsiSvcGenNewKey(EtsiSvcCtx* svcCtx, EtsiKeyType keyType, EtsiKey* key)
{
    int ret = WOLFKM_NOT_COMPILED_IN;
    const char* keyTypeStr = wolfEtsiKeyGetTypeStr(keyType);

    if (svcCtx == NULL || key == NULL || keyTypeStr == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    XLOG(WOLFKM_LOG_WARN, "Generating new %s key\n", keyTypeStr);

    ret = wolfEtsiKeyGen(key, keyType, &svcCtx->rng);
    if (ret == 0) {
        key->expires = wolfGetCurrentTimeT() + svcCtx->config.renewSec;

        wolfEtsiKeyPrint(key);

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

static int SetupKeyPackage(SvcConn* conn, EtsiSvcCtx* svcCtx)
{
    int ret = 0, i;
    EtsiSvcConn* etsiConn;
    HttpHeader headers[3];
    struct tm tm;
    char expiresStr[100];
    EtsiKey* key = NULL;
    int wakeKg = 0;

    if (conn == NULL || conn->svcConnCtx == NULL || svcCtx == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    etsiConn = (EtsiSvcConn*)conn->svcConnCtx;

    headers[0].type = HTTP_HDR_CONTENT_TYPE;
    headers[0].string = "application/pkcs8";
    headers[1].type = HTTP_HDR_CONNECTION;
    headers[1].string = "Keep-Alive";
    headers[2].type = HTTP_HDR_EXPIRES;
    headers[2].string = expiresStr;
    memset(expiresStr, 0, sizeof(expiresStr));

    /* find key based on group and optional contextStr */
    pthread_mutex_lock(&svcCtx->lock);
    for (i=0; i<ETSI_SVC_MAX_ACTIVE_KEYS; i++) {
        if ((word32)svcCtx->keys[i].type == etsiConn->groupNum) {
            word32 ctxStrSz = (word32)strlen(etsiConn->contextStr);
            if (ctxStrSz == 0 || (ctxStrSz == (word32)strlen(svcCtx->keys[i].contextStr) &&
                    strncmp(svcCtx->keys[i].contextStr, etsiConn->contextStr, ctxStrSz) == 0)) {
                key = &svcCtx->keys[i];
                break;
            }
        }
    }
    /* if one doesn't exist for this group then trigger generation */
    if (key == NULL) {
        /* assign free slot */
        for (i=0; i<ETSI_SVC_MAX_ACTIVE_KEYS; i++) {
            if ((word32)svcCtx->keys[i].type == 0) {
                key = &svcCtx->keys[i];
                break;
            }
        }
        /* if no free slots then find oldest key */
        if (key == NULL) {
            time_t oldestTime = 0;
            for (i=0; i<ETSI_SVC_MAX_ACTIVE_KEYS; i++) {
                if (oldestTime == 0 || oldestTime > svcCtx->keys[i].expires)
                    oldestTime = svcCtx->keys[i].expires;
            }
            for (i=0; i<ETSI_SVC_MAX_ACTIVE_KEYS; i++) {
                if (oldestTime == svcCtx->keys[i].expires) {
                    key = &svcCtx->keys[i];
                    break;
                }
            }
        }
        ret = EtsiSvcGenNewKey(svcCtx, etsiConn->groupNum, key);
    }

    if (ret == 0) {
        /* Format Expires Time */
        localtime_r(&key->expires, &tm);
        strftime(expiresStr, sizeof(expiresStr), HTTP_DATE_FMT, &tm);

        /* set contextStr */
        strncpy(key->contextStr, etsiConn->contextStr, sizeof(key->contextStr));

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
        pthread_mutex_lock(&svcCtx->kgMutex);
        pthread_cond_signal(&svcCtx->kgCond);
        pthread_mutex_unlock(&svcCtx->kgMutex);
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
    EtsiSvcCtx* svcCtx = (EtsiSvcCtx*)svc->svcCtx;
    EtsiKey* key;
    time_t now, nextExpires;
    int renewSec, keyGenCount;
    struct timespec max_wait = {0, 0};

    /* generate default key */
    pthread_mutex_lock(&svcCtx->lock);
    key = &svcCtx->keys[0];
    (void)EtsiSvcGenNewKey(svcCtx, svcCtx->config.keyTypeDef, key);
    pthread_mutex_unlock(&svcCtx->lock);

    do {
        keyGenCount = 0;
        nextExpires = 0;

        /* renew any expired keys */
        pthread_mutex_lock(&svcCtx->lock);
        now = wolfGetCurrentTimeT();
        for (i=0; i<ETSI_SVC_MAX_ACTIVE_KEYS; i++) {
            if (svcCtx->keys[i].type != ETSI_KEY_TYPE_UNKNOWN) {
                int expired, maxUses;
                expired = (svcCtx->keys[i].expires > 0 &&
                                                now >= svcCtx->keys[i].expires);
                maxUses = (svcCtx->keys[i].useCount >=
                                                    svcCtx->config.maxUseCount);
                /* check if expired or use count exceeded */
                if (expired || maxUses) {
                    ret = EtsiSvcGenNewKey(svcCtx, svcCtx->keys[i].type,
                        &svcCtx->keys[i]);
                    (void)ret; /* ignore error, logged in EtsiSvcGenNewKey */

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
    } while (1);

    return NULL;
}

static int wolfEtsiSvc_DoResponse(SvcConn* conn)
{
    int ret;

    if (conn == NULL || conn->stream == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ETSI response pointers\n");
        return WOLFKM_BAD_ARGS;
    }
    if (conn->responseSz == 0) {
        XLOG(WOLFKM_LOG_ERROR, "ETSI HTTP Response / Key not found!\n");
        return WOLFKM_BAD_KEY;
    }

    /* send response, which is in the reused request buffer */
    ret = wolfKeyMgr_DoSend(conn, (byte*)conn->response, conn->responseSz);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "ETSI DoSend failed: %d\n", ret);
        return WOLFKM_BAD_SEND;
    }
    XLOG(WOLFKM_LOG_INFO, "Sent ETSI Response (%d bytes)\n", conn->responseSz);

    return ret;
}

/* the key request handler */
int wolfEtsiSvc_DoRequest(SvcConn* conn)
{
    int ret = 0;
    SvcInfo* svc;
    EtsiSvcCtx* svcCtx;
    EtsiSvcConn* etsiConn;;

    if (conn == NULL || conn->svc == NULL || conn->stream == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ETSI Request pointers\n");
        return WOLFKM_BAD_ARGS;
    }

    XLOG(WOLFKM_LOG_INFO, "Got ETSI Request (%d bytes)\n", conn->requestSz);

    if (conn->svcConnCtx == NULL) {
        /* Creating connection context */
        XLOG(WOLFKM_LOG_INFO, "Creating connection context\n");
        conn->svcConnCtx = malloc(sizeof(EtsiSvcConn));
        if (conn->svcConnCtx == NULL) {
            return WOLFKM_BAD_MEMORY;
        }
        memset(conn->svcConnCtx, 0, sizeof(EtsiSvcConn));
    }
    svc = conn->svc;
    svcCtx = (EtsiSvcCtx*)svc->svcCtx;
    etsiConn = (EtsiSvcConn*)conn->svcConnCtx;

    ret = wolfHttpServer_ParseRequest(&etsiConn->req, conn->request,
        conn->requestSz);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "ETSI HTTP Server Parse failed: %d\n", ret);
        return WOLFKM_BAD_REQUEST_TYPE;
    }
    wolfHttpRequestPrint(&etsiConn->req);

    /* Get fingerprint */
    if (wolfHttpUriGetItem(etsiConn->req.uri, "fingerprints=",
        etsiConn->fingerprint, sizeof(etsiConn->fingerprint)) > 0) {
        XLOG(WOLFKM_LOG_DEBUG, "Fingerprint: %s\n", etsiConn->fingerprint);
    }

    /* Get groups - borrow contextStr variable */
    if (wolfHttpUriGetItem(etsiConn->req.uri, "groups=",
        etsiConn->contextStr, sizeof(etsiConn->contextStr)) > 0) {
        const char* groupName;
        etsiConn->groupNum = (word32)strtol(etsiConn->contextStr, NULL, 16);
        groupName = wolfEtsiKeyGetTypeStr((EtsiKeyType)etsiConn->groupNum);
        XLOG(WOLFKM_LOG_DEBUG, "Group: %s (%d)\n",
            groupName, etsiConn->groupNum);
        if (groupName == NULL) {
            etsiConn->groupNum = 0;
        }
        /* clear borrowed contextStr */
        memset(etsiConn->contextStr, 0, sizeof(etsiConn->contextStr));
    }

    /* Get context string */
    if (wolfHttpUriGetItem(etsiConn->req.uri, "contextstr=",
        etsiConn->contextStr, sizeof(etsiConn->contextStr)) > 0) {
        XLOG(WOLFKM_LOG_DEBUG, "Context: %s\n", etsiConn->contextStr);
    }

#ifdef WOLFKM_VAULT
    /* find uses fingerprint only */
    if (etsiConn->groupNum > 0 && strlen(etsiConn->fingerprint) > 0) {
        wolfVaultItem item;
        byte name[WOLFKM_VAULT_NAME_MAX_SZ];
        word32 nameSz = (word32)sizeof(name);
        memset(&item, 0, sizeof(item));
        ret = wolfHexStringToByte(etsiConn->fingerprint,
            strlen(etsiConn->fingerprint), name, nameSz);
        if (ret > 0) {
            nameSz = ret;
            ret = 0;
        }
        if (ret == 0) {
            ret = wolfVaultGet(svcCtx->vault, &item, etsiConn->groupNum,
                name, nameSz);
            if (ret == 0) {
                ret = SetupKeyFindResponse(conn, &item);
            }
            wolfVaultFreeItem(&item);
        }
    }
    else
#endif
    if (etsiConn->groupNum > 0) {
        ret = SetupKeyPackage(conn, svcCtx);
    }

    if (ret != 0) {
        /* TODO: Setup error response */
    }

    /* Send Response */
    if (ret == 0) {
        ret = wolfEtsiSvc_DoResponse(conn);
    }

    return ret;
}

void wolfEtsiSvc_ConnClose(SvcConn* conn)
{
    if (conn && conn->svcConnCtx) {
        free(conn->svcConnCtx);
        conn->svcConnCtx = NULL;
    }
}

int wolfEtsiSvc_DoNotify(SvcConn* conn)
{
    int ret = 0;
    SvcInfo* svc;
    EtsiSvcCtx* svcCtx;
    EtsiSvcConn* etsiConn;

    if (conn == NULL || conn->svc == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ETSI notify pointers\n");
        return WOLFKM_BAD_ARGS;
    }

    svc = conn->svc;
    svcCtx = (EtsiSvcCtx*)svc->svcCtx;
    etsiConn = (EtsiSvcConn*)conn->svcConnCtx;

    if (etsiConn != NULL && etsiConn->req.type == HTTP_METHOD_PUT) {
        /* update key */
        ret = SetupKeyPackage(conn, svcCtx);

        /* push key to active push threads */
        if (ret == 0)  {
            /* send updated key */
            ret = wolfEtsiSvc_DoResponse(conn);
        }
    }

    return ret;
}

int wolfEtsiSvc_HandleTimeout(SvcConn* conn)
{
    EtsiSvcConn* etsiConn;

    if (conn == NULL || conn->svcConnCtx == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ETSI timeout pointers\n");
        return WOLFKM_BAD_ARGS;
    }

    etsiConn = (EtsiSvcConn*)conn->svcConnCtx;

    /* if we received an HTTP request then keep open */
    if (etsiConn->req.type != HTTP_METHOD_UNKNOWN) {
        return 0; /* keep open (return non-zero value to close connection) */
    }
    return 1; /* close connection */
}

SvcInfo* wolfEtsiSvc_Init(const EtsiSvcConfig* config)

{
    int ret;
    SvcInfo* svc = &gEtsiService;
    EtsiSvcCtx* svcCtx = (EtsiSvcCtx*)svc->svcCtx;

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

int wolfEtsiSvc_Start(SvcInfo* svc, struct event_base* mainBase,
    const char* listenPort)
{
    int ret;
    EtsiSvcCtx* svcCtx;

    if (svc == NULL)
        return WOLFKM_BAD_ARGS;

    svcCtx = (EtsiSvcCtx*)svc->svcCtx;

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

void wolfEtsiSvc_Cleanup(SvcInfo* svc)
{
    if (svc) {
        EtsiSvcCtx* svcCtx = (EtsiSvcCtx*)svc->svcCtx;

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

        pthread_mutex_destroy(&svcCtx->kgMutex);
        pthread_cond_destroy(&svcCtx->kgCond);

        pthread_mutex_destroy(&svcCtx->lock);
    }
}

#if defined(WOLFKM_VAULT) && defined(WOLFKM_VAULT_ENC)
/* key: returned AES key */
/* keyEnc: key information stored in vault header */
static int wolfEtsiSvcVaultAuthCb(wolfVaultCtx* ctx, byte* key, word32 keySz,
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
        if (!newKey) {
            /* Generate key for encryption */
            ret = wc_RNG_GenerateBlock(&rng, key, keySz);
        }

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
        else {
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

int wolfEtsiSvc_SetVaultFile(SvcInfo* svc, const char* vaultFile)
{
    int ret = 0;
    EtsiSvcCtx* svcCtx;

    if (svc == NULL || vaultFile == NULL)
        return WOLFKM_BAD_ARGS;


    svcCtx = (EtsiSvcCtx*)svc->svcCtx;
#ifdef WOLFKM_VAULT
    ret = wolfVaultOpen(&svcCtx->vault, vaultFile);
    if (ret == 0) {
        wolfVaultPrintInfo(svcCtx->vault);

    #ifdef WOLFKM_VAULT_ENC
        ret = wolfVaultAuth(svcCtx->vault, wolfEtsiSvcVaultAuthCb, svc);
    #endif
    }
#endif
    (void)svcCtx;
    return ret;
}
