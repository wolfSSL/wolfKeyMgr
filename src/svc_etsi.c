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

#ifdef WOLFKM_ETSI_SERVICE

/* shared context for worker threads */
typedef struct EtsiSvcCtx {
    /* latest shared key data */
    EtsiKey key;
    word32  renewSec;
    word32  index;

    /* wolf key struct union */
    union {
    #ifdef HAVE_ECC
        ecc_key ecc;
    #endif
    #if !defined(NO_DH) && defined(WOLFSSL_DH_EXTRA)
        DhKey dh;
    #endif
    #ifdef HAVE_CURVE25519
        curve25519_key x25519;
    #endif
    #ifdef HAVE_CURVE448
        curve448_key x448;
    #endif
    } wolfKey;

    /* Key Gen worker thread */
    WC_RNG          rng;
    pthread_mutex_t lock; /* queue lock */
    pthread_t       thread; /* key gen worker */
} EtsiSvcCtx;
static EtsiSvcCtx gSvcCtx;

/* the top level service */
static SvcInfo etsiService = {
    .desc = "ETSI",

    /* Callbacks */
    .requestCb = wolfEtsiSvc_DoRequest,
    .timeoutCb = wolfEtsiSvc_HandleTimeout,
    .initThreadCb = wolfEtsiSvc_WorkerInit,
    .freeThreadCb = wolfEtsiSvc_WorkerFree,
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

/* worker thread objects */
typedef struct EtsiSvcThread {
    word32 index;
    EtsiKeyType keyType;
    byte   httpRspBuf[ETSI_MAX_RESPONSE_SZ];
    word32 httpRspSz;
} EtsiSvcThread;

typedef struct EtsiSvcConn {
    HttpReq req;
    char fingerprint[HTTP_MAX_URI];
    char contextStr[HTTP_MAX_URI];
    word32 groupNum;
} EtsiSvcConn;

#ifdef HAVE_ECC
static int GenNewKeyEcc(EtsiSvcCtx* svcCtx, EtsiKeyType keyType)
{
    int ret;
    int curveId = ECC_CURVE_DEF, keySize = 32;

    /* Determine ECC Key Size and Curve */
    switch (keyType) {
        case ETSI_KEY_TYPE_SECP160K1:
            curveId = ECC_SECP160K1; keySize = 20; break;
        case ETSI_KEY_TYPE_SECP160R1:
            curveId = ECC_SECP160R1; keySize = 20; break;
        case ETSI_KEY_TYPE_SECP160R2:
            curveId = ECC_SECP160R2; keySize = 20; break;
        case ETSI_KEY_TYPE_SECP192K1:
            curveId = ECC_SECP192K1; keySize = 24; break;
        case ETSI_KEY_TYPE_SECP192R1:
            curveId = ECC_SECP192R1; keySize = 24; break;
        case ETSI_KEY_TYPE_SECP224K1:
            curveId = ECC_SECP224K1; keySize = 28; break;
        case ETSI_KEY_TYPE_SECP224R1:
            curveId = ECC_SECP224R1; keySize = 28; break;
        case ETSI_KEY_TYPE_SECP256K1:
            curveId = ECC_SECP256K1; keySize = 32; break;
        case ETSI_KEY_TYPE_SECP256R1:
            curveId = ECC_SECP256R1; keySize = 32; break;
        case ETSI_KEY_TYPE_SECP384R1:
            curveId = ECC_SECP384R1; keySize = 48; break;
        case ETSI_KEY_TYPE_SECP521R1:
            curveId = ECC_SECP521R1; keySize = 66; break;
        case ETSI_KEY_TYPE_BRAINPOOLP256R1:
            curveId = ECC_BRAINPOOLP256R1; keySize = 32; break;
        case ETSI_KEY_TYPE_BRAINPOOLP384R1:
            curveId = ECC_BRAINPOOLP384R1; keySize = 48; break;
        case ETSI_KEY_TYPE_BRAINPOOLP512R1:
            curveId = ECC_BRAINPOOLP512R1; keySize = 64; break;
        default:
            break;
    }

    ret = wc_ecc_init(&svcCtx->wolfKey.ecc);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "ECC Init Failed! %d\n", ret);
        return WOLFKM_BAD_KEY;
    }
        
    ret = wc_ecc_make_key_ex(&svcCtx->rng, keySize, &svcCtx->wolfKey.ecc,
        curveId);
    if (ret == 0) {
        /* Export as DER IETF RFC 5915 */
        svcCtx->key.responseSz = sizeof(svcCtx->key.response);
        ret = wc_EccKeyToDer(&svcCtx->wolfKey.ecc, (byte*)svcCtx->key.response,
            svcCtx->key.responseSz);
        if (ret >= 0) {
            svcCtx->key.responseSz = ret;
            ret = 0;
        }
    }

    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "ECC Key Generation Failed! %d\n", ret);
        wc_ecc_free(&svcCtx->wolfKey.ecc);
    }

    return ret;
}
#endif

#if !defined(NO_DH) && defined(WOLFSSL_DH_EXTRA)

static int GenNewKeyDh(EtsiSvcCtx* svcCtx, EtsiKeyType keyType)
{
    int ret;
    const DhParams* params = NULL;
    word32 privKeySz = 0, pubKeySz = 0;
    byte privKey[MAX_DH_PRIV_SZ];
    byte pubKey[MAX_DH_PUB_SZ];

    switch (keyType) {
    #ifdef HAVE_FFDHE_2048
        case ETSI_KEY_TYPE_FFDHE_2048:
            params = wc_Dh_ffdhe2048_Get(); privKeySz = 29; break;
    #endif
    #ifdef HAVE_FFDHE_3072
        case ETSI_KEY_TYPE_FFDHE_3072:
            params = wc_Dh_ffdhe3072_Get(); privKeySz = 34; break;
    #endif
    #ifdef HAVE_FFDHE_4096
        case ETSI_KEY_TYPE_FFDHE_4096:
            params = wc_Dh_ffdhe4096_Get(); privKeySz = 39; break;
    #endif
    #ifdef HAVE_FFDHE_6144
        case ETSI_KEY_TYPE_FFDHE_6144:
            params = wc_Dh_ffdhe6144_Get(); privKeySz = 46; break;
    #endif
    #ifdef HAVE_FFDHE_8192
        case ETSI_KEY_TYPE_FFDHE_8192:
            params = wc_Dh_ffdhe8192_Get(); privKeySz = 52; break;
    #endif
        default:
            break;
    }

    if (params == NULL) {
        return WOLFKM_NOT_COMPILED_IN;
    }

    ret = wc_InitDhKey(&svcCtx->wolfKey.dh);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "DH Init Failed! %d\n", ret);
        return WOLFKM_BAD_KEY;
    }

    /* Set key params */
    ret = wc_DhSetKey(&svcCtx->wolfKey.dh,
        params->p, params->p_len,
        params->g, params->g_len);
    if (ret == 0) {
        /* Generate a new key pair */
        pubKeySz = params->p_len;
        ret = wc_DhGenerateKeyPair(&svcCtx->wolfKey.dh, &svcCtx->rng,
            privKey, &privKeySz,
            pubKey, &pubKeySz);
    }
    if (ret == 0) {
        if (params->p_len != pubKeySz) {
            /* Zero pad the front of the public key to match prime "p" size */
            memmove(pubKey + params->p_len - pubKeySz, pubKey, pubKeySz);
            memset(pubKey, 0, params->p_len - pubKeySz);
        }

        /* load public and private key info into DkKey */
        ret = wc_DhImportKeyPair(&svcCtx->wolfKey.dh,
            privKey, privKeySz,
            pubKey, pubKeySz);
    }

    if (ret == 0) {
        /* export DH key as DER */
        /* Note: Proper support for wc_DhPrivKeyToDer was added v4.8.0 or 
         *       later (see PR 3832) */
        svcCtx->key.responseSz = sizeof(svcCtx->key.response);
        ret = wc_DhPrivKeyToDer(&svcCtx->wolfKey.dh, (byte*)svcCtx->key.response,
            &svcCtx->key.responseSz);
        if (ret >= 0)
            ret = 0; /* size is returned in keyBufSz */
    }

    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "DH Key Generation Failed! %d\n", ret);
        wc_FreeDhKey(&svcCtx->wolfKey.dh);
    }

    return ret;
}
#endif /* !NO_DH */

/* caller should lock svcCtx->lock */
static void FreeSvcKey(EtsiSvcCtx* svcCtx)
{
    if (svcCtx == NULL || svcCtx->key.type == ETSI_KEY_TYPE_UNKNOWN) {
        return;
    }

#ifdef HAVE_ECC
    if (svcCtx->key.type >= ETSI_KEY_TYPE_SECP160K1 && 
        svcCtx->key.type <= ETSI_KEY_TYPE_BRAINPOOLP512R1) {
        wc_ecc_free(&svcCtx->wolfKey.ecc);
    }
#endif
#if !defined(NO_DH) && defined(WOLFSSL_DH_EXTRA)
    if (svcCtx->key.type >= ETSI_KEY_TYPE_FFDHE_2048 && 
        svcCtx->key.type <= ETSI_KEY_TYPE_FFDHE_8192) {
        wc_FreeDhKey(&svcCtx->wolfKey.dh);
    }
#endif
#ifdef HAVE_CURVE25519
    if (svcCtx->key.type == ETSI_KEY_TYPE_X25519) {
        wc_curve25519_free(&svcCtx->wolfKey.x25519);
    }
#endif
#ifdef HAVE_CURVE448
    if (svcCtx->key.type == ETSI_KEY_TYPE_X448) {
        wc_curve448_free(&svcCtx->wolfKey.x448);
    }
#endif
    svcCtx->key.type = ETSI_KEY_TYPE_UNKNOWN;
}

static int GenNewKey(EtsiSvcCtx* svcCtx)
{
    int ret = NOT_COMPILED_IN;
    EtsiKeyType keyType;

    keyType = svcCtx->key.type;

    /* Free old key type */
    FreeSvcKey(svcCtx);

#ifdef HAVE_ECC
    if (keyType >= ETSI_KEY_TYPE_SECP160K1 && 
        keyType <= ETSI_KEY_TYPE_BRAINPOOLP512R1) {
        XLOG(WOLFKM_LOG_WARN, "Generating new %s key (index %d)\n",
            wolfEtsiKeyGetTypeStr(keyType), svcCtx->index);
        ret = GenNewKeyEcc(svcCtx, keyType);
    }
#endif
#if !defined(NO_DH) && defined(WOLFSSL_DH_EXTRA)
    if (keyType >= ETSI_KEY_TYPE_FFDHE_2048 && 
        keyType <= ETSI_KEY_TYPE_FFDHE_8192) {
        XLOG(WOLFKM_LOG_WARN, "Generating new %s key (index %d)\n",
            wolfEtsiKeyGetTypeStr(keyType), svcCtx->index);
        ret = GenNewKeyDh(svcCtx, keyType);
    }
#endif
#ifdef HAVE_CURVE25519
    if (keyType == ETSI_KEY_TYPE_X25519) {
        /* TODO: X25519 Key Gen */
        XLOG(WOLFKM_LOG_WARN, "Generating new X25519 key (index %d)\n",
            svcCtx->index);
    }
#endif
#ifdef HAVE_CURVE448
    if (keyType == ETSI_KEY_TYPE_X448) {
        /* TODO: X448 Key Gen */
        //curveId = ECC_X448;
        //keySize = 56;
        XLOG(WOLFKM_LOG_WARN, "Generating new X448 key (index %d)\n",
            svcCtx->index);
    }
#endif

    if (ret == 0) {
        svcCtx->key.expires = wolfGetCurrentTimeT() + svcCtx->renewSec;
        svcCtx->key.type = keyType;
        svcCtx->index++;

        wolfEtsiKeyPrint(&svcCtx->key);
    }

    return ret;
}

static int SetupKeyPackage(EtsiSvcCtx* svcCtx, EtsiSvcThread* etsiThread)
{
    int ret = 0;
    char expiresStr[100];
    HttpHeader headers[3];
    headers[0].type = HTTP_HDR_CONTENT_TYPE;
    headers[0].string = "application/pkcs8";
    headers[1].type = HTTP_HDR_CONNECTION;
    headers[1].string = "Keep-Alive";
    headers[2].type = HTTP_HDR_EXPIRES;
    headers[2].string = expiresStr;
    memset(expiresStr, 0, sizeof(expiresStr));

    XLOG(WOLFKM_LOG_DEBUG, "Synchronizing key to worker thread\n"); 
    if (etsiThread->index != svcCtx->index) {
        /* Format Expires Time */
        struct tm tm;
        localtime_r(&svcCtx->key.expires, &tm);
        strftime(expiresStr, sizeof(expiresStr), HTTP_DATE_FMT, &tm);

        /* Wrap key in HTTP server response */
        etsiThread->httpRspSz = sizeof(etsiThread->httpRspBuf);
        ret = wolfHttpServer_EncodeResponse(0, NULL, 
            etsiThread->httpRspBuf, &etsiThread->httpRspSz, headers, 
            sizeof(headers)/sizeof(HttpHeader), (byte*)svcCtx->key.response,
            svcCtx->key.responseSz);
        if (ret != 0) {
            pthread_mutex_unlock(&svcCtx->lock);
            XLOG(WOLFKM_LOG_ERROR, "Error encoding HTTP response: %d\n", ret);
            return ret;
        }

        etsiThread->index = svcCtx->index;
        etsiThread->keyType = svcCtx->key.type;
    }

    return ret;
}

static void* KeyPushWorker(void* arg)
{
    int ret;
    SvcInfo* svc = (SvcInfo*)arg;
    EtsiSvcCtx* svcCtx = (EtsiSvcCtx*)svc->svcCtx;

    do {
        /* generate new key */
        pthread_mutex_lock(&svcCtx->lock);
        ret = GenNewKey(svcCtx);
        pthread_mutex_unlock(&svcCtx->lock);
        if (ret != 0) {
            XLOG(WOLFKM_LOG_ERROR, "ETSI Key Generation Failed %d\n", ret);
            return NULL;
        }

        /* push to any connected clients */
        wolfKeyMgr_NotifyAllClients(svc);

        /* wait seconds */
        sleep(svcCtx->renewSec);
    } while (1);

    return NULL;
}

int wolfEtsiSvc_DoResponse(SvcConn* conn)
{
    int ret;
    EtsiSvcThread* etsiThread;

    if (conn == NULL || conn->stream == NULL || conn->svcThreadCtx == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ETSI response pointers\n");
        return WOLFKM_BAD_ARGS;
    }
    etsiThread = (EtsiSvcThread*)conn->svcThreadCtx;
    if (etsiThread->httpRspSz == 0) {
        XLOG(WOLFKM_LOG_ERROR, "ETSI HTTP Response / Key not found!\n");
        return WOLFKM_BAD_KEY;
    }

    /* send already setup key */
    memcpy(conn->request, etsiThread->httpRspBuf, etsiThread->httpRspSz);
    conn->requestSz = etsiThread->httpRspSz;

    /* send response, which is in the reused request buffer */
    ret = wolfKeyMgr_DoSend(conn, (byte*)conn->request, conn->requestSz);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "ETSI DoSend failed: %d\n", ret);
        return WOLFKM_BAD_SEND;
    }
    XLOG(WOLFKM_LOG_INFO, "Sent ETSI Response (%d bytes)\n", conn->requestSz);

    return ret;
}

/* the key request handler */
int wolfEtsiSvc_DoRequest(SvcConn* conn)
{
    int ret;
    SvcInfo* svc;
    EtsiSvcCtx* svcCtx;
    EtsiSvcConn* etsiConn;
    EtsiSvcThread* etsiThread;

    if (conn == NULL || conn->svc == NULL || conn->stream == NULL || 
            conn->svcThreadCtx == NULL) {
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
    etsiThread = (EtsiSvcThread*)conn->svcThreadCtx;

    ret = wolfHttpServer_ParseRequest(&etsiConn->req, conn->request,
        conn->requestSz);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "ETSI HTTP Server Parse failed: %d\n", ret);
        return WOLFKM_BAD_REQUEST_TYPE;
    }
    wolfHttpRequestPrint(&etsiConn->req);

    /* Get fingerprint */
    ret = wolfHttpUriGetItem(etsiConn->req.uri, "fingerprints=",
        etsiConn->fingerprint, sizeof(etsiConn->fingerprint));
    if (ret > 0)
        XLOG(WOLFKM_LOG_DEBUG, "Fingerprint: %s\n", etsiConn->fingerprint);

    /* Get groups - borrow contextStr variable */
    ret = wolfHttpUriGetItem(etsiConn->req.uri, "groups=",
        etsiConn->contextStr, sizeof(etsiConn->contextStr));
    if (ret > 0) {
        const char* groupName;
        etsiConn->groupNum = (word32)strtol(etsiConn->contextStr, NULL, 16);
        groupName = wolfEtsiKeyGetTypeStr((EtsiKeyType)etsiConn->groupNum);
        XLOG(WOLFKM_LOG_DEBUG, "Group: %s (%d)\n", groupName, etsiConn->groupNum);
        if (groupName == NULL) {
            etsiConn->groupNum = 0;
        }
        /* clear borrowed contextStr */
        memset(etsiConn->contextStr, 0, sizeof(etsiConn->contextStr));
    }

    /* Get context string */
    ret = wolfHttpUriGetItem(etsiConn->req.uri, "contextstr=",
        etsiConn->contextStr, sizeof(etsiConn->contextStr));
    if (ret > 0)
        XLOG(WOLFKM_LOG_DEBUG, "Context: %s\n", etsiConn->contextStr);


    /* If generated key doesn't match, force it now */
    if (etsiConn->groupNum > 0 && 
            etsiThread->keyType != (EtsiKeyType)etsiConn->groupNum) {
        pthread_mutex_lock(&svcCtx->lock);
        svcCtx->key.type = (EtsiKeyType)etsiConn->groupNum;
        ret = GenNewKey(svcCtx);
        if (ret == 0) {
            ret = SetupKeyPackage(svcCtx, etsiThread);
        }
        pthread_mutex_unlock(&svcCtx->lock);
    }

    /* Send Response */
    return wolfEtsiSvc_DoResponse(conn);
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
    int ret;
    SvcInfo* svc;
    EtsiSvcCtx* svcCtx;
    EtsiSvcThread* etsiThread;
    EtsiSvcConn* etsiConn;

    if (conn == NULL || conn->svc == NULL || conn->svcThreadCtx == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ETSI notify pointers\n");
        return WOLFKM_BAD_ARGS;
    }

    svc = conn->svc;
    svcCtx = (EtsiSvcCtx*)svc->svcCtx;
    etsiThread = (EtsiSvcThread*)conn->svcThreadCtx;
    etsiConn = (EtsiSvcConn*)conn->svcConnCtx;

    /* update key */
    pthread_mutex_lock(&svcCtx->lock);
    ret = SetupKeyPackage(svcCtx, etsiThread);
    pthread_mutex_unlock(&svcCtx->lock);

    /* push key to active push threads */
    if (ret == 0 && etsiConn != NULL && 
            etsiConn->req.type == HTTP_METHOD_PUT) {
        /* send updated key - already populated in httpRspBuf */
        ret = wolfEtsiSvc_DoResponse(conn);
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

/* Called for startup of each worker thread */
int wolfEtsiSvc_WorkerInit(SvcInfo* svc, void** svcThreadCtx)
{
    int ret = 0;
    EtsiSvcCtx* svcCtx = (EtsiSvcCtx*)svc->svcCtx;
    EtsiSvcThread* etsiThread = malloc(sizeof(*etsiThread));
    if (etsiThread == NULL) {
        return WOLFKM_BAD_MEMORY;
    }
    memset(etsiThread, 0, sizeof(*etsiThread));

    /* make sure we have a key package setup to send */
    pthread_mutex_lock(&svcCtx->lock);
    ret = SetupKeyPackage(svcCtx, etsiThread);
    pthread_mutex_unlock(&svcCtx->lock);

    *svcThreadCtx = etsiThread;

    return ret;
}

void wolfEtsiSvc_WorkerFree(SvcInfo* svc, void* svcThreadCtx)
{
    if (svcThreadCtx == NULL)
        return;

    (void)svc;

    free((EtsiSvcThread*)svcThreadCtx);
}

#endif /* WOLFKM_ETSI_SERVICE */


SvcInfo* wolfEtsiSvc_Init(struct event_base* mainBase, int renewSec,
    EtsiKeyType keyTypeDef)
{
#ifdef WOLFKM_ETSI_SERVICE
    int ret;
    char* listenPort = WOLFKM_ETSISVC_PORT;
    SvcInfo* svc = &etsiService;
    EtsiSvcCtx* svcCtx = (EtsiSvcCtx*)svc->svcCtx;

    ret = wc_InitRng(&svcCtx->rng);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Error initializing RNG %d\n", ret);
        return NULL;
    }

    pthread_mutex_init(&svcCtx->lock, NULL);

    svcCtx->renewSec = renewSec;
    svcCtx->key.type = keyTypeDef;

    /* start key generation thread */
    if (pthread_create(&svcCtx->thread, NULL, KeyPushWorker, svc) != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Error creating keygen worker\n");
        wolfEtsiSvc_Cleanup(svc);
        return NULL;
    }

    /* setup listening events */
    ret = wolfKeyMgr_AddListeners(svc, AF_INET6, listenPort, mainBase);  /* 6 may contain a 4 */
    if (ret < 0)
        ret = wolfKeyMgr_AddListeners(svc, AF_INET, listenPort, mainBase);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "Failed to bind at least one ETSI listener,"
                               "already running?\n");
        wolfEtsiSvc_Cleanup(svc);
        return NULL;
    }

    return svc;
#else
    (void)mainBase;
    (void)renewSec;

    return NULL;
#endif
}

void wolfEtsiSvc_Cleanup(SvcInfo* svc)
{
    if (svc) {
#ifdef WOLFKM_ETSI_SERVICE
        EtsiSvcCtx* svcCtx = (EtsiSvcCtx*)svc->svcCtx;

        if (svc->keyBuffer) {
            free(svc->keyBuffer);
            svc->keyBuffer = NULL;
        }
        if (svc->certBuffer) {
            free(svc->certBuffer);
            svc->certBuffer = NULL;
        }

        FreeSvcKey(svcCtx);
        wc_FreeRng(&svcCtx->rng);
        pthread_mutex_destroy(&svcCtx->lock);
    }
#endif
}
