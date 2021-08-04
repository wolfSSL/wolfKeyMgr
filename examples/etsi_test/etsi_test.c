/* etsi_test.c
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

#include "wolfkeymgr/mod_etsi.h"
#include "examples/etsi_test/etsi_test.h"
#include "examples/test_config.h"

#define WOLFKM_ETST_CLIENT_DEF_REQUESTS     1       /* per thread */
#define WOLFKM_ETST_CLIENT_DEF_TIMEOUT_SEC 10

#ifndef EX_USAGE
#define EX_USAGE 2
#endif

#ifndef EXIT_FAILURE
#define EXIT_FAILURE 1
#endif

#define REQ_TYPE_GET  1
#define REQ_TYPE_PUSH 2
#define REQ_TYPE_FIND 3

typedef struct WorkThreadInfo {
    const char* host;
    int requests;
    int timeoutSec;
    int requestType;
    const char* contextStr;
    const char* fingerprint;
    char* saveResp;
    word16 port;
    const char* keyFile;
    const char* keyPass;
    const char* clientCertFile;
    const char* caFile;
    EtsiKeyType keyType;
} WorkThreadInfo;

typedef struct WorkThreadCtx {
    WorkThreadInfo* info; /* shared */

    EtsiKey key;
    WOLFSSL_CTX* ctx;
} WorkThreadCtx;


/* for error response in errorMode, 0 on success */
static int DoErrorMode(void)
{
    /* TODO: Add error case */

    return 0;
}

static int keyCb(EtsiClientCtx* client, EtsiKey* key, void* userCtx)
{
    int ret = 0;
    WorkThreadCtx* tctx = (WorkThreadCtx*)userCtx;
    WorkThreadInfo* info = tctx->info;

    /* test use-case setting static ephemeral key */
    if (tctx->ctx) {
    #ifdef WOLFSSL_STATIC_EPHEMERAL
        int keyAlgo = wolfEtsiKeyGetPkType(key);

        ret = wolfSSL_CTX_set_ephemeral_key(tctx->ctx,
            keyAlgo, (char*)key->response, key->responseSz,
            WOLFSSL_FILETYPE_ASN1);
    #endif
    }
    if (ret == 0) {
        wolfEtsiKeyPrint(key);

        if (info->saveResp != NULL) {
            wolfSaveFile(info->saveResp, (byte*)key->response, key->responseSz);
        }
    }
    else {
        XLOG(WOLFKM_LOG_INFO, "Key Error: %s (%d)\n", wolfKeyMgr_GetError(ret), ret);
    }

    (void)client;

    return ret; /* non-zero will close client */
}

/* ETSI Asymmetric Key Request */
static int DoKeyRequest(EtsiClientCtx* client, WorkThreadCtx* tctx)
{
    int ret = WOLFKM_BAD_ARGS;
    WorkThreadInfo* info = tctx->info;

    /* push: will wait for server to push new keys */
    /* get:  will ask server for key and return */
    if (info->requestType == REQ_TYPE_GET) {
        ret = wolfEtsiClientGet(client, &tctx->key, info->keyType, NULL,
            info->contextStr, info->timeoutSec);
        /* positive return means new key returned */
        /* zero means, same key is used */
        /* negative means error */
        if (ret > 0) {
            /* use same "push" callback to test key use / print */
            keyCb(client, &tctx->key, tctx);
            ret = 0;
        }
        else if (ret == 0) {
            XLOG(WOLFKM_LOG_INFO, "ETSI Key Cached (valid for %lu sec)\n",
                tctx->key.expires - wolfGetCurrentTimeT());
            sleep(1); /* wait 1 second */
        }
    }
    else if (info->requestType == REQ_TYPE_PUSH) {
        /* blocking call and new keys from server will issue callback */
        ret = wolfEtsiClientPush(client, info->keyType, NULL, NULL, keyCb, tctx);
    }
    else if (info->requestType == REQ_TYPE_FIND) {
        /* find key from server  call and new keys from server will issue callback */
        ret = wolfEtsiClientFind(client, &tctx->key, info->keyType,
            info->fingerprint, info->contextStr, info->timeoutSec);
        if (ret > 0) {
            /* use same "push" callback to test key use / print */
            keyCb(client, &tctx->key, tctx);
            ret = 0;
        }
    }

    if (ret != 0) {
        XLOG(WOLFKM_LOG_INFO, "ETSI Key Request Failed! %d\n", ret);
    }
    return ret;
}

/* Do requests per thread, persistent connection */
static void* DoRequests(void* arg)
{
    int i;
    int ret = -1;
    WorkThreadCtx* tctx = (WorkThreadCtx*)arg;
    WorkThreadInfo* info = (WorkThreadInfo*)tctx->info;

    EtsiClientCtx* client = wolfEtsiClientNew();
    if (client == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Error creating ETSI client %d!\n", ret);
        return NULL;
    }
    ret = wolfEtsiClientAddCA(client, info->caFile);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Error loading ETSI server CA %d!\n", ret);
    }
    ret = wolfEtsiClientSetKey(client, info->keyFile, info->keyPass,
        info->clientCertFile, WOLFSSL_FILETYPE_PEM);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Error loading ETSI client key/cert %d!\n", ret);
    }
    ret = wolfEtsiClientConnect(client, info->host, info->port, 
        info->timeoutSec);
    if (ret == 0) {
        /* setup test CTX to demonstrate loading static ephemeral */
        tctx->ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());

        for (i = 0; i < info->requests; i++) {
            ret = DoKeyRequest(client, tctx);
            if (ret != 0) {
                XLOG(WOLFKM_LOG_ERROR, "DoKeyRequest failed: %d\n", ret);
                break;
            }
        }

        wolfSSL_CTX_free(tctx->ctx);
        tctx->ctx = NULL;
    }

    wolfEtsiClientFree(client);

    return NULL;
}



/* usage help */
static void Usage(void)
{
    printf("%s %s\n",  "etsi_test", PACKAGE_VERSION);
    printf("-?          Help, print this usage\n");
    printf("-e          Error mode, force error response\n");
    printf("-h <str>    Host to connect to, default %s\n", ETSI_TEST_HOST);
    printf("-p <num>    Port to connect to, default %s\n", ETSI_TEST_PORT_STR);
    printf("-t <num>    Thread pool size (stress test), default  %d\n", 0);
    printf("-l <num>    Log Level (1=Error to 4=Debug), default %d\n", WOLFKM_DEFAULT_LOG_LEVEL);
    printf("-r <num>    Requests per thread, default %d\n", WOLFKM_ETST_CLIENT_DEF_REQUESTS);
    printf("-f <file>   <file> to store ETSI response\n");
    printf("-u          Use ETSI Push (default is get)\n");
    printf("-s <sec>    Timeout seconds (default %d)\n", WOLFKM_ETST_CLIENT_DEF_TIMEOUT_SEC);

    printf("-k <pem>    TLS Client TLS Key, default %s\n", ETSI_TEST_CLIENT_KEY);
    printf("-w <pass>   TLS Client Key Password, default %s\n", ETSI_TEST_CLIENT_PASS);
    printf("-c <pem>    TLS Client Certificate, default %s\n", ETSI_TEST_CLIENT_CERT);
    printf("-A <pem>    TLS CA Certificate, default %s\n", ETSI_TEST_CLIENT_CA);
    printf("-K <keyt>   Key Type: SECP256R1, FFDHE_2048, X25519 or X448 (default %s)\n",
        wolfEtsiKeyGetTypeStr(ETSI_TEST_KEY_TYPE));
    printf("-F <fprint> Fingerprint used for multiple servers (first 80-bit of pkey hash as hex string)\n");
    printf("-C <name>   Find key using public key name (hex string)\n");
}

int etsi_test(int argc, char** argv)
{
    int         ch, i;
    int         ret;
    int         errorMode = 0;
    int         poolSize = 0;  /* number of threads */
    enum log_level_t logLevel = WOLFKM_DEFAULT_LOG_LEVEL;
    WorkThreadInfo info;

    memset(&info, 0, sizeof(info));
    info.requests = WOLFKM_ETST_CLIENT_DEF_REQUESTS;
    info.host = ETSI_TEST_HOST;
    info.timeoutSec = WOLFKM_ETST_CLIENT_DEF_TIMEOUT_SEC;
    info.port = atoi(ETSI_TEST_PORT_STR);
    info.keyFile = ETSI_TEST_CLIENT_KEY;
    info.keyPass = ETSI_TEST_CLIENT_PASS;
    info.clientCertFile = ETSI_TEST_CLIENT_CERT;
    info.caFile = ETSI_TEST_CLIENT_CA;
    info.requestType = REQ_TYPE_GET;
    info.keyType = ETSI_TEST_KEY_TYPE;

    /* argument processing */
    while ((ch = getopt(argc, argv, "?eh:p:t:l:r:f:gus:k:w:c:A:K:F:C:")) != -1) {
        switch (ch) {
            case '?' :
                Usage();
                exit(EX_USAGE);
            case 'h' :
                info.host = optarg;
                break;
            case 'f' :
                info.saveResp = optarg;
                break;
            case 'p' :
                info.port = atoi(optarg);
                break;
            case 't' :
                poolSize = atoi(optarg);
                break;
            case 'r' :
                info.requests = atoi(optarg);
                break;
            case 'e' :
                errorMode = 1;
                break;
            case 'l' :
                logLevel = atoi(optarg);
                if (logLevel < WOLFKM_LOG_ERROR || logLevel > WOLFKM_LOG_DEBUG) {
                    perror("loglevel [1:4] only");
                    exit(EX_USAGE);
                }
                break;
            case 'g':
                /* keeping -g GET option for backwards compatibility (on by default) */
                break;
            case 'u':
                info.requestType = REQ_TYPE_PUSH;
                break;
            case 's' :
                info.timeoutSec = atoi(optarg);
                break;
            case 'k':
                info.keyFile= optarg;
                break;
            case 'w':
                info.keyPass = optarg;
                break;
            case 'c':
                info.clientCertFile = optarg;
                break;
            case 'A':
                info.caFile = optarg;
                break;
            case 'K':
            {
                /* find key type */
                for (i=(int)ETSI_KEY_TYPE_MIN; i<=(int)ETSI_KEY_TYPE_FFDHE_8192; i++) {
                    const char* keyStr = wolfEtsiKeyGetTypeStr((EtsiKeyType)i);
                    if (keyStr != NULL) {
                        if (strncmp(optarg, keyStr, strlen(keyStr)) == 0) {
                            info.keyType = (EtsiKeyType)i;
                            break;
                        }
                    }
                }
                break;
            }
            case 'F':
                /* sha256 hash of public key - 10 bytes (80 bits) as hex string */
                info.requestType = REQ_TYPE_FIND;
                info.fingerprint = optarg;
                break;
            case 'C':
                /* optional ID for server on key GET / PUT */
                info.contextStr = optarg;
                break;
            default:
                Usage();
                exit(EX_USAGE);
        }
    }

    /* log setup */
    wolfKeyMgr_SetLogFile(NULL, 0, logLevel);
    XLOG(WOLFKM_LOG_INFO, "Starting client\n");

    if (errorMode)
        return DoErrorMode();
    
    wolfEtsiClientInit();

    if (poolSize == 0) {
        WorkThreadCtx tctx;
        memset(&tctx, 0, sizeof(tctx));
        tctx.info = &info; /* shared info */
        DoRequests(&tctx);
    }
    else {
        /* stress testing with a thread pool */
        pthread_t* tids;
        WorkThreadCtx* tctx;

        /* thread id holder */
        tids = (pthread_t*)calloc(poolSize, sizeof(pthread_t));
        if (tids == NULL) {
            XLOG(WOLFKM_LOG_ERROR, "calloc tids failed\n");
            exit(EXIT_FAILURE);
        }

        tctx = (WorkThreadCtx*)calloc(poolSize, sizeof(WorkThreadCtx));
        if (tctx == NULL) {
            XLOG(WOLFKM_LOG_ERROR, "calloc tctx failed\n");
            free(tids);
            exit(EXIT_FAILURE);
        }

        /* create workers */
        for (i = 0; i < poolSize; i++) {
            tctx[i].info = &info; /* shared info */
            if (pthread_create(&tids[i], NULL, DoRequests, &tctx[i]) != 0){
                XLOG(WOLFKM_LOG_ERROR, "pthread_create failed\n");
                exit(EXIT_FAILURE);
            }
        }

        /* wait until they're all done */
        for (i = 0; i < poolSize; i++) {
            ret = pthread_join(tids[i], NULL);
            XLOG(WOLFKM_LOG_INFO, "pthread_join ret = %d\n", ret);
        }

        free(tids);
        free(tctx);
    }
    wolfEtsiClientCleanup();

    return 0;
}

#ifndef NO_MAIN_DRIVER
int main(int argc, char** argv)
{
    return etsi_test(argc, argv);
}
#endif
