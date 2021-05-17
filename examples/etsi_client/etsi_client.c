/* etsi_client.c
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

#include "etsi_client.h"
#include "mod_etsi.h"

#define WOLFKM_ETST_CLIENT_DEF_TIMEOUT_SEC 10

#ifndef EX_USAGE
#define EX_USAGE 2
#endif

#ifndef EXIT_FAILURE
#define EXIT_FAILURE 1
#endif


typedef struct WorkThreadInfo {
    const char* host;
    int requests;
    int timeoutSec;
    int useGet;
    char* saveResp;
    word16 port;
    const char* keyFile;
    const char* keyPass;
    const char* clientCertFile;
    const char* caFile;
    EtsiKey key;
    WOLFSSL_CTX* ctx; /* test ctx loading static ephemeral key */
} WorkThreadInfo;


/* for error response in errorMode, 0 on success */
static int DoErrorMode(void)
{
    /* TODO: Add error case */

    return 0;
}

static int keyCb(EtsiClientCtx* client, EtsiKey* key, void* userCtx)
{
    int ret = 0;
    WorkThreadInfo* info = (WorkThreadInfo*)userCtx;

    /* test use-case setting static ephemeral key */
    if (info->ctx) {
        ret = wolfSSL_CTX_set_ephemeral_key(info->ctx,
            WC_PK_TYPE_ECDH, key->response, key->responseSz,
            WOLFSSL_FILETYPE_ASN1);
    }
    wolfEtsiKeyPrint(key);
    if (info->saveResp != NULL) {
        wolfSaveFile(info->saveResp, (byte*)key->response, key->responseSz);
    }

    return ret; /* non-zero will close client */
}

/* ETSI Asymmetric Key Request */
static int DoKeyRequest(EtsiClientCtx* client, WorkThreadInfo* info)
{
    int ret;
    EtsiKeyType keyType = ETSI_KEY_TYPE_SECP256R1;

    /* push: will wait for server to push new keys */
    /* get:  will ask server for key and return */
    if (info->useGet) {
        ret = wolfEtsiClientGet(client, &info->key, keyType, NULL, NULL,
            info->timeoutSec);
        /* positive return means new key returned */
        /* zero means, same key is used */
        /* negative means error */
        if (ret > 0) {
            /* use same "push" callback to test key use / print */
            keyCb(client, &info->key, info);
            ret = 0;
        }
        else if (ret == 0) {
            XLOG(WOLFKM_LOG_INFO, "ETSI Key Cached (valid for %lu sec)\n",
                info->key.expires - wolfGetCurrentTimeT());
            sleep(1); /* wait 1 second */
        }
    }
    else {
        /* blocking call and new keys from server will issue callback */
        ret = wolfEtsiClientPush(client, keyType, NULL, NULL, keyCb, info);
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
    WorkThreadInfo* info = (WorkThreadInfo*)arg;
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
        info->ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());

        for (i = 0; i < info->requests; i++) {
            ret = DoKeyRequest(client, info);
            if (ret != 0) {
                XLOG(WOLFKM_LOG_ERROR, "DoKeyRequest failed: %d\n", ret);
                break;
            }
        }

        wolfSSL_CTX_free(info->ctx);
        info->ctx = NULL;
    }

    wolfEtsiClientFree(client);

    return NULL;
}



/* usage help */
static void Usage(void)
{
    printf("%s %s\n",  "etsi_client", PACKAGE_VERSION);
    printf("-?          Help, print this usage\n");
    printf("-e          Error mode, force error response\n");
    printf("-h <str>    Host to connect to, default %s\n", WOLFKM_DEFAULT_HOST);
    printf("-p <num>    Port to connect to, default %s\n", WOLFKM_DEFAULT_ETSISVC_PORT);
    printf("-t <num>    Thread pool size (stress test), default  %d\n", 0);
    printf("-l <num>    Log Level (1=Error to 4=Debug), default %d\n", WOLFKM_DEFAULT_LOG_LEVEL);
    printf("-r <num>    Requests per thread, default %d\n",
                                                          WOLFKM_DEFAULT_REQUESTS);
    printf("-f <file>   <file> to store ETSI response\n");
    printf("-u          Use ETSI Push (default is get)\n");
    printf("-s <sec>    Timeout seconds (default %d)\n", WOLFKM_ETST_CLIENT_DEF_TIMEOUT_SEC);

    printf("-k <pem>    TLS Client TLS Key, default %s\n", WOLFKM_ETSICLIENT_KEY);
    printf("-w <pass>   TLS Client Key Password, default %s\n", WOLFKM_ETSICLIENT_PASS);
    printf("-c <pem>    TLS Client Certificate, default %s\n", WOLFKM_ETSICLIENT_CERT);
    printf("-A <pem>    TLS CA Certificate, default %s\n", WOLFKM_ETSICLIENT_CA);
}

int main(int argc, char** argv)
{
    int         ch, i;
    int         ret;
    int         errorMode = 0;
    pthread_t*  tids;          /* our threads */
    int         poolSize = 0;  /* number of threads */
    enum log_level_t logLevel = WOLFKM_DEFAULT_LOG_LEVEL;
    WorkThreadInfo info;

    memset(&info, 0, sizeof(info));
    info.requests = WOLFKM_DEFAULT_REQUESTS;
    info.host = WOLFKM_DEFAULT_HOST;
    info.timeoutSec = WOLFKM_ETST_CLIENT_DEF_TIMEOUT_SEC;
    info.port = atoi(WOLFKM_DEFAULT_ETSISVC_PORT);
    info.keyFile = WOLFKM_ETSICLIENT_KEY;
    info.keyPass = WOLFKM_ETSICLIENT_PASS;
    info.clientCertFile = WOLFKM_ETSICLIENT_CERT;
    info.caFile = WOLFKM_ETSICLIENT_CA;
    info.useGet = 1;

#ifdef DISABLE_SSL
    usingTLS = 0;    /* can only disable at build time */
#endif

    /* argument processing */
    while ((ch = getopt(argc, argv, "?eh:p:t:l:r:f:gus:k:w:c:A:")) != -1) {
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
                info.useGet = 0;
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
        DoRequests(&info);
    }
    else {
        /* stress testing with a thread pool */

        /* thread id holder */
        tids = calloc(poolSize, sizeof(pthread_t));
        if (tids == NULL) {
            XLOG(WOLFKM_LOG_ERROR, "calloc tids failed\n");
            exit(EXIT_FAILURE);
        }

        /* create workers */
        for (i = 0; i < poolSize; i++) {
            if (pthread_create(&tids[i], NULL, DoRequests, &info) != 0){
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
    }
    wolfEtsiClientCleanup();

    return 0;
}
