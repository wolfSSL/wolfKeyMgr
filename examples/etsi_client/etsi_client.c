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
} WorkThreadInfo;


/* for error response in errorMode, 0 on success */
static int DoErrorMode(void)
{
    /* TODO: Add error case */

    return 0;
}

/* ETSI Asymmetric Key Request */
static int DoKeyRequest(EtsiClientCtx* client, int useGet, char* saveResp,
    int timeoutSec)
{
    int     ret;
    EtsiClientType type;
    byte    response[ETSI_MAX_RESPONSE_SZ];
    word32  responseSz;
    ecc_key key;

    if (useGet) {
        type = ETSI_CLIENT_GET;
    }
    else {
        type = ETSI_CLIENT_PUSH;
    }

    /* for push run until error */
    do {
        responseSz = sizeof(response);
        ret = wolfEtsiClientGet(client, type, NULL, timeoutSec,
            response, &responseSz);
        if (ret == 0) {
            ret = wc_ecc_init(&key);
            if (ret == 0) {
                ret = wolfEtsiLoadKey(&key, response, responseSz);
                if (ret == 0) {
                    byte pubX[32*2+1], pubY[32*2+1];
                    word32 pubXLen = sizeof(pubX), pubYLen = sizeof(pubY);
                    ret = wc_ecc_export_ex(&key,
                        pubX, &pubXLen,
                        pubY, &pubYLen, 
                        NULL, NULL, WC_TYPE_HEX_STR);
                    if (ret == 0) {
                        XLOG(WOLFKM_LOG_INFO, "Pub X: %s\n", pubX);
                        XLOG(WOLFKM_LOG_INFO, "Pub Y: %s\n", pubY);

                        if (saveResp) {
                            wolfSaveFile(saveResp, response, responseSz);
                        }
                    }
                }
                wc_ecc_free(&key);
            }
        }

        if (ret != 0) {
            XLOG(WOLFKM_LOG_INFO, "ETSI Key Request Failed! %d\n", ret);
        }
    } while (!useGet && ret == 0);

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
        for (i = 0; i < info->requests; i++) {
            ret = DoKeyRequest(client, info->useGet, info->saveResp,
                info->timeoutSec);
            if (ret != 0) {
                XLOG(WOLFKM_LOG_ERROR, "DoKeyRequest failed: %d\n", ret);
                break;
            }
        }
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
    printf("-g          Use HTTP GET (default is Push with HTTP PUT)\n");
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

#ifdef DISABLE_SSL
    usingTLS = 0;    /* can only disable at build time */
#endif

    /* argument processing */
    while ((ch = getopt(argc, argv, "?eh:p:t:l:r:f:gs:k:w:c:A:")) != -1) {
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
                info.useGet = 1;
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
        info.requests = 1; /* only 1 request for this */
        DoRequests(&info);
    }
    else {
        /* stress testing with a thread pool */

        /* thread id holder */
        tids = calloc(poolSize, sizeof(pthread_t));
        if (tids == NULL) {
            XLOG(WOLFKM_LOG_ERROR, "calloc tids failed");
            exit(EXIT_FAILURE);
        }

        /* create workers */
        for (i = 0; i < poolSize; i++) {
            if (pthread_create(&tids[i], NULL, DoRequests, &info) != 0){
                XLOG(WOLFKM_LOG_ERROR, "pthread_create failed");
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
