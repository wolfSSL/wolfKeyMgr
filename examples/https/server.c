/* server.c
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

#include "wolfkeymgr/mod_tls.h"
#include "wolfkeymgr/mod_http.h"
#include "wolfkeymgr/mod_etsi.h"
#include "examples/test_config.h"

#include <signal.h>        /* signal */

static volatile int mStop = 0;
static WKM_SOCKET_T listenFd = WKM_SOCKET_INVALID;

static void sig_handler(const int sig)
{
    printf("SIGINT handled = %d.\n", sig);
    wolfSocketClose(listenFd);
    listenFd = WKM_SOCKET_INVALID;
    mStop = 1;
}

static int etsi_key_cb(EtsiKey* key, void* cbCtx)
{
    WOLFSSL_CTX* ctx = (WOLFSSL_CTX*)cbCtx;
    int ret = wolfEtsiKeyLoadCTX(key, ctx);
    if (ret == NOT_COMPILED_IN) {
        ret = 0; /* this is okay - if feature is not compiled in */
    }
    return ret;
}

/* usage help */
static void Usage(void)
{
    printf("%s %s\n",  "https/server", PACKAGE_VERSION);
    printf("-?          Help, print this usage\n");
    printf("-d          Disable ETSI Key Manager loading\n");
    printf("-p <num>    Port to listen, default %d\n", HTTPS_TEST_PORT);
    printf("-l <num>    Log Level (1=Error to 4=Debug), default %d\n",
        WOLFKM_DEFAULT_LOG_LEVEL);
    printf("-h <keymgr> Key Manager URL (default %s)\n", ETSI_TEST_URL);
}

int https_server_test(int argc, char** argv)
{
    int ret;
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl = NULL;
    HttpReq req;
    byte data[HTTPS_TEST_MAX_DATA];
    int dataSz;
    HttpHeader headers[2];
    const char* body = HTTPS_TEST_RESPONSE;
    SOCKADDR_IN_T clientAddr;
    int port = HTTPS_TEST_PORT;
    enum log_level_t logLevel = WOLFKM_DEFAULT_LOG_LEVEL;
    const char* etsiServer = ETSI_TEST_URL;
    int ch, useKeyMgr = 1;

    signal(SIGINT, sig_handler);

    /* argument processing */
    while ((ch = getopt(argc, argv, "?p:l:dh:")) != -1) {
        switch (ch) {
            case '?' :
                Usage();
                exit(EX_USAGE);
            case 'p' :
                port = atoi(optarg);
                break;
            case 'l' :
                logLevel = atoi(optarg);
                if (logLevel < WOLFKM_LOG_ERROR || logLevel > WOLFKM_LOG_DEBUG) {
                    perror("loglevel [1:4] only");
                    exit(EX_USAGE);
                }
                break;
            case 'd':
                useKeyMgr = 0;
                break;
            case 'h':
                etsiServer = optarg;
                break;
            default:
                Usage();
                exit(EX_USAGE);
        }
    }

    printf("HTTPS Server: Port %d\n", port);

    wolfSSL_Init();

    /* log setup */
    /* wolfSSL_Debugging_ON(); */
    wolfKeyMgr_SetLogFile(NULL, 0, logLevel);

    ctx = wolfTlsServerNew();
    if (ctx == NULL) { ret = WOLFKM_BAD_MEMORY; goto exit; }

    ret = wolfTlsAddCA(ctx, HTTPS_TEST_CA);
    if (ret != 0) goto exit;

    ret = wolfTlsSetKey(ctx, HTTPS_TEST_KEY, NULL, HTTPS_TEST_CERT,
        WOLFSSL_FILETYPE_PEM);
    if (ret != 0) goto exit;

    /* setup listener */
    ret = wolfSockListen(&listenFd, port);
    if (ret != 0) goto exit;

    do {
        if (useKeyMgr) {
            ret = etsi_client_get_all(etsiServer, etsi_key_cb, ctx);
            if (ret != 0) {
                printf("\nFailure connecting to key manager\n");
                printf("Make sure ./src/wolfkeymgr is running\n");
                mStop = 1;
                goto end_sess;
            }
        }

        ret = wolfTlsAccept(ctx, listenFd, &ssl, &clientAddr,
            HTTPS_TEST_TIMEOUT_SEC);
        if (ret == WOLFKM_BAD_TIMEOUT) continue;
        if (ret != 0) goto end_sess;

        printf("TLS Accept %s\n", wolfSocketAddrStr(&clientAddr));

        /* Get HTTP request and print */
        dataSz = (int)sizeof(data);
        ret = wolfTlsRead(ssl, data, &dataSz, HTTPS_TEST_TIMEOUT_SEC);
        if (ret < 0) goto end_sess;

        ret = wolfHttpServer_ParseRequest(&req, data, dataSz);
        if (ret == 0) {
            wolfHttpRequestPrint(&req);
        }

        /* Build response */
        headers[0].type = HTTP_HDR_CONTENT_TYPE;
        headers[0].string = "text/html";
        headers[1].type = HTTP_HDR_CONNECTION;
        headers[1].string = "keep-alive";
        dataSz = (int)sizeof(data);
        ret = wolfHttpServer_EncodeResponse(200, NULL,
            data, (word32*)&dataSz,
            headers, sizeof(headers)/sizeof(HttpHeader),
            (const byte*)body, strlen(body));
        if (ret == 0) {
            ret = wolfTlsWrite(ssl, data, dataSz);
        }

end_sess:

        /* Done - send TLS shutdown message */
        if (ssl) {
            (void)wolfTlsClose(ssl, ret >= 0 ? 1 : 0);
            ssl = NULL;
        }

        if (ret < 0) {
            printf("HTTPS Server Error %d: %s\n", ret, wolfTlsGetErrorStr(ret));
        }
    } while (mStop == 0);

exit:
    if (listenFd != WKM_SOCKET_INVALID)
        wolfSocketClose(listenFd);
    if (ctx)
        wolfTlsFree(ctx);

    wolfSSL_Cleanup();

    return ret;
}

#ifndef NO_MAIN_DRIVER
int main(int argc, char* argv[])
{
    return https_server_test(argc, argv);
}
#endif
