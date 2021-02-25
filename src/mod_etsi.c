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

#ifdef WOLFKM_ETSI_SERVICE

#include "wolfkeymgr/mod_etsi.h"

struct EtsiClientCtx {
    WOLFSSL_CTX*   sslCtx;
    WOLFSSL*       ssl;
    EtsiClientType type;
};

EtsiClientCtx* wolfEtsiClientNew(void)
{
    EtsiClientCtx* client = (EtsiClientCtx*)malloc(sizeof(EtsiClientCtx));
    if (client) {
        memset(client, 0, sizeof(EtsiClientCtx));
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
    if (client == NULL) {
        return WOLFKM_BAD_ARGS;
    }
    return wolfTlsSetKey(client->sslCtx, keyFile, keyPassword, certFile, fileType);
}

int wolfEtsiClientAddCA(EtsiClientCtx* client, const char* caFile)
{
    int ret;
    if (client == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    ret = wolfTlsAddCA(client->sslCtx, caFile);
    return ret;
}

int wolfEtsiClientConnect(EtsiClientCtx* client, const char* host,
    word16 port, int timeoutSec)
{
    int ret;

    if (client == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    ret = wolfTlsConnect(client->sslCtx, &client->ssl, host, port, timeoutSec);
    if (ret == 0) {
        XLOG(WOLFKM_LOG_INFO, "Connected to ETSI service\n");
    }
    else {
        XLOG(WOLFKM_LOG_ERROR, "Failure connecting to ETSI service %d\n", ret);   
    }

    return ret;
}

static int EtsiClientMakeRequest(EtsiClientType type, const char* fingerprint,
    byte* request, word32* requestSz)
{
    int ret;
    HttpHeader headers[1];
    headers[0].type = HTTP_HDR_ACCEPT;
    headers[0].string = "application/pkcs8";
    
    /* Build HTTP ETSI request */
    if (type == ETSI_CLIENT_PUSH) {
        const char* uri = "/enterprise-transport-security/keys";
        ret = wolfHttpClient_EncodeRequest(HTTP_METHOD_PUT, uri, request,
            requestSz, headers, sizeof(headers)/sizeof(HttpHeader));
    }
    else {
        char uri[128]; /* 62 + fingerprint */
        snprintf(uri, sizeof(uri), 
            "/.well-known/enterprise-transport-security/keys?fingerprints=%s",
            fingerprint == NULL ? "" : fingerprint);
        ret = wolfHttpClient_EncodeRequest(HTTP_METHOD_GET, uri, request, 
            requestSz, headers, sizeof(headers)/sizeof(HttpHeader));
    }
    if (ret > 0)
        ret = 0;
    return ret;
}

int wolfEtsiClientGet(EtsiClientCtx* client, 
    EtsiClientType type, const char* fingerprint, int timeoutSec,
    byte* response, word32* responseSz)
{
    int    ret;
    byte   request[ETSI_MAX_REQUEST_SZ];
    word32 requestSz = ETSI_MAX_REQUEST_SZ;
    int    pos;
    HttpRsp rsp;

    if (client == NULL || response == NULL || responseSz == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    /* only send request if we need to */
    if (type != ETSI_CLIENT_PUSH || client->type != type) {
        ret = EtsiClientMakeRequest(type, fingerprint, request, &requestSz);
        if (ret != 0) {
            XLOG(WOLFKM_LOG_INFO, "EtsiClientMakeRequest failed: %d\n", ret);
            return ret;
        }

        /* send key request */
        pos = 0;
        while (pos < requestSz) {
            ret = wolfTlsWrite(client->ssl, (byte*)request + pos,
                requestSz - pos);
            if (ret < 0) {
                XLOG(WOLFKM_LOG_INFO, "DoClientSend failed: %d (%s)\n", ret,
                    wolfSSL_ERR_reason_error_string(ret));
                return ret;
            }
            pos += ret;
        }
        XLOG(WOLFKM_LOG_INFO, "Sent %s request (%d bytes)\n", 
            type == ETSI_CLIENT_PUSH ? "push" : "single get", requestSz);
        client->type = type;
    }

    do {
        /* get key response */
        ret = wolfTlsRead(client->ssl, response, *responseSz, timeoutSec);
        if (ret < 0) {
            XLOG(WOLFKM_LOG_ERROR, "DoClientRead failed: %d\n", ret);
            break;
        }
        /* zero respnse means try again */
    } while (ret == 0);
    
    if (ret > 0) {
        /* parse HTTP server response */
        *responseSz = ret;
        ret = wolfHttpClient_ParseResponse(&rsp, response, *responseSz);
        if (ret == 0 && rsp.body && rsp.bodySz > 0) {
            wolfHttpResponsePrint(&rsp);

            /* move payload (body) to response */
            memcpy(response, rsp.body, rsp.bodySz);
            *responseSz = rsp.bodySz;
        }
        else {
            XLOG(WOLFKM_LOG_ERROR, "Error parsing HTTP response! %d\n", ret);
        }
    }

    if (ret == 0) {
        /* asymmetric key package response */
        XLOG(WOLFKM_LOG_INFO, "Got ETSI response (%d bytes)\n", *responseSz);
    }

    return ret;
}

int wolfEtsiLoadKey(ecc_key* key, byte* buffer, word32 length)
{
    int ret;
    word32 idx = 0;

    if (key == NULL || buffer == NULL || length == 0) {
        return WOLFKM_BAD_ARGS;
    }

    /* Parsing key package */
    ret = wc_EccPrivateKeyDecode(buffer, &idx, key, length);

    return ret;
}

int wolfEtsiClientClose(EtsiClientCtx* client)
{
    int ret = 0;
    if (client && client->ssl) {
        /* send shutdown */
        ret = wolfTlsClose(client->ssl, 1);
        client->ssl = NULL;
    }
    return ret;
}

void wolfEtsiClientFree(EtsiClientCtx* client)
{
    if (client) {
        if (client->ssl) {
            wolfTlsClose(client->ssl, 0);
            client->ssl = NULL;
        }
        if (client->sslCtx) {
            wolfTlsFree(client->sslCtx);
            client->sslCtx = NULL;
        }
        free(client);
    }
}

int wolfEtsiClientInit(void)
{
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
