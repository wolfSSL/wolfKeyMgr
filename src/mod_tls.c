/* mod_tls.c
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

/* Using custom context type to manage sockets */
typedef struct wolfTlsCbCtx {
    SOCKET_T sockFd;
} wolfTlsCbCtx;

/* wolfSSL I/O Receive CallBack */
static int wkmTlsReadCb(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    int ret;
    wolfTlsCbCtx* cbCtx;

    if (ssl == NULL || ctx == NULL) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    cbCtx = (wolfTlsCbCtx*)ctx;

    ret = wolfSocketRead(cbCtx->sockFd, (byte*)buf, sz);
    if (ret <= 0) {
        int err = wolfSocketLastError(ret);
        if (err == SOCKET_EWOULDBLOCK || err == SOCKET_EAGAIN) {
            return WOLFSSL_CBIO_ERR_WANT_READ;
        }
        
        XLOG(WOLFKM_LOG_ERROR, "wkmTlsReadCb error %d (errno %d: %s)\n",
            ret, err, strerror(err));

        if (err == SOCKET_ECONNRESET) {
            return WOLFSSL_CBIO_ERR_CONN_RST;
        }
        else if (err == SOCKET_EINTR) {
            return WOLFSSL_CBIO_ERR_ISR;
        }
        else if (err == SOCKET_EPIPE) {
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        }
        else {
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
    return ret;
}

/* wolfSSL I/O Send CallBack */
static int wkmTlsWriteCb(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    int ret;
    wolfTlsCbCtx* cbCtx;

    if (ssl == NULL || ctx == NULL) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    cbCtx = (wolfTlsCbCtx*)ctx;

    ret = wolfSocketWrite(cbCtx->sockFd, (byte*)buf, sz);
    if (ret <= 0) {
        int err = wolfSocketLastError(ret);

        if (err == SOCKET_EWOULDBLOCK || err == SOCKET_EAGAIN) {
            return WOLFSSL_CBIO_ERR_WANT_WRITE;
        }

        XLOG(WOLFKM_LOG_ERROR, "wkmTlsWriteCb error %d (errno %d: %s)\n",
            ret, err, strerror(err));

        if (err == SOCKET_ECONNRESET) {
            return WOLFSSL_CBIO_ERR_CONN_RST;
        }
        else if (err == SOCKET_EINTR) {
            return WOLFSSL_CBIO_ERR_ISR;
        }
        else if (err == SOCKET_EPIPE) {
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        }
        else {
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
    return ret;
}

#ifdef WOLFSSL_ENCRYPTED_KEYS
static int wkmTlsPasswordCallBack(char* passwd, int sz, int rw, void* userdata)
{
    (void)rw;
    (void)userdata;
    if (userdata != NULL) {
        strncpy(passwd, (char*)userdata, sz);
        return (int)strlen((char*)userdata);
    }
    else {
        /* generic default password */
        strncpy(passwd, "wolfssl", sz);
        return 8;
    }
}
#endif

static void wolfTlsInitCtxDefaults(WOLFSSL_CTX* ctx)
{
    wolfSSL_SetIORecv(ctx, wkmTlsReadCb);
    wolfSSL_SetIOSend(ctx, wkmTlsWriteCb);

#ifdef WOLFSSL_ENCRYPTED_KEYS
    wolfSSL_CTX_set_default_passwd_cb(ctx, wkmTlsPasswordCallBack);
#endif
}

#ifndef NO_WOLFSSL_CLIENT
WOLFSSL_CTX* wolfTlsClientNew(void)
{
    WOLFSSL_CTX* ctx;
#if defined(WOLFSSL_TLS13) && !defined(WOLFSSL_NO_TLS12)
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
#else
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
#endif
    if (ctx == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Error allocating TLS client context\n");
        return NULL;
    }
    wolfTlsInitCtxDefaults(ctx);
    return ctx;
}
#endif

#ifndef NO_WOLFSSL_SERVER
WOLFSSL_CTX* wolfTlsServerNew(void)
{
    WOLFSSL_CTX* ctx;
#if defined(WOLFSSL_TLS13) && !defined(WOLFSSL_NO_TLS12)
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
#else
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
#endif
    if (ctx == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Error allocating TLS server context\n");
        return NULL;
    }
    wolfTlsInitCtxDefaults(ctx);
    return ctx;
}
#endif

int wolfTlsAddCA(WOLFSSL_CTX* ctx, const char* caFile)
{
    int ret;
    if (ctx == NULL || caFile == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    ret = wolfSSL_CTX_load_verify_locations(ctx, caFile, NULL);
    if (ret != WOLFSSL_SUCCESS) {
        XLOG(WOLFKM_LOG_ERROR, "Error loading TLS CA %s into context. Error: %s (%d)\n", 
            caFile, wolfSSL_ERR_reason_error_string(ret), ret);
        return WOLFKM_BAD_FILE;
    }

    return 0;
}

int wolfTlsSetKey(WOLFSSL_CTX* ctx, const char* keyFile, 
    const char* keyPassword, const char* certFile, int fileType)
{
    int ret = WOLFSSL_FAILURE;
    if (ctx == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    if (keyFile) {
        if (fileType == WOLFSSL_FILETYPE_PEM && keyPassword) {
            wolfSSL_CTX_set_default_passwd_cb_userdata(ctx, (void*)keyPassword);
        }
        ret = wolfSSL_CTX_use_PrivateKey_file(ctx, keyFile, fileType);
    }
    if (ret == WOLFSSL_SUCCESS && certFile) {
        ret = wolfSSL_CTX_use_certificate_file(ctx, certFile, fileType);
    }

    if (ret != WOLFSSL_SUCCESS) {
        XLOG(WOLFKM_LOG_ERROR, "Error loading client key/cert\n");
        ret = WOLFKM_BAD_CERT;
    }
    else {
        return 0; /* convert to zero = success */
    }
    return ret;
}

static int wolfTlsInitSslDefaults(WOLFSSL_CTX* ctx, WOLFSSL** ssl)
{
    if (ctx == NULL || ssl == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    if (*ssl == NULL) {
        wolfTlsCbCtx* cbCtx;
        WOLFSSL* tssl = wolfSSL_new(ctx);
        if (tssl == NULL) {
            XLOG(WOLFKM_LOG_ERROR, "wolfSSL_new memory failure\n");
            return WOLFKM_BAD_MEMORY;
        }

        cbCtx = (wolfTlsCbCtx*)malloc(sizeof(wolfTlsCbCtx));
        if (cbCtx == NULL) {
            wolfSSL_free(tssl);
            return WOLFKM_BAD_MEMORY;
        }
        memset(cbCtx, 0, sizeof(wolfTlsCbCtx));

        wolfSSL_SetIOReadCtx(tssl, cbCtx);
        wolfSSL_SetIOWriteCtx(tssl, cbCtx);

        *ssl = tssl;
    }
    return 0;
}

static int wolfTlsNegotiate(WOLFSSL* ssl, SOCKET_T sockFd, int timeoutSec)
{
    int ret;
    do {
        ret = wolfSSL_negotiate(ssl);
        if (ret != WOLFSSL_SUCCESS) {
            ret = wolfSSL_get_error(ssl, 0);
            if (ret == WOLFSSL_ERROR_WANT_READ ||
                ret == WOLFSSL_ERROR_WANT_WRITE) {
                /* do select on socket for timeout */
                ret = wolfSockSelect(sockFd, 1, 1);
                if (ret == WKM_SOCKET_SELECT_RECV_READY ||
                    ret == WKM_SOCKET_SELECT_TIMEOUT) {
                    ret = 0; /* try again */
                    timeoutSec--;
                }
                else
                    ret = WOLFKM_BAD_TIMEOUT;
            }
        }
        else {
            ret = 0; /* success */
            break; /* done */
        }
    } while (ret == 0 && timeoutSec > 0);
    if (timeoutSec <= 0)
        ret = WOLFKM_BAD_TIMEOUT;
    return ret;
}


#ifndef NO_WOLFSSL_CLIENT
int wolfTlsConnect(WOLFSSL_CTX* ctx, WOLFSSL** ssl, const char* host,
    word16 port, int timeoutSec)
{
    int ret;
    wolfTlsCbCtx* cbCtx;

    ret = wolfTlsInitSslDefaults(ctx, ssl);
    if (ret != 0)
        return ret;

    cbCtx = (wolfTlsCbCtx*)wolfSSL_GetIOReadCtx(*ssl);
    if (cbCtx == NULL)
        return WOLFKM_BAD_ARGS;
    if (cbCtx->sockFd == WKM_SOCKET_INVALID)
        ret = wolfSockConnect(&cbCtx->sockFd, host, port, timeoutSec);
    if (ret == 0)
        ret = wolfTlsNegotiate(*ssl, cbCtx->sockFd, timeoutSec);
    return ret;
}
#endif

#ifndef NO_WOLFSSL_SERVER
int wolfTlsAccept(WOLFSSL_CTX* ctx, WKM_SOCKET_T listenFd, WOLFSSL** ssl,
    SOCKADDR_IN_T* clientAddr, int timeoutSec)
{
    int ret;
    wolfTlsCbCtx* cbCtx;

    ret = wolfTlsInitSslDefaults(ctx, ssl);
    if (ret != 0)
        return ret;

    cbCtx = (wolfTlsCbCtx*)wolfSSL_GetIOReadCtx(*ssl);
    if (cbCtx == NULL)
        return WOLFKM_BAD_ARGS;

    ret = wolfSockAccept(listenFd, &cbCtx->sockFd, clientAddr, timeoutSec);
    if (ret == 0)
        ret = wolfTlsNegotiate(*ssl, cbCtx->sockFd, timeoutSec);
    return ret;
}
#endif

/* return bytes read or < 0 on error */
int wolfTlsRead(WOLFSSL* ssl, byte* p, int* len, int timeoutSec)
{
    int ret, err = 0;
    wolfTlsCbCtx* cbCtx;

    if (ssl == NULL || len == NULL || (p == NULL && *len > 0)) {
        return WOLFKM_BAD_ARGS;
    }

    cbCtx = (wolfTlsCbCtx*)wolfSSL_GetIOReadCtx(ssl);
    if (cbCtx == NULL)
        return WOLFKM_BAD_ARGS;
    do {
        ret = wolfSSL_read(ssl, p, *len);
        if (ret < 0) {
            err = wolfSSL_get_error(ssl, 0);
        }
        if (ret == 0 || err == WOLFSSL_ERROR_WANT_READ) {
            ret = wolfSockSelect(cbCtx->sockFd, timeoutSec, 1);
            if (ret == WKM_SOCKET_SELECT_RECV_READY)
                ret = 0; /* data ready */
            else if (ret == WKM_SOCKET_SELECT_ERROR_READY)
                ret = WOLFKM_BAD_SOCKET; /* socket error */
            else
                ret = WOLFKM_BAD_TIMEOUT; /* timeout */
            err = 0; /* reset error */
        }
    } while (ret == 0);

    if (ret > 0) {
        *len = ret;
    }
    else if (timeoutSec <= 0) {
        ret = WOLFKM_BAD_TIMEOUT;
    }
    else if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "wolfTlsRead error %d: %s\n",
            err, wolfSSL_ERR_reason_error_string(err));        
    }
    return ret;
}

/* return sent bytes or < 0 on error */
int wolfTlsWrite(WOLFSSL* ssl, byte* p, int len)
{
    int ret, err = 0;
    wolfTlsCbCtx* cbCtx;

    if (ssl == NULL || (p == NULL && len > 0)) {
        return WOLFKM_BAD_ARGS;
    }
    
    cbCtx = (wolfTlsCbCtx*)wolfSSL_GetIOWriteCtx(ssl);
    if (cbCtx == NULL)
        return WOLFKM_BAD_ARGS;

    do {
        ret = wolfSSL_write(ssl, p, len);
        if (ret < 0) {
            err = wolfSSL_get_error(ssl, 0);
        }
        if (ret == 0 || err == WOLFSSL_ERROR_WANT_WRITE) {
            /* no timeout available, so block for up to 1 second */
            ret = wolfSockSelect(cbCtx->sockFd, 1, 0);
            if (ret == WKM_SOCKET_SELECT_SEND_READY)
                ret = 0; /* data ready */
            else if (ret == WKM_SOCKET_SELECT_ERROR_READY)
                ret = WOLFKM_BAD_SOCKET; /* socket error */
            else
                ret = WOLFKM_BAD_TIMEOUT; /* timeout */
            err = 0; /* reset error */
        }
    } while (ret == 0);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "wolfTlsWrite error %d: %s\n",
            err, wolfSSL_ERR_reason_error_string(err));
    }
    return ret;
}

int wolfTlsClose(WOLFSSL* ssl, int sendShutdown)
{
    int ret = 0;
    wolfTlsCbCtx* cbCtx;

    if (ssl == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    if (ssl && sendShutdown) {
        ret = wolfSSL_shutdown(ssl);
    }
    
    cbCtx = wolfSSL_GetIOReadCtx(ssl);
    if (cbCtx) {
        wolfSocketClose(cbCtx->sockFd);
        free(cbCtx);
    }
    wolfSSL_free(ssl);
    return ret;
}

void wolfTlsFree(WOLFSSL_CTX* ctx)
{
    if (ctx) {
        wolfSSL_CTX_free(ctx);
    }
}

const char* wolfTlsGetErrorStr(int ret)
{
    if (ret < WOLFKM_ERROR_BEGIN)
        return wolfKeyMgr_GetError(ret);
    return wolfSSL_ERR_reason_error_string(ret);
}
