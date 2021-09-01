/* mod_tls.h
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

#ifndef WOLFKM_TLS_H
#define WOLFKM_TLS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "wolfkeymgr/wkm_types.h"
#include "wolfkeymgr/wkm_utils.h"
#include "wolfkeymgr/mod_socket.h"


/* wolfssl headers */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>


/* TLS Client / Connect */
#ifndef NO_WOLFSSL_CLIENT
WOLFKM_API WOLFSSL_CTX* wolfTlsClientNew(void);
WOLFKM_API int wolfTlsConnect(WOLFSSL_CTX* ctx, WOLFSSL** ssl,
    const char* host, word16 port, int timeoutSec);
#endif

/* TLS Server / Accept */
#ifndef NO_WOLFSSL_SERVER
WOLFKM_API WOLFSSL_CTX* wolfTlsServerNew(void);
WOLFKM_API int wolfTlsAccept(WOLFSSL_CTX* ctx, WKM_SOCKET_T listenFd,
    WOLFSSL** ssl, SOCKADDR_IN_T* clientAddr, int timeoutSec);
#endif

/* Generic TLS */
WOLFKM_API int  wolfTlsAddCA(WOLFSSL_CTX* ctx, const char* caFile);
WOLFKM_API int  wolfTlsSetKey(WOLFSSL_CTX* ctx, const char* keyFile,
    const char* keyPassword, const char* certFile, int fileType);
WOLFKM_API int  wolfTlsRead(WOLFSSL* ssl, byte* p, int* len, int timeoutSec);
WOLFKM_API int  wolfTlsWrite(WOLFSSL* ssl, byte* p, int len);
WOLFKM_API int  wolfTlsClose(WOLFSSL* ssl, int sendShutdown);
WOLFKM_API void wolfTlsFree(WOLFSSL_CTX* ctx);
WOLFKM_API const char* wolfTlsGetErrorStr(int ret);

#ifdef __cplusplus
}
#endif

#endif /* WOLFKM_TLS_H */
