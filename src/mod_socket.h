/* mod_socket.h
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

#ifndef WOLFKM_SOCKET_H
#define WOLFKM_SOCKET_H

#ifdef __cplusplus
extern "C" {
#endif

#include "wkm_types.h"
#include "wkm_utils.h"

#ifdef USE_WINDOWS_API
    #include <winsock2.h>
    #include <process.h>
    #ifdef USE_IPV6  /* don't require newer SDK for IPV4 */
        #include <ws2tcpip.h>
        #include <wspiapi.h>
    #endif
    #define WKM_SOCKET_T SOCKET
    #define WKM_SOCKET_INVALID       ((WKM_SOCKET_T)INVALID_SOCKET)
    #define WKM_SOCKET_IS_INVALID(s) ((WKM_SOCKET_T)(s) == WKM_SOCKET_INVALID)
#else
    #include <unistd.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <sys/ioctl.h>
    #include <sys/time.h>
    #include <sys/socket.h>
    #include <pthread.h>
    #include <fcntl.h>
    #ifdef USE_IPV6
        #include <netdb.h>
    #endif
    #include <errno.h>
    #define WKM_SOCKET_T int
    #define WKM_SOCKET_INVALID       (WKM_SOCKET_T)(0)
    #define WKM_SOCKET_IS_INVALID(s) ((WKM_SOCKET_T)(s) < WKM_SOCKET_INVALID)
#endif

enum {
    WKM_SOCKET_SELECT_FAIL,
    WKM_SOCKET_SELECT_TIMEOUT,
    WKM_SOCKET_SELECT_RECV_READY,
    WKM_SOCKET_SELECT_SEND_READY,
    WKM_SOCKET_SELECT_ERROR_READY
};


WOLFKM_API int  wolfSockConnect(WKM_SOCKET_T* sockfd, const char* ip, word16 port, int timeoutSec);
WOLFKM_API int  wolfSockSetBlockingMode(WKM_SOCKET_T sockfd, int nonBlocking);
WOLFKM_API int  wolfSocketRead(WKM_SOCKET_T sockfd, byte* buffer, word32 length);
WOLFKM_API int  wolfSockSelect(WKM_SOCKET_T sockfd, int timeoutSec, int rx);
WOLFKM_API int  wolfSocketWrite(WKM_SOCKET_T sockfd, const byte* buffer, word32 length);
WOLFKM_API void wolfSocketClose(WKM_SOCKET_T sockfd);
WOLFKM_API int  wolfSocketLastError(int err);

#ifdef __cplusplus
}
#endif

#endif /* WOLFKM_SOCKET_H */
