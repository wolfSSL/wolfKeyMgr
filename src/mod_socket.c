/* mod_socket.c
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

#include "mod_socket.h"


#ifdef USE_IPV6
    typedef struct sockaddr_in6 SOCKADDR_IN_T;
    #define AF_INET_V    AF_INET6
#else
    typedef struct sockaddr_in  SOCKADDR_IN_T;
    #define AF_INET_V    AF_INET
#endif

#ifndef XHTONS
    #define XHTONS(a) htons((a))
#endif

static int build_addr(SOCKADDR_IN_T* addr, const char* peer, word16 port)
{
    int ret = 0;
    int useLookup = 0;

    (void)useLookup;

    if (addr == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "invalid argument to build_addr, addr is NULL");
        return WOLFKM_BAD_ARGS;
    }

    XMEMSET(addr, 0, sizeof(SOCKADDR_IN_T));

#ifndef USE_IPV6
    /* peer could be in human readable form */
    if ( ((size_t)peer != INADDR_ANY) && isalpha((int)peer[0])) {
        struct hostent* entry = gethostbyname(peer);
        if (entry) {
            XMEMCPY(&addr->sin_addr.s_addr, entry->h_addr_list[0],
                   entry->h_length);
            useLookup = 1;
        }
        else {
            XLOG(WOLFKM_LOG_ERROR, "no entry for host");
            return WOLFKM_BAD_HOST;
        }
    }

    addr->sin_family = AF_INET_V;
    addr->sin_port = XHTONS(port);
    if ((size_t)peer == INADDR_ANY)
        addr->sin_addr.s_addr = INADDR_ANY;
    else {
        if (!useLookup)
            addr->sin_addr.s_addr = inet_addr(peer);
    }
#else
    addr->sin6_family = AF_INET_V;
    addr->sin6_port = XHTONS(port);
    if ((size_t)peer == INADDR_ANY) {
        addr->sin6_addr = in6addr_any;
    }
    else {
        struct addrinfo  hints;
        struct addrinfo* answer = NULL;
        int    ret;
        char   strPort[80];

        XMEMSET(&hints, 0, sizeof(hints));

        hints.ai_family   = AF_INET_V;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        XSNPRINTF(strPort, sizeof(strPort), "%d", port);
        strPort[79] = '\0';

        ret = getaddrinfo(peer, strPort, &hints, &answer);
        if (ret < 0 || answer == NULL) {
            XLOG(WOLFKM_LOG_ERROR, "getaddrinfo failed");
            return WOLFKM_BAD_HOST;
        }

        XMEMCPY(addr, answer->ai_addr, answer->ai_addrlen);
        freeaddrinfo(answer);
    }
#endif
    return ret;
}


static int tcp_socket(WKM_SOCKET_T* sockfd)
{
    *sockfd = socket(AF_INET_V, SOCK_STREAM, IPPROTO_TCP);
    if (WKM_SOCKET_IS_INVALID(*sockfd)) {
        XLOG(WOLFKM_LOG_ERROR, "socket failed\n");
        return WOLFKM_BAD_MEMORY;
    }
    return 0;
}

/* if timeoutSec == 0 then no timeout and using blocking mode */
int wolfSockConnect(WKM_SOCKET_T* sockfd, const char* ip, word16 port,
    int timeoutSec)
{
    int ret, err;
    SOCKADDR_IN_T addr;
    
    ret = build_addr(&addr, ip, port);
    if (ret != 0) {
        return ret;
    }
    
    ret = tcp_socket(sockfd);
    if (ret == 0) {
        if (timeoutSec > 0) {
            /* enable non-blocking */
            wolfSockSetBlockingMode(*sockfd, 1);
        }

        ret = connect(*sockfd, (const struct sockaddr*)&addr, sizeof(addr));
        if (ret < 0) {
            err = wolfSocketLastError(ret);
            if (err == EINPROGRESS && timeoutSec > 0) {
                /* wait on send or error */
                ret = wolfSockSelect(*sockfd, timeoutSec, 0);
                if (ret == WKM_SOCKET_SELECT_SEND_READY) {
                    ret = 0; /* completed successfully */
                }
                else {
                    ret = WOLFKM_BAD_TIMEOUT;
                }
            }
        }
    }
    if (ret != 0) {
        err = wolfSocketLastError(ret);
        XLOG(WOLFKM_LOG_ERROR, "tcp connect failed: %d (%s)", 
            err, strerror(err));
    }

    return ret;
}

int wolfSockSelect(WKM_SOCKET_T sockfd, int timeoutSec, int rx)
{
    int res;
    fd_set fds, errfds;
    fd_set* recvfds = NULL;
    fd_set* sendfds = NULL;
    WKM_SOCKET_T nfds = 0;
    struct timeval timeout = {(timeoutSec > 0) ? timeoutSec : 0, 0};

    if (WKM_SOCKET_IS_INVALID(sockfd)) {
        return WOLFKM_BAD_ARGS;
    }

#ifndef USE_WINDOWS_API
    nfds = (int)sockfd + 1;
#endif

    FD_ZERO(&fds);
    FD_SET(sockfd, &fds);
    FD_ZERO(&errfds);
    FD_SET(sockfd, &errfds);

    if (rx)
        recvfds = &fds;
    else
        sendfds = &fds;

    res = select(nfds, recvfds, sendfds, &errfds, &timeout);
    if (res == 0)
        return WKM_SOCKET_SELECT_TIMEOUT;
    else if (res > 0) {
        if (FD_ISSET(sockfd, &fds)) {
            if (rx)
                return WKM_SOCKET_SELECT_RECV_READY;
            else
                return WKM_SOCKET_SELECT_SEND_READY;
        }
        else if(FD_ISSET(sockfd, &errfds))
            return WKM_SOCKET_SELECT_ERROR_READY;
    }

    return WKM_SOCKET_SELECT_FAIL;
}

int wolfSockSetBlockingMode(WKM_SOCKET_T sockfd, int nonBlocking)
{
    int ret = 0;

#ifdef USE_WINDOWS_API
    unsigned long blocking = nonBlocking;
    ret = ioctlsocket(sockfd, FIONBIO, &blocking);
    if (ret == SOCKET_ERROR)
        ret = -1;
#else
    ret = fcntl(sockfd, F_GETFL, 0);
    if (ret >= 0) {
        if (nonBlocking)
            ret |= O_NONBLOCK;
        else
            ret &= ~O_NONBLOCK;
        ret = fcntl(sockfd, F_SETFL, ret);
    }
#endif
    if (ret < 0) {
        int err = wolfSocketLastError(ret);
        XLOG(WOLFKM_LOG_ERROR,
            "wolfSockSetBlockingMode failed %d (errno %d: %s)\n",
            ret, err, strerror(err));
    }
    return ret;
}

int wolfSocketRead(WKM_SOCKET_T sockfd, byte* buffer, word32 length)
{
    return (int)recv(sockfd, buffer, length, 0);
}

int wolfSocketWrite(WKM_SOCKET_T sockfd, const byte* buffer,
    word32 length)
{
    return (int)send(sockfd, buffer, length, 0);
}

void wolfSocketClose(WKM_SOCKET_T sockfd)
{
    if (WKM_SOCKET_IS_INVALID(sockfd)) {
    #ifdef USE_WINDOWS_API
        closesocket(sockfd);
    #else
        close(sockfd);
    #endif
    }
}

int wolfSocketLastError(int err)
{
    (void)err; /* Suppress unused arg */

#ifdef USE_WINDOWS_API
    return WSAGetLastError();
#elif defined(WOLFSSL_LINUXKM)
    return err; /* Return provided error value */
#else
    return errno;
#endif
}
