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

#include "wolfkeymgr/mod_socket.h"


static int build_addr(SOCKADDR_IN_T* addr, const char* peer, word16 port)
{
    int ret = 0;
    int useLookup = 0;

    (void)useLookup;

    if (addr == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "invalid argument to build_addr, addr is NULL\n");
        return WOLFKM_BAD_ARGS;
    }

    memset(addr, 0, sizeof(SOCKADDR_IN_T));

#ifndef USE_IPV6
    /* peer could be in human readable form */
    if ( ((size_t)peer != INADDR_ANY) && isalpha((int)peer[0])) {
        struct hostent* entry = gethostbyname(peer);
        if (entry) {
            memcpy(&addr->sin_addr.s_addr, entry->h_addr_list[0],
                   entry->h_length);
            useLookup = 1;
        }
        else {
            XLOG(WOLFKM_LOG_ERROR, "no entry for host\n");
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

        memset(&hints, 0, sizeof(hints));

        hints.ai_family   = AF_INET_V;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        XSNPRINTF(strPort, sizeof(strPort), "%d", port);
        strPort[79] = '\0';

        ret = getaddrinfo(peer, strPort, &hints, &answer);
        if (ret < 0 || answer == NULL) {
            XLOG(WOLFKM_LOG_ERROR, "getaddrinfo failed\n");
            return WOLFKM_BAD_HOST;
        }

        memcpy(addr, answer->ai_addr, answer->ai_addrlen);
        freeaddrinfo(answer);
    }
#endif
    return ret;
}


static int tcp_socket(WKM_SOCKET_T* sockFd)
{
    *sockFd = socket(AF_INET_V, SOCK_STREAM, IPPROTO_TCP);
    if (WKM_SOCKET_IS_INVALID(*sockFd)) {
        XLOG(WOLFKM_LOG_ERROR, "socket failed\n");
        return WOLFKM_BAD_MEMORY;
    }
    return 0;
}

/* if timeoutSec == 0 then no timeout and using blocking mode */
int wolfSockConnect(WKM_SOCKET_T* sockFd, const char* ip, word16 port,
    int timeoutSec)
{
    int ret, err = 0;
    SOCKADDR_IN_T addr;

    if (sockFd == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    ret = build_addr(&addr, ip, port);
    if (ret != 0) {
        return ret;
    }

    ret = tcp_socket(sockFd);
    if (ret == 0) {
        if (timeoutSec > 0) {
            /* enable non-blocking */
            wolfSockSetBlockingMode(*sockFd, 1);
        }

        ret = connect(*sockFd, (const struct sockaddr*)&addr, sizeof(addr));
        if (ret < 0) {
            err = wolfSocketLastError(ret);
            if (err == EINPROGRESS && timeoutSec > 0) {
                /* wait on send or error */
                ret = wolfSockSelect(*sockFd, timeoutSec, 0);
                if (ret == WKM_SOCKET_SELECT_SEND_READY) {
                    /* make sure socket is not reporting an error */
                    ret = wolfSocketGetError(*sockFd, &err);
                }
            }
        }
    }
    else {
        err = wolfSocketLastError(ret);
    }

    if (err != 0) {
        XLOG(WOLFKM_LOG_ERROR, "tcp connect failed: %d (%s)\n",
            err, strerror(err));
        ret = err;
    }

    return ret;
}

#define SOCK_LISTEN_MAX_QUEUE 5
int wolfSockListen(WKM_SOCKET_T* listenFd, word16 port)
{
    int ret;
    SOCKADDR_IN_T addr;

    if (listenFd == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    ret = build_addr(&addr, NULL, port);
    if (ret != 0) {
        return ret;
    }

    ret = tcp_socket(listenFd);
    if (ret == 0) {
        ret = bind(*listenFd, (const struct sockaddr*)&addr, sizeof(addr));
    }
    if (ret == 0) {
        ret = listen(*listenFd, SOCK_LISTEN_MAX_QUEUE);
    }

    if (ret < 0) {
        int err = wolfSocketLastError(ret);
        XLOG(WOLFKM_LOG_ERROR, "tcp listen failed: %d err %d (%s)\n",
            ret, err, strerror(err));
        ret = err;
    }

    return ret;

}

int wolfSockAccept(WKM_SOCKET_T listenFd, WKM_SOCKET_T* clientFd,
    SOCKADDR_IN_T* clientAddr, int timeoutSec)
{
    int ret = 0;
    socklen_t clientAddrLen = (socklen_t)sizeof(SOCKADDR_IN_T);

    if (WKM_SOCKET_IS_INVALID(listenFd) || clientFd == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    if (timeoutSec > 0) {
        /* enable non-blocking */
        wolfSockSetBlockingMode(listenFd, 1);
    }

    /* use select to indicate connection is ready */
    /* wait on recv or error */
    ret = wolfSockSelect(listenFd, timeoutSec, 1);
    if (ret == WKM_SOCKET_SELECT_RECV_READY) {
        *clientFd = accept(listenFd, (struct sockaddr*)clientAddr, &clientAddrLen);
        if (WKM_SOCKET_IS_INVALID(*clientFd)) {
            int err = wolfSocketLastError(ret);
            XLOG(WOLFKM_LOG_ERROR, "tcp accept failed: %d (%s)\n",
                err, strerror(err));
            ret = err;
        }
        else {
            ret = 0;
        }
    }
    return ret;
}


int wolfSockSelect(WKM_SOCKET_T sockFd, int timeoutSec, int rx)
{
    int res;
    fd_set fds, errfds;
    fd_set* recvfds = NULL;
    fd_set* sendfds = NULL;
    WKM_SOCKET_T nfds = 0;
    struct timeval timeout = {(timeoutSec > 0) ? timeoutSec : 0, 0};

    if (WKM_SOCKET_IS_INVALID(sockFd)) {
        return WOLFKM_BAD_ARGS;
    }

#ifndef USE_WINDOWS_API
    nfds = (int)sockFd + 1;
#endif

    FD_ZERO(&fds);
    FD_SET(sockFd, &fds);
    FD_ZERO(&errfds);
    FD_SET(sockFd, &errfds);

    if (rx)
        recvfds = &fds;
    else
        sendfds = &fds;

    res = select(nfds, recvfds, sendfds, &errfds, &timeout);
    if (res == 0)
        return WKM_SOCKET_SELECT_TIMEOUT;
    else if (res > 0) {
        /* check error first, then rx/tx */
        if (FD_ISSET(sockFd, &errfds)) {
            return WKM_SOCKET_SELECT_ERROR_READY;
        }
        else if (FD_ISSET(sockFd, &fds)) {
            if (rx)
                return WKM_SOCKET_SELECT_RECV_READY;
            else
                return WKM_SOCKET_SELECT_SEND_READY;
        }
    }

    return WKM_SOCKET_SELECT_FAIL;
}

int wolfSockSetBlockingMode(WKM_SOCKET_T sockFd, int nonBlocking)
{
    int ret = 0;

#ifdef USE_WINDOWS_API
    unsigned long blocking = nonBlocking;
    ret = ioctlsocket(sockFd, FIONBIO, &blocking);
    if (ret == SOCKET_ERROR)
        ret = -1;
#else
    ret = fcntl(sockFd, F_GETFL, 0);
    if (ret >= 0) {
        if (nonBlocking)
            ret |= O_NONBLOCK;
        else
            ret &= ~O_NONBLOCK;
        ret = fcntl(sockFd, F_SETFL, ret);
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

int wolfSocketRead(WKM_SOCKET_T sockFd, byte* buffer, word32 length)
{
    return (int)recv(sockFd, buffer, length, 0);
}

int wolfSocketWrite(WKM_SOCKET_T sockFd, const byte* buffer,
    word32 length)
{
    return (int)send(sockFd, buffer, length, 0);
}

void wolfSocketClose(WKM_SOCKET_T sockFd)
{
    if (WKM_SOCKET_IS_INVALID(sockFd)) {
    #ifdef USE_WINDOWS_API
        closesocket(sockFd);
    #else
        close(sockFd);
    #endif
    }
}

int wolfSocketGetError(WKM_SOCKET_T sockFd, int* so_error)
{
    socklen_t len = (socklen_t)sizeof(*so_error);
    return getsockopt(sockFd, SOL_SOCKET, SO_ERROR, so_error, &len);
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

char* wolfSocketAddrStr(SOCKADDR_IN_T* addr)
{
#ifndef USE_IPV6
    static char output[32];
    memset(output, 0, sizeof(output));
    if (addr) {
        byte *p = (byte*)&addr->sin_addr;
        snprintf(output, sizeof(output), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    }
    return output;
#else
    static char output[42];
    return (char*)inet_ntop(AF_INET6, addr, output, 42);
#endif
}
