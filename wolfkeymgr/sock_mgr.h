/* sock_mgr.h
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

#ifndef SOCK_MGR_H
#define SOCK_MGR_H

#include <stdlib.h>
#include <string.h>
#include <pthread.h>               /* thread header */
#include <sysexits.h>              /* exit status header */
#include <event2/event-config.h>   /* event headers */
#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/dns.h>

#include "wolfkeymgr/wkm_types.h"

/* wolfssl headers */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>


#ifdef __cplusplus
extern "C" {
#endif

/* string constants */

/* program constants */
#define MAX_SOCKADDR_SZ   32
#define MAX_SERVICES      1

/* program types */

/* forward declarations */
typedef struct ConnItem ConnItem;
typedef struct SvcConn SvcConn;
typedef struct SvcInfo SvcInfo;
typedef struct EventThread EventThread;

/* service connection */
typedef int  (*svcRequestFunc)(SvcConn*);
typedef int  (*svcTimeoutFunc)(SvcConn*);
typedef int  (*svcNotifyFunc)(SvcConn*);
typedef void (*svcCloseFunc)(SvcConn*);
typedef int  (*initThreadFunc)(SvcInfo*, void**);
typedef void (*freeThreadFunc)(SvcInfo*, void*);

/* overall statistics */
typedef struct {
    pthread_mutex_t lock;                   /* stats lock, only global uses */
    uint64_t        totalConnections;       /* total connections ever */
    uint64_t        completedRequests;      /* completed requests ever */
    uint32_t        timeouts;               /* total requests that timed out */
    uint32_t        currentConnections;     /* current active connections */
    uint32_t        maxConcurrent;          /* max concurrent connections */
    time_t          began;                  /* time we started */
    double          responseTime;           /* total response time */
} SvcStats;

struct SvcInfo {
    const char* desc;

    /* service callbacks */
    svcRequestFunc  requestCb;
    svcTimeoutFunc  timeoutCb;
    svcNotifyFunc   notifyCb;
    svcCloseFunc    closeCb;

    /* TLS certificate / key - As DER/ASN.1*/
    byte*           keyBuffer;
    byte*           certBuffer;
    byte*           caBuffer;
    word32          keyBufferSz;
    word32          certBufferSz;
    word32          caBufferSz;

    /* Shared context for all threads */
    void*           svcCtx;

    /* internal members */
    struct timeval  readto;         /* our event timeout */
    int             initCount;      /* number of worker threads done setting up */
    pthread_mutex_t initLock;       /* for initCount */
    pthread_cond_t  initCond;       /* for initCount */
    EventThread*    threads;        /* worker thread pool */
    unsigned int    threadPoolSize; /* our reference here */
    ConnItem*       freeConnItems;  /* free connection item list */
    pthread_mutex_t itemLock;       /* for freeItems */
    SvcStats        globalStats;    /* global (all threads) total stats */
    WOLFSSL_CTX*    sslCtx;         /* ssl context factory */
};

/* signal processing holder */
typedef struct {
    struct event_base* base;        /* base event that setup signal handler */
    struct event*      ev;          /* actual signal event */
    SvcInfo*           svc[MAX_SERVICES];
} SignalArg;

/* each connection item */
struct ConnItem {
    ConnItem* next;                        /* next item on freeList */
    int       fd;                          /* file descriptor */
    char      peerAddr[MAX_SOCKADDR_SZ];   /* copy of peer sockaddr */
    SvcInfo*  svc;
};

/* queue for connections, shared between main thread and worker threads */
typedef struct {
    ConnItem*       head;     /* head of queue */
    ConnItem*       tail;     /* tail of queue */
    pthread_mutex_t lock;     /* queue lock */
} ConnQueue;

struct SvcConn {
    struct bufferevent* stream;       /* buffered stream */
    WOLFSSL*            ssl;          /* ssl object */
    word32              requestSz;    /* bytes in request buffer */
    byte                request[MAX_REQUEST_SIZE];   /* full input request */
    word32              responseSz;   /* bytes in response buffer */
    byte                response[MAX_RESPONSE_SIZE]; /* full response */
    SvcInfo*            svc;
    void*               svcConnCtx;   /* context for the connection specific to the service */
    double              start;        /* response processing time start */
    EventThread*        me;
    SvcConn*            next;
    SvcConn*            prev;
};

typedef struct SvcConnList {
    SvcConn* head;
    /* no locking needed, this list is only accedded by the working thread */
} SvcConnList;


/* each thread in the pool has some unique data */
struct EventThread {
    pthread_t          tid;            /* this thread's ID */
    struct event_base* threadBase;     /* base handle for this thread */
    struct event*      notify;         /* listen event for notify pipe */
    ConnQueue*         connections;    /* queue for new connections */
    int                notifyRecv;     /* receiving end of notification pipe */
    int                notifySend;     /* sending end of notification pipe */
    SvcInfo*           svc;
    SvcConnList        freeSvcConns;   /* free connection list */
    SvcConnList        activeSvcConns; /* active connection list */
};


/* Key Manager Functions */
WOLFKM_LOCAL int  wolfKeyMgr_MakeDaemon(int chDir);
WOLFKM_LOCAL void wolfKeyMgr_SetMaxFiles(int max);
WOLFKM_LOCAL void wolfKeyMgr_SetCore(void);
WOLFKM_LOCAL void wolfKeyMgr_SignalCb(evutil_socket_t fd, short event, void* arg);
WOLFKM_LOCAL void wolfKeyMgr_ShowStats(SvcInfo* svc);
WOLFKM_LOCAL FILE* wolfKeyMgr_GetPidFile(const char* pidFile, pid_t pid);
WOLFKM_LOCAL void wolfKeyMgr_SetTimeout(SvcInfo* svc, word32 timeoutSec);

WOLFKM_LOCAL int wolfKeyMgr_AddListeners(SvcInfo* svc, int af_v, const char* listenPort, struct event_base* mainBase);
WOLFKM_LOCAL int wolfKeyMgr_ServiceInit(SvcInfo* svc, int numThreads);
WOLFKM_LOCAL void wolfKeyMgr_ServiceCleanup(SvcInfo* svc);
WOLFKM_LOCAL void wolfKeyMgr_FreeListeners(void);

WOLFKM_LOCAL int wolfKeyMgr_DoSend(SvcConn* conn, byte* resp, int respSz);
WOLFKM_LOCAL int wolfKeyMgr_NotifyAllClients(SvcInfo* svc);
WOLFKM_LOCAL int wolfKeyMgr_LoadKeyFile(SvcInfo* svc, const char* fileName, int fileType, const char* password);
WOLFKM_LOCAL int wolfKeyMgr_LoadCertFile(SvcInfo* svc, const char* fileName, int fileType);
WOLFKM_LOCAL int wolfKeyMgr_LoadCAFile(SvcInfo* svc, const char* fileName, int fileType);


#ifdef __cplusplus
}
#endif

#endif /* SOCK_MGR_H */
