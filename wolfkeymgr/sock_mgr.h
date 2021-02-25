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
#define MAX_REQUEST_SIZE (16*1024)
#define MAX_SERVICES      1

/* program types */

/* forward declarations */
typedef struct connItem connItem;
typedef struct svcConn svcConn;
typedef struct svcInfo svcInfo;
typedef struct eventThread eventThread;

/* service connection */
typedef int  (*svcRequestFunc)(svcConn*);
typedef int  (*svcTimeoutFunc)(svcConn*);
typedef int  (*svcNotifyFunc)(svcConn*);
typedef void (*svcCloseFunc)(svcConn*);
typedef int  (*initThreadFunc)(svcInfo*, void**);
typedef void (*freeThreadFunc)(svcInfo*, void*);

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
} stats;

struct svcInfo {
    const char* desc;

    /* service callbacks */
    initThreadFunc  initThreadCb;
    svcRequestFunc  requestCb;
    svcTimeoutFunc  timeoutCb;
    svcNotifyFunc   notifyCb;
    freeThreadFunc  freeThreadCb;
    svcCloseFunc    closeCb;
    
    /* TLS certificate / key - As DER/ASN.1*/
    int             noTLS;
    byte*           keyBuffer;
    byte*           certBuffer;
    byte*           caBuffer;
    word32          keyBufferSz;
    word32          certBufferSz;
    word32          caBufferSz;
    int             disableMutalAuth;

    /* Shared context for all threads */
    void*           svcCtx;

    /* internal members */
    struct timeval  readto;         /* our event timeout */
    int             initCount;      /* number of worker threads done setting up */
    pthread_mutex_t initLock;       /* for initCount */
    pthread_cond_t  initCond;       /* for initCount */
    eventThread*    threads;        /* worker thread pool */
    int             threadPoolSize; /* our reference here */
    connItem*       freeConnItems;  /* free connection item list */
    pthread_mutex_t itemLock;       /* for freeItems */
    stats           globalStats;    /* global (all threads) total stats */
    WOLFSSL_CTX*    sslCtx;         /* ssl context factory */
};

/* signal processing holder */
typedef struct {
    struct event_base* base;        /* base event that setup signal handler */
    struct event*      ev;          /* actual signal event */
    svcInfo*           svc[MAX_SERVICES];
} signalArg;

/* each connection item */
struct connItem {
    connItem* next;                        /* next item on freeList */
    int       fd;                          /* file descriptor */
    char      peerAddr[MAX_SOCKADDR_SZ];   /* copy of peer sockaddr */
    svcInfo*  svc;
};

/* queue for connections, shared between main thread and worker threads */
typedef struct {
    connItem*       head;     /* head of queue */
    connItem*       tail;     /* tail of queue */
    pthread_mutex_t lock;     /* queue lock */
} connQueue;

struct svcConn {
    struct bufferevent* stream;       /* buffered stream */
    WOLFSSL*            ssl;          /* ssl object */
    word32              requestSz;    /* bytes in request buffer */
    byte                request[MAX_REQUEST_SIZE]; /* full input request */
    svcInfo*            svc;
    void*               svcThreadCtx; /* context for the thread */
    void*               svcConnCtx;   /* context for the connection specific to the service */
    double              start;        /* response processing time start */
    eventThread*        me;
    svcConn*            next;
    svcConn*            prev;
};

typedef struct svcConnList {
    svcConn* head;
    /* no locking needed, this list is only accedded by the working thread */
} svcConnList;


/* each thread in the pool has some unique data */
struct eventThread {
    pthread_t          tid;            /* this thread's ID */
    struct event_base* threadBase;     /* base handle for this thread */
    struct event*      notify;         /* listen event for notify pipe */
    connQueue*         connections;    /* queue for new connections */
    int                notifyRecv;     /* receiving end of notification pipe */
    int                notifySend;     /* sending end of notification pipe */
    svcInfo*           svc;
    void*              svcThreadCtx;
    svcConnList        freeSvcConns;   /* free connection list */
    svcConnList        activeSvcConns; /* active connection list */
};


typedef struct KeyManager {
    struct event_base* mainBase;
    FILE*              pidF;
} KeyManager_t;



/* Key Manager Functions */
WOLFKM_LOCAL int  wolfKeyMgr_MakeDaemon(int chDir);
WOLFKM_LOCAL void wolfKeyMgr_SetMaxFiles(int max);
WOLFKM_LOCAL void wolfKeyMgr_SetCore(void);
WOLFKM_LOCAL void wolfKeyMgr_SignalCb(evutil_socket_t fd, short event, void* arg);
WOLFKM_LOCAL int  wolfKeyMgr_SigIgnore(int sig);
WOLFKM_LOCAL void wolfKeyMgr_ShowStats(svcInfo* svc);
WOLFKM_LOCAL FILE* wolfKeyMgr_GetPidFile(const char* pidFile, pid_t pid);
WOLFKM_LOCAL void wolfKeyMgr_SetTimeout(svcInfo* svc, word32 timeoutSec);

WOLFKM_LOCAL int wolfKeyMgr_AddListeners(svcInfo* svc, int af_v, char* listenPort, struct event_base* mainBase);
WOLFKM_LOCAL int wolfKeyMgr_ServiceInit(svcInfo* svc, int numThreads);
WOLFKM_LOCAL void wolfKeyMgr_ServiceCleanup(svcInfo* svc);
WOLFKM_LOCAL void wolfKeyMgr_FreeListeners(void);

WOLFKM_LOCAL int wolfKeyMgr_DoSend(svcConn* conn, byte* resp, int respSz);
WOLFKM_LOCAL int wolfKeyMgr_NotifyAllClients(svcInfo* svc);
WOLFKM_LOCAL int wolfKeyMgr_LoadKeyFile(svcInfo* svc, const char* fileName, int fileType, const char* password);
WOLFKM_LOCAL int wolfKeyMgr_LoadCertFile(svcInfo* svc, const char* fileName, int fileType);
WOLFKM_LOCAL int wolfKeyMgr_LoadCAFile(svcInfo* svc, const char* fileName, int fileType);


#ifdef __cplusplus
}
#endif

#endif /* SOCK_MGR_H */
