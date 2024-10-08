/* sock_mgr.c
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

#include <stdio.h>        /* system headers */
#include <stdlib.h>
#include <ctype.h>        /* isupper */
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include "wolfkeymgr/keymanager.h"

/* per thread stats, doesn't use lock */
static __thread SvcStats threadStats;


/* listener list */
typedef struct listener listener;
struct listener {
    struct evconnlistener* ev_listen; /* event listener */
    listener* next;                   /* next on list */
};
static listener* listenerList = NULL; /* main list of listeners */

/* commands for worker threads */
static char kCancel = 'c'; /* cancel */
static char kWake   = 'w'; /* send wakeup flag */
static char kNotify = 'n'; /* notify */

static void StatsPrint(SvcStats* local);

/* --- INLINE LOCAL FUNCTIONS --- */
/* turn on TCP NODELAY for socket */
static inline void TcpNoDelay(int fd)
{
    int flags = 1;

    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void*)&flags, sizeof(flags))
                   < 0)
        XLOG(WOLFKM_LOG_INFO, "setsockopt TCP_NODELAY failed\n");
}

/* Initialize all stats to zero, pre allocs may increment some counters */
static void InitStats(SvcStats* myStats)
{
    /* do not use memset, lock already init */
    myStats->totalConnections   = 0;
    myStats->completedRequests  = 0;
    myStats->timeouts           = 0;
    myStats->currentConnections = 0;
    myStats->maxConcurrent      = 0;
    myStats->began              = 0;
    myStats->responseTime       = 0.0f;
}

/* Add to current per thread connection stats, handle max too */
static inline void IncrementCurrentConnections(SvcConn* conn)
{
    threadStats.currentConnections++;
    if (threadStats.currentConnections > threadStats.maxConcurrent)
        threadStats.maxConcurrent = threadStats.currentConnections;
    (void)conn;
}


/* Add to total per thread connection stats */
static inline void IncrementTotalConnections(SvcConn* conn)
{
    threadStats.totalConnections++;
    IncrementCurrentConnections(conn);
}


/* Add to total per thread completed stats */
static inline void IncrementCompleted(SvcConn* conn)
{
    threadStats.completedRequests++;
    threadStats.responseTime += wolfGetCurrentTime() - conn->start;
}


/* Add to total per thread timeout stats */
static inline void IncrementTimeouts(SvcConn* conn)
{
    threadStats.timeouts++;
    (void)conn;
}


/* Decrement current per thread connection stats */
static inline void DecrementCurrentConnections(SvcConn* conn)
{
    threadStats.currentConnections--;
    (void)conn;
}


/* --- LOCAL FUNCTIONS --- */
/* Get string version of libevent address info */
static int GetAddrInfoString(struct evutil_addrinfo* addr, char* buf, size_t bufSz)
{
    int ret = -1;
    char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

    if (buf) {
        memset(buf, 0, bufSz);
    }
    if (addr) {
        ret = getnameinfo(
            (struct sockaddr*)addr->ai_addr,
            (socklen_t)addr->ai_addrlen,
            hbuf, sizeof(hbuf),
            sbuf, sizeof(sbuf),
            (NI_NUMERICHOST | NI_NUMERICSERV));
        if (ret == 0) {
            snprintf(buf, bufSz, "%s:%s", hbuf, sbuf);
        }
    }

    return ret;
}

/* our listener error call back to use our logging */
static void OurListenerError(struct evconnlistener* listener, void* ptr)
{
    int  err = EVUTIL_SOCKET_ERROR();

    (void)ptr;

    XLOG(WOLFKM_LOG_ERROR, "Got an error %d (%s) on the listener. \n",
                                      err, evutil_socket_error_to_string(err));

    if (err == EMFILE || err == ENFILE || err == ENOMEM) {
        XLOG(WOLFKM_LOG_WARN, "Backing off listener, no open files\n");
        usleep(WOLFKM_BACKOFF_TIME);
    }
    /* for invalid argument disable listener */
    if (err == EINVAL) {
        /* this can happen if ss -kill socket is run,
         * otherwise causes libevent error callback loop */
        evconnlistener_disable(listener);
    }
}

/* Initialize the connection queue */
static void ConnQueueInit(ConnQueue* cq)
{
    cq->head = NULL;
    cq->tail = NULL;
    pthread_mutex_init(&cq->lock, NULL);
}

/* put connection item back onto the free connection item list */
static void ConnItemFree(ConnItem* item)
{
    pthread_mutex_lock(&item->svc->itemLock);
    item->next = item->svc->freeConnItems;
    item->svc->freeConnItems = item;
    pthread_mutex_unlock(&item->svc->itemLock);
}

/* Get a new connection item */
static ConnItem* ConnItemNew(SvcInfo* svc)
{
    ConnItem* item;

    pthread_mutex_lock(&svc->itemLock);
    if ( (item = svc->freeConnItems) )
        svc->freeConnItems = item->next;
    pthread_mutex_unlock(&svc->itemLock);

    if (item == NULL) {
        /* free list empty, add more items to the free list pool */
        XLOG(WOLFKM_LOG_INFO, "Setting up new %s conn item pool\n", svc->desc);
        item = (ConnItem*)malloc(sizeof(ConnItem) * WOLFKM_CONN_ITEMS);
        if (item) {
            int i;

            /* the first one is the new item */
            for (i = 1; i < WOLFKM_CONN_ITEMS; i++)
                item[i].next = &item[i+1];

            pthread_mutex_lock(&svc->itemLock);
            item[WOLFKM_CONN_ITEMS-1].next = svc->freeConnItems;
            svc->freeConnItems = &item[1];
            pthread_mutex_unlock(&svc->itemLock);
        }
        else {
            XLOG(WOLFKM_LOG_ERROR, "ConnItemNew pool malloc error\n");
        }
    }

    if (item) {
        item->next = NULL;
        item->fd   = -1;
        item->svc  = svc;
    }

    return item;
}

/* push an item onto the connection queue */
static void ConnQueuePush(ConnQueue* cq, ConnItem* item)
{
    item->next = NULL;

    pthread_mutex_lock(&cq->lock);

    if (cq->tail == NULL)  /* empty ? */
        cq->head = item;
    else
        cq->tail->next = item;
    cq->tail = item;      /*  add to the end either way */

    pthread_mutex_unlock(&cq->lock);
}

/* pop an item off the connection queue */
static ConnItem* ConnQueuePop(ConnQueue* cq)
{
    ConnItem* item;

    pthread_mutex_lock(&cq->lock);

    if ( (item = cq->head) ) {
        cq->head = item->next;
        if (cq->head == NULL)   /* are we now empty */
            cq->tail = NULL;
    }

    pthread_mutex_unlock(&cq->lock);

    return item;
}

static void ServiceConnListDel(SvcConnList* list, SvcConn* conn)
{
    if (conn->prev)
        conn->prev->next = conn->next;
    else
        list->head = conn->next;
    if (conn->next)
        conn->next->prev = conn->prev;
}

static void ServiceConnListAddFront(SvcConnList* list, SvcConn* conn)
{
    conn->next = list->head;
    if (list->head)
        list->head->prev = conn;
    list->head = conn;
}

static SvcConn* ServiceConnListPop(SvcConnList* list)
{
    SvcConn* conn = list->head;
    if (conn) {
        list->head = conn->next;
    }
    return conn;
}

/* put connection item back onto the free item list, handle stats */
void ServiceConnFree(SvcConn* conn)
{
    EventThread* me;

    if (conn == NULL)
        return;

    me = conn->me;

    if (conn->svc) {
        XLOG(WOLFKM_LOG_DEBUG, "Freeing %s Service Connection\n",
            conn->svc->desc);
    }
    DecrementCurrentConnections(conn);

    if (conn->svc && conn->svc->closeCb) {
        conn->svc->closeCb(conn);
    }

    /* release per connection resources */
    if (conn->stream) {
        bufferevent_free(conn->stream);
        conn->stream = NULL;
    }

    if (conn->ssl) {
        wolfSSL_free(conn->ssl);
        conn->ssl = NULL;
    }

    /* remove "conn" from source list */
    ServiceConnListDel(&me->activeSvcConns, conn);

    /* add "conn" to destination list */
    ServiceConnListAddFront(&me->freeSvcConns, conn);
}

static int ServiceConnGrowPool(EventThread* me)
{
    SvcInfo* svc = me->svc;
    SvcConn* conn;

    XLOG(WOLFKM_LOG_INFO, "Growing %s service conn pool\n", svc->desc);

    conn = (SvcConn*)malloc(sizeof(SvcConn) * WOLFKM_CONN_ITEMS);
    if (conn) {
        int i;

        /* the first one is the new item */
        for (i = 0; i < WOLFKM_CONN_ITEMS; i++) {
            ServiceConnListAddFront(&me->freeSvcConns, &conn[i]);
        }
        return 0;
    }

    XLOG(WOLFKM_LOG_ERROR, "ServiceConnGrowPool malloc error\n");
    return WOLFKM_BAD_MEMORY;
}

/* get a new service connection, handle stats */
static SvcConn* ServiceConnNew(EventThread* me)
{
    SvcInfo* svc = me->svc;
    SvcConn* conn;

    conn = ServiceConnListPop(&me->freeSvcConns);
    if (conn == NULL) {
        /* free list empty, add more items to the free list pool */
        ServiceConnGrowPool(me);

        conn = ServiceConnListPop(&me->freeSvcConns);
    }

    /* get first free connection */
    if (conn) {
        /* per connection inits */
        conn->next      = NULL;
        conn->prev      = NULL;
        conn->stream    = NULL;
        conn->ssl       = NULL;
        conn->start     = 0.0f;
        conn->requestSz = 0;
        conn->responseSz= 0;
        conn->svc       = svc;
        conn->me        = me;
        IncrementTotalConnections(conn);

        /* add "conn" to active list */
        ServiceConnListAddFront(&me->activeSvcConns, conn);
    }

    return conn;
}


/* worker event has been canceled, clean up */
static void WorkerExit(void* arg)
{
    EventThread* me = (EventThread*)arg;
    SvcInfo* svc = me->svc;
    SvcConn *conn, *next;

    /* put per thread stats into global stats */
    /* do this before closing active connections,
     * so we can see how many were connected */
    pthread_mutex_lock(&svc->globalStats.lock);
    svc->globalStats.totalConnections   += threadStats.totalConnections;
    svc->globalStats.completedRequests  += threadStats.completedRequests;
    svc->globalStats.timeouts           += threadStats.timeouts;
    svc->globalStats.currentConnections += threadStats.currentConnections;
    svc->globalStats.maxConcurrent      += threadStats.maxConcurrent;
    svc->globalStats.responseTime       += threadStats.responseTime;
    pthread_mutex_unlock(&svc->globalStats.lock);

    /* close all active connections */
    conn = me->activeSvcConns.head;
    while (conn) {
        next = conn->next;
        ServiceConnFree(conn);
        conn = next;
    }

    event_del(me->notify);
    event_base_loopexit(me->threadBase, NULL);

    XLOG(WOLFKM_LOG_INFO, "Worker thread exiting, tid = %ld\n",
                        (long)pthread_self());

    pthread_exit(NULL);
}


/* our event callback */
static void EventCb(struct bufferevent* bev, short what, void* ctx)
{
    SvcConn* conn = (SvcConn*)ctx;

    XLOG(WOLFKM_LOG_INFO, "EventCb what = %d\n", what);

    if (what & BEV_EVENT_TIMEOUT) {
        int doClose = 1;
        if (conn && conn->svc && conn->svc->timeoutCb) {
            doClose = conn->svc->timeoutCb(conn);
        }
        if (doClose) {
            XLOG(WOLFKM_LOG_INFO, "Got timeout on connection, closing\n");
            ServiceConnFree(conn);
            IncrementTimeouts(conn);
        }
        else {
            /* reset read/write enable */
            XLOG(WOLFKM_LOG_INFO, "Keeping connection open\n");
            bufferevent_enable(conn->stream, (EV_READ | EV_WRITE));
        }
        return;
    }

    if (what & BEV_EVENT_EOF) {
        XLOG(WOLFKM_LOG_INFO, "Peer ended connection, closing\n");
        ServiceConnFree(conn);
        return;
    }

    if (what & BEV_EVENT_ERROR) {
        XLOG(WOLFKM_LOG_INFO, "Generic connection error, closing\n");
        ServiceConnFree(conn);
        return;
    }

    (void)bev;
}


/* return number of bytes read, 0 on wouldblock, < 0 on error */
static int DoRead(struct bufferevent* bev, SvcConn* conn)
{
    int ret = 0;

    if (conn->ssl == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "DoRead() usingTLS but no SSL object\n");
        return -1;
    }

    ret = wolfSSL_read(conn->ssl,
                            conn->request + conn->requestSz,
                            sizeof(conn->request) - conn->requestSz);
    if (ret < 0) {
        int err = wolfSSL_get_error(conn->ssl, 0);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            ret = 0;     /* translate to 0 wouldblock */
        else if (err > 0)
            ret = -err;  /* keep negative */
        else
            ret = err;

        if (ret != 0)
            XLOG(WOLFKM_LOG_ERROR, "wolfSSL_read err = %s\n",
                                wolfSSL_ERR_reason_error_string(err));
    }
    (void)bev;
    return ret;
}


/* our read callback */
static void ReadCb(struct bufferevent* bev, void* ctx)
{
    SvcConn* conn = (SvcConn*)ctx;
    int       ret;

    if (bev == NULL || conn == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ReadCb pointers\n");
        return;
    }

    ret = DoRead(bev, conn);
    if (ret == 0) {
        /* EWOULDBLOCK, ok */
        return;
    }
    else if (ret > 0) {
        conn->requestSz += ret;

        /* handle request with callback */
        if (conn->svc && conn->svc->requestCb) {
            conn->start = wolfGetCurrentTime();
            ret = conn->svc->requestCb(conn);
            if (ret < 0) {
                /* error */
                XLOG(WOLFKM_LOG_ERROR, "Do request error %d\n", ret);
                ServiceConnFree(conn);
                conn = NULL;
            }
            else {
                /* success on request */
                IncrementCompleted(conn);
            }
        }
        if (conn) {
            /* reset request size for next request */
            conn->requestSz = 0;
        }
    }
    else {
        /* ret < 0, we have an actual error */
        XLOG(WOLFKM_LOG_ERROR, "DoRead error %d\n", ret);
        ServiceConnFree(conn);
    }
}


/* Process an incoming connection item, called when input is placed on event
   wakeup pipe */
static void ThreadEventProcess(int fd, short which, void* arg)
{
    char         buffer[1]; /* at least size of kCancel, kNotify and kWake */
    EventThread* me = (EventThread*)arg;
    ConnItem*    item;

    if (read(fd, buffer, sizeof(buffer)) != sizeof(buffer)) {
        XLOG(WOLFKM_LOG_ERROR, "thread notify receive read error\n");
    }
    /* on exit get sent 'c' for cancel, usually get 'w' for wakeup */
    else if (memcmp(buffer, &kCancel, sizeof(kCancel)) == 0) {
        WorkerExit(me);
        return;
    }
    else if (memcmp(buffer, &kNotify, sizeof(kNotify)) == 0) {
        SvcConn* conn = me->activeSvcConns.head, conn_lcl;
        if (conn == NULL) {
            /* Setup an empty connection for notify only */
            memset(&conn_lcl, 0, sizeof(conn_lcl));
            conn = &conn_lcl;
            conn->svc          = me->svc;
            conn->me           = me;
        }
        while (conn) {
            if (conn->svc->notifyCb) {
                conn->svc->notifyCb(conn);
            }
            conn = conn->next;
        }
        return;
    }

    item = ConnQueuePop(me->connections);
    if (item) {
        /* Do new connection here from item->fd */
        int clientFd = item->fd;
        SvcConn* conn = ServiceConnNew(me);

        ConnItemFree(item);  /* no longer need item, give it back */

        if (conn == NULL) {
            XLOG(WOLFKM_LOG_ERROR, "ServiceConnNew() failed\n");
            close(clientFd);
            return;
        }

        XLOG(WOLFKM_LOG_INFO, "New %s service conn\n", me->svc->desc);

        conn->stream = bufferevent_socket_new(me->threadBase, clientFd,
                             (BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS));
        if (conn->stream == NULL) {
            XLOG(WOLFKM_LOG_ERROR, "bufferevent_socket_new() failed\n");
            ServiceConnFree(conn);
            close(clientFd); /* normally ServiceConnFree would close fd by stream
                                but since stream is NULL, force it */
            return;
        }
        else {
            conn->ssl = wolfSSL_new(conn->svc->sslCtx);
            if (conn->ssl == NULL) {
                XLOG(WOLFKM_LOG_ERROR, "wolfSSL_New() failed\n");
                ServiceConnFree(conn);
                return;
            }
            wolfSSL_SetIOReadCtx( conn->ssl, conn->stream);
            wolfSSL_SetIOWriteCtx(conn->ssl, conn->stream);
        }

        bufferevent_setcb(conn->stream, ReadCb, NULL, EventCb, conn);
        bufferevent_set_timeouts(conn->stream, &conn->svc->readto, NULL);
        bufferevent_enable(conn->stream, (EV_READ | EV_WRITE));
    }

    (void)which;
}

/* Individual thread setup */
static void SetupThread(SvcInfo* svc, EventThread* me)
{
    /* thread base */
    me->threadBase = event_base_new();
    if (me->threadBase == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Error allocating thread's event base\n");
        exit(EXIT_FAILURE);
    }

    /* notify event pipe */
    me->notify = event_new(me->threadBase, me->notifyRecv,
                           (EV_READ | EV_PERSIST), ThreadEventProcess, me);
    if (event_add(me->notify, NULL) == -1) {
        XLOG(WOLFKM_LOG_ERROR, "Error adding event for monitor pipe\n");
        exit(EXIT_FAILURE);
    }

    /* create connection queue */
    me->connections = malloc(sizeof(ConnQueue));
    if (me->connections == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Error allocating thread's Connection Queue\n");
        exit(EXIT_FAILURE);
    }
    ConnQueueInit(me->connections);
    me->svc = svc;
}


/* Signal Thread setup done and running */
static void SignalSetup(SvcInfo* svc)
{
    /* signal ready */
    pthread_mutex_lock(&svc->initLock);
    svc->initCount++;
    pthread_cond_signal(&svc->initCond);
    pthread_mutex_unlock(&svc->initLock);
}


/* worker event to signal done with thread setup, starts loop */
static void* WorkerEvent(void* arg)
{
    EventThread* me = (EventThread*)arg;

    ServiceConnGrowPool(me);
    InitStats(&threadStats);

    /* tell creator we're ready */
    me->tid = pthread_self();
    SignalSetup(me->svc);

    /* start thread's loop */
    event_base_loop(me->threadBase, 0);

    return NULL;
}


/* Make a new Worker thread */
static void MakeWorker(void* (*f)(void*), void* arg)
{
    pthread_t      thread;
    pthread_attr_t attr;

    pthread_attr_init(&attr);

    if (pthread_create(&thread, &attr, f, arg) != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Error creating worker\n");
        exit(EXIT_FAILURE);
    }
}


/* wolfSSL I/O Receive CallBack */
static int wolfsslRecvCb(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    int ret;
    struct bufferevent* bev = (struct bufferevent*)ctx;

    (void)ssl;

    if (bev == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "wolfSSL ReceiveCb NULL ctx\n");
        return -1;
    }

    ret = evbuffer_remove(bufferevent_get_input(bev), buf, sz);
    if (ret == 0) {
        return WOLFSSL_CBIO_ERR_WANT_READ;  /* ok, wouldblock */
    }
    else if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "wolfssl ReceiveCb error %d\n", ret);
        ret = WOLFSSL_CBIO_ERR_GENERAL;
    }

    return ret;
}


/* wolfSSL I/O Send CallBack */
static int wolfsslSendCb(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    int ret;
    struct bufferevent* bev = (struct bufferevent*)ctx;

    (void)ssl;

    if (bev == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "wolfSSL SendCb NULL ctx\n");
        return -1;
    }

    ret = evbuffer_add(bufferevent_get_output(bev), buf, sz);
    if (ret == 0) {
        return sz;
    }
    else if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "wolfssl SendCb error %d\n", ret);
        ret = WOLFSSL_CBIO_ERR_GENERAL;
    }

    return ret;
}


/* setup ssl context */
static int InitServerTLS(SvcInfo* svc)
{
    int ret;

    svc->sslCtx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (svc->sslCtx == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Error allocating TLS 1.3 context\n");
        return WOLFKM_BAD_MEMORY;
    }
    wolfSSL_CTX_SetIORecv(svc->sslCtx, wolfsslRecvCb);
    wolfSSL_CTX_SetIOSend(svc->sslCtx, wolfsslSendCb);

    if (svc->caBuffer) {
        ret = wolfSSL_CTX_load_verify_buffer(svc->sslCtx, svc->caBuffer,
            svc->caBufferSz, WOLFSSL_FILETYPE_ASN1);
        if (ret != WOLFSSL_SUCCESS) {
            XLOG(WOLFKM_LOG_ERROR, "Error loading TLS cert into context\n");
            wolfSSL_CTX_free(svc->sslCtx); svc->sslCtx = NULL;
            return ret;
        }
    }

    if (svc->certBuffer) {
        ret = wolfSSL_CTX_use_certificate_buffer(svc->sslCtx, svc->certBuffer,
            svc->certBufferSz, WOLFSSL_FILETYPE_ASN1);
        if (ret != WOLFSSL_SUCCESS) {
            XLOG(WOLFKM_LOG_ERROR, "Error loading TLS cert into context\n");
            wolfSSL_CTX_free(svc->sslCtx); svc->sslCtx = NULL;
            return ret;
        }
    }

    if (svc->keyBuffer) {
        ret = wolfSSL_CTX_use_PrivateKey_buffer(svc->sslCtx, svc->keyBuffer,
            svc->keyBufferSz, WOLFSSL_FILETYPE_ASN1);
        if (ret != WOLFSSL_SUCCESS) {
            XLOG(WOLFKM_LOG_ERROR, "Error loading TLS key into context\n");
            wolfSSL_CTX_free(svc->sslCtx); svc->sslCtx = NULL;
            return ret;
        }
    }

    /* mutual authentication */
    wolfSSL_CTX_set_verify(svc->sslCtx,
        (WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT), NULL);

    return 0;
}

/* dispatcher thread accept callback */
static void AcceptCB(struct evconnlistener* listener, evutil_socket_t fd,
    struct sockaddr* a, int slen, void* p)
{
    SvcInfo* svc = (SvcInfo*)p;
    static int lastThread = -1;       /* last used thread ID */
    int currentId = (lastThread + 1) % svc->threadPoolSize; /* round robin */
    EventThread* thread = svc->threads + currentId;
    ConnItem*    item = ConnItemNew(svc);

    if (item == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Unable to process accept request, low memory\n");
        close(fd);
        return;
    }

    lastThread = currentId;

    item->fd = fd;
    memset(item->peerAddr, 0, sizeof(item->peerAddr));
    if (slen <= (int)sizeof(item->peerAddr)) {
        memcpy(item->peerAddr, a, slen);
    }

    TcpNoDelay(fd);

    /* push connection item and notify thread */
    ConnQueuePush(thread->connections, item);

    if (write(thread->notifySend, &kWake, sizeof(kWake)) != sizeof(kWake)) {
        XLOG(WOLFKM_LOG_ERROR, "Write to thread notify send pipe failed\n");
    }
    XLOG(WOLFKM_LOG_INFO, "Accepted a connection, sent to thread %d\n",
        currentId);

    (void)listener;
}


/* --- PUBLIC FUNCTIONS --- */

/* Our signal handler callback */
void wolfKeyMgr_SignalCb(evutil_socket_t fd, short event, void* arg)
{
    SignalArg* sigArg = (SignalArg*)arg;
    int        sigId = event_get_signal(sigArg->ev);
    int        i;

    if (sigId == SIGINT)
        XLOG(WOLFKM_LOG_INFO, "SIGINT handled.\n");
    else if (sigId == SIGTERM)
        XLOG(WOLFKM_LOG_INFO, "SIGTERM handled.\n");
    else {
        XLOG(WOLFKM_LOG_INFO, "Got unknown signal %d\n", sigId);
    }

    /* end main loop */
    XLOG(WOLFKM_LOG_INFO, "Ending main thread loop\n");
    event_base_loopexit(sigArg->base, NULL);

    for (i=0; i< MAX_SERVICES; i++) {
        wolfKeyMgr_ServiceCleanup(sigArg->svc[i]);
    }

    wolfKeyMgr_CloseLog();

    (void)fd;
    (void)event;
}

static void StatsPrint(SvcStats* local)
{
    double avgResponse = 0.0f;

    if (local->responseTime > 0.0f && local->completedRequests > 0) {
        avgResponse = local->responseTime / local->completedRequests;
        avgResponse *= 1000; /* convert to ms */
    }

    /* always show stats */
    XLOG(WOLFKM_LOG_ERROR, "Current stats:\n"
             "total   connections  = %19llu\n"
             "completed            = %19llu\n"
             "timeouts             = %19u\n"
             "current connections  = %19u\n"
             "max     concurrent   = %19u\n"
             "uptime  in seconds   = %19lu\n"
             "average response(ms) = %19.3f\n",
             (unsigned long long)local->totalConnections,
             (unsigned long long)local->completedRequests,
             local->timeouts,
             local->currentConnections,
             local->maxConcurrent,
             time(NULL) - local->began,
             avgResponse);
}

/* Show our statistics */
void wolfKeyMgr_ShowStats(SvcInfo* svc)
{
    SvcStats local;

    if (svc == NULL)
        return;

    pthread_mutex_lock(&svc->globalStats.lock);
    local = svc->globalStats;
    pthread_mutex_unlock(&svc->globalStats.lock);

    /* adjust max conncurrent since now per thread */
    if (local.maxConcurrent < svc->threadPoolSize)
        local.maxConcurrent = local.maxConcurrent ? 1 : 0;
    else
        local.maxConcurrent -= svc->threadPoolSize - 1;

    StatsPrint(&local);
}


/* set our timeout on connections */
void wolfKeyMgr_SetTimeout(SvcInfo* svc, word32 timeoutSec)
{
    if (svc) {
        svc->readto.tv_sec  = timeoutSec;
        svc->readto.tv_usec = 0;
    }
}


/* make sure rlimt files is at least what user wants */
void wolfKeyMgr_SetMaxFiles(int max)
{
    struct rlimit now;

    if (getrlimit(RLIMIT_NOFILE, &now) == 0) {
        if (now.rlim_cur < (size_t)max)
            now.rlim_cur = (size_t)max;
        if (now.rlim_max < now.rlim_cur)
            now.rlim_max = now.rlim_cur;

        if (setrlimit(RLIMIT_NOFILE, &now) != 0) {
            XLOG(WOLFKM_LOG_ERROR, "Error on setrlimit max files\n");
            exit(EX_OSERR);
        }
    }
    else {
        XLOG(WOLFKM_LOG_ERROR, "Error on getrlimit max files\n");
        exit(EX_OSERR);
    }
}


/* Set core max file */
void wolfKeyMgr_SetCore(void)
{
    struct rlimit old, change;

    if (getrlimit(RLIMIT_CORE, &old) == 0) {
        /* infinity first */
        change.rlim_cur = change.rlim_max = RLIM_INFINITY;
        if (setrlimit(RLIMIT_CORE, &change) != 0) {
            /* ok, just try old max */
            change.rlim_cur = change.rlim_max = old.rlim_max;
            if (setrlimit(RLIMIT_CORE, &change) != 0) {
                XLOG(WOLFKM_LOG_ERROR, "Error on setrlimit core\n");
                exit(EX_OSERR);
            }
        }
    } else {
        XLOG(WOLFKM_LOG_ERROR, "Error on getrlimit core\n");
        exit(EX_OSERR);
    }
}

/* Start process as daemon */
/* see Advanced Programming in the Unix Environment, chapter 13 */
int wolfKeyMgr_MakeDaemon(int chDir)
{
    int fd;

    switch (fork()) {
        case -1:
            return -1;
        case 0:                   /* child */
            break;
        default:
            exit(EXIT_SUCCESS);   /* parent goes bye-bye */
    }

    if (setsid() == -1) {         /* become session leader */
        XLOG(WOLFKM_LOG_ERROR, "setsid\n");
        return -1;
    }

    /* optionally change working directory */
    if (chDir) {
        if (chdir("/") != 0) {    /* change working directory */
            XLOG(WOLFKM_LOG_ERROR, "chdir\n");
            return -1;
        }
    }

    umask(0);                     /* always successful */

    fd = open("/dev/null", O_RDWR, 0);
    if (fd == -1) {
        XLOG(WOLFKM_LOG_ERROR, "open /dev/null\n");
        return -1;
    }

    if (dup2(fd, STDIN_FILENO) < 0 || dup2(fd, STDOUT_FILENO) < 0 ||
                                      dup2(fd, STDERR_FILENO) < 0) {
        XLOG(WOLFKM_LOG_ERROR, "dup2 std filenos\n");
        return -1;
    }

    if (close(fd) < 0) {
        XLOG(WOLFKM_LOG_ERROR, "close\n");
        return -1;
    }

    return 0;
}

/* Check for already running process using exclusive lock on pidfile.
 * Returns NULL if process is already running, otherwise writes pid to
 * pidfile and returns FILE pointer to pidfile with an exclusive lock.
 */
FILE* wolfKeyMgr_GetPidFile(const char* pidFile, pid_t pid)
{
    FILE* f;
    int   fd;

    if (!pidFile) {
        XLOG(WOLFKM_LOG_ERROR, "Missing pidfile path\n");
        return NULL; /* Fail */
    }

    /* Open pidfile for writing.  If already exists, do not truncate,
     * but otherwise create it. */
    if ((f = fopen(pidFile, "r+")) == NULL) {
        if (errno != ENOENT) {
            XLOG(WOLFKM_LOG_ERROR, "fopen %s\n", strerror(errno));
            return NULL; /* Fail */
        }
        if ((f = fopen(pidFile, "w")) == NULL) {
            XLOG(WOLFKM_LOG_ERROR, "fopen %s\n", strerror(errno));
            return NULL; /* Fail */
        }
    }

    fd = fileno(f);
    if (fd == -1) {
        XLOG(WOLFKM_LOG_ERROR, "fileno %s\n", strerror(errno));
        return NULL; /* Fail */
    }

    if (lockf(fd, F_TLOCK, 0) == -1) {
        XLOG(WOLFKM_LOG_ERROR, "lockf %s\n", strerror(errno));
        return NULL; /* Fail */
    }

    /* Truncate pidfile */
    if (ftruncate(fd, 0) == -1) {
        XLOG(WOLFKM_LOG_ERROR, "ftruncate %s\n", strerror(errno));
        return NULL; /* Fail */
    }

    /* Write pid */
    fprintf(f, "%ld\n", (long)pid);
    if (fflush(f) == EOF) {
        XLOG(WOLFKM_LOG_ERROR, "fflush %s\n", strerror(errno));
        return NULL;
    }

    return f;
}

/* try to add listeners on interface version
 * return count of listener interfaces added.
 */
int wolfKeyMgr_AddListeners(SvcInfo* svc, int af_v, const char* listenPort,
    struct event_base* mainBase)
{
    int                     err;
    int                     addCount = 0;
    struct evutil_addrinfo  hints;
    struct evutil_addrinfo* answer = NULL;
    struct evutil_addrinfo* current = NULL;  /* list traversal */
    char addrStr[NI_MAXHOST + NI_MAXSERV];

    /* listening addr info */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = af_v;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;         /* TCP */
    hints.ai_flags    = EVUTIL_AI_PASSIVE;   /* any addr */

    err = evutil_getaddrinfo(NULL, listenPort, &hints, &answer);
    if (err < 0 || answer == NULL) {
        XLOG(WOLFKM_LOG_WARN, "Failed to evutil_getaddrinfo for listen\n");
        return -1;
    }
    current = answer;

    while (current) {
        listener* ls = (listener*)malloc(sizeof(listener));
        if (ls == NULL) {
            XLOG(WOLFKM_LOG_ERROR, "Failed to alloc listener\n");
            exit(EXIT_FAILURE);
        }

        GetAddrInfoString(current, addrStr, sizeof(addrStr));
        XLOG(WOLFKM_LOG_INFO, "Binding listener %s\n", addrStr);

        ls->ev_listen = evconnlistener_new_bind(mainBase, AcceptCB, svc,
            (LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC | LEV_OPT_REUSEABLE),
            -1, current->ai_addr, current->ai_addrlen);
        if (ls->ev_listen == NULL) {
            XLOG(WOLFKM_LOG_WARN, "Failed to bind listener: Error %d: %s\n",
                errno, strerror(errno));
            free(ls);
            ls = NULL;
        }
        current = current->ai_next;

        if (ls) {
            addCount++;
            evconnlistener_set_error_cb(ls->ev_listen, OurListenerError);
            ls->next = listenerList;  /* prepend to list */
            listenerList = ls;
        }
    }
    evutil_freeaddrinfo(answer);

    return addCount;
}

/* Initialize all worker threads */
int wolfKeyMgr_ServiceInit(SvcInfo* svc, int numThreads)
{
    int ret = 0, i;
    int fds[2];
    ConnItem*  item;

    /* pthread inits */
    pthread_mutex_init(&svc->initLock, NULL);
    pthread_cond_init(&svc->initCond, NULL);
    pthread_mutex_init(&svc->itemLock, NULL);
    pthread_mutex_init(&svc->globalStats.lock, NULL);

    /* get thread memory */
    svc->threads = calloc(numThreads, sizeof(EventThread));
    if (svc->threads == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Error allocating thread pool\n");
        return WOLFKM_BAD_MEMORY;
    }

    /* pre allocate pool memory */
    item = ConnItemNew(svc);
    ConnItemFree(item);
    InitStats(&svc->globalStats); /* items above for pre alloc shouldn't count */

    /* set the start time and pool size */
    svc->globalStats.began = time(NULL);
    svc->threadPoolSize = numThreads;

    /* setup each thread */
    for (i = 0; i < numThreads; i++) {
        if (pipe(fds)) {
            XLOG(WOLFKM_LOG_ERROR, "Error making notify pipe %s\n", strerror(errno));
            return WOLFKM_BAD_FILE;
        }

        svc->threads[i].notifyRecv = fds[0];
        svc->threads[i].notifySend = fds[1];
        SetupThread(svc, &svc->threads[i]);
    }

    /* start threads */
    for (i = 0; i < numThreads; i++) {
        MakeWorker(WorkerEvent, &svc->threads[i]); /* event monitor */
    }

    /* wait until each is ready */
    pthread_mutex_lock(&svc->initLock);
    while (svc->initCount < numThreads) {
        pthread_cond_wait(&svc->initCond, &svc->initLock);
    }
    pthread_mutex_unlock(&svc->initLock);

    /* setup ssl ctx */
    ret = InitServerTLS(svc);

    return ret;
}

void wolfKeyMgr_ServiceCleanup(SvcInfo* svc)
{
    int i, ret;

    if (svc == NULL)
        return;

    /* cancel each thread */
    XLOG(WOLFKM_LOG_INFO, "Sending cancel to threads\n");
    for (i = 0; i < (int)svc->threadPoolSize; i++) {
        if (write(svc->threads[i].notifySend, &kCancel,
                sizeof(kCancel)) != sizeof(kCancel)) {
            XLOG(WOLFKM_LOG_ERROR, "Write to cancel thread notify failed\n");
            return;
        }
    }

    /* join each thread */
    XLOG(WOLFKM_LOG_INFO, "Joining threads\n");
    for (i = 0; i < (int)svc->threadPoolSize; i++) {
        ret = pthread_join(svc->threads[i].tid, NULL);

        XLOG(WOLFKM_LOG_DEBUG, "Join ret = %d\n", ret);
    }

    /* free custom resources */
    wolfSSL_CTX_free(svc->sslCtx);
    svc->sslCtx = NULL;
}

/* return sent bytes or < 0 on error */
int wolfKeyMgr_DoSend(SvcConn* conn, byte* resp, int respSz)
{
    int ret = -1;

    if (conn->ssl == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "DoSend() usingTLS but no SSL object\n");
        return -1;
    }

    ret = wolfSSL_write(conn->ssl, resp, respSz);
    if (ret < 0) {
        int err = wolfSSL_get_error(conn->ssl, 0);
        if (err == WOLFSSL_ERROR_WANT_WRITE) {
            ret = 0; /* translate to 0 wouldblock */
        }
        else {
            XLOG(WOLFKM_LOG_ERROR, "wolfSSL_write error %d: %s\n",
                                    err, wolfSSL_ERR_reason_error_string(err));
        }
    }
    return ret;
}

int wolfKeyMgr_NotifyAllClients(SvcInfo* svc)
{
    int i;
    /* loop through each worker thread and notify */
    for (i = 0; i < (int)svc->threadPoolSize; i++) {
        EventThread* me = (EventThread*)&svc->threads[i];
        if (me->svc == svc) {
            if (write(me->notifySend, &kNotify, sizeof(kNotify)) !=
                    sizeof(kNotify)) {
                XLOG(WOLFKM_LOG_ERROR, "Notify thread failed!\n");
            }
        }
    }
    return 0;
}

/* release listener resources */
void wolfKeyMgr_FreeListeners(void)
{
    while (listenerList) {
        listener* next = listenerList->next;

        evconnlistener_free(listenerList->ev_listen);
        free(listenerList);
        listenerList = next;
    }
}

/* load the key file name into our buffer  */
int wolfKeyMgr_LoadKeyFile(SvcInfo* svc, const char* fileName, int fileType,
    const char* password)
{
    int ret;

    ret = wolfLoadFileBuffer(fileName, &svc->keyBuffer, &svc->keyBufferSz);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_INFO, "error loading key file %s\n", fileName);
        return ret;
    }

    if (fileType == WOLFSSL_FILETYPE_PEM) {
        ret = wc_KeyPemToDer(
            svc->keyBuffer, svc->keyBufferSz,
            svc->keyBuffer, svc->keyBufferSz,
            password);
        if (ret <= 0) {
            XLOG(WOLFKM_LOG_ERROR, "Error converting Key file %s from PEM to DER: %d\n",
                fileName, ret);
            free(svc->keyBuffer); svc->keyBuffer = NULL;
            return WOLFKM_BAD_KEY;
        }
        svc->keyBufferSz = ret;
    }

    XLOG(WOLFKM_LOG_INFO, "loaded key file %s\n", fileName);
    return 0;
}

/* load the certificate file into our buffer */
int wolfKeyMgr_LoadCertFile(SvcInfo* svc, const char* fileName, int fileType)
{
    int ret;

    ret = wolfLoadFileBuffer(fileName, &svc->certBuffer, &svc->certBufferSz);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_INFO, "error loading certificate file %s\n", fileName);
        return ret;
    }

    if (fileType == WOLFSSL_FILETYPE_PEM) {
        /* convert to DER */
        ret = wc_CertPemToDer(
            svc->certBuffer, svc->certBufferSz,
            svc->certBuffer, svc->certBufferSz,
            CERT_TYPE);
        if (ret <= 0) {
            XLOG(WOLFKM_LOG_ERROR, "Error converting file %s from PEM to DER: %d\n",
                fileName, ret);
            free(svc->certBuffer); svc->certBuffer = NULL;
            return WOLFKM_BAD_CERT;
        }
        svc->certBufferSz = ret;
    }

    XLOG(WOLFKM_LOG_INFO, "loaded certificate file %s\n", fileName);
    return 0;
}

int wolfKeyMgr_LoadCAFile(SvcInfo* svc, const char* fileName, int fileType)
{
    int ret;

    ret = wolfLoadFileBuffer(fileName, &svc->caBuffer, &svc->caBufferSz);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_INFO, "error loading certificate file %s\n", fileName);
        return ret;
    }

    if (fileType == WOLFSSL_FILETYPE_PEM) {
        /* convert to DER */
        ret = wc_CertPemToDer(
            svc->caBuffer, svc->caBufferSz,
            svc->caBuffer, svc->caBufferSz,
            CERT_TYPE);
        if (ret <= 0) {
            XLOG(WOLFKM_LOG_ERROR, "Error converting file %s from PEM to DER: %d\n",
                fileName, ret);
            free(svc->caBuffer); svc->caBuffer = NULL;
            return WOLFKM_BAD_CERT;
        }
        svc->caBufferSz = ret;
    }

    XLOG(WOLFKM_LOG_INFO, "loaded CA certificate file %s\n", fileName);
    return 0;
}
