/* svc_cert.c
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

#include "keymanager.h"

#ifdef WOLFKM_CERT_SERVICE

/* default max signs before re-init */
/* 1,600,000 max / 32 (seed) / 10 (our safety) */
#define CERTSVC_MAX_SIGNS 5000 

typedef struct certSvcInfo {
    int     maxSigns;  /* max b4 re-init */
    int     signCount; /* per thread signing count */
    WC_RNG  rng;       /* per thread rng */
    ecc_key eccKey;    /* per thread ecc key */

    /* Subject for certs */
    char subjectStr[ASN_NAME_MAX*2]; /* from file, for matching request */
    int  subjectStrLen;              /* length of above str for matching */
} certSvcInfo;

/* verify request message */
typedef struct verifyReq {
    byte*  key;       /* key        pointer into request  */
    byte*  msg;       /* message    pointer into request */
    byte*  sig;       /* signature pointer into request */
    word16 keyLen;    /* length of key       in bytes */
    word16 msgLen;    /* length of message   in bytes */
    word16 sigLen;    /* length of signature in bytes */
} verifyReq;


static svcInfo certService = {
    .desc = "Certificate",

    /* Callbacks */
    .requestCb = wolfCertSvc_DoRequest,
    .initThreadCb = wolfCertSvc_WorkerInit,
    .freeThreadCb = wolfCertSvc_WorkerFree,

    /* TLS Certificate and Buffer */
    .certBuffer = NULL,
    .certBufferSz = 0,
    .keyBuffer = NULL,
    .keyBufferSz = 0,
};


/* load our cert file subject (that's always us) into our buffer */
static int SetCertSubject(svcInfo* svc, certSvcInfo* certSvc)
{
    WOLFSSL_X509_NAME* subject = NULL;
    WOLFSSL_X509* x509 = wolfSSL_X509_load_certificate_buffer(svc->certBuffer,
        svc->certBufferSz, WOLFSSL_FILETYPE_ASN1);
    if (x509 == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "load X509 cert buffer failed\n");
        return WOLFKM_BAD_MEMORY;
    }
    XLOG(WOLFKM_LOG_INFO, "loaded X509 cert buffer\n");

    subject = wolfSSL_X509_get_subject_name(x509);
    if (subject == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "get subject name failed\n");
        wolfSSL_X509_free(x509);
        return WOLFKM_BAD_MEMORY;
    }

    certSvc->subjectStr[0] = '\0';
    certSvc->subjectStr[sizeof(certSvc->subjectStr)-1] = '\0';
    if (wolfSSL_X509_NAME_oneline(subject, certSvc->subjectStr, 
            sizeof(certSvc->subjectStr)-1) == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "get subject name oneline failed\n");
        wolfSSL_X509_free(x509);
        return WOLFKM_BAD_X509_GET_NAME;
    }
    certSvc->subjectStrLen = strlen(certSvc->subjectStr);
    XLOG(WOLFKM_LOG_INFO, "X509 subject %s\n", certSvc->subjectStr);

    wolfSSL_X509_free(x509);
    /* subject doesn't need to be freed, points into x509 */

    return 0;
}


/* parse in verify response, 0 on success */
static int ParseVerifyRequest(byte* request, int requestSz, verifyReq* vr)
{
    byte* requestMax = request + requestSz;

    /* make sure we can read in key legnth */
    if (request + WORD16_LEN > requestMax) {
        XLOG(WOLFKM_LOG_ERROR, "Bad VerifyRequest size for keyLen\n"); 
        return WOLFKM_BAD_VERIFY_SIZE;
    }
    ato16(request, &vr->keyLen);
    request += WORD16_LEN;

    /* make sure we can read in key */
    if (request + vr->keyLen > requestMax) {
        XLOG(WOLFKM_LOG_ERROR, "Bad VerifyRequest size for key\n"); 
        return WOLFKM_BAD_VERIFY_SIZE; 
    }
    vr->key  = request;
    request += vr->keyLen;

    /* make sure we can read in msg legnth */
    if (request + WORD16_LEN > requestMax) {
        XLOG(WOLFKM_LOG_ERROR, "Bad VerifyRequest size for msgLen\n"); 
        return WOLFKM_BAD_VERIFY_SIZE; 
    }
    ato16(request, &vr->msgLen);
    request += WORD16_LEN;

    /* make sure we can read in msg */
    if (request + vr->msgLen > requestMax) {
        XLOG(WOLFKM_LOG_ERROR, "Bad VerifyRequest size for msg\n"); 
        return WOLFKM_BAD_VERIFY_SIZE; 
    }
    vr->msg  = request;
    request += vr->msgLen;

    /* make sure we can read in sig legnth */
    if (request + WORD16_LEN > requestMax) {
        XLOG(WOLFKM_LOG_ERROR, "Bad VerifyRequest size for sigLen\n"); 
        return WOLFKM_BAD_VERIFY_SIZE;
    }
    ato16(request, &vr->sigLen);
    request += WORD16_LEN;

    /* make sure we can read in msg */
    if (request + vr->sigLen > requestMax) {
        XLOG(WOLFKM_LOG_ERROR, "Bad VerifyRequest size for sig\n"); 
        return WOLFKM_BAD_VERIFY_SIZE;
    }
    vr->sig  = request;
    request += vr->sigLen;

    (void)request;  /* silence scan-build, leave request += for changes */

    return 0;
}


/* create our verify response (place into request buffer), 0 on success */
static int GenerateVerify(svcConn* conn)
{
    int    ret;
    wc_Sha256 sha256;
    int    stat   = 0;
    word32 outlen = 1;
    byte   hash[WC_SHA256_DIGEST_SIZE];
    verifyReq vr;
    ecc_key verifyKey;

    /* we put response into request buffer since we already have it */
    byte* request   = conn->request;
    byte* hdrSz     = request + CERT_HEADER_SZ_OFFSET;
    int   requestSz = conn->requestSz - CERT_HEADER_SZ;

    /* make header */
    request[CERT_HEADER_VERSION_OFFSET] = CERT_VERSION;
    request[CERT_HEADER_TYPE_OFFSET]    = VERIFY_RESPONSE;
    request += CERT_HEADER_SZ;

    /* get input */
    ret = ParseVerifyRequest(request, requestSz, &vr);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ParseVerifyRequest: %d\n", ret); 
        return ret;
    }

    /* import key */
    wc_ecc_init(&verifyKey);
    ret = wc_ecc_import_x963(vr.key, vr.keyLen, &verifyKey);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ParseVerifyRequest import key: %d\n", ret); 
        return ret;
    }

    /* make hash */
    wc_InitSha256(&sha256);
    wc_Sha256Update(&sha256, vr.msg, vr.msgLen);
    wc_Sha256Final(&sha256, hash);

    /* do verify */
    ret = wc_ecc_verify_hash(vr.sig, vr.sigLen, hash, sizeof(hash), &stat,
                             &verifyKey);
    wc_ecc_free(&verifyKey);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "Bad ParseVerifyRequest verify hash: %d\n", ret); 
        return ret;
    }

    /* store answer */
    *request = stat ? 0x1 : 0x0;

    /* out size */
    c16toa((unsigned short)outlen, hdrSz);  /* size in header */
    conn->requestSz = outlen + CERT_HEADER_SZ;

    return 0;
}


/* increment signing counter, re-init rng if over max signs, 0 on success */
static int IncrementSignCounter(svcConn* conn)
{
    int ret = 0;
    certSvcInfo* certSvc = (certSvcInfo*)conn->svcThreadCtx;

    certSvc->signCount++;
    if (certSvc->signCount > certSvc->maxSigns) {
        XLOG(WOLFKM_LOG_INFO, "Sign cout over threshold, rng re-init: %d\n",
                                                            certSvc->signCount);
        wc_FreeRng(&certSvc->rng);
        ret = wc_InitRng(&certSvc->rng);
        if (ret < 0) {
            XLOG(WOLFKM_LOG_ERROR, "RNG re-init failed: %d\n", ret);
            return ret;
        }
        certSvc->signCount = 0;  /* re-init success, counter back to zero */
    }

    return ret;
}


/* create our signing response (place into request buffer), 0 on success */
static int GenerateSign(svcConn* conn)
{
    int    ret;
    word32 outlen = sizeof(conn->request);
    wc_Sha256 sha256;
    byte   hash[WC_SHA256_DIGEST_SIZE];

    /* we put response into request buffer since we already have it */
    byte* request   = conn->request;
    byte* hdrSz     = request + CERT_HEADER_SZ_OFFSET;
    int   requestSz = conn->requestSz - CERT_HEADER_SZ;

    certSvcInfo* certSvc = (certSvcInfo*)conn->svcThreadCtx;

    /* make header */
    request[CERT_HEADER_VERSION_OFFSET] = CERT_VERSION;
    request[CERT_HEADER_TYPE_OFFSET]    = SIGN_RESPONSE;
    request += CERT_HEADER_SZ;

    /* make hash */
    wc_InitSha256(&sha256);
    wc_Sha256Update(&sha256, request, requestSz);
    wc_Sha256Final(&sha256, hash);

    /* actual sign */
    ret = IncrementSignCounter(conn);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "Increment Sign Counter failed: %d\n", ret);
        return ret;
    }
    ret = wc_ecc_sign_hash(hash, sizeof(hash), request, &outlen, &certSvc->rng, &certSvc->eccKey);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "Sign failed: %d\n", ret);
        return ret;
    }
    c16toa((unsigned short)outlen, hdrSz); /* size in header */
    conn->requestSz = outlen + CERT_HEADER_SZ;

    return 0;
}


/* create our cert response (place into request buffer), 0 on success */
static int GenerateCert(svcConn* conn)
{
    int ret;

    /* we put response into request buffer since we already have it */
    byte* request   = conn->request;
    byte* hdrSz     = request + CERT_HEADER_SZ_OFFSET;
    int   requestSz = conn->requestSz - CERT_HEADER_SZ;

    certSvcInfo* certSvc = (certSvcInfo*)conn->svcThreadCtx;

    /* make header */
    request[CERT_HEADER_VERSION_OFFSET] = CERT_VERSION;
    request[CERT_HEADER_TYPE_OFFSET]    = CERT_RESPONSE;
    request += CERT_HEADER_SZ;

    /* actual sign */
    ret = IncrementSignCounter(conn);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "Increment Sign Counter failed: %d\n", ret);
        return ret;
    }
    ret = wc_SignCert(requestSz, CTC_SHA256wECDSA, request,
                sizeof(conn->request), NULL, &certSvc->eccKey, &certSvc->rng);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "SignCert failed: %d\n", ret);
        return ret;
    }
    else {
        /* let's do sanity check on request issuer vs our subject */
        int  issuerStrLen;
        char issuerStr[sizeof(certSvc->subjectStr)];
        WOLFSSL_X509_NAME* issuer;
        WOLFSSL_X509* x509 = wolfSSL_X509_d2i(NULL, request, ret);
        if (x509 == NULL) {
            XLOG(WOLFKM_LOG_ERROR, "X509 d2i failed\n");
            return WOLFKM_BAD_X509_D2I;
        }

        issuer = wolfSSL_X509_get_issuer_name(x509);
        if (issuer == NULL) {
            XLOG(WOLFKM_LOG_ERROR, "X509 get issuer failed\n");
            wolfSSL_X509_free(x509);
            return WOLFKM_BAD_X509_GET_NAME;
        }

        issuerStr[0] = '\0';
        issuerStr[sizeof(issuerStr)-1] = '\0';
        if (wolfSSL_X509_NAME_oneline(issuer, issuerStr, sizeof(issuerStr)-1) ==
                                                                  NULL) {
            XLOG(WOLFKM_LOG_ERROR, "X509 get name oneline failed\n");
            wolfSSL_X509_free(x509);
            return WOLFKM_BAD_X509_ONELINE;
        }

        issuerStrLen = strlen(issuerStr);
        if (issuerStrLen <= 0 || certSvc->subjectStrLen <= 0) {
            XLOG(WOLFKM_LOG_ERROR, "X509 str lens bad\n");
            wolfSSL_X509_free(x509);
            return WOLFKM_BAD_X509_MATCH;
        }
        if (memcmp(issuerStr, certSvc->subjectStr, min(issuerStrLen, 
                certSvc->subjectStrLen)) != 0) {
            XLOG(WOLFKM_LOG_ERROR, "X509 memcmp match failed on request\n");
            wolfSSL_X509_free(x509);
            return WOLFKM_BAD_X509_MATCH;
        }

        XLOG(WOLFKM_LOG_INFO, "X509 issuer subject match\n");
        wolfSSL_X509_free(x509);
        /* issuer doesn't need to be freed, points into x509 */
    }


    c16toa((unsigned short)ret, hdrSz);  /* size in header */
    conn->requestSz = ret + CERT_HEADER_SZ;

    return 0;
}


/* create our error response (place into request buffer), 0 on success */
static int GenerateError(svcConn* conn, int err)
{
    int   totalSz = WORD16_LEN * 2;  /* error code + string length */
    int   strLen;
    char  tmp[WOLFSSL_MAX_ERROR_SZ];
    char* errStr = tmp;
    short int serr = (short int)err;

    /* we put response into request buffer since we already have it */
    byte* request   = conn->request;
    byte* hdrSz     = request + CERT_HEADER_SZ_OFFSET;

    /* make header */
    request[CERT_HEADER_VERSION_OFFSET] = CERT_VERSION;
    request[CERT_HEADER_TYPE_OFFSET]    = ERROR_RESPONSE;
    request += CERT_HEADER_SZ;

    c16toa((unsigned short)serr, request);  /* error code */
    request += WORD16_LEN;

    tmp[0]                     = '\0';
    tmp[WOLFSSL_MAX_ERROR_SZ-1] = '\0';

    if (err < WOLFKM_ERROR_BEGIN) /* WOLFKM_ERROR uses lower errors than wolfSSL */
        errStr = (char*)wolfKeyMgr_GetError(err); 
    else
        wolfSSL_ERR_error_string(err, errStr);

    strLen = strlen(errStr);                    /* str length */
    c16toa((unsigned short)strLen, request); 
    request += WORD16_LEN;

    memcpy(request, errStr, strLen);            /* error string */
    totalSz += strLen;

    c16toa((unsigned short)totalSz, hdrSz);     /* size in header */
    conn->requestSz = totalSz + CERT_HEADER_SZ;

    return 0;
}


static const char* GetRequestStr(int type)
{
    switch (type) {
        case CERT_REQUEST:
            return "CERT Type";

        case SIGN_REQUEST:
            return "SIGN Type";

        case VERIFY_REQUEST:
            return "VERIFY Type";

        default:
            return "Unknown type";
    }
}


/* verify input request, 0 on success, 1 on need more input, <0 error */
static int VerifyHeader(svcConn* conn, int* type)
{
    unsigned short size = 0;

    if (conn == NULL || type == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Bad VerifyHeader pointers\n"); 
        return WOLFKM_BAD_ARGS;
    }

    /* need full header to verify, ok, just continue */
    if (conn->requestSz < CERT_HEADER_SZ) {
        XLOG(WOLFKM_LOG_INFO, "Not enough input to process request header\n"); 
        return 1;
    }

    /* version */
    if (conn->request[CERT_HEADER_VERSION_OFFSET] != CERT_VERSION) {
        XLOG(WOLFKM_LOG_ERROR, "Bad version on request header\n"); 
        return WOLFKM_BAD_VERSION;
    }

    /* type */
    *type = conn->request[CERT_HEADER_TYPE_OFFSET];
    XLOG(WOLFKM_LOG_INFO, "Request type = %s\n", GetRequestStr(*type));
    if (*type != CERT_REQUEST && *type != SIGN_REQUEST &&
                                 *type != VERIFY_REQUEST) {
        XLOG(WOLFKM_LOG_ERROR, "Not a valid REQUEST header\n"); 
        return WOLFKM_BAD_REQUEST_TYPE;
    }

    /* size */
    ato16(&conn->request[CERT_HEADER_SZ_OFFSET], &size);
    XLOG(WOLFKM_LOG_DEBUG, "Request header size = %d, read = %d\n", size,
                         conn->requestSz); 
    if (size > (conn->requestSz - CERT_HEADER_SZ)) {
        XLOG(WOLFKM_LOG_INFO, "Not enough input to process full request\n"); 
        return 1;
    } else if (size < (conn->requestSz - CERT_HEADER_SZ)) {
        XLOG(WOLFKM_LOG_ERROR, "Request data bigger than request header size\n");
        return WOLFKM_BAD_HEADER_SZ;
    }

    return 0;
}


/* Response message handler by type, 0 on success */
static int DoResponse(svcConn* conn, int type)
{
    conn->start = wolfKeyMgr_GetCurrentTime();  /* response start time */

    switch (type) {
        case CERT_REQUEST:
            return GenerateCert(conn);

        case SIGN_REQUEST:
            return GenerateSign(conn);

        case VERIFY_REQUEST:
            return GenerateVerify(conn);

        default:
            XLOG(WOLFKM_LOG_ERROR, "Bad DoResponse Type: %d\n", type);
            return WOLFKM_BAD_REQUEST_TYPE;
    }
}


/* the certificate service request handler */
int wolfCertSvc_DoRequest(svcConn* conn)
{
    int ret;
    int type = -1;

    if (conn == NULL || conn->stream == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Bad DoRequest pointers\n");
        return WOLFKM_BAD_ARGS;
    }

    XLOG(WOLFKM_LOG_INFO, "Got Cert Request\n");

    /* verify input, let error fall down to send error */
    ret = VerifyHeader(conn, &type);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "Verify request failed: %d\n", ret);
    }
    else if (ret == 1) {
        XLOG(WOLFKM_LOG_INFO, "Verify request needs more input\n");
        return WOLFKM_BAD_HEADER_SZ;
    }

    /* Make response, if ok */
    if (ret == 0) {
        ret = DoResponse(conn, type);
        if (ret < 0)
            XLOG(WOLFKM_LOG_ERROR, "DoResponse failed: %d\n", ret);
    }

    /* if not ok let's send error response */
    if (ret < 0) {
        ret = GenerateError(conn, ret);
        if (ret < 0) {
            XLOG(WOLFKM_LOG_ERROR, "GenerateError failed: %d, closing\n", ret);
            return WOLFKM_BAD_ARGS;
        }
        XLOG(WOLFKM_LOG_INFO, "Generated Error response: %d\n", ret);
    }
    else {
        /* success */
    }

    ret = wolfKeyMgr_DoSend(conn, conn->request, conn->requestSz);
    /* send it, response is now in request buffer */
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "Certificate DoSend failed: %d\n", ret);
        return WOLFKM_BAD_SEND;
    }
    XLOG(WOLFKM_LOG_INFO, "Sent Cert Response\n");
    return 0;
}

/* Called for startup of each worker thread */
int wolfCertSvc_WorkerInit(svcInfo* svc, void** threadCtx)
{
    int ret;
    word32 idx;
    certSvcInfo* certSvc;

    certSvc = malloc(sizeof(*certSvc));
    if (certSvc == NULL) {
        return WOLFKM_BAD_MEMORY;
    }
    memset(certSvc, 0, sizeof(*certSvc));
    certSvc->maxSigns = CERTSVC_MAX_SIGNS;

    *threadCtx = certSvc;

    /* do per thread rng, key init */
    ret = wc_InitRng(&certSvc->rng);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "RNG Init failed %d\n", ret);
        return ret;
    }

    wc_ecc_init(&certSvc->eccKey);
    idx = 0;
    ret = wc_EccPrivateKeyDecode(svc->keyBuffer, &idx, &certSvc->eccKey, 
        svc->keyBufferSz);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "EccPrivateKeyDecode failed %d\n", ret);
        wc_FreeRng(&certSvc->rng);
        return ret;
    }

    /* setup subject for certificate service */
    ret = SetCertSubject(svc, certSvc);

    return ret;
}

void wolfCertSvc_WorkerFree(svcInfo* svc, void* threadCtx)
{
    certSvcInfo* certSvc = (certSvcInfo*)threadCtx;

    if (svc == NULL || threadCtx == NULL)
        return;

    wc_FreeRng(&certSvc->rng);
    wc_ecc_free(&certSvc->eccKey);
    free(certSvc);
}

#endif /* WOLFKM_CERT_SERVICE */


svcInfo* wolfCertSvc_Init(struct event_base* mainBase, word32 timeoutSec)
{
#ifdef WOLFKM_CERT_SERVICE
    int ret;
    char* listenPort = WOLFKM_CERTSVC_PORT;

    ret = wolfKeyMgr_LoadKeyFile(&certService, WOLFKM_CERTSVC_KEY, 
        WOLFSSL_FILETYPE_PEM, WOLFKM_CERTSVC_KEY_PASSWORD);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Error loading TLS key\n");
        return NULL;
    }

    ret = wolfKeyMgr_LoadCertFile(&certService, WOLFKM_CERTSVC_CERT, 
        WOLFSSL_FILETYPE_PEM);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Error loading TLS certificate\n");
        return NULL;
    }

    /* setup listening events */
    ret = wolfKeyMgr_AddListeners(&certService, AF_INET6, listenPort, mainBase);  /* 6 may contain a 4 */
    if (ret < 0) {
        ret = wolfKeyMgr_AddListeners(&certService, AF_INET, listenPort, mainBase);
    }
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "Failed to bind at least one listener,"
                               "already running?\n");
        wolfCertSvc_Cleanup(&certService);
        return NULL;
    }

    wolfKeyMgr_SetTimeout(&certService, timeoutSec);

    return &certService;
#else
    return NULL;
#endif
}

void wolfCertSvc_Cleanup(svcInfo* svc)
{
    if (svc == NULL)
        return;
#ifdef WOLFKM_CERT_SERVICE
    if (certService.keyBuffer) {
        free(certService.keyBuffer);
        certService.keyBuffer = NULL;
    }
    if (certService.certBuffer) {
        free(certService.certBuffer);
        certService.certBuffer = NULL;
    }
#endif
}
