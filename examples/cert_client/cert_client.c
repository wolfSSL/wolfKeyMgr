/* cert_client.c
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

#include "cert_client.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/ssl.h>
#include <wolfssl/test.h>

#include "src/keymanager.h"
#include "src/svc_cert.h"

static pthread_t*  tids;          /* our threads */
static int         poolSize = 0;  /* number of threads */
static word16      port;          /* peer port */
static const char* host =  WOLFKM_DEFAULT_HOST;  /* peer host */
static int         doCert   = 1;  /* cert request flag, on by default */
static int         doSign   = 0;  /* sign request flag */

static WOLFSSL_CTX* sslCtx;       /* ssl context factory */
static int usingTLS = 1;          /* ssl is on by default */


/* return sent bytes or < 0 on error */
static int DoClientSend(int sockfd, WOLFSSL* ssl, const byte* p, int len)
{
    int ret = -1;

    if (usingTLS == 0) {
        ret = send(sockfd, p, len, 0);
    } else {
        ret = wolfSSL_write(ssl, p, len);
        if (ret < 0) {
            int err = wolfSSL_get_error(ssl, 0);
            XLOG(WOLFKM_LOG_ERROR, "DoClientSend error %d: %s\n",
                                   err, wolfSSL_ERR_reason_error_string(err));
            if (err < 0) ret = err;
        }
    }

    return ret;
}


/* return bytes read or < 0 on error */
static int DoClientRead(int sockfd, WOLFSSL* ssl, byte* p, int len)
{
    int ret;

    if (usingTLS == 0) {
        ret = recv(sockfd, p, len, 0);
    } else {
        ret = wolfSSL_read(ssl, p, len);
        if (ret < 0) {
            int err = wolfSSL_get_error(ssl, 0);
            XLOG(WOLFKM_LOG_ERROR, "DoClientRead error %d: %s\n",
                                   err, wolfSSL_ERR_reason_error_string(err));
            if (err < 0) ret = err;
        }
    }

    return ret;
}


/* create new ssl object */
static WOLFSSL* NewSSL(int sockfd)
{
    WOLFSSL* ssl;

    if (usingTLS == 0) return NULL;

    ssl = wolfSSL_new(sslCtx);
    if (ssl == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "wolfSSL_new memory failure");
        exit(EXIT_FAILURE);
    }
    wolfSSL_set_fd(ssl, sockfd);

    return ssl;
}


/* verify signature against service with default cert key, 0 on success */
static int DoVerifyRequest(const void* msg, word32 msgSz, byte* signature,
                           word32 signSz, SOCKET_T sockfd, WOLFSSL* ssl)
{
    int     ret;
    int     requestSz = 0;
    byte    tmp[4096];
    byte*   request = tmp;  /* use to build header in front */
    int     sent = 0;
    word16   sSz    = 0;
    word32   outLen = 0;
    byte     answer = 0;

    WOLFSSL_EVP_PKEY* public = NULL;
    WOLFSSL_X509*    x509 = wolfSSL_X509_load_certificate_file(
            WOLFKM_CERTSVC_CERT, WOLFSSL_FILETYPE_PEM);
    /* write header */
    tmp[CERT_HEADER_VERSION_OFFSET] = CERT_VERSION;
    tmp[CERT_HEADER_TYPE_OFFSET]    = VERIFY_REQUEST;
    request += CERT_HEADER_SZ;


    if (x509 == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Unable to convert cert %s to x509\n",
                                                    WOLFKM_CERTSVC_CERT);
        return -1;
    }
    public = wolfSSL_X509_get_pubkey(x509);
    if (public == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Unable to get pub key from  %s\n",
                                                         WOLFKM_CERTSVC_CERT);
        return -1;
    }

    if (WORD16_LEN * 3 + msgSz + signSz + public->pkey_sz > sizeof(tmp)) {
        XLOG(WOLFKM_LOG_ERROR, "Verify request size too big\n");
        return -1;
    }
    /* key size */
    c16toa((word16)public->pkey_sz, request+outLen);
    outLen += WORD16_LEN;

    /* key */
    memcpy(request+outLen, public->pkey.ptr, public->pkey_sz);
    outLen += public->pkey_sz;

    /* msg size */
    c16toa((word16)msgSz, request+outLen);
    outLen += WORD16_LEN;

    /* msg */
    memcpy(request+outLen, msg, msgSz);
    outLen += msgSz;

    /* sig size */
    c16toa((word16)signSz, request+outLen);
    outLen += WORD16_LEN;

    /* signature */
    memcpy(request+outLen, signature, signSz);
    outLen += signSz;

    /* put size in header */
    c16toa((word16)outLen, tmp+CERT_HEADER_SZ_OFFSET);
    requestSz = outLen + CERT_HEADER_SZ;

    /* send it off */
    XLOG(WOLFKM_LOG_INFO, "Created verify request\n");

    while (sent < requestSz) {
        ret = DoClientSend(sockfd, ssl, tmp + sent, requestSz - sent);
        if (ret < 0) {
            XLOG(WOLFKM_LOG_INFO, "DoClientSend failed: %d\n", ret);
            exit(EXIT_FAILURE);
        }
        sent += ret;
        if (sent == requestSz)
            break;
    }
    XLOG(WOLFKM_LOG_INFO, "Sent request\n");

    ret = DoClientRead(sockfd, ssl, tmp, sizeof(tmp));
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "DoClientRead failed: %d\n", ret);
        exit(EXIT_FAILURE);
    }
    else if (ret == 0) {
        XLOG(WOLFKM_LOG_ERROR, "peer closed: %d\n", ret);
        exit(EXIT_FAILURE);
    }
    requestSz = ret - CERT_HEADER_SZ;
    XLOG(WOLFKM_LOG_INFO, "Got response sz = %d\n", requestSz);

    /* verify response header */
    if (tmp[CERT_HEADER_VERSION_OFFSET] != CERT_VERSION) {
        XLOG(WOLFKM_LOG_ERROR, "Bad response version\n");
        exit(EXIT_FAILURE);
    }

    if (tmp[CERT_HEADER_TYPE_OFFSET] != VERIFY_RESPONSE) {
        XLOG(WOLFKM_LOG_ERROR, "Bad response type\n");
        exit(EXIT_FAILURE);
    }

    ato16(tmp+CERT_HEADER_SZ_OFFSET, &sSz);  /* header size */
    if (sSz != requestSz || sSz != 1) {
        XLOG(WOLFKM_LOG_ERROR, "Bad response header size = %d\n", sSz);
        exit(EXIT_FAILURE);
    }

    /* store answer */
    answer = *request;
    if (answer != 0x1) {
        XLOG(WOLFKM_LOG_ERROR, "Bad verify answer = %02x\n", answer);
        exit(EXIT_FAILURE);
    }

    wolfSSL_X509_free(x509);
    wolfSSL_EVP_PKEY_free(public);

    return 0;
}


/* force bad version header, 0 on success */
static int DoBadVersion(void)
{
    int     ret;
    int     requestSz = 0;
    byte    tmp[4096];
    byte*   request = tmp;  /* use to build header in front */
    int     sent = 0;
    SOCKET_T sockfd;
    word16   eSz    = 0;
    short    error  = 0;
    WOLFSSL* ssl = NULL;

    memset(tmp, 0, sizeof(tmp));

    /* write header */
    tmp[CERT_HEADER_VERSION_OFFSET] = CERT_VERSION + 5;
    tmp[CERT_HEADER_TYPE_OFFSET]    = CERT_REQUEST;
    request += CERT_HEADER_SZ;

    /* put size in header */
    c16toa((word16)requestSz, tmp+CERT_HEADER_SZ_OFFSET);
    requestSz = requestSz + CERT_HEADER_SZ;

    /* send it off */
    XLOG(WOLFKM_LOG_INFO, "Sending Bad Version request\n");
    tcp_connect(&sockfd, host, port, 0, 0, NULL);
    ssl = NewSSL(sockfd);
    XLOG(WOLFKM_LOG_INFO, "Connected to cert service\n");

    while (sent < requestSz) {
        ret = DoClientSend(sockfd, ssl, tmp + sent, requestSz - sent);
        if (ret < 0) {
            XLOG(WOLFKM_LOG_INFO, "DoClientSend failed: %d\n", ret);
            exit(EXIT_FAILURE);
        }
        sent += ret;
        if (sent == requestSz)
            break;
    }
    XLOG(WOLFKM_LOG_INFO, "Sent request\n");

    ret = DoClientRead(sockfd, ssl, tmp, sizeof(tmp));
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "DoClientRead failed: %d\n", ret);
        exit(EXIT_FAILURE);
    }
    else if (ret == 0) {
        XLOG(WOLFKM_LOG_ERROR, "peer closed: %d\n", ret);
        exit(EXIT_FAILURE);
    }
    requestSz = ret - CERT_HEADER_SZ;
    XLOG(WOLFKM_LOG_INFO, "Got response sz = %d\n", requestSz);
    CloseSocket(sockfd);
    wolfSSL_free(ssl);

    /* verify response header */
    if (tmp[CERT_HEADER_VERSION_OFFSET] != CERT_VERSION) {
        XLOG(WOLFKM_LOG_ERROR, "Bad response version\n");
        exit(EXIT_FAILURE);
    }

    if (tmp[CERT_HEADER_TYPE_OFFSET] != ERROR_RESPONSE) {
        XLOG(WOLFKM_LOG_ERROR, "Bad response type\n");
        exit(EXIT_FAILURE);
    }

    ato16(tmp+CERT_HEADER_SZ_OFFSET, &eSz);  /* header size */
    if (eSz < WORD16_LEN * 2) {
        XLOG(WOLFKM_LOG_ERROR, "Bad response header size = %d\n", eSz);
        exit(EXIT_FAILURE);
    }

    ato16(request, &eSz);  /* error code */
    request += WORD16_LEN;
    error = eSz;
    XLOG(WOLFKM_LOG_INFO, "Error code = %d\n", error);

    ato16(request, &eSz);  /* error string size */
    request += WORD16_LEN;
    XLOG(WOLFKM_LOG_INFO, "Error string = %s, sz = %d\n", request, eSz);

    return 0;
}


/* for error response in errorMode, 0 on success */
static int DoErrorMode(void)
{
    int ret = DoBadVersion();
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "BadVersion request didn't fail\n");
        return -1;
    }


    return 0;
}


/* verify cert sign response against msg with default cert, 0 on success */
static int DoOurVerify(const void* msg, word32 msgSz, byte* signature,
                       word32 signSz)
{
    int              ret  = -1;
    int              stat = -1;
    wc_Sha256        sha256;
    byte             hash[WC_SHA256_DIGEST_SIZE];
    ecc_key          verifyKey;
    WOLFSSL_EVP_PKEY* public = NULL;
    WOLFSSL_X509*     x509 = wolfSSL_X509_load_certificate_file(WOLFKM_CERTSVC_CERT,
                                                              WOLFSSL_FILETYPE_PEM);
    if (x509 == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Unable to convert cert %s to x509\n",
                                                    WOLFKM_CERTSVC_CERT);
        return -1;
    }
    public = wolfSSL_X509_get_pubkey(x509);
    if (public == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Unable to get pub key from  %s\n",
                                                         WOLFKM_CERTSVC_CERT);
        return -1;
    }

    wc_ecc_init(&verifyKey);
    ret = wc_ecc_import_x963((byte*)public->pkey.ptr, public->pkey_sz,
                             &verifyKey);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "Unable to import ecc key from  %s\n",
                                                            WOLFKM_CERTSVC_CERT);
        return -1;
    }

    wc_InitSha256(&sha256);
    wc_Sha256Update(&sha256, msg, msgSz);
    wc_Sha256Final(&sha256, hash);

    ret = wc_ecc_verify_hash(signature, signSz, hash, sizeof(hash), &stat,
                             &verifyKey);
    if (ret < 0 || stat != 1) {
        XLOG(WOLFKM_LOG_ERROR, "Unable verify signature, ret = %d, stat = %d\n",
                                                        ret, stat);
        return -1;
    }

    wolfSSL_X509_free(x509);
    wolfSSL_EVP_PKEY_free(public);
    wc_ecc_free(&verifyKey);

    return 0;
}


/* one sign request
*/
static int DoSignRequest(SOCKET_T sockfd, WOLFSSL* ssl)
{
    int     ret;
    int     requestSz = 0;
    byte    tmp[4096];
    byte*   request = tmp;  /* use to build header in front */
    int     sent = 0;
    const char* msg = "Everybody gets Friday Off!";
    word32   msgSz = (word32)strlen(msg);
    word16   sSz = 0;

    /* write header */
    tmp[CERT_HEADER_VERSION_OFFSET] = CERT_VERSION;
    tmp[CERT_HEADER_TYPE_OFFSET]    = SIGN_REQUEST;
    request += CERT_HEADER_SZ;

    /* request message */
    memcpy(request, msg, msgSz);

    c16toa((word16)msgSz, tmp+CERT_HEADER_SZ_OFFSET); /* msg size */
    requestSz = msgSz + CERT_HEADER_SZ;               /* into header */

    XLOG(WOLFKM_LOG_INFO, "Created sign request\n");

    while (sent < requestSz) {
        ret = DoClientSend(sockfd, ssl, tmp + sent, requestSz - sent);
        if (ret < 0) {
            XLOG(WOLFKM_LOG_INFO, "DoClientSend failed: %d\n", ret);
            exit(EXIT_FAILURE);
        }
        sent += ret;
        if (sent == requestSz)
            break;
    }
    XLOG(WOLFKM_LOG_INFO, "Sent request\n");

    ret = DoClientRead(sockfd, ssl, tmp, sizeof(tmp));
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "DoClientRead failed: %d\n", ret);
        exit(EXIT_FAILURE);
    }
    else if (ret == 0) {
        XLOG(WOLFKM_LOG_ERROR, "peer closed: %d\n", ret);
        exit(EXIT_FAILURE);
    }
    requestSz = ret - CERT_HEADER_SZ;
    XLOG(WOLFKM_LOG_INFO, "Got response sz = %d\n", requestSz);

    /* verify response header */
    if (tmp[CERT_HEADER_VERSION_OFFSET] != CERT_VERSION) {
        XLOG(WOLFKM_LOG_ERROR, "Bad response version\n");
        exit(EXIT_FAILURE);
    }

    if (tmp[CERT_HEADER_TYPE_OFFSET] != SIGN_RESPONSE) {
        XLOG(WOLFKM_LOG_ERROR, "Bad response type\n");
        exit(EXIT_FAILURE);
    }

    ato16(tmp+CERT_HEADER_SZ_OFFSET, &sSz);  /* header size */
    if (sSz != requestSz) {
        XLOG(WOLFKM_LOG_ERROR, "Bad response header size = %d\n", sSz);
        exit(EXIT_FAILURE);
    }

    /* check signature ourselves */
    ret = DoOurVerify(msg, msgSz, request, requestSz);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Our signature verify failure  = %d\n", ret);
        exit(EXIT_FAILURE);
    }

    /* check verify with service */
    ret = DoVerifyRequest(msg, msgSz, request, requestSz, sockfd, ssl);
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Service signature verify failure  = %d\n", ret);
        exit(EXIT_FAILURE);
    }

    return 0;
}



/* one cert request, savePem specifies whether to save the pem to the filesystem
   can't reuse the save file in threaded mode so main thread does a save once
   then threaded testing doesn't save it
*/
static int DoCertRequest(char* savePem, char* dumpFile, SOCKET_T sockfd,
                         WOLFSSL* ssl)
{
    /* gen request */
    int     ret;
    int     pemSz;
    Cert    reqCert;
    WC_RNG  rng;
    ecc_key reqKey;
    byte    tmp[4096];
    byte*   request = tmp;  /* use to build header in front */
    byte    pem[4096];
    int     requestSz = 0;
    
    int     sent = 0;
    FILE*   pemFile = NULL;
    WOLFSSL_CERT_MANAGER* cm;
    word16  sSz = 0;

    /* write header */
    tmp[CERT_HEADER_VERSION_OFFSET] = CERT_VERSION;
    tmp[CERT_HEADER_TYPE_OFFSET]    = CERT_REQUEST;
    request += CERT_HEADER_SZ;

    ret = wc_InitRng(&rng);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_INFO, "ecc_make_key failed: %d\n", ret);
        return ret;
    }
    wc_ecc_init(&reqKey);
    wc_InitCert(&reqCert);
    reqCert.sigType = CTC_SHA256wECDSA;

    ret = wc_ecc_make_key(&rng, 32, &reqKey);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_INFO, "ecc_make_key failed: %d\n", ret);
        return ret;
    }

    strncpy(reqCert.subject.country, "US", CTC_NAME_SIZE);
    strncpy(reqCert.subject.state, "OR", CTC_NAME_SIZE);
    strncpy(reqCert.subject.locality, "Portland", CTC_NAME_SIZE);
    strncpy(reqCert.subject.org, "user", CTC_NAME_SIZE);
    strncpy(reqCert.subject.unit, "front", CTC_NAME_SIZE);
    strncpy(reqCert.subject.commonName, "todd user", CTC_NAME_SIZE);
    strncpy(reqCert.subject.email, "todd@user.com", CTC_NAME_SIZE);

    ret = wc_SetIssuer(&reqCert, WOLFKM_CERTSVC_CERT);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_INFO, "SetIssuer failed: %d\n", ret);
        wc_ecc_free(&reqKey);
        return ret;
    }

    ret = wc_MakeCert(&reqCert, request, sizeof(tmp), NULL, &reqKey, &rng);
    wc_ecc_free(&reqKey);
    if (ret < 0) {
        XLOG(WOLFKM_LOG_INFO, "MakeCert failed: %d\n", ret);
        return ret;
    }
    if (dumpFile) {
        FILE* raw = fopen(dumpFile, "wb");
        if (raw == NULL) {
            XLOG(WOLFKM_LOG_INFO, "Can't use dump file %s for writing\n",dumpFile);
            exit(EXIT_FAILURE);
        }
        if ((int)fwrite(request, ret, 1, raw) != 1) {
            XLOG(WOLFKM_LOG_ERROR, "fwrite failed\n");
            exit(EXIT_FAILURE);
        }
        fclose(raw);
    }
    c16toa((word16)ret, tmp+CERT_HEADER_SZ_OFFSET); /* der sz (ret) goes */
    requestSz = ret + CERT_HEADER_SZ;               /* into header */

    XLOG(WOLFKM_LOG_INFO, "Created cert request\n");

    while (sent < requestSz) {
        ret = DoClientSend(sockfd, ssl, tmp + sent, requestSz - sent);
        if (ret < 0) {
            XLOG(WOLFKM_LOG_INFO, "DoClientSend failed: %d\n", ret);
            exit(EXIT_FAILURE);
        }
        sent += ret;
        if (sent == requestSz)
            break;
    }
    XLOG(WOLFKM_LOG_INFO, "Sent request\n");

    ret = DoClientRead(sockfd, ssl, tmp, sizeof(tmp));
    if (ret < 0) {
        XLOG(WOLFKM_LOG_ERROR, "DoClientRead failed: %d\n", ret);
        exit(EXIT_FAILURE);
    }
    else if (ret == 0) {
        XLOG(WOLFKM_LOG_ERROR, "peer closed: %d\n", ret);
        exit(EXIT_FAILURE);
    }
    requestSz = ret - CERT_HEADER_SZ;
    XLOG(WOLFKM_LOG_INFO, "Got response\n");

    /* verify response header */
    if (tmp[CERT_HEADER_VERSION_OFFSET] != CERT_VERSION) {
        XLOG(WOLFKM_LOG_ERROR, "Bad response version\n");
        exit(EXIT_FAILURE);
    }

    if (tmp[CERT_HEADER_TYPE_OFFSET] != CERT_RESPONSE) {
        XLOG(WOLFKM_LOG_ERROR, "Bad response type\n");
        exit(EXIT_FAILURE);
    }

    ato16(tmp+CERT_HEADER_SZ_OFFSET, &sSz);  /* header size */
    if (sSz != requestSz) {
        XLOG(WOLFKM_LOG_ERROR, "Bad response header size = %d\n", sSz);
        exit(EXIT_FAILURE);
    }

    /* convert to pem */
    pemSz = wc_DerToPem(request, requestSz, pem, sizeof(pem), CERT_TYPE);
    if (pemSz < 0) {
        XLOG(WOLFKM_LOG_INFO, "wc_DerToPem failed: %d\n", pemSz);
        exit(EXIT_FAILURE);
    }

    if (savePem) {
        /* store it */
        pemFile = fopen(savePem, "wb");
        if (pemFile == NULL) {
            XLOG(WOLFKM_LOG_ERROR, "pemFile fopen failed %s\n", savePem);
            exit(EXIT_FAILURE);
        }
        ret = (int)fwrite(pem, pemSz, 1, pemFile);
        if (ret != 1) {
            XLOG(WOLFKM_LOG_ERROR, "fwrite failed\n");
            exit(EXIT_FAILURE);
        }
        fclose(pemFile);
    }

    /* do sanity verify */
    cm = wolfSSL_CertManagerNew();
    if (cm == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "wolfSSL_CertManagerNew failed\n");
        exit(EXIT_FAILURE);
    }
    ret = wolfSSL_CertManagerLoadCA(cm, WOLFKM_CERTSVC_CERT, NULL);
    if (ret != SSL_SUCCESS) {
        XLOG(WOLFKM_LOG_ERROR, "wolfSSL_CertManagerLoadCA failed: %d\n", ret);
        exit(EXIT_FAILURE);
    }
    ret = wolfSSL_CertManagerVerifyBuffer(cm, pem, pemSz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
        XLOG(WOLFKM_LOG_ERROR, "wolfSSL_CertManagerVerifyBuffer failed: %d\n",ret);
        exit(EXIT_FAILURE);
    }
    wolfSSL_CertManagerFree(cm);
    XLOG(WOLFKM_LOG_INFO, "Response verify OK\n");

#if defined(HAVE_HASHDRBG)
    wc_FreeRng(&rng);
#endif

    return 0;
}


/* cert requests per thread, persistent connection */
static void* DoRequests(void* arg)
{
    int i;
    int requests = *(int*)arg;
    WOLFSSL* ssl = NULL;

    SOCKET_T sockfd;
    tcp_connect(&sockfd, host, port, 0, 0, NULL);
    ssl = NewSSL(sockfd);

    for (i = 0; i < requests; i++) {
        int ret = -1;

        if (doCert)
            ret = DoCertRequest(NULL, NULL, sockfd, ssl);
        else if (doSign)
            ret = DoSignRequest(sockfd, ssl);
        if (ret != 0) {
            XLOG(WOLFKM_LOG_ERROR, "DoRequests failed: %d\n", ret);
            exit(EXIT_FAILURE);
        }
    }

    CloseSocket(sockfd);
    wolfSSL_free(ssl);

    return NULL;
}


/* setup SSL */
static int InitClientTLS(void)
{
    int ret;

#if 0
    wolfSSL_Debugging_ON();
#endif
    wolfSSL_Init();

    sslCtx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (sslCtx == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Can't alloc TLS 1.3 context");
        return WOLFKM_BAD_MEMORY;
    }

    ret = wolfSSL_CTX_load_verify_locations(sslCtx, WOLFKM_CERTSVC_CERT, NULL);
    if (ret != WOLFSSL_SUCCESS) {
        XLOG(WOLFKM_LOG_ERROR, "Can't load TLS CA cert into context. Error: %s (%d)\n", 
            wolfSSL_ERR_reason_error_string(ret), ret);
        wolfSSL_CTX_free(sslCtx); sslCtx = NULL;
        return ret;
    }
    return 0;
}


/* usage help */
static void Usage(void)
{
    printf("%s %s\n", "client", PACKAGE_VERSION);
    printf("-?          Help, print this usage\n");
    printf("-s          Do signature request instead of cert request\n");
    printf("-e          Error mode, force error response\n");
    printf("-h <str>    Host to connect to, default %s\n", WOLFKM_DEFAULT_HOST);
    printf("-p <num>    Port to connect to, default %s\n", WOLFKM_CERTSVC_PORT);
    printf("-t <num>    Thread pool size (stress test), default  %d\n", 0);
    printf("-l <num>    Log Level, default %d\n", WOLFKM_DEFAULT_LOG_LEVEL);
    printf("-r <num>    Requests per thread, default %d\n",
                                                          WOLFKM_DEFAULT_REQUESTS);
    printf("-d <file>   Dump raw binary cert request fo <file>\n");
    printf("-f <file>   <file> to store cert response in PEM\n");
}


int main(int argc, char** argv)
{
    int         ch;
    int         i;
    int         ret;
    char*       dumpFile = NULL;        /* dump raw request cert */
    char*       savePem  = NULL;        /* dump PEM response cert */
    int         requests = WOLFKM_DEFAULT_REQUESTS;
    int         errorMode = 0;
    SOCKET_T    sockfd;
    WOLFSSL*    ssl = NULL;
    enum log_level_t logLevel = WOLFKM_DEFAULT_LOG_LEVEL;

    port       = atoi(WOLFKM_CERTSVC_PORT);

#ifdef DISABLE_SSL
    usingTLS = 0;    /* can only disable at build time */
#endif

    /* argument processing */
    while ((ch = getopt(argc, argv, "?seh:p:t:l:r:d:f:")) != -1) {
        switch (ch) {
            case '?' :
                Usage();
                exit(EX_USAGE);
            case 'h' :
                host = optarg;
                break;
            case 'd' :
                dumpFile = optarg;
                break;
            case 'f' :
                savePem = optarg;
                break;
            case 'p' :
                port = atoi(optarg);
                break;
            case 't' :
                poolSize = atoi(optarg);
                break;
            case 'r' :
                requests = atoi(optarg);
                break;
            case 's' :
                doSign = 1;
                doCert = 0;
                break;
            case 'e' :
                errorMode = 1;
                break;
            case 'l' :
                logLevel = atoi(optarg);
                if (logLevel < WOLFKM_LOG_DEBUG || logLevel > WOLFKM_LOG_ERROR) {
                    perror("loglevel [1:4] only");
                    exit(EX_USAGE);
                }
                break;

            default:
                Usage();
                exit(EX_USAGE);
        }
    }

    /* log setup */
    wolfKeyMgr_SetLogFile(NULL, 0, logLevel);
    XLOG(WOLFKM_LOG_INFO, "Starting client\n");

    if (errorMode)
        return DoErrorMode();

    if (usingTLS) {
        ret = InitClientTLS();
        if (ret != 0) {
            exit(EXIT_FAILURE);
        }
    }

    tcp_connect(&sockfd, host, port, 0, 0, NULL);
    ssl = NewSSL(sockfd);
    XLOG(WOLFKM_LOG_INFO, "Connected to cert service\n");

    if (doCert) {
        /* Do a cert test and save the pem */
        ret = DoCertRequest(savePem, dumpFile, sockfd, ssl);
        if (ret != 0) {
            XLOG(WOLFKM_LOG_ERROR, "DoCertRequest savePem failed: %d\n", ret);
            exit(EXIT_FAILURE);
        }
        XLOG(WOLFKM_LOG_INFO, "First cert test worked!\n");
    }
    else if (doSign) {
        /* Do a sign test */
        ret = DoSignRequest(sockfd, ssl);
        if (ret != 0) {
            XLOG(WOLFKM_LOG_ERROR, "DoSignRequest failed: %d\n", ret);
            exit(EXIT_FAILURE);
        }
        XLOG(WOLFKM_LOG_INFO, "First sign test worked!\n");
    }

    CloseSocket(sockfd);
    wolfSSL_free(ssl);

    /* are we stress testing with a thread pool ? */
    if (poolSize) {
        /* thread id holder */
        tids = calloc(poolSize, sizeof(pthread_t));
        if (tids == NULL) {
            XLOG(WOLFKM_LOG_ERROR, "calloc tids failed");
            exit(EXIT_FAILURE);
        }

        /* create workers */
        for (i = 0; i < poolSize; i++) {
            if (pthread_create(&tids[i], NULL, DoRequests, &requests) != 0){
                XLOG(WOLFKM_LOG_ERROR, "pthread_create failed");
                exit(EXIT_FAILURE);
            }
        }

        /* wait until they're all done */
        for (i = 0; i < poolSize; i++) {
            ret = pthread_join(tids[i], NULL);
            XLOG(WOLFKM_LOG_INFO, "pthread_join ret = %d\n", ret);
        }

        free(tids);
    }

    wolfSSL_CTX_free(sslCtx);
    wolfSSL_Cleanup();

    return 0;
}
