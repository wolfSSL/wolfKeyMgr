/* unit_tests.c
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

#include "wolfkeymgr/mod_vault.h"
#include "wolfkeymgr/mod_http.h"
#include "wolfkeymgr/mod_socket.h"
#include "wolfkeymgr/mod_ets.h"
#include "wolfkeymgr/wkm_utils.h"
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include <string.h>
#include <stdio.h>
#ifndef USE_WINDOWS_API
#include <unistd.h>
#include <sys/socket.h>
#endif

#if defined(WOLFKM_VAULT) && defined(WOLFKM_VAULT_ENC)
/* key: returned AES key */
/* keyEnc: key information stored in vault header */
static int wolfEtsSvcVaultAuthCb(wolfVaultCtx* ctx, byte* key, word32 keySz,
    byte* keyEnc, word32 keyEncSz, void* cbCtx)
{
    int ret;

    /* For testing use fixed key */
    static byte k1[] = {
        0x1e, 0xa6, 0x61, 0xc5, 0x8d, 0x94, 0x3a, 0x0e,
        0x48, 0x01, 0xe4, 0x2f, 0x4b, 0x09, 0x47, 0x14,
        0x9e, 0x7f, 0x9f, 0x8e, 0x3e, 0x68, 0xd0, 0xc7,
        0x50, 0x52, 0x10, 0xbd, 0x31, 0x1a, 0x0e, 0x7c,
        0xd6, 0xe1, 0x3f, 0xfd, 0xf2, 0x41, 0x8d, 0x8d,
        0x19, 0x11, 0xc0, 0x04, 0xcd, 0xa5, 0x8d, 0xa3,
        0xd6, 0x19, 0xb7, 0xe2, 0xb9, 0x14, 0x1e, 0x58,
        0x31, 0x8e, 0xea, 0x39, 0x2c, 0xf4, 0x1b, 0x08
    };
    if (keySz > sizeof(k1))
        keySz = sizeof(k1);
    memcpy(key, k1, keySz);
    ret = 0;

    (void)ctx;
    (void)keyEnc;
    (void)keyEncSz;
    (void)cbCtx;

    return ret;
}
#endif

static int vault_test(void)
{
    int ret = 0;
#ifdef WOLFKM_VAULT
    int i;
    wolfVaultCtx* ctx = NULL;
    wolfVaultItem item;
    const char* testFile = "vault.bin";
    struct vaultTestItems {
        word32 type;
        const char* name;
        const char* data;
    } testItems[] = {
        {1, "testname1", "testdata1"},
        {2, "testname2", "testdata2"}
    };

    ret = wolfVaultOpen(&ctx, testFile);
    if (ret == 0) {
        wolfVaultPrintInfo(ctx);

    #ifdef WOLFKM_VAULT_ENC
        /* setup security callback */
        ret = wolfVaultAuth(ctx, wolfEtsSvcVaultAuthCb, NULL);
    #endif

        /* add items */
        for (i=0; i<(int)(sizeof(testItems)/sizeof(struct vaultTestItems)); i++) {
            ret = wolfVaultAdd(ctx, testItems[i].type,
                (const byte*)testItems[i].name, strlen(testItems[i].name)+1,
                (const byte*)testItems[i].data, strlen(testItems[i].data)+1);
            if (ret != 0) {
                printf("Vault add failed: %d\n", ret);
                break;
            }
        }

        /* get items */
        for (i=0; i<(int)(sizeof(testItems)/sizeof(struct vaultTestItems)); i++) {
            ret = wolfVaultGet(ctx, &item, testItems[i].type,
                (const byte*)testItems[i].name, strlen(testItems[i].name)+1);
            if (ret != 0) {
                printf("Vault get failed: %d\n", ret);
                break;
            }

            if (item.dataSz != strlen(testItems[i].data)+1 ||
                memcmp(item.data,
                    testItems[i].data, strlen(testItems[i].data)+1) != 0)
            {
                printf("Vault item data test failed\n");
                ret = -1;
            }
            wolfVaultFreeItem(&item);
        }

        wolfVaultClose(ctx); /* ignore return code */
    }
#endif /* WOLFKM_VAULT */
    return ret;
}

static int http_test(void)
{
    int ret = 0;
    int rc;
    const char* m;
    word32 mlen;
    char enc[64];
    char dec[64];
    char tiny[4];
    HttpRsp rsp;
    HttpReq req;
    char goodRsp[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nDATA";
    char badRsp[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nDATA";
    char goodReq[] =
        "GET /path HTTP/1.1\r\nHost: x\r\nAccept: application/pkcs8\r\n\r\n";
    char noHdrReq[] = "GET / HTTP/1.1\r\n\r\n";
    HttpHeader hdrs[1];
    char small[8];
    word32 smallSz;

    /* TRACE must encode as "TRACE", not "DELETE" */
    m = wolfHttpGetMethodStr(HTTP_METHOD_TRACE, &mlen);
    if (m == NULL || strcmp(m, "TRACE") != 0) {
        printf("  method TRACE string wrong: %s\n", m ? m : "(null)");
        ret = -1;
    }

    /* lowercase percent-encoding must decode correctly */
    rc = wolfHttpUriDecode("%2a%5f", 6, dec, sizeof(dec));
    if (rc != 2 || (byte)dec[0] != '*' || (byte)dec[1] != '_') {
        printf("  lowercase hex decode failed rc=%d\n", rc);
        ret = -1;
    }

    /* reserved characters must percent-encode and round-trip */
    rc = wolfHttpUriEncode("a&b", 3, enc, sizeof(enc));
    if (rc < 0 || rc >= (int)sizeof(enc)) {
        printf("  uri encode failed rc=%d\n", rc);
        ret = -1;
    }
    else {
        enc[rc] = '\0';
        if (strcmp(enc, "a%26b") != 0) {
            printf("  uri encode wrong output: %s\n", enc);
            ret = -1;
        }
        rc = wolfHttpUriDecode(enc, strlen(enc), dec, sizeof(dec));
        if (rc != 3 || strcmp(dec, "a&b") != 0) {
            printf("  uri encode/decode round-trip failed: %s\n", dec);
            ret = -1;
        }
    }

    /* decode must always null terminate, even when the output is full */
    rc = wolfHttpUriDecode("AAAAAAAA", 8, tiny, sizeof(tiny));
    if (rc != -1 || tiny[sizeof(tiny)-1] != '\0' || strlen(tiny) != 3) {
        printf("  uri decode did not null terminate on overflow rc=%d\n", rc);
        ret = -1;
    }

    /* a response missing the blank-line terminator must be rejected */
    rc = wolfHttpClient_ParseResponse(&rsp, badRsp, (word32)strlen(badRsp));
    if (rc != HTTP_ERROR_EXPECTED_CRLF) {
        printf("  truncated response not rejected rc=%d\n", rc);
        ret = -1;
    }

    /* a well-formed response must still parse with the correct body */
    rc = wolfHttpClient_ParseResponse(&rsp, goodRsp, (word32)strlen(goodRsp));
    if (rc != 0 || rsp.code != 200 || rsp.bodySz != 4 ||
            memcmp(rsp.body, "DATA", 4) != 0) {
        printf("  valid response parse failed rc=%d code=%d bodySz=%d\n",
            rc, rsp.code, rsp.bodySz);
        ret = -1;
    }

    /* header count must be exact; the blank-line terminator is not a header */
    rc = wolfHttpServer_ParseRequest(&req, (byte*)goodReq,
        (word32)strlen(goodReq));
    if (rc != 0 || req.type != HTTP_METHOD_GET || req.headerCount != 2) {
        printf("  request parse wrong rc=%d type=%d headers=%d\n",
            rc, req.type, req.headerCount);
        ret = -1;
    }

    /* a request with no headers must report zero headers */
    rc = wolfHttpServer_ParseRequest(&req, (byte*)noHdrReq,
        (word32)strlen(noHdrReq));
    if (rc != 0 || req.headerCount != 0) {
        printf("  no-header request parse wrong rc=%d headers=%d\n",
            rc, req.headerCount);
        ret = -1;
    }

    /* encoding into an undersized buffer must error, not overflow */
    hdrs[0].type = HTTP_HDR_CONTENT_TYPE;
    hdrs[0].string = "application/pkcs8";
    smallSz = sizeof(small);
    rc = wolfHttpServer_EncodeResponse(200, "OK", (byte*)small, &smallSz,
        hdrs, 1, NULL, 0);
    if (rc != WOLFKM_BAD_ARGS) {
        printf("  encode into small buffer did not error rc=%d\n", rc);
        ret = -1;
    }

    return ret;
}

static int utils_test(void)
{
    int ret = 0;
    int rc;
    byte hexout[8];

    /* odd-length hex input must not read past the buffer */
    memset(hexout, 0, sizeof(hexout));
    rc = wolfHexStringToByte("abc", 3, hexout, sizeof(hexout));
    if (rc != 1 || hexout[0] != 0xab) {
        printf("  odd-length hex decode failed rc=%d byte=%02x\n",
            rc, hexout[0]);
        ret = -1;
    }

    return ret;
}

static int socket_test(void)
{
    int ret = 0;
#ifndef USE_WINDOWS_API
    WKM_SOCKET_T fd;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (WKM_SOCKET_IS_INVALID(fd)) {
        printf("  socket() failed, skipping\n");
        return 0;
    }

    wolfSocketClose(fd);

    /* a valid socket must actually be closed; a second close should fail */
    if (close(fd) == 0) {
        printf("  wolfSocketClose did not close a valid socket\n");
        ret = -1;
    }
#endif
    return ret;
}

static int vault_reopen_test(void)
{
    int ret = 0;
#ifdef WOLFKM_VAULT
    wolfVaultCtx* ctx = NULL;
    wolfVaultItem item;
    const char* testFile = "vault_reopen.bin";
    const byte name[] = "reopenName";
    const byte data[] = "reopenData";

    unlink(testFile);

    ret = wolfVaultOpen(&ctx, testFile);
#ifdef WOLFKM_VAULT_ENC
    if (ret == 0)
        ret = wolfVaultAuth(ctx, wolfEtsSvcVaultAuthCb, NULL);
#endif
    if (ret == 0)
        ret = wolfVaultAdd(ctx, 7, name, sizeof(name), data, sizeof(data));
    if (ctx != NULL)
        wolfVaultClose(ctx);

    /* reopen and get the item without adding first */
    ctx = NULL;
    if (ret == 0)
        ret = wolfVaultOpen(&ctx, testFile);
#ifdef WOLFKM_VAULT_ENC
    if (ret == 0)
        ret = wolfVaultAuth(ctx, wolfEtsSvcVaultAuthCb, NULL);
#endif
    if (ret == 0) {
        memset(&item, 0, sizeof(item));
        ret = wolfVaultGet(ctx, &item, 7, name, sizeof(name));
        if (ret == 0) {
            if (item.dataSz != sizeof(data) ||
                    memcmp(item.data, data, sizeof(data)) != 0) {
                printf("  reopened vault item mismatch\n");
                ret = -1;
            }
            wolfVaultFreeItem(&item);
        }
        else {
            printf("  vault get after reopen failed: %d\n", ret);
        }
    }
    if (ctx != NULL)
        wolfVaultClose(ctx);
    unlink(testFile);
#endif
    return ret;
}

static int vault_corrupt_test(void)
{
    int ret = 0;
#ifdef WOLFKM_VAULT
    /* on-disk vault format constants (must match mod_vault.c) */
    const uint32_t headerId = 0x666C6F57U;
    const uint32_t headerVer = 1;
    const uint32_t badHeaderSz = 0; /* too small: would underflow the read */
    const char* testFile = "vault_corrupt.bin";
    wolfVaultCtx* ctx = NULL;
    byte payload[64];
    FILE* f;

    unlink(testFile);

    f = fopen(testFile, "wb");
    if (f == NULL)
        return -1;
    fwrite(&headerId, 1, sizeof(headerId), f);
    fwrite(&headerVer, 1, sizeof(headerVer), f);
    fwrite(&badHeaderSz, 1, sizeof(badHeaderSz), f);
    memset(payload, 0xAA, sizeof(payload));
    fwrite(payload, 1, sizeof(payload), f);
    fclose(f);

    /* an undersized header must recreate cleanly, not overflow the buffer */
    ret = wolfVaultOpen(&ctx, testFile);
    if (ret == 0 && ctx != NULL)
        wolfVaultClose(ctx);
    unlink(testFile);
#endif
    return ret;
}

static int fingerprint_test(void)
{
    int ret = 0;
#if defined(HAVE_ECC) && !defined(NO_SHA256)
    WC_RNG rng;
    EtsKey key;
    ecc_key ecKey;
    word32 idx = 0;
    byte pub[MAX_ECC_BYTES * 2];
    word32 pubXLen = (word32)sizeof(pub) / 2;
    word32 pubYLen = (word32)sizeof(pub) / 2;
    word32 keySize = 0;
    byte digest[WC_SHA256_DIGEST_SIZE];
    int rngInit = 0, eccInit = 0;

    memset(&key, 0, sizeof(key));
    ret = wc_InitRng(&rng);
    if (ret == 0) {
        rngInit = 1;
        ret = wolfEtsKeyGen(&key, ETS_KEY_TYPE_SECP256R1, &rng);
    }
    if (ret == 0) {
        ret = wc_ecc_init(&ecKey);
    }
    if (ret == 0) {
        eccInit = 1;
        ret = wc_EccPrivateKeyDecode((byte*)key.response, &idx, &ecKey,
            key.responseSz);
    }
    if (ret == 0) {
        keySize = (word32)wc_ecc_size(&ecKey);
        ret = wc_ecc_export_ex(&ecKey, pub, &pubXLen, pub + keySize, &pubYLen,
            NULL, NULL, WC_TYPE_UNSIGNED_BIN);
    }
    if (ret == 0) {
        ret = wc_Sha256Hash(pub, keySize * 2, digest);
    }
    if (ret == 0) {
        /* fingerprint is the truncated SHA-256 of the public key */
        if (memcmp(key.fingerprint, digest, sizeof(key.fingerprint)) != 0) {
            printf("  fingerprint is not the SHA-256 of the public key\n");
            ret = -1;
        }
        /* and must not be the raw public key bytes (the original bug) */
        if (ret == 0 &&
                memcmp(key.fingerprint, pub, sizeof(key.fingerprint)) == 0) {
            printf("  fingerprint matches raw public key (regression)\n");
            ret = -1;
        }
    }

    if (eccInit)
        wc_ecc_free(&ecKey);
    if (rngInit)
        wc_FreeRng(&rng);
#endif
    return ret;
}

int main(int argc, char** argv)
{
    int ret = 0;
    int rc;
    enum log_level_t logLevel = WOLFKM_DEFAULT_LOG_LEVEL;

    (void)argc;
    (void)argv;

    /* log setup */
    wolfKeyMgr_SetLogFile(NULL, 0, logLevel);
    printf("Key Manager Unit Test\n");

    rc = vault_test();
    printf("Vault Open Test: %s\n", rc == 0 ? "pass" : "fail");
    if (rc != 0) ret = rc;

    rc = http_test();
    printf("HTTP Test: %s\n", rc == 0 ? "pass" : "fail");
    if (rc != 0) ret = rc;

    rc = utils_test();
    printf("Utils Test: %s\n", rc == 0 ? "pass" : "fail");
    if (rc != 0) ret = rc;

    rc = socket_test();
    printf("Socket Test: %s\n", rc == 0 ? "pass" : "fail");
    if (rc != 0) ret = rc;

    rc = vault_reopen_test();
    printf("Vault Reopen Test: %s\n", rc == 0 ? "pass" : "fail");
    if (rc != 0) ret = rc;

    rc = vault_corrupt_test();
    printf("Vault Corrupt Header Test: %s\n", rc == 0 ? "pass" : "fail");
    if (rc != 0) ret = rc;

    rc = fingerprint_test();
    printf("Fingerprint Test: %s\n", rc == 0 ? "pass" : "fail");
    if (rc != 0) ret = rc;

    return ret;
}
