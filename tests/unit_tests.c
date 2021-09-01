/* api.c
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

#if defined(WOLFKM_VAULT) && defined(WOLFKM_VAULT_ENC)
/* key: returned AES key */
/* keyEnc: key information stored in vault header */
static int wolfEtsiSvcVaultAuthCb(wolfVaultCtx* ctx, byte* key, word32 keySz,
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
    //const char* testPass = "password";
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
        ret = wolfVaultAuth(ctx, wolfEtsiSvcVaultAuthCb, NULL);
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

int main(int argc, char** argv)
{
    int ret;
    enum log_level_t logLevel = WOLFKM_DEFAULT_LOG_LEVEL;

    (void)argc;
    (void)argv;

    /* log setup */
    wolfKeyMgr_SetLogFile(NULL, 0, logLevel);
    printf("Key Manager Unit Test\n");

    ret = vault_test();
    printf("Vault Open Test: %s\n", ret == 0 ? "pass" : "fail");

    return ret;
}
