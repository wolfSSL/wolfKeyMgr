/* mod_vault.h
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

#ifndef WOLFKM_VAULT_H
#define WOLFKM_VAULT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "wolfkeymgr/wkm_types.h"
#include "wolfkeymgr/wkm_utils.h"

/* wolfssl headers */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#ifndef WOLFKM_VAULT_NAME_MAX_SZ
#define WOLFKM_VAULT_NAME_MAX_SZ 16
#endif
#ifndef WOLFKM_VAULT_ENC_KEYSZ
#define WOLFKM_VAULT_ENC_KEYSZ (2048/8)
#endif

/* build-time option to disable vault encryption */
#ifndef WOLFKM_NO_VAULT_ENC
#define WOLFKM_VAULT_ENC
#endif

/* opaque type for wolfVaultCtx (pointer reference only) */
typedef struct wolfVaultCtx wolfVaultCtx;

typedef struct wolfVaultItem {
    word32 type;
    word32 nameSz;
    word32 dataSz;
    time_t timestamp;
    byte*  data; /* always dynamic - free using wolfVaultFreeItem */
    byte   name[WOLFKM_VAULT_NAME_MAX_SZ]; /* name is hash of public key or leading bits from it */
} wolfVaultItem;

/* open vault file */
WOLFKM_API int wolfVaultOpen(wolfVaultCtx** ctx, const char* file);

/* key: the AES key to use for encryption/decryption, keyEnc: optional data to store in vault header */
typedef int (*VaultAuthCbFunc)(wolfVaultCtx* ctx, byte* key, word32 keySz, byte* keyEnc, word32 keyEncSz, void* cbCtx);
/* setup authentication callback to get encryption key */
WOLFKM_API int wolfVaultAuth(wolfVaultCtx* ctx, VaultAuthCbFunc cb, void* cbCtx);

/* add item to vault */
WOLFKM_API int wolfVaultAdd(wolfVaultCtx* ctx, word32 type, const byte* name, word32 nameSz, const byte* data, word32 dataSz);
/* get copy of item from vault */
WOLFKM_API int wolfVaultGet(wolfVaultCtx* ctx, wolfVaultItem* item, word32 type, const byte* name, word32 nameSz);
/* free a wolfVaultItem structure */
WOLFKM_API void wolfVaultFreeItem(wolfVaultItem* item);
/* delete a single item from the vault */
WOLFKM_API int wolfVaultDelete(wolfVaultCtx* ctx, word32 type, const byte* name, word32 nameSz);
/* archive items older than specified date from vault */
WOLFKM_API int wolfVaultArchive(wolfVaultCtx* ctx, word32 timestamp);
/* close vault file */
WOLFKM_API void wolfVaultClose(wolfVaultCtx* ctx);

WOLFKM_API void wolfVaultPrintInfo(wolfVaultCtx* ctx);

#ifdef __cplusplus
}
#endif

#endif /* WOLFKM_VAULT_H */
