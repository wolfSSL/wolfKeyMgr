/* mod_vault.c
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
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <stdio.h>

#ifdef WOLFKM_VAULT

#if defined(WOLFKM_VAULT_ENC) && !defined(HAVE_AESGCM)
    #error Vault encryption requires AES GCM
#endif

#define VAULT_HEADER_ID  0x666C6F57U /* Wolf - little endian */
#define VAULT_ITEM_ID    0x6B636150U /* Pack - little endian */
#define VAULT_HEADER_VER 1
#define VAULT_HASH_SZ    16 /* AES_BLOCK_SIZE and SHA256 Digest */

/* struct stored to file - header is not encrypted */
typedef struct VaultHeader {
    uint32_t id;           /* should be VAULT_HEADER_ID */
    uint32_t version;      /* should be VAULT_HEADER_VER */
    uint32_t headerSz;     /* size of header including id/version */

    uint32_t vaultCount;   /* number of items in vault */
    size_t   vaultSz;      /* size not including header */

    uint8_t  hash[VAULT_HASH_SZ]; /* integrity for vault file (TODO) */
#ifdef WOLFKM_VAULT_ENC
    uint8_t  keyEnc[WOLFKM_VAULT_ENC_KEYSZ];
#endif
} VaultHeader_t;

/* struct for item stored to file - item header not encrypted */
typedef struct VaultItem {
    uint32_t id;           /* should be VAULT_ITEM_ID */
    uint32_t type;
    uint32_t nameSz;
    uint32_t dataSz;
    time_t   timestamp;
    uint8_t  tag[VAULT_HASH_SZ]; /* integrity of encrypted data GCM auth tag */
    uint8_t  name[WOLFKM_VAULT_NAME_MAX_SZ]; /* actual size stored is nameSz */
    /* then data - only data is encrypted */
} VaultItem_t;

#define VAULT_ITEM_PRE_SZ()      (sizeof(VaultItem_t) -  WOLFKM_VAULT_NAME_MAX_SZ)
#define VAULT_ITEM_HEAD_SZ(item) (VAULT_ITEM_PRE_SZ() + (item)->nameSz)
#define VAULT_ITEM_SZ(item)      (VAULT_ITEM_HEAD_SZ(item) + (item)->dataSz)

struct wolfVaultCtx {
    FILE*           fd;
    wolfSSL_Mutex   lock;
    VaultHeader_t   header;
    VaultItem_t     item;    /* cached last item */
    size_t          itemPos; /* cached last item position in file */

    VaultAuthCbFunc authCb;
    void*           authCbCtx;

#if defined(WOLFKM_VAULT_ENC) && defined(HAVE_AESGCM)
    Aes  aes;
    byte aesInit:1; /* has AES been initialized (key set) */
#endif
};

static void wolfVaultPrintItem(enum log_level_t level, const char* desc,
    VaultItem_t* item);

static size_t wolfVaultGetSize(wolfVaultCtx* ctx)
{
    size_t sz = 0;
    if (ctx && fseek(ctx->fd, 0, SEEK_END) == 0) {
        sz = ftell(ctx->fd);
        rewind(ctx->fd);
    }
    return sz;
}

static int wolfVaultFlush(wolfVaultCtx* ctx)
{
    int ret;

    if (ctx == NULL)
        return WOLFKM_BAD_ARGS;

    ret = wc_LockMutex(&ctx->lock);
    if (ret == 0) {
        /* update vault header */
        fseek(ctx->fd, 0, SEEK_SET);
        ret = (int)fwrite(&ctx->header, 1, sizeof(ctx->header), ctx->fd);
        ret = (ret == sizeof(ctx->header)) ? 0 : WOLFKM_BAD_FILE;

        fflush(ctx->fd);

        wc_UnLockMutex(&ctx->lock);
    }
    return ret;
}

static int wolfVaultCreateNew(wolfVaultCtx* ctx, const char* file)
{
    int ret;

    /* create vault file */
    ctx->fd = fopen(file, "wb+");
    if (ctx->fd == NULL) {
        return WOLFKM_BAD_FILE;
    }

    /* write header */
    memset(&ctx->header, 0, sizeof(ctx->header));
    ctx->header.id = VAULT_HEADER_ID;
    ctx->header.version = VAULT_HEADER_VER;
    ctx->header.headerSz = sizeof(ctx->header);
    ret = (int)fwrite(&ctx->header, 1, sizeof(ctx->header), ctx->fd);
    ret = (ret == sizeof(ctx->header)) ? 0 : WOLFKM_BAD_FILE;

    return ret;
}

int wolfVaultOpen(wolfVaultCtx** ctx, const char* file)
{
    int ret = WOLFKM_BAD_FILE;
    wolfVaultCtx* ctx_new;
    size_t vaultSz = 0;

    if (ctx == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    ctx_new = (wolfVaultCtx*)malloc(sizeof(wolfVaultCtx));
    if (ctx_new == NULL) {
        return WOLFKM_BAD_MEMORY;
    }

    memset(ctx_new, 0, sizeof(*ctx_new));
    wc_InitMutex(&ctx_new->lock);

    /* try opening vault file */
    ctx_new->fd = fopen(file, "rb+");
    if (ctx_new->fd != NULL) {
        byte* headPtr = (byte*)&ctx_new->header;
        int headSz = (int)sizeof(uint32_t)*3;

        /* read header - front (id, version and size) */
        ret = fread(headPtr, 1, headSz, ctx_new->fd);
        ret = (ret == headSz) ? 0 : WOLFKM_BAD_FILE;
        headPtr += headSz;

        /* validate vault header */
        if (ret == 0 && ctx_new->header.id != VAULT_HEADER_ID) {
            XLOG(WOLFKM_LOG_ERROR, "Header ID mismatch %u != %u\n",
                VAULT_HEADER_ID, ctx_new->header.id);
            ret = WOLFKM_BAD_FILE;
        }
        if (ret == 0 && ctx_new->header.version != VAULT_HEADER_VER) {
            XLOG(WOLFKM_LOG_ERROR, "Header version mismatch %u != %u\n",
                VAULT_HEADER_VER, ctx_new->header.version);
            ret = WOLFKM_BAD_FILE;
        }

        if (ret == 0 && ctx_new->header.headerSz > sizeof(ctx_new->header)) {
            XLOG(WOLFKM_LOG_ERROR, "Header size invalid! %u != %u\n",
                (uint32_t)sizeof(ctx_new->header), ctx_new->header.headerSz);
            ret = WOLFKM_BAD_FILE;
        }

        /* read remainder */
        headSz = ctx_new->header.headerSz-headSz;
        ret = (int)fread(headPtr, 1, headSz, ctx_new->fd);
        ret = (ret == headSz) ? 0 : WOLFKM_BAD_FILE;

        vaultSz = wolfVaultGetSize(ctx_new);
        if (vaultSz > ctx_new->header.headerSz)
            vaultSz -= ctx_new->header.headerSz;
        if (ret == 0 && ctx_new->header.vaultSz != vaultSz) {
            XLOG(WOLFKM_LOG_ERROR, "Vault size does not match actual %lu != %lu\n",
                vaultSz, ctx_new->header.vaultSz);
            ret = WOLFKM_BAD_FILE;
        }
    }

    if (ret != 0) {
        /* resetting vault */
        XLOG(WOLFKM_LOG_ERROR, "Vault open failed, creating new\n");
        ret = wolfVaultCreateNew(ctx_new, file);
        vaultSz = 0;
    }
    if (ret == 0) {
        XLOG(WOLFKM_LOG_INFO, "Vault %s opened (%lu bytes)\n", file, vaultSz);
    }
    else {
        if (ctx_new->fd != NULL)
            fclose(ctx_new->fd);
        wc_FreeMutex(&ctx_new->lock);
        free(ctx_new);
        ctx_new = NULL;
    }

    *ctx = ctx_new;

    return ret;
}

#ifdef WOLFKM_VAULT_ENC

static int wolfVaultSetupKey(wolfVaultCtx* ctx)
{
    int ret;

#ifdef HAVE_AESGCM
    byte key[AES_256_KEY_SIZE];
    word32 keySz = (word32)sizeof(key);

    /* make sure key has been setup */
    if (ctx->aesInit) {
        return 0; /* already done */
    }

    /* get the key and init the structure */
    ret = 0;
    if (ctx->authCb == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Vault authentication callback not setup!\n");
        ret = WOLFKM_BAD_ARGS;
    }

    if (ret == 0) {
        memset(key, 0, sizeof(key));
        ret = ctx->authCb(ctx, key, keySz, ctx->header.keyEnc,
            (word32)sizeof(ctx->header.keyEnc), ctx->authCbCtx);
    }
    if (ret == 0) {
        ret = wc_AesGcmSetKey(&ctx->aes, key, keySz);
    }
    if (ret == 0) {
        ctx->aesInit = 1;
    }
    else {
        XLOG(WOLFKM_LOG_ERROR, "Error %d setting up AES key!\n", ret);
    }
#endif

    return ret;
}

/* Caller needs to handle ctx->lock */
static int wolfVaultDecrypt(wolfVaultCtx* ctx, byte* data, word32 dataSz,
    size_t sector, const byte* tag, word32 tagSz)
{
    int ret = WOLFKM_NOT_COMPILED_IN;

#ifdef HAVE_AESGCM
    byte iv[GCM_NONCE_MID_SZ];

    memset(iv, 0, sizeof(iv));
    memcpy(iv, &sector, sizeof(sector));

    ret = wc_AesGcmDecrypt(&ctx->aes, data, data, dataSz, iv, sizeof(iv),
        tag, tagSz, NULL, 0);
#endif
    return ret;
}

/* Caller needs to handle ctx->lock */
static int wolfVaultEncrypt(wolfVaultCtx* ctx, byte* data, word32 dataSz,
    size_t sector, byte* tag, word32 tagSz)
{
    int ret = WOLFKM_NOT_COMPILED_IN;

#ifdef HAVE_AESGCM
    byte iv[GCM_NONCE_MID_SZ];
    memset(iv, 0, sizeof(iv));
    memcpy(iv, &sector, sizeof(sector));

    ret = wc_AesGcmEncrypt(&ctx->aes, data, data, dataSz, iv, sizeof(iv),
        tag, tagSz, NULL, 0);
#endif
    return ret;
}
#endif /* WOLFKM_VAULT_ENC */

/* setup authentication callback to get encryption key */
int wolfVaultAuth(wolfVaultCtx* ctx, VaultAuthCbFunc cb, void* cbCtx)
{
    int ret;
    if (ctx == NULL)
        return WOLFKM_BAD_ARGS;

    ret = wc_LockMutex(&ctx->lock);
    if (ret != 0)
        return ret;

    ctx->authCb = cb;
    ctx->authCbCtx = cbCtx;

    wc_UnLockMutex(&ctx->lock);
    return ret;
}

/* add item to vault */
int wolfVaultAdd(wolfVaultCtx* ctx, word32 type, const byte* name, word32 nameSz,
    const byte* data, word32 dataSz)
{
    int ret;
    word32 headSz;
    byte* dataEnc = NULL;

    if (ctx == NULL)
        return WOLFKM_BAD_ARGS;

    ret = wc_LockMutex(&ctx->lock);
    if (ret != 0)
        return ret;

#ifdef WOLFKM_VAULT_ENC
    /* make sure key has been setup */
    ret = wolfVaultSetupKey(ctx);
    if (ret != 0) {
        wc_UnLockMutex(&ctx->lock);
        return ret;
    }
#endif

    /* build vault item internal version */
    memset(&ctx->item, 0, sizeof(ctx->item));
    ctx->item.id = VAULT_ITEM_ID;
    ctx->item.type = type;
    if (nameSz > WOLFKM_VAULT_NAME_MAX_SZ)
        nameSz = WOLFKM_VAULT_NAME_MAX_SZ;
    ctx->item.nameSz = nameSz;
    memcpy(ctx->item.name, name, nameSz);
    ctx->item.timestamp = wolfGetCurrentTimeT();
    ctx->item.dataSz = dataSz;
    headSz = (word32)VAULT_ITEM_HEAD_SZ(&ctx->item);

    /* add to end of file */
    ret = fseek(ctx->fd, 0, SEEK_END);
    if (ret == 0) {
        ctx->itemPos = ftell(ctx->fd);
    }

#ifdef WOLFKM_VAULT_ENC
    if (ret == 0) {
        dataEnc = malloc(dataSz);
        if (dataEnc == NULL)
            ret = WOLFKM_BAD_MEMORY;
    }
    if (ret == 0) {
        memcpy(dataEnc, data, dataSz);

        ret = wolfVaultEncrypt(ctx, dataEnc, dataSz, ctx->itemPos,
            ctx->item.tag, sizeof(ctx->item.tag));
    }
#else
    dataEnc = (byte*)data;
#endif

    wolfVaultPrintItem(WOLFKM_LOG_DEBUG, "Add", &ctx->item);

    /* write item header and data */
    if (ret == 0) {
        ret = (int)fwrite(&ctx->item, 1, headSz, ctx->fd);
        ret = (ret == (int)headSz) ? 0 : WOLFKM_BAD_FILE;
    }
    if (ret == 0) {
        ret = (int)fwrite(dataEnc, 1, dataSz, ctx->fd);
        ret = (ret == (int)dataSz) ? 0 : WOLFKM_BAD_FILE;
    }
    if (ret == 0) {
        ctx->header.vaultCount++;
        ctx->header.vaultSz += headSz + dataSz;
        /* TODO: Extend header hash? */
    }
#ifdef WOLFKM_VAULT_ENC
    if (dataEnc) {
        free(dataEnc);
    }
#endif
    wc_UnLockMutex(&ctx->lock);

    /* on success flush to disk */
    if (ret == 0) {
        ret = wolfVaultFlush(ctx);
    }

    return ret;
}

static int wolfVaultGetItemHeader(wolfVaultCtx* ctx, size_t itemPos)
{
    int ret;
    word32 headSz = VAULT_ITEM_PRE_SZ();

    ret = fseek(ctx->fd, itemPos, SEEK_SET);
    if (ret == 0) {
        /* read pre-header */
        ret = (int)fread(&ctx->item, 1, headSz, ctx->fd);
        ret = (ret == (int)headSz) ? 0 : WOLFKM_BAD_FILE;
    }
    if (ret == 0 && ctx->item.id != VAULT_ITEM_ID) {
        ret = WOLFKM_BAD_FILE;
    }
    if (ret == 0) {
        if (ctx->item.nameSz > WOLFKM_VAULT_NAME_MAX_SZ)
            ctx->item.nameSz = WOLFKM_VAULT_NAME_MAX_SZ;
        /* read name */
        ret = (int)fread(&ctx->item.name, 1, ctx->item.nameSz, ctx->fd);
        ret = (ret == (int)ctx->item.nameSz) ? 0 : WOLFKM_BAD_FILE;
    }
    if (ret == 0) {
        ctx->itemPos = itemPos; /* store last cached position */
    }
    return ret;
}

static int wolfVaultGetItemData(wolfVaultCtx* ctx, wolfVaultItem* item)
{
    int ret = 0;

#ifdef WOLFKM_VAULT_ENC
    /* make sure key has been setup */
    ret = wolfVaultSetupKey(ctx);
    if (ret != 0) {
        return ret;
    }
#endif

    /* populate header */
    memset(item, 0, sizeof(*item));
    item->type = ctx->item.type;
    item->nameSz = ctx->item.nameSz;
    if (item->nameSz > WOLFKM_VAULT_NAME_MAX_SZ)
        item->nameSz = WOLFKM_VAULT_NAME_MAX_SZ;
    memcpy(item->name, ctx->item.name, item->nameSz);
    item->timestamp = ctx->item.timestamp;
    item->dataSz = ctx->item.dataSz;
    item->data = malloc(item->dataSz);
    if (item->data == NULL)
        ret = WOLFKM_BAD_MEMORY;
    if (ret == 0) {
        ret = (int)fread(item->data, 1, item->dataSz, ctx->fd);
        ret = (ret == (int)item->dataSz) ? 0 : WOLFKM_BAD_FILE;
    }
#ifdef WOLFKM_VAULT_ENC
    if (ret == 0) {
        ret = wolfVaultDecrypt(ctx, item->data, item->dataSz, ctx->itemPos,
            ctx->item.tag, sizeof(ctx->item.tag));
    }
#endif
    /* on error release allocated memory */
    if (ret != 0 && item->data) {
        free(item->data);
        item->data = NULL;
    }
    return ret;
}

/* get copy of item from vault */
int wolfVaultGet(wolfVaultCtx* ctx, wolfVaultItem* item, word32 type,
    const byte* name, word32 nameSz)
{
    int ret;
    size_t itemPos;
    int rolloverCount = 0;

    if (ctx == NULL || item == NULL)
        return WOLFKM_BAD_ARGS;

    ret = wc_LockMutex(&ctx->lock);
    if (ret != 0)
        return ret;

    itemPos = ctx->itemPos; /* start from last cached position */
    while (ret == 0) {
        ret = wolfVaultGetItemHeader(ctx, itemPos);
        if (ret == 0) {
            wolfVaultPrintItem(WOLFKM_LOG_DEBUG, "Get", &ctx->item);

            if (ctx->item.type == type && ctx->item.nameSz == nameSz &&
                (memcmp(ctx->item.name, name, ctx->item.nameSz) == 0)) {
                /* found item, get data and return */
                ret = wolfVaultGetItemData(ctx, item);
                break;
            }
        }

        /* skip to next item */
        itemPos += VAULT_ITEM_SZ(&ctx->item);
        /* check if at end of file */
        if (itemPos >= ctx->header.headerSz + ctx->header.vaultSz) {
            rolloverCount++;
            if (rolloverCount > 1) {
                ret = WOLFKM_BAD_FILE; /* not found */
                break;
            }
            itemPos = ctx->header.headerSz; /* reset to top of data */
        }
    };

    wc_UnLockMutex(&ctx->lock);
    return ret;
}

/* free a wolfVaultItem structure */
int wolfVaultFreeItem(wolfVaultItem* item)
{
    if (item && item->data != NULL) {
        free(item->data);
        item->data = NULL;
    }
    return 0;
}

/* delete a single item from the vault */
int wolfVaultDelete(wolfVaultCtx* ctx, word32 type, const byte* name,
    word32 nameSz)
{
    int ret;

    if (ctx == NULL || name == NULL)
        return WOLFKM_BAD_ARGS;

    ret = wc_LockMutex(&ctx->lock);
    if (ret != 0)
        return ret;

    /* TODO: Implement delete */
    /* ctx->header.vaultCount -= X; */
    /* ctx->header.vaultSz -= X; */

    (void)ctx;
    (void)name;
    (void)nameSz;
    (void)type;

    wc_UnLockMutex(&ctx->lock);
    return WOLFKM_BAD_ARGS;
}

/* archive items older than specified date from vault */
int wolfVaultArchive(wolfVaultCtx* ctx, word32 timestamp)
{
    int ret;

    if (ctx == NULL)
        return WOLFKM_BAD_ARGS;

    ret = wc_LockMutex(&ctx->lock);
    if (ret != 0)
        return ret;

    /* TODO: Implement archive */
    /* ctx->header.vaultCount -= X; */
    /* ctx->header.vaultSz -= X; */

    (void)ctx;
    (void)timestamp;

    wc_UnLockMutex(&ctx->lock);
    return WOLFKM_BAD_ARGS;
}

/* close vault file */
int wolfVaultClose(wolfVaultCtx* ctx)
{
    int ret;

    if (ctx == NULL)
        return WOLFKM_BAD_ARGS;

    ret = wolfVaultFlush(ctx);
    fclose(ctx->fd);
    wc_FreeMutex(&ctx->lock);
    free(ctx);
    return ret;
}

int wolfVaultPrintInfo(wolfVaultCtx* ctx)
{
    if (ctx == NULL)
        return WOLFKM_BAD_ARGS;

    XLOG(WOLFKM_LOG_INFO, "Version: %d\n", ctx->header.version);
    XLOG(WOLFKM_LOG_INFO, "Header Size: %d\n", ctx->header.headerSz);
    XLOG(WOLFKM_LOG_INFO, "Item Count: %d\n", ctx->header.vaultCount);
    XLOG(WOLFKM_LOG_INFO, "Total Size: %lu\n", ctx->header.vaultSz);

    return 0;
}

static void wolfVaultPrintItem(enum log_level_t level, const char* desc,
    VaultItem_t* item)
{
    if (item == NULL)
        return;
    XLOG(level, "Vault %s Item: Type %d, Name %d, Data %d, Timestamp %lu\n",
        desc, item->type, item->nameSz, item->dataSz, item->timestamp);
#ifdef DEBUG_VAULT
    wolfPrintBinLevel(level, item->name, item->nameSz);
#endif
}

#endif /* WOLFKM_VAULT */
