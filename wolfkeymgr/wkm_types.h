/* wkm_types.h
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

#ifndef WOLFKM_TYPES_H
#define WOLFKM_TYPES_H

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#include "wolfkeymgr/visibility.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/ecc.h>


#ifdef WOLFKM_ETSI_SERVICE
    #ifndef HAVE_ECC
        #error This service requires ECC support
    #endif
#endif


/* key manager errors */
enum  {
    WOLFKM_BAD_ARGS          = -1001,
    WOLFKM_BAD_MEMORY        = -1002,
    WOLFKM_BAD_FILE          = -1003,
    WOLFKM_BAD_KEY           = -1004,
    WOLFKM_BAD_CERT          = -1005,
    WOLFKM_BAD_SEND          = -1006,
    WOLFKM_NOT_COMPILED_IN   = -1007,
    WOLFKM_BAD_HOST          = -1008,
    WOLFKM_BAD_TIMEOUT       = -1009,
    WOLFKM_BAD_REQUEST_TYPE  = -1100,

    WOLFKM_ERROR_BEGIN = WOLFKM_BAD_ARGS
};

/* Log levels */
enum log_level_t {
    WOLFKM_LOG_ERROR = 1,
    WOLFKM_LOG_WARN  = 2,
    WOLFKM_LOG_INFO  = 3,
    WOLFKM_LOG_DEBUG = 4,
    WOLFKM_DEFAULT_LOG_LEVEL = WOLFKM_LOG_DEBUG
};

#define XLOG wolfKeyMgr_Log


#endif /* WOLFKM_TYPES_H */
