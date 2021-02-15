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

#include "config.h"
#include "visibility.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

/* key manager errors */
enum  {
    WOLFKM_BAD_VERIFY_SIZE   = -1001,
    WOLFKM_BAD_ARGS          = -1002,
    WOLFKM_BAD_MEMORY        = -1002,
    WOLFKM_BAD_FILE          = -1003,
    WOLFKM_BAD_KEY           = -1004,
    WOLFKM_BAD_CERT          = -1005,
    WOLFKM_BAD_SEND          = -1006,
    WOLFKM_BAD_LISTENER      = -1007,
    WOLFKM_NOT_COMPILED_IN   = -1008,
    WOLFKM_BAD_HEADER_SZ     = -1100,
    WOLFKM_BAD_VERSION       = -1101,
    WOLFKM_BAD_REQUEST_TYPE  = -1102,
    WOLFKM_BAD_X509_D2I      = -1103,
    WOLFKM_BAD_X509_GET_NAME = -1104,
    WOLFKM_BAD_X509_ONELINE  = -1105,
    WOLFKM_BAD_X509_MATCH    = -1106,

    WOLFKM_ERROR_BEGIN = WOLFKM_BAD_VERIFY_SIZE
};

/* Log levels */
enum log_level_t {
    WOLFKM_LOG_ERROR = 4,
    WOLFKM_LOG_WARN  = 3,
    WOLFKM_LOG_INFO  = 2,
    WOLFKM_LOG_DEBUG = 1,
    WOLFKM_DEFAULT_LOG_LEVEL = WOLFKM_LOG_DEBUG
};

#ifdef __GNUC__
#define ATT_STRFUNC __attribute__((format(printf, 2, 3)))
#else
#define ATT_STRFUNC
#endif

#define XLOG wolfKeyMgr_Log

#endif /* WOLFKM_TYPES_H */
