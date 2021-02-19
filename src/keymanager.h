/* keymanager.h
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

#ifndef KEYMANAGER_H
#define KEYMANAGER_H

/* wolfssl headers */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>


/* Key Manager Headers */
#include "wkm_types.h"
#include "wkm_utils.h"
#include "mod_http.h"
#include "mod_etsi.h"
#include "sock_mgr.h"
#include "svc_etsi.h"


/* wolfssl headers */
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/random.h>


/* string constants */
#define WOLFKM_DEFAULT_LOG_NAME     NULL
#define WOLFKM_DEFAULT_PID          "./wolfkeymgr.pid"


/* program constants */
enum ProgramConstMisc {
    WOLFKM_DEFAULT_FILES       =  1024,        /* default max open files */
    WOLFKM_DEFAULT_TIMEOUT     =    60,        /* default timeout in seconds */
    WOLFKM_CONN_ITEMS          =  1024,        /* new conn item pool size */
    WOLFKM_BACKOFF_TIME        = 10000,        /* in microseconds */
};


#endif /* KEYMANAGER_H */
