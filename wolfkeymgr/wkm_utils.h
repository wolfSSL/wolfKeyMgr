/* wkm_utils.h
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

#ifndef WOLFKM_UTILS_H
#define WOLFKM_UTILS_H

#include "wolfkeymgr/wkm_types.h"


#ifdef __GNUC__
#define ATT_STRFUNC __attribute__((format(printf, 2, 3)))
#else
#define ATT_STRFUNC
#endif


/* Helper / Utility Functions */
WOLFKM_API const char* wolfKeyMgr_GetError(int err);
WOLFKM_API const char* wolfKeyMgr_GetLogLevel(enum log_level_t level);
WOLFKM_API void wolfKeyMgr_Log(enum log_level_t, const char* fmt, ...) ATT_STRFUNC;
WOLFKM_API void wolfKeyMgr_SetLogFile(const char* fileName, int daemon, enum log_level_t level);
WOLFKM_API void wolfKeyMgr_CloseLog(void);

WOLFKM_API double wolfGetCurrentTime(void);

WOLFKM_API int wolfLoadFileBuffer(const char* fileName, byte** buffer, word32* sz);
WOLFKM_API void wolfPrintBin(const byte* buffer, word32 length);
WOLFKM_API int wolfSaveFile(const char* file, byte* buffer, word32 length);

WOLFKM_API int wolfSigIgnore(int sig);

/* misc functions */
#if !defined(min) && !defined(WOLFSSL_HAVE_MIN)
static inline int min(int a, int b)
{
    return a < b ? a : b;
}
#endif

/* convert short to network byte order, no alignment required */
static inline void c16toa(unsigned short u16, unsigned char* c)
{
    c[0] = (u16 >> 8) & 0xff;
    c[1] =  u16 & 0xff;
}

/* convert opaque to 16 bit integer */
static inline void ato16(const unsigned char* c, unsigned short* u16)
{
    *u16 = (c[0] << 8) | (c[1]);
}


#endif /* WOLFKM_UTILS_H */
