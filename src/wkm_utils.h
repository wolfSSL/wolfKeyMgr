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

#include "wkm_types.h"


/* Helper / Utility Functions */
const char* wolfKeyMgr_GetError(int err);
const char* wolfKeyMgr_GetLogLevel(enum log_level_t level);
void wolfKeyMgr_Log(enum log_level_t, const char* fmt, ...) ATT_STRFUNC;
void wolfKeyMgr_SetLogFile(const char* fileName, int daemon, enum log_level_t level);

char* wolfKeyMgr_UriEncode(const byte *s, char *enc);
byte* wolfKeyMgr_UriDecode(const char *s, byte *dec);
double wolfKeyMgr_GetCurrentTime(void);

int wolfKeyMgr_LoadFileBuffer(const char* fileName, byte** buffer, word32* sz);
void wolfKeyMgr_PrintBin(const byte* buffer, word32 length);

/* misc functions */
void c16toa(unsigned short, unsigned char*);
void ato16(const unsigned char*, unsigned short*);
#if !defined(min) && !defined(WOLFSSL_HAVE_MIN)
int min(int a, int b);
#endif



#endif /* WOLFKM_UTILS_H */
