/* visibility.h
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

#ifndef WOLFKM_VISIBILITY_H
#define WOLFKM_VISIBILITY_H


/* Visibility control macros */
/* WOLFKM_API is used for the public API symbols.
        It either imports or exports (or does nothing for static builds)

   WOLFKM_LOCAL is used for non-API symbols (private).
*/

#if defined(BUILDING_WKM)
    #if defined(_MSC_VER) || defined(__MINGW32__) || defined(__CYGWIN__)
        #if defined(WOLFKM_DLL)
            #define WOLFKM_API __declspec(dllexport)
        #else
            #define WOLFKM_API
        #endif
        #define WOLFKM_LOCAL
    #elif defined(HAVE_VISIBILITY) && HAVE_VISIBILITY
        #define WOLFKM_API   __attribute__ ((visibility("default")))
        #define WOLFKM_LOCAL __attribute__ ((visibility("hidden")))
    #elif defined(__SUNPRO_C) && (__SUNPRO_C >= 0x550)
        #define WOLFKM_API   __global
        #define WOLFKM_LOCAL __hidden
    #else
        #define WOLFKM_API
        #define WOLFKM_LOCAL
    #endif /* HAVE_VISIBILITY */
#else /* BUILDING_WKM */
    #if defined(_MSC_VER) || defined(__MINGW32__) || defined(__CYGWIN__)
        #if defined(WOLFKM_DLL)
            #define WOLFKM_API __declspec(dllimport)
        #else
            #define WOLFKM_API
        #endif
        #define WOLFKM_LOCAL
    #else
        #define WOLFKM_API
        #define WOLFKM_LOCAL
    #endif
#endif /* BUILDING_WOLFKM */


#endif /* WOLFKM_VISIBILITY_H */
