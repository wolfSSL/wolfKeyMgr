/* mod_https.h
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

#ifndef WOLFKM_HTTP_H
#define WOLFKM_HTTP_H

#ifdef __cplusplus
extern "C" {
#endif

#include "wkm_types.h"

/* Configurable HTTP Settings */
#ifndef HTTP_HDR_MAX_ITEMS
#define HTTP_HDR_MAX_ITEMS 10
#endif

/* HTTP Types */
typedef enum HttpMethodType {
    HTTP_METHOD_UNKNOWN,
    HTTP_METHOD_OPTIONS,
    HTTP_METHOD_GET,
    HTTP_METHOD_HEAD,
    HTTP_METHOD_POST,
    HTTP_METHOD_PUT,
    HTTP_METHOD_DELETE,
    HTTP_METHOD_TRACE,
    HTTP_METHOD_CONNECT,
} HttpMethodType;

typedef enum HttpHeaderType {
    HTTP_HDR_UNKNOWN,
    HTTP_HDR_ACCEPT,
    HTTP_HDR_ACCEPT_CHARSET,
    HTTP_HDR_ACCEPT_ENCODING,
    HTTP_HDR_ACCEPT_LANGUAGE,
    HTTP_HDR_ACCEPT_RANGES,
    HTTP_HDR_AGE,
    HTTP_HDR_ALLOW,
    HTTP_HDR_AUTHORIZATION,
    HTTP_HDR_CACHE_CONTROL,
    HTTP_HDR_COOKIE,
    HTTP_HDR_CONNECTION,
    HTTP_HDR_CONTENT_ENCODING,
    HTTP_HDR_CONTENT_LANGUAGE,
    HTTP_HDR_CONTENT_LENGTH,
    HTTP_HDR_CONTENT_LOCATION,
    HTTP_HDR_CONTENT_MD5,
    HTTP_HDR_CONTENT_RANGE,
    HTTP_HDR_CONTENT_TYPE,
    HTTP_HDR_DATE,
    HTTP_HDR_ETAG,
    HTTP_HDR_EXPECT,
    HTTP_HDR_EXPIRES,
    HTTP_HDR_FROM,
    HTTP_HDR_HOST,
    HTTP_HDR_IF_MATCH,
    HTTP_HDR_IF_MODIFIED_SINCE,
    HTTP_HDR_IF_NONE_MATCH,
    HTTP_HDR_IF_RANGE,
    HTTP_HDR_IF_UNMODIFIED_SINCE,
    HTTP_HDR_LAST_MODIFIED,
    HTTP_HDR_LOCATION,
    HTTP_HDR_MAX_FORWARDS,
    HTTP_HDR_PRAGMA,
    HTTP_HDR_PROXY_AUTHENTICATE,
    HTTP_HDR_PROXY_AUTHORIZATION,
    HTTP_HDR_RANGE,
    HTTP_HDR_REFERER,
    HTTP_HDR_RETRY_AFTER,
    HTTP_HDR_TE,
    HTTP_HDR_TRAILER,
    HTTP_HDR_TRANSFER_ENCODING,
    HTTP_HDR_UPGRADE,
    HTTP_HDR_UPGRADE_INSECURE_REQUESTS,
    HTTP_HDR_USER_AGENT,
    HTTP_HDR_VARY,
    HTTP_HDR_VIA,
    HTTP_HDR_WARNING,
    HTTP_HDR_WWW_AUTHENTICATE,
} HttpHeaderType;

typedef enum HttpErrorCodes {
    HTTP_ERROR_EXPECTED_CRLF   = -2000,
    HTTP_ERROR_EXPECTED_METHOD = -2001,

} HttpErrorCodes;

typedef struct HttpHeader {
    HttpHeaderType type;
    char*          header;
    char*          string;
} HttpHeader;

typedef struct HttpReq {
    HttpMethodType type;
    char*          method;
    char*          uri;
    char*          version;
    word32         headerCount;
    HttpHeader     headers[HTTP_HDR_MAX_ITEMS];
} HttpReq;


int wolfKeyMgr_HttpParse(HttpReq* req, char* buf, word32 sz);
void wolfKeyMgr_HttpReqDump(HttpReq* req);


#ifdef __cplusplus
}
#endif

#endif /* WOLFKM_HTTP_H */
