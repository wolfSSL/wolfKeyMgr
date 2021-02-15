/* mod_https.c
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

#include "mod_https.h"
#include "wkm_utils.h"
#include <string.h>

static const char* kCrlf = "\r\n";

static void HttpParseMethod(HttpReq* req, char* method)
{
    if (strncmp(method, "GET", 3) == 0) {
        req->type = HTTP_METHOD_GET;
    }
    else if (strncmp(method, "HEAD", 4) == 0) {
        req->type = HTTP_METHOD_HEAD;
    }
    else if (strncmp(method, "POST", 4) == 0) {
        req->type = HTTP_METHOD_POST;
    }
    else if (strncmp(method, "PUT", 3) == 0) {
        req->type = HTTP_METHOD_PUT;
    }
    else if (strncmp(method, "DELETE", 6) == 0) {
        req->type = HTTP_METHOD_DELETE;
    }
    else if (strncmp(method, "TRACE", 5) == 0) {
        req->type = HTTP_METHOD_TRACE;
    }
    else if (strncmp(method, "CONNECT", 7) == 0) {
        req->type = HTTP_METHOD_CONNECT;
    }    
}

static void HttpParseHeader(HttpReq* req, char* hdrStr)
{
    HttpHeader* hdr;
    word32 itemSz = 0;

    if (req->headerCount >= HTTP_HDR_MAX_ITEMS)
        return;
    
    hdr = &req->headers[req->headerCount];
    memset(hdr, 0, sizeof(*hdr));

    if (strncmp(hdrStr, "Accept: ", 8) == 0) {
        hdr->type = HTTP_HDR_ACCEPT;
        itemSz = 8;
    }

    hdrStr[itemSz-2] = '\0'; /* null terminate */
    hdr->header = hdrStr;
    hdr->string = hdrStr + itemSz;
    req->headerCount++;
}

/* Parse incoming request into `HttpReq` struct */
int wolfKeyMgr_HttpParse(HttpReq* req, char* buf, word32 sz)
{
    int ret = 0;
    char* sec = buf, *endline, *last;
    word32 len = sz;
    word32 itemSz;

    if (req == NULL)  {
        return WOLFKM_BAD_ARGS;
    }
    memset(req, 0, sizeof(*req));

    /* Method */
    /* find first space */
    endline = strchr(sec, ' ');
    if (endline) {
        *endline = '\0'; /* null terminate string */
        HttpParseMethod(req, sec);
    }
    if (req->type == HTTP_METHOD_UNKNOWN) {
        return HTTP_ERROR_EXPECTED_METHOD;
    }
    req->method = sec;
    itemSz = strlen(sec) + 1; /* include space */    
    sec += itemSz; len -= itemSz;

    /* Find end of line */
    endline = strstr(sec, kCrlf);
    if (endline == NULL) {
        return HTTP_ERROR_EXPECTED_CRLF;
    }
    *endline = '\0'; /* null terminate string */

    /* HTTP Header Version */
    /* locate last space */
    last = strrchr(sec, ' ');
    if (last) {
        req->version = last + 1;
        *last = '\0';
    }

    /* Set URI */
    req->uri = sec;
    sec = endline + 2; /* 2=length of CRLF */

    /* Parse headers */
    endline = strstr(sec, kCrlf); /* Find end of line */
    while (endline) {
        *endline = '\0'; /* null terminate line */
        HttpParseHeader(req, sec);
        endline += 2; /* 2=length of CRLF */
        endline = strstr(endline, kCrlf); /* Find end of line */
    }

    return ret;
}

void wolfKeyMgr_HttpReqDump(HttpReq* req)
{
    int i;

    if (req == NULL)
        return;

    XLOG(WOLFKM_LOG_DEBUG, "HTTP %s\n", req->method);
    XLOG(WOLFKM_LOG_DEBUG, "\tVersion: %s\n", req->version);
    XLOG(WOLFKM_LOG_DEBUG, "\tURI: %s\n",req->uri);
    XLOG(WOLFKM_LOG_DEBUG, "\tHeaders: %d\n", req->headerCount);
    for (i=0; i<req->headerCount; i++) {
        XLOG(WOLFKM_LOG_DEBUG, "\t\t%s: %s\n",
            req->headers[i].header, req->headers[i].string);
    }
}
