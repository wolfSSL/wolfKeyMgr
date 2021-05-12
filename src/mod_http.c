/* mod_http.c
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

/* HTTP 1.1 Client and Server Module */

#include "wolfkeymgr/mod_http.h"
#include "wolfkeymgr/wkm_utils.h"

#include <string.h>

static const char* kCrlf = "\r\n";
static const char* kHTTPVer = "HTTP/1.1";

const char* wolfHttpGetMethodStr(HttpMethodType type, word32* strLen)
{
    const char* str = NULL;
    switch (type) {
        case HTTP_METHOD_GET:
            str = "GET";
            break;
        case HTTP_METHOD_HEAD:
            str = "HEAD";
            break;
        case HTTP_METHOD_POST:
            str = "POST";
            break;
        case HTTP_METHOD_PUT:
            str = "PUT";
            break;
        case HTTP_METHOD_DELETE:
            str = "DELETE";
            break;
        case HTTP_METHOD_TRACE:
            str = "DELETE";
            break;
        case HTTP_METHOD_CONNECT:
            str = "CONNECT";
            break;

        default:
            str = NULL;
    }
    if (str && strLen) {
        *strLen = (word32)strlen(str);
    }
    return str;
}

const char* wolfHttpGetHeaderStr(HttpHeaderType type, word32* strLen)
{
    const char* str = NULL;
    switch (type) {
        case HTTP_HDR_ACCEPT:
            str = "Accept: ";
            break;
        case HTTP_HDR_ACCEPT_RANGES:
            str = "Accept-Ranges: ";
            break;
        case HTTP_HDR_CONNECTION:
            str = "Connection: ";
            break;
        case HTTP_HDR_CONTENT_LENGTH:
            str = "Content-Length: ";
            break;
        case HTTP_HDR_CONTENT_TYPE:
            str = "Content-Type: ";
            break;
        case HTTP_HDR_HOST:
            str = "Host: ";
            break;
        case HTTP_HDR_EXPIRES:
            str = "Expires: ";
            break;
        /* TODO: Add more header types */

        default:
            str = NULL;
    }
    if (str && strLen) {
        *strLen = (word32)strlen(str);
    }
    return str;
}

static HttpMethodType HttpParseMethod(char* method)
{
    HttpMethodType type;
    const char* str;
    word32 len;
    
    /* loop through methods and find match */
    for (type=HTTP_METHOD_UNKNOWN; type<HTTP_METHOD_LAST; type++) {
        if ((str = wolfHttpGetMethodStr(type, &len))) {
            if (strncmp(method, str, len) == 0) {
                return type;
            }
        }
    }
    return HTTP_METHOD_UNKNOWN;
}

static void HttpParseHeader(HttpHeader* headers, word32* headerCount, char* hdrStr)
{
    HttpHeader* hdr;
    HttpHeaderType type;
    const char* str;
    word32 len;
    word32 itemSz = 0;

    if (*headerCount >= HTTP_HDR_MAX_ITEMS)
        return;
    
    hdr = &headers[*headerCount];
    memset(hdr, 0, sizeof(*hdr));

    hdr->type = HTTP_HDR_UNKNOWN;

    /* loop through header types and find match */
    for (type=HTTP_HDR_UNKNOWN; type<HTTP_HDR_LAST; type++) {
        if ((str = wolfHttpGetHeaderStr(type, &len))) {
            if (strncmp(hdrStr, str, len) == 0) {
                itemSz = len;
                hdr->type = type;
                break;
            }
        }
    }

    hdr->string = hdrStr + itemSz;
    (*headerCount)++;
}

/* Parse incoming server request into `HttpReq` struct */
int wolfHttpServer_ParseRequest(HttpReq* req, byte* buf, word32 sz)
{
    char* sec = (char*)buf, *endline, *last;
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
        req->type = HttpParseMethod(sec);
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
        HttpParseHeader(req->headers, &req->headerCount, sec);
        endline += 2; /* 2=length of CRLF */
        endline = strstr(endline, kCrlf); /* Find end of line */
    }

    return 0;
}

int wolfHttpServer_EncodeResponse(int rspCode, const char* message, 
    byte* response, word32* responseSz, HttpHeader* headers, word32 headerCount,
    const byte* body, word32 bodySz)
{
    int i;
    HttpHeader* hdr;
    char* out = (char*)response;
    word32 remain;

    if (response == NULL || responseSz == NULL || *responseSz == 0 || 
            (headers == NULL && headerCount > 0)) {
        return WOLFKM_BAD_ARGS;
    }
    remain = *responseSz - 1; /* room for null term */

    /* default to "200 OK" */
    if (rspCode == 0) {
        rspCode = 200;
    }
    if (message == NULL) {
        message = "OK";
    }

    /* append version and response code / message */
    i = snprintf(out, remain, "%s %d %s\r\n", kHTTPVer, rspCode, message);
    if (i > 0) {
        out += i;
        remain -= i;
    }

    /* append headers */
    for (i=0; i<headerCount && remain > 0; i++) {
        hdr = &headers[i];

        i = snprintf(out, remain, "%s%s\r\n", 
            wolfHttpGetHeaderStr(hdr->type, NULL), hdr->string);
        if (i > 0) {
            out += i;
            remain -= i;
        }
    }

    /* append content length */
    if (bodySz > 0) {
        i = snprintf(out, remain, "%s%d\r\n", 
            wolfHttpGetHeaderStr(HTTP_HDR_CONTENT_LENGTH, NULL), bodySz);
        if (i > 0) {
            out += i;
            remain -= i;
        }
    }

    /* add trailing crlf and body */
    i = snprintf(out, remain, "\r\n");
    if (i > 0) {
        out += i;
        remain -= i;
    }

    /* append body (optional) */
    if (body && bodySz > 0) {
        if (bodySz > remain)
            bodySz = remain;
        memcpy(out, body, bodySz);
        out += bodySz;
        remain -= bodySz;
    }

    /* calculate total length */
    *responseSz = (word32)((size_t)out - (size_t)response);

    /* null terminate */
    response[*responseSz] = '\0';

    return 0;
}

int wolfHttpClient_ParseResponse(HttpRsp* rsp, char* buf, word32 sz)
{
    char* sec = buf, *endline;
    word32 len = sz;
    word32 itemSz;

    if (rsp == NULL)  {
        return WOLFKM_BAD_ARGS;
    }
    memset(rsp, 0, sizeof(*rsp));

    /* HTTP Header Version */
    /* find first space */
    endline = strchr(sec, ' ');
    if (endline) {
        *endline = '\0'; /* null terminate string */
    }
    rsp->version = sec;
    itemSz = strlen(sec) + 1; /* include space */    
    sec += itemSz; len -= itemSz;

    /* HTTP Response Code */
    /* find next space */
    endline = strchr(sec, ' ');
    if (endline) {
        *endline = '\0'; /* null terminate string */
    }
    rsp->code = atoi(sec);
    itemSz = strlen(sec) + 1; /* include space */    
    sec += itemSz; len -= itemSz;

    /* HTTP Response Message */
    /* find end of line */
    endline = strstr(sec, kCrlf);
    if (endline == NULL) {
        return HTTP_ERROR_EXPECTED_CRLF;
    }
    *endline = '\0'; /* null terminate string */

    rsp->message = sec;
    sec = endline + 2; /* 2=length of CRLF */

    /* Parse headers */
    endline = strstr(sec, kCrlf); /* Find end of line */
    while (endline) {
        /* if next characters are CRLF then we've reached end */
        if (strlen(sec) >= 2 && sec[0] == '\r' && sec[1] == '\n') {
            endline += 2;
            break;
        }
        *endline = '\0'; /* null terminate line */
        HttpParseHeader(rsp->headers, &rsp->headerCount, sec);
        endline += 2; /* 2=length of CRLF */
        sec = endline;
        endline = strstr(sec, kCrlf); /* Find end of line */
    }

    /* calculate total length */
    itemSz = (word32)((size_t)endline - (size_t)buf);

    /* Set Body */
    rsp->body = endline;
    rsp->bodySz = sz - itemSz;

    return 0;
}

int wolfHttpClient_EncodeRequest(HttpMethodType type, const char* uri,
    byte* request, word32* requestSz, HttpHeader* headers, word32 headerCount)
{
    int i;
    HttpHeader* hdr;
    char* out = (char*)request;
    word32 remain;

    if (request == NULL || requestSz == NULL || *requestSz == 0 || 
            uri == NULL || (headers == NULL && headerCount > 0)) {
        return WOLFKM_BAD_ARGS;
    }
    remain = *requestSz - 1; /* room for null term */

    /* append method */
    i = snprintf(out, remain, "%s %s %s\r\n",
        wolfHttpGetMethodStr(type, NULL), uri, kHTTPVer);
    if (i > 0) {
        out += i;
        remain -= i;
    }

    /* append headers */
    for (i=0; i<headerCount && remain > 0; i++) {
        hdr = &headers[i];

        i = snprintf(out, remain, "%s%s\r\n", 
            wolfHttpGetHeaderStr(hdr->type, NULL), hdr->string);
        if (i > 0) {
            out += i;
            remain -= i;
        }
    }

    /* calculate total length */
    *requestSz = (word32)((size_t)out - (size_t)request);

    /* null terminate */
    request[*requestSz] = '\0';

    return 0;
}

void wolfHttpRequestPrint(HttpReq* req)
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
            wolfHttpGetHeaderStr(req->headers[i].type, NULL),
            req->headers[i].string);
    }
}

void wolfHttpResponsePrint(HttpRsp* rsp)
{
    int i;

    if (rsp == NULL)
        return;

    XLOG(WOLFKM_LOG_DEBUG, "HTTP %s\n", rsp->version);
    XLOG(WOLFKM_LOG_DEBUG, "\tCode %d: %s\n", rsp->code, rsp->message);
    XLOG(WOLFKM_LOG_DEBUG, "\tHeaders: %d\n", rsp->headerCount);
    for (i=0; i<rsp->headerCount; i++) {
        XLOG(WOLFKM_LOG_DEBUG, "\t\t%s: %s\n",
            wolfHttpGetHeaderStr(rsp->headers[i].type, NULL),
            rsp->headers[i].string);
    }
    XLOG(WOLFKM_LOG_DEBUG, "\tBody Size: %d\n", rsp->bodySz);
}


char* wolfHttpUriEncode(const byte *s, char *enc)
{
    for (; *s; s++){
        if (*s == '*' || *s == '-' || *s == '.' || *s == '_') {
            char a = (char)(*s >> 4), b = (char)(*s & 0xff);
            *enc++ = '%';
            *enc++ = (a < 10) ? '0' + a : 'A' + a - 10;
            *enc++ = (b < 10) ? '0' + b : 'A' + b - 10;
        }
        else if (*s == ' ')
            *enc++ = '+';
        else
            *enc++ = *s;
    }
    return enc;
}

static int hex_to_char(char a, byte* out)
{
    if (a >= '0' && a <= '9')
        a -= '0';
    else if (a >= 'A' && a <= 'F')
        a -= 'A' - 10;
    else if (a >= 'a' && a <= 'f')
        a -= 'a' - 'A' - 10;
    else
        return 0;
    *out = (byte)a;
    return 1;
}

byte* wolfHttpUriDecode(const char *s, byte *dec)
{
    byte a, b;
    for (; *s; s++){
        if (*s == '%' && 
                hex_to_char((char)s[1], &a) && 
                hex_to_char((char)s[2], &b)) {
            *dec++ = (a << 4 | b);
            s+=2;
        }
        else if (*s == '+') {
            *dec++ = ' ';
        }
        else {
            *dec++ = *s;
        }
    }
    return dec;
}

int wolfHttpUrlDecode(HttpUrl* url, char* s)
{
    char* dec;
    if (url == NULL || s == NULL) {
        return WOLFKM_BAD_ARGS;
    }
    memset(url, 0, sizeof(*url));

    /* find :// */
    dec = strstr(s, "://");
    if (dec == NULL) {
        return WOLFKM_BAD_ARGS;
    }

    *dec = '\0';
    url->protocol = s;
    s = dec+3;

    /* find next "/" */
    url->domain = s;
    dec = strstr(s, "/");
    if (dec) {
        *dec = '\0';
        url->path = dec+1;
    }
    
    /* find ":" */
    dec = strstr(s, ":");
    if (dec) {
        /* port specified */
        url->port = atoi(dec+1);
        *dec = '\0';
    }
    return 0;
}
