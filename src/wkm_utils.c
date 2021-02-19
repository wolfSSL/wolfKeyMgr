/* wkm_utils.c
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

#include "wkm_utils.h"

#include <time.h>
#include <sys/time.h>

/* our log file */
static FILE* logFile = NULL;
static enum log_level_t logLevel = WOLFKM_DEFAULT_LOG_LEVEL;


const char* wolfKeyMgr_GetError(int err)
{
    switch (err) {
        case WOLFKM_BAD_ARGS:
            return "Bad Function arguments";
        case WOLFKM_BAD_MEMORY:
            return "Bad memory allocation";
        case WOLFKM_BAD_FILE:
            return "Error openning file";
        case WOLFKM_BAD_KEY:
            return "Error loading key";
        case WOLFKM_BAD_CERT:
            return "Error loading cert";
        case WOLFKM_BAD_SEND:
            return "Error sending data";
        case WOLFKM_NOT_COMPILED_IN:
            return "Option not compiled in";
        case WOLFKM_BAD_HOST:
            return "Error resolving host name";
        case WOLFKM_BAD_TIMEOUT:
            return "Timeout error";
        case WOLFKM_BAD_REQUEST_TYPE:
            return "Bad Header Request Type";

        default:
            XLOG(WOLFKM_LOG_ERROR, "Unknown error %d\n", err); 
            break;
    }
    return "Unknown error number";
}

/* set the log file we want to use, use stderr as default  */
void wolfKeyMgr_SetLogFile(const char* fileName, int daemon, enum log_level_t level)
{
    logLevel = level;

    if (daemon == 0 && fileName == NULL)
        logFile = stderr;
    else if (daemon == 1 && fileName == NULL) {
        perror("Daemon needs a log file, can't write to stderr");
        exit(EXIT_FAILURE);
    }
    else {
        /* let's use user specificed log file */
        logFile = fopen(fileName, "a+");
        if (logFile == NULL) {
            perror("Can't open log file for writing");
            exit(EXIT_FAILURE);
        }
    }
}


/* log level string */
const char* wolfKeyMgr_GetLogLevel(enum log_level_t level)
{
    switch (level) {
        case WOLFKM_LOG_INFO:
            return "INFO";

        case WOLFKM_LOG_WARN:
            return "WARNING";

        case WOLFKM_LOG_ERROR:
            return "ERROR";

        case WOLFKM_LOG_DEBUG:
            return "DEBUG";

        default:
            return "UNKNOWN";
    }
}

/* our logging function */
void wolfKeyMgr_Log(enum log_level_t level, const char* fmt, ...)
{
    va_list vlist;
    char    timeStr[80];
    char    msgStr[1024];
    time_t  current;
    struct  tm local;

    if (level < logLevel)
        return;   /* don't need to output */

    if (logFile == NULL)
        return;   /* can't output */

    /* prefix timestamp */
    timeStr[0] = '\0';
    current = time(NULL);
    if (localtime_r(&current, &local)) {
        /* make pretty */
        strftime(timeStr, sizeof(timeStr), "%b %d %T %Y", &local);
    }        
    timeStr[sizeof(timeStr)-1] = '\0';

    /* format msg */
    msgStr[0] = '\0';
    va_start(vlist, fmt);
    vsnprintf(msgStr, sizeof(msgStr), fmt, vlist);
    va_end(vlist);
    msgStr[sizeof(msgStr)-1] = '\0';

    fprintf(logFile, "%s: [%s] %s", 
        timeStr, wolfKeyMgr_GetLogLevel(level), msgStr);
}

/* generic API's for loading a file buffer */
int wolfLoadFileBuffer(const char* fileName, byte** buffer, word32* sz)
{
    FILE* tmpFile;
    long fileSz;
    size_t bytesRead = 0;

    if (fileName == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "file name is null\n");
        return WOLFKM_BAD_ARGS;
    }

    tmpFile = fopen(fileName, "rb");
    if (tmpFile == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "file %s can't be opened for reading\n",
                            fileName);
        return WOLFKM_BAD_FILE;
    }

    fseek(tmpFile, 0, SEEK_END);
    fileSz = ftell(tmpFile);
    rewind(tmpFile);
    if (fileSz  > 0) {
        *sz = (word32)fileSz;

        if (buffer) {
            *buffer = (byte*)malloc(fileSz+1);
            if (*buffer == NULL) {
                fclose(tmpFile);
                return WOLFKM_BAD_MEMORY;
            }
        }
    }

    if (buffer && *sz > 0) {
        bytesRead = fread(*buffer, 1, *sz, tmpFile);
    }
    fclose(tmpFile);

    if (buffer && bytesRead == 0) {
        XLOG(WOLFKM_LOG_ERROR, "file %s can't be read\n", fileName);
        free(*buffer); *buffer = NULL;
        return WOLFKM_BAD_FILE;
    }

    return 0;
}

/* return time in seconds with precision */
double wolfGetCurrentTime(void)
{
    struct timeval tv;

    gettimeofday(&tv, 0);

    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000;
}

#define LINE_LEN 16
void wolfPrintBin(const byte* buffer, word32 length)
{
    word32 i, sz;
    char line[(LINE_LEN * 4) + 4], *tmp;

    if (!buffer) {
        printf("\tNULL");
        return;
    }

    while (length > 0) {
        sz = length;
        if (sz > LINE_LEN)
            sz = LINE_LEN;

        tmp = line;
        tmp += sprintf(tmp, "\t");
        for (i = 0; i < LINE_LEN; i++) {
            if (i < length)
                tmp += sprintf(tmp, "%02x ", buffer[i]);
            else
                tmp += sprintf(tmp, "   ");
        }
        tmp += sprintf(tmp, "| ");
        for (i = 0; i < sz; i++) {
            if (buffer[i] > 31 && buffer[i] < 127)
                tmp += sprintf(tmp, "%c", buffer[i]);
            else
                tmp += sprintf(tmp, ".");
        }
        XLOG(WOLFKM_LOG_DEBUG, "%s\n", line);

        buffer += sz;
        length -= sz;
    }
}

int wolfSaveFile(const char* file, byte* buffer, word32 length)
{
    word32 ret;
    FILE* raw = fopen(file, "wb");
    if (raw == NULL) {
        XLOG(WOLFKM_LOG_INFO, "Error saving response to %s\n", file);
        return -1;
    }
    ret = (word32)fwrite(buffer, 1, length, raw);
    fclose(raw);
    if (ret != length) {
        XLOG(WOLFKM_LOG_ERROR, "fwrite failed\n");
        return -1;
    }
    return 0;
}
