/* keymanager.c
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

#include "keymanager.h"

#include <unistd.h>    /* getopt */
#include <signal.h>    /* SIGPIPE */

/* usage help */
static void Usage(void)
{
    printf("%s\n", PACKAGE_STRING);
    printf("-?          Help, print this usage\n");
    printf("-c          Don't chdir / in daemon mode\n");
    printf("-d          Daemon mode, run in background\n");
    printf("-f <str>    Pid File name, default %s\n", WOLFKM_DEFAULT_PID);
    printf("-l <str>    Log file name, default %s\n",
                          WOLFKM_DEFAULT_LOG_NAME ? WOLFKM_DEFAULT_LOG_NAME : "None");
    printf("-m <num>    Max open files, default  %d\n", WOLFKM_DEFAULT_FILES);
    printf("-s <num>    Seconds to timeout, default %d\n", WOLFKM_DEFAULT_TIMEOUT);
    printf("-t <num>    Thread pool size, default  %ld\n",
                                                 sysconf(_SC_NPROCESSORS_CONF));
    printf("-v <num>    Log Level, default %d\n", WOLFKM_DEFAULT_LOG_LEVEL);
}


int main(int argc, char** argv)
{
    int ret;
    int ch;
    int daemon        = 0;
    int core          = 0;
    int poolSize      = (int)sysconf(_SC_NPROCESSORS_CONF);
    int maxFiles      = WOLFKM_DEFAULT_FILES;
    enum log_level_t logLevel = WOLFKM_DEFAULT_LOG_LEVEL;
    char*  logName    = WOLFKM_DEFAULT_LOG_NAME;
    char*  pidName    = WOLFKM_DEFAULT_PID;
    struct event*           signalEvent = NULL; /* signal event handle */
    struct event_base*      mainBase = NULL;    /* main thread's base  */
    signalArg               sigArg;
    FILE*                   pidF = 0;
    svcInfo* etsiSvc = NULL;
    word32 timeoutSec  = WOLFKM_DEFAULT_TIMEOUT;

    /* argument processing */
    while ((ch = getopt(argc, argv, "?dcns:t:m:l:f:v:")) != -1) {
        switch (ch) {
            case '?' :
                Usage();
                exit(EXIT_SUCCESS);
            case 'd' :
                daemon = 1;
                break;
            case 'c' :
                core = 1;
                break;
            case 's' :
            {
                int sec = atoi(optarg);
                if (sec < 0) {
                    perror("timeout positive values only accepted");
                    exit(EX_USAGE);
                }
                timeoutSec = (word32)sec;
                break;
            }
            case 't' :
                poolSize = atoi(optarg);
                break;
            case 'm' :
                maxFiles = atoi(optarg);
                break;
            case 'l' :
                logName = optarg;
                break;
            case 'f' :
                pidName = optarg;
                break;
            case 'v' :
                logLevel = atoi(optarg);
                if (logLevel < WOLFKM_LOG_DEBUG || logLevel > WOLFKM_LOG_ERROR) {
                    perror("loglevel [1:4] only");
                    exit(EX_USAGE);
                }
                break;

            default:
                Usage();
                exit(EX_USAGE);
        }
    }

    /* Create daemon */
    if (daemon) {
        if (logName == NULL) {
            perror("daemon mode needs a log file, can't write to stderr");
            exit(EXIT_FAILURE);
        }
        if (wolfKeyMgr_MakeDaemon(core == 0) == -1) {
            perror("Failed to make into daemon");
            exit(EXIT_FAILURE);
        }
    }
    else
        setbuf(stderr, NULL);

    /* start log */
    wolfKeyMgr_SetLogFile(logName, daemon, logLevel);
    XLOG(WOLFKM_LOG_INFO, "Starting Key Manager\n");

    if (CheckCtcSettings() != 1) {
        XLOG(WOLFKM_LOG_ERROR, "wolfSSL math library mismatch in settings\n");
        exit(EXIT_FAILURE);
    }

#ifdef USE_FAST_MATH
    if (CheckFastMathSettings() != 1) {
        XLOG(WOLFKM_LOG_ERROR, "wolfSSL fast math library mismatch\n");
        exit(EXIT_FAILURE);
    }
#endif

    /* Init wolfSSL */
#if 0
    wolfSSL_Debugging_ON();
#endif
    wolfSSL_Init();

    /* main thread base event */
    mainBase = event_base_new();
    if (mainBase == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Failed to event_base_new\n");
        ret = EXIT_FAILURE; goto exit;
    }

    /* setup signal stuff */
    if (wolfKeyMgr_SigIgnore(SIGPIPE) == -1) {
        XLOG(WOLFKM_LOG_ERROR, "Failed to ignore SIGPIPE\n");
        ret = EX_OSERR; goto exit;
    }

    /* setup pid before binding listeners */
    pidF = wolfKeyMgr_GetPidFile(pidName, getpid());
    if (pidF == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Failed to get pidfile (already running?)\n");
        ret = EXIT_FAILURE; goto exit;
    }

    /* set max files */
    wolfKeyMgr_SetMaxFiles(maxFiles);

    /********** ETSI Service **********/
    etsiSvc = wolfEtsiSvc_Init(mainBase, timeoutSec);
    if (etsiSvc) {
        /* thread setup - cleanup handled in sigint handler */
        wolfKeyMgr_ServiceInit(etsiSvc, poolSize);
    }

    /* SIGINT handler */
    signalEvent = event_new(mainBase, SIGINT, (EV_SIGNAL | EV_PERSIST), 
        wolfKeyMgr_SignalCb, &sigArg);
    memset(&sigArg, 0, sizeof(sigArg));
    sigArg.ev   = signalEvent;
    sigArg.base = mainBase;
    sigArg.svc[0] = etsiSvc;
    if (event_add(signalEvent, NULL) == -1) {
        XLOG(WOLFKM_LOG_ERROR, "Can't add event for signal\n");
        ret = EXIT_FAILURE; goto exit;
    }

    /* start main loop */
    event_base_dispatch(mainBase);

    /* we're done with loop */
    ret = EXIT_SUCCESS;
    XLOG(WOLFKM_LOG_INFO, "Done with main thread dispatching\n");
    wolfKeyMgr_ShowStats(etsiSvc);

exit:
    /* Cleanup pid file */
    if (pidF) {
        fclose(pidF);
        unlink(pidName);
    }

    wolfKeyMgr_FreeListeners();

    wolfEtsiSvc_Cleanup(etsiSvc);
    if (signalEvent) event_del(signalEvent);
    if (mainBase) event_base_free(mainBase);
    wolfSSL_Cleanup();

    XLOG(WOLFKM_LOG_INFO, "Exit Key Manager (ret %d)\n", ret);

    exit(ret);
}
