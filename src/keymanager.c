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

#include "wolfkeymgr/keymanager.h"

#include <unistd.h>    /* getopt */
#include <signal.h>    /* SIGPIPE */

/* usage help */
static void Usage(void)
{
    printf("%s\n", PACKAGE_STRING);
    printf("-?          Help, print this usage\n");
    printf("-i          Don't chdir / in daemon mode\n");
    printf("-b          Daemon mode, run in background\n");
    printf("-p <str>    Pid File name, default %s\n", WOLFKM_DEFAULT_PID);
    printf("-l <num>    Log Level (1=Error to 4=Debug), default %d\n", WOLFKM_DEFAULT_LOG_LEVEL);
    printf("-f <str>    Log file name, default %s\n",
                          WOLFKM_DEFAULT_LOG_NAME ? WOLFKM_DEFAULT_LOG_NAME : "None");
    printf("-o <num>    Max open files, default  %d\n", WOLFKM_DEFAULT_FILES);
    printf("-s <num>    Seconds to timeout, default %d\n", WOLFKM_DEFAULT_TIMEOUT);
    printf("-r <num>    Key renewal timeout, default %d\n", WOLFKM_KEY_RENEW_TIMEOUT);
    printf("-t <num>    Thread pool size, default  %ld\n",
                                                 sysconf(_SC_NPROCESSORS_CONF));
    printf("-d          TLS Disable Mutual Authentication\n");
    printf("-k <pem>    TLS Server TLS Key, default %s\n", WOLFKM_ETSISVC_KEY);
    printf("-w <pass>   TLS Server Key Password, default %s\n", WOLFKM_ETSISVC_KEY_PASSWORD);
    printf("-c <pem>    TLS Server Certificate, default %s\n", WOLFKM_ETSISVC_CERT);
    printf("-A <pem>    TLS CA Certificate, default %s\n", WOLFKM_ETSISVC_CA);
}

static int wolfKeyMgr_AddSigHandler(struct event_base* mainBase,
    SignalArg* sigArg, int sig)
{
    struct event* signalEvent = event_new(mainBase, sig,
        (EV_SIGNAL | EV_PERSIST), wolfKeyMgr_SignalCb, sigArg);
    sigArg->base = mainBase;
    sigArg->ev   = signalEvent;
    return event_add(signalEvent, NULL);
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
    struct event_base*      mainBase = NULL;    /* main thread's base  */
    FILE*                   pidF = 0;
    SvcInfo* etsiSvc = NULL;
    int sec;
    word32 timeoutSec  = WOLFKM_DEFAULT_TIMEOUT, renewSec = WOLFKM_KEY_RENEW_TIMEOUT;
    int disableMutualAuth = 0; /* on by default */
    const char* serverKey = WOLFKM_ETSISVC_KEY;
    const char* serverKeyPass = WOLFKM_ETSISVC_KEY_PASSWORD;
    const char* serverCert = WOLFKM_ETSISVC_CERT;
    const char* caCert = WOLFKM_ETSISVC_CA;
    SignalArg sigArgInt, sigArgTerm;

    /* argument processing */
    while ((ch = getopt(argc, argv, "?bis:t:o:f:l:dk:w:c:A:r:")) != -1) {
        switch (ch) {
            case '?' :
                Usage();
                exit(EXIT_SUCCESS);
            case 'b' :
                daemon = 1;
                break;
            case 'i' :
                core = 1;
                break;
            case 's' :
                sec = atoi(optarg);
                if (sec < 0) {
                    perror("timeout positive values only accepted");
                    exit(EX_USAGE);
                }
                timeoutSec = (word32)sec;
                break;
            case 't' :
                poolSize = atoi(optarg);
                break;
            case 'o' :
                maxFiles = atoi(optarg);
                break;
            case 'f' :
                logName = optarg;
                break;
            case 'p' :
                pidName = optarg;
                break;
            case 'l' :
                logLevel = atoi(optarg);
                if (logLevel < WOLFKM_LOG_ERROR || logLevel > WOLFKM_LOG_DEBUG) {
                    perror("loglevel [1:4] only");
                    exit(EX_USAGE);
                }
                break;
            case 'd':
                disableMutualAuth = 1;
                break;
            case 'k':
                serverKey = optarg;
                break;
            case 'w':
                serverKeyPass = optarg;
                break;
            case 'c':
                serverCert = optarg;
                break;
            case 'A':
                caCert = optarg;
                break;
            case 'r':
                sec = atoi(optarg);
                if (sec < 0) {
                    perror("timeout positive values only accepted");
                    exit(EX_USAGE);
                }
                renewSec = (word32)sec;
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

    /* Initialize variables */
    memset(&sigArgInt, 0, sizeof(sigArgInt));
    memset(&sigArgTerm, 0, sizeof(sigArgTerm));

    /* main thread base event */
    mainBase = event_base_new();
    if (mainBase == NULL) {
        XLOG(WOLFKM_LOG_ERROR, "Failed to event_base_new\n");
        ret = EXIT_FAILURE; goto exit;
    }

    /* setup signal stuff */
    if (wolfSigIgnore(SIGPIPE) == -1) {
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
    etsiSvc = wolfEtsiSvc_Init(mainBase, renewSec);
    if (etsiSvc) {
        /* set socket timeut */
        wolfKeyMgr_SetTimeout(etsiSvc, timeoutSec);

        ret = wolfKeyMgr_LoadCAFile(etsiSvc, caCert, WOLFSSL_FILETYPE_PEM);
        if (ret != 0) {
            XLOG(WOLFKM_LOG_ERROR, "Error loading ETSI TLS CA cert\n");
        }

        ret = wolfKeyMgr_LoadKeyFile(etsiSvc, serverKey, 
            WOLFSSL_FILETYPE_PEM, serverKeyPass);
        if (ret != 0) {
            XLOG(WOLFKM_LOG_ERROR, "Error loading ETSI TLS key\n");
        }

        ret = wolfKeyMgr_LoadCertFile(etsiSvc, serverCert, 
            WOLFSSL_FILETYPE_PEM);
        if (ret != 0) {
            XLOG(WOLFKM_LOG_ERROR, "Error loading ETSI TLS certificate\n");
        }

        etsiSvc->disableMutalAuth = disableMutualAuth;

        /* thread setup - cleanup handled in sigint handler */
        wolfKeyMgr_ServiceInit(etsiSvc, poolSize);
    }

    sigArgInt.svc[0] = etsiSvc;
    sigArgTerm.svc[0] = etsiSvc;

    ret = wolfKeyMgr_AddSigHandler(mainBase, &sigArgInt, SIGINT);
    if (ret == 0) {
        ret = wolfKeyMgr_AddSigHandler(mainBase, &sigArgTerm, SIGTERM);
    }
    if (ret != 0) {
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
    if (sigArgInt.ev) event_del(sigArgInt.ev);
    if (sigArgTerm.ev) event_del(sigArgTerm.ev);
    if (mainBase) event_base_free(mainBase);
    wolfSSL_Cleanup();

    XLOG(WOLFKM_LOG_INFO, "Exit Key Manager (ret %d)\n", ret);

    exit(ret);
}
