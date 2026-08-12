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
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#define WOLFKM_PASSWORD_MAX 255

static int LoadPasswordFile(const char* fileName, char* password,
    size_t passwordSz)
{
    int ret = 0;
    int fd;
    size_t length = 0;
    ssize_t readSz;
    struct stat fileStat;
    char input[WOLFKM_PASSWORD_MAX + 3];

    if (fileName == NULL || password == NULL || passwordSz < 2)
        return WOLFKM_BAD_ARGS;

    fd = open(fileName, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return WOLFKM_BAD_FILE;

    if (fstat(fd, &fileStat) != 0 || !S_ISREG(fileStat.st_mode) ||
            (fileStat.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        ret = WOLFKM_BAD_FILE;
    }
    while (ret == 0 && length < sizeof(input)) {
        readSz = read(fd, input + length, sizeof(input) - length);
        if (readSz > 0) {
            length += (size_t)readSz;
        }
        else if (readSz == 0) {
            break;
        }
        else if (errno != EINTR) {
            ret = WOLFKM_BAD_FILE;
        }
    }
    if (ret == 0 && length == sizeof(input))
        ret = WOLFKM_BAD_ARGS;
    if (ret == 0 && length > 0 && input[length - 1] == '\n') {
        length--;
        if (length > 0 && input[length - 1] == '\r')
            length--;
    }
    else if (ret == 0 && length > 0 && input[length - 1] == '\r') {
        length--;
    }
    if (ret == 0) {
        if (length == 0 || length >= passwordSz ||
                memchr(input, '\0', length) != NULL) {
            ret = WOLFKM_BAD_ARGS;
        }
        else {
            memcpy(password, input, length);
            password[length] = '\0';
        }
    }

    close(fd);
    wolfKeyMgr_ForceZero(input, sizeof(input));
    if (ret != 0)
        wolfKeyMgr_ForceZero(password, (word32)passwordSz);

    return ret;
}

/* usage help */
static void Usage(void)
{
    printf("%s\n", PACKAGE_STRING);
    printf("-?          Help, print this usage\n");
    printf("-i          Do not chdir / in daemon mode\n");
    printf("-b          Daemon mode, run in background\n");
    printf("-p <str>    Pid File name, default %s\n", WOLFKM_DEFAULT_PID);
    printf("-P <port>   Listener port, default %s\n", WOLFKM_ETSSVC_PORT);
    printf("-l <num>    Log Level (1=Error to 4=Debug), default %d\n", WOLFKM_DEFAULT_LOG_LEVEL);
    printf("-f <str>    Log file name, default %s\n",
                          WOLFKM_DEFAULT_LOG_NAME ? WOLFKM_DEFAULT_LOG_NAME : "None");
    printf("-o <num>    Max open files, default  %d\n", WOLFKM_DEFAULT_FILES);
    printf("-s <num>    Seconds to timeout non-push connections, default %d\n", WOLFKM_DEFAULT_TIMEOUT);
    printf("-r <num>    Key renewal timeout, default %d\n", WOLFKM_KEY_RENEW_TIMEOUT);
    printf("-u <num>    Key renewal max use count, default %d\n", WOLFKM_KEY_RENEW_MAX_USES);
    printf("-t <num>    Thread pool size, default  %ld\n",
                                                 sysconf(_SC_NPROCESSORS_CONF));
    printf("-k <pem>    TLS Server Key (required)\n");
    printf("-W <file>   TLS Server Key Password File (required)\n");
    printf("-c <pem>    TLS Server Certificate (required)\n");
    printf("-A <pem>    TLS CA Certificate (required)\n");
    printf("-K <keyt>   Key Type: SECP256R1, FFDHE_2048, X25519 or X448 (default %s)\n",
        wolfEtsKeyGetTypeStr(WOLFKM_ETSSVC_DEF_KEY_TYPE));
    printf("-v <file>   Vault file for key storage, default %s\n", WOLFKM_ETSSVC_VAULT);
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
    int daemon = 0;
    int core = 0;
    int poolSize = (int)sysconf(_SC_NPROCESSORS_CONF);
    int maxFiles = WOLFKM_DEFAULT_FILES;
    enum log_level_t logLevel = WOLFKM_DEFAULT_LOG_LEVEL;
    char* logName = WOLFKM_DEFAULT_LOG_NAME;
    char* pidName = WOLFKM_DEFAULT_PID;
    struct event_base* mainBase = NULL;    /* main thread's base  */
    FILE* pidF = 0;
    SvcInfo* etsSvc = NULL;
    word32 timeoutSec  = WOLFKM_DEFAULT_TIMEOUT;
    const char* serverKey = NULL;
    const char* serverKeyPassFile = NULL;
    const char* serverCert = NULL;
    const char* caCert = NULL;
    char serverKeyPass[WOLFKM_PASSWORD_MAX + 1];
    SignalArg sigArgInt, sigArgTerm;
    const char* vaultFile = WOLFKM_ETSSVC_VAULT;
    const char* listenPort = WOLFKM_ETSSVC_PORT;
    EtsSvcConfig config;

    memset(&config, 0, sizeof(config));
    memset(serverKeyPass, 0, sizeof(serverKeyPass));
    config.keyTypeDef = WOLFKM_ETSSVC_DEF_KEY_TYPE;
    config.renewSec = WOLFKM_KEY_RENEW_TIMEOUT;
    config.maxUseCount = WOLFKM_KEY_RENEW_MAX_USES;

    /* argument processing */
    opterr = 0;
    while ((ch = getopt(argc, argv, "bis:t:o:f:l:k:W:c:A:r:u:K:v:p:P:")) != -1) {
        switch (ch) {
            case '?' :
                Usage();
                exit(optopt == '?' ? EXIT_SUCCESS : EX_USAGE);
            case 'b' :
                daemon = 1;
                break;
            case 'i' :
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
            case 'o' :
                maxFiles = atoi(optarg);
                break;
            case 'f' :
                logName = optarg;
                break;
            case 'p' :
                pidName = optarg;
                break;
            case 'P':
                listenPort = optarg;
                break;
            case 'l' :
                logLevel = atoi(optarg);
                if (logLevel < WOLFKM_LOG_ERROR || logLevel > WOLFKM_LOG_DEBUG) {
                    perror("loglevel [1:4] only");
                    exit(EX_USAGE);
                }
                break;
            case 'k':
                serverKey = optarg;
                break;
            case 'W':
                serverKeyPassFile = optarg;
                break;
            case 'c':
                serverCert = optarg;
                break;
            case 'A':
                caCert = optarg;
                break;
            case 'r':
            {
                int sec = atoi(optarg);
                if (sec < 0) {
                    perror("key renew must be positive value");
                    exit(EX_USAGE);
                }
                config.renewSec = (word32)sec;
                break;
            }
            case 'u':
            {
                int uses = atoi(optarg);
                if (uses < 0) {
                    perror("key max uses must be positive value");
                    exit(EX_USAGE);
                }
                config.maxUseCount = (word32)uses;
                break;
            }
            case 'K':
            {
                /* find key type */
                int i;
                for (i=(int)ETS_KEY_TYPE_MIN; i<=(int)ETS_KEY_TYPE_FFDHE_8192; i++) {
                    const char* keyStr = wolfEtsKeyGetTypeStr((EtsKeyType)i);
                    if (keyStr != NULL) {
                        if (strncmp(optarg, keyStr, strlen(keyStr)) == 0) {
                            config.keyTypeDef = (EtsKeyType)i;
                            break;
                        }
                    }
                }
                break;
            }
            case 'v':
                vaultFile = optarg;
                break;
            default:
                Usage();
                exit(EX_USAGE);
        }
    }

    if (serverKey == NULL || serverKeyPassFile == NULL || serverCert == NULL ||
            caCert == NULL) {
        fprintf(stderr, "TLS key, password file, certificate and CA are required\n");
        Usage();
        exit(EX_USAGE);
    }
    ret = LoadPasswordFile(serverKeyPassFile, serverKeyPass,
        sizeof(serverKeyPass));
    if (ret != 0) {
        fprintf(stderr, "TLS key password file must be non-empty and "
            "accessible only by its owner\n");
        exit(EX_USAGE);
    }
    /* Create daemon */
    if (daemon) {
        if (logName == NULL) {
            perror("daemon mode needs a log file, cannot write to stderr");
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
    XLOG(WOLFKM_LOG_INFO, "\tTo exit use ctrl+c\n");

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

    /********** ETS Service **********/
    etsSvc = wolfEtsSvc_Init(&config);
    if (etsSvc) {
        /* set socket timeout */
        wolfKeyMgr_SetTimeout(etsSvc, timeoutSec);

        ret = wolfKeyMgr_LoadCAFile(etsSvc, caCert, WOLFSSL_FILETYPE_PEM);
        if (ret != 0) {
            XLOG(WOLFKM_LOG_ERROR, "Error %d loading ETS TLS CA cert\n", ret);
            goto exit;
        }

        ret = wolfKeyMgr_LoadKeyFile(etsSvc, serverKey,
            WOLFSSL_FILETYPE_PEM, serverKeyPass);
        wolfKeyMgr_ForceZero(serverKeyPass, sizeof(serverKeyPass));
        if (ret != 0) {
            XLOG(WOLFKM_LOG_ERROR, "Error %d loading ETS TLS key\n", ret);
            goto exit;
        }

        ret = wolfKeyMgr_LoadCertFile(etsSvc, serverCert,
            WOLFSSL_FILETYPE_PEM);
        if (ret != 0) {
            XLOG(WOLFKM_LOG_ERROR, "Error %d loading ETS TLS certificate\n", ret);
            goto exit;
        }

        /* open vault and use server key for encryption */
        ret = wolfEtsSvc_SetVaultFile(etsSvc, vaultFile);
        if (ret != 0) {
            XLOG(WOLFKM_LOG_ERROR, "Error opening vault: %d\n", ret);
            goto exit;
        }

        wolfEtsSvc_Start(etsSvc, mainBase, listenPort);

        /* thread setup - cleanup handled in sigint handler */
        wolfKeyMgr_ServiceInit(etsSvc, poolSize);
    }

    sigArgInt.svc[0] = etsSvc;
    sigArgTerm.svc[0] = etsSvc;

    ret = wolfKeyMgr_AddSigHandler(mainBase, &sigArgInt, SIGINT);
    if (ret == 0) {
        ret = wolfKeyMgr_AddSigHandler(mainBase, &sigArgTerm, SIGTERM);
    }
    if (ret != 0) {
        XLOG(WOLFKM_LOG_ERROR, "Error adding event for signal\n");
        ret = EXIT_FAILURE; goto exit;
    }

    /* start main loop */
    event_base_dispatch(mainBase);

    /* we're done with loop */
    ret = EXIT_SUCCESS;
    XLOG(WOLFKM_LOG_INFO, "Done with main thread dispatching\n");
    wolfKeyMgr_ShowStats(etsSvc);

exit:
    wolfKeyMgr_ForceZero(serverKeyPass, sizeof(serverKeyPass));

    /* Cleanup pid file */
    if (pidF) {
        fclose(pidF);
        unlink(pidName);
    }

    wolfKeyMgr_FreeListeners();

    wolfEtsSvc_Cleanup(etsSvc);
    if (sigArgInt.ev) event_del(sigArgInt.ev);
    if (sigArgTerm.ev) event_del(sigArgTerm.ev);
    if (mainBase) event_base_free(mainBase);
    wolfSSL_Cleanup();

    XLOG(WOLFKM_LOG_INFO, "Exit Key Manager (ret %d)\n", ret);

    exit(ret);
}
