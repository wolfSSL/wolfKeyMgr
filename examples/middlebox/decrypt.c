/* decrypt.c
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

/* Support for ETSI Key Manager */

#include "wolfkeymgr/options.h"
#include "wolfkeymgr/mod_etsi.h"
#include "examples/middlebox/decrypt.h"
#include "examples/test_config.h"

#include <stdio.h>         /* printf */
#include <stdlib.h>        /* EXIT_SUCCESS */

#ifdef WOLFKM_SNIFFER

#include "wolfssl/sniffer.h"

#ifdef _MSC_VER
    /* builds on *nix too, for scanf device and port */
    #define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap/pcap.h>     /* pcap stuff */
#include <string.h>        /* strcmp */
#include <signal.h>        /* signal */
#include <ctype.h>         /* isprint */

#ifndef _WIN32
    #include <sys/socket.h>    /* AF_INET */
    #include <arpa/inet.h>
    #include <netinet/in.h>
#endif


typedef unsigned char byte;

enum {
    ETHER_IF_FRAME_LEN = 14,   /* ethernet interface frame length */
    NULL_IF_FRAME_LEN =   4,   /* no link interface frame length  */
};



static pcap_t* pcap = NULL;
static pcap_if_t* alldevs = NULL;
static int isOfflinePcap = 0;

static EtsiClientCtx* gEtsiClient;

static void etsi_client_cleanup(void)
{
    if (gEtsiClient) {
        wolfEtsiClientFree(gEtsiClient);
        gEtsiClient = NULL;

        wolfEtsiClientCleanup();
    }
}
static int etsi_client_connect(char* urlStr)
{
    int ret = 0;
    static HttpUrl url;
    
    /* setup key manager connection */
    if (gEtsiClient == NULL) {
        wolfEtsiClientInit();

        gEtsiClient = wolfEtsiClientNew();
        if (gEtsiClient) {
            wolfEtsiClientAddCA(gEtsiClient, ETSI_TEST_CLIENT_CA);
            wolfEtsiClientSetKey(gEtsiClient,
                ETSI_TEST_CLIENT_KEY, ETSI_TEST_CLIENT_PASS,
                ETSI_TEST_CLIENT_CERT, WOLFSSL_FILETYPE_PEM);

            if (urlStr) {
                memset(&url, 0, sizeof(url));
                wolfHttpUrlDecode(&url, urlStr);
            }

            ret = wolfEtsiClientConnect(gEtsiClient, url.domain, url.port,
                ETSI_TEST_TIMEOUT_MS);
            if (ret != 0) {
                printf("Error connecting to ETSI server! %d\n", ret);
                
                etsi_client_cleanup();
            }
        }
        else {
            ret = WOLFKM_BAD_MEMORY;
        }
    }
    return ret;
}

static int etsi_client_get(char* urlStr, EtsiKey* key)
{
    int ret;
    
    ret = etsi_client_connect(urlStr);
    if (ret == 0 && key) {
        ret = wolfEtsiClientGet(gEtsiClient, key, ETSI_TEST_KEY_TYPE, 
            NULL, NULL, ETSI_TEST_TIMEOUT_MS);
        /* positive return means new key returned */
        /* zero means, same key is used */
        /* negative means error */
        if (ret < 0) {
            printf("Error getting ETSI static ephemeral key! %d\n", ret);
            etsi_client_cleanup();
        }
        else {
            printf("Got ETSI static ephemeral key (%d bytes)\n",
                key->responseSz);
            wolfEtsiKeyPrint(key);
        }
    }
    return ret;
}

#ifdef WOLFSSL_SNIFFER_KEY_CALLBACK
static int etsi_client_find(char* urlStr, EtsiKey* key, int namedGroup, 
    const byte* pub, word32 pubSz)
{
    int ret;
    
    ret = etsi_client_connect(urlStr);
    if (ret == 0 && key) {
        char fpStr[ETSI_MAX_FINGERPRINT_STR];
        word32 fpStrSz = (word32)sizeof(fpStr);
        ret = wolfEtsiCalcTlsFingerprint((EtsiKeyType)namedGroup, pub, pubSz,
            fpStr, &fpStrSz);
        if (ret == 0) {
            ret = wolfEtsiClientFind(gEtsiClient, key, namedGroup, fpStr,
                NULL, ETSI_TEST_TIMEOUT_MS);
        }
        if (ret < 0) {
            printf("Error finding ETSI static ephemeral key! %d\n", ret);
            etsi_client_cleanup();
        }
        else {
            printf("Found ETSI static ephemeral key (%d bytes)\n",
                key->responseSz);
            wolfEtsiKeyPrint(key);
        }
        (void)fpStrSz;
    }
    return ret;
}

static int myKeyCb(void* vSniffer, int namedGroup,
    const unsigned char* srvPub, unsigned int srvPubSz,
    const unsigned char* cliPub, unsigned int cliPubSz,
    DerBuffer* privKey, void* cbCtx, char* error)
{
    int ret;
    static EtsiKey key;

    ret = etsi_client_find(NULL, &key, namedGroup, srvPub, srvPubSz);
    if (ret >= 0) {
        byte* keyBuf = NULL;
        word32 keySz = 0;
        wolfEtsiKeyGetPtr(&key, &keyBuf, &keySz);

        if (privKey->length != keySz) {
            void* heap = privKey->heap;
            wc_FreeDer(&privKey);
            wc_AllocDer(&privKey, keySz, PRIVATEKEY_TYPE, heap);
        }
        memcpy(privKey->buffer, keyBuf, keySz);
        ret = 0; /* mark success */
    }

    (void)vSniffer;
    (void)cliPub;
    (void)cliPubSz;
    (void)cbCtx;
    (void)error;

    return ret;
}
#endif

static void FreeAll(void)
{
    if (pcap)
        pcap_close(pcap);
    if (alldevs)
        pcap_freealldevs(alldevs);
#ifndef _WIN32
    ssl_FreeSniffer();
#endif
}


#ifdef WOLFSSL_SNIFFER_STATS
static void DumpStats(void)
{
    SSLStats sslStats;
    ssl_ReadStatistics(&sslStats);

    printf("SSL Stats (sslStandardConns):%lu\n",
            sslStats.sslStandardConns);
    printf("SSL Stats (sslClientAuthConns):%lu\n",
            sslStats.sslClientAuthConns);
    printf("SSL Stats (sslResumedConns):%lu\n",
            sslStats.sslResumedConns);
    printf("SSL Stats (sslEphemeralMisses):%lu\n",
            sslStats.sslEphemeralMisses);
    printf("SSL Stats (sslResumeMisses):%lu\n",
            sslStats.sslResumeMisses);
    printf("SSL Stats (sslCiphersUnsupported):%lu\n",
            sslStats.sslCiphersUnsupported);
    printf("SSL Stats (sslKeysUnmatched):%lu\n",
            sslStats.sslKeysUnmatched);
    printf("SSL Stats (sslKeyFails):%lu\n",
            sslStats.sslKeyFails);
    printf("SSL Stats (sslDecodeFails):%lu\n",
            sslStats.sslDecodeFails);
    printf("SSL Stats (sslAlerts):%lu\n",
            sslStats.sslAlerts);
    printf("SSL Stats (sslDecryptedBytes):%lu\n",
            sslStats.sslDecryptedBytes);
    printf("SSL Stats (sslEncryptedBytes):%lu\n",
            sslStats.sslEncryptedBytes);
    printf("SSL Stats (sslEncryptedPackets):%lu\n",
            sslStats.sslEncryptedPackets);
    printf("SSL Stats (sslDecryptedPackets):%lu\n",
            sslStats.sslDecryptedPackets);
    printf("SSL Stats (sslKeyMatches):%lu\n",
            sslStats.sslKeyMatches);
    printf("SSL Stats (sslEncryptedConns):%lu\n",
            sslStats.sslEncryptedConns);
}
#endif /* WOLFSSL_SNIFFER_STATS */


static void sig_handler(const int sig)
{
    printf("SIGINT handled = %d.\n", sig);
    FreeAll();
#ifdef WOLFSSL_SNIFFER_STATS
    DumpStats();
#endif
    if (sig)
        exit(EXIT_SUCCESS);
}

static void err_sys(const char* msg)
{
    fprintf(stderr, "%s\n", msg);
    if (msg)
        exit(EXIT_FAILURE);
}

#ifdef _WIN32
    #define SNPRINTF _snprintf
#else
    #define SNPRINTF snprintf
#endif


static char* iptos(const struct in_addr* addr)
{
    static char output[32];
    byte *p = (byte*)&addr->s_addr;

    snprintf(output, sizeof(output), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);

    return output;
}

static const char* ip6tos(const struct in6_addr* addr)
{
    static char output[42];
    return inet_ntop(AF_INET6, addr, output, 42);
}


/* try and load as both static ephemeral and private key */
/* only fail if no key is loaded */
/* Allow comma seperated list of files */
static int load_key(const char* name, const char* server, int port, 
    const char* keyFiles, const char* passwd, char* err)
{
    int ret = -1;
    int loadCount = 0;
    char *keyFile, *ptr = NULL;

    keyFile = strtok_r((char*)keyFiles, ",", &ptr);
    while (keyFile != NULL) {
        /* is URL? */
        if (strncmp(keyFile, "https://", 8) == 0) {
            EtsiKey key;
            memset(&key, 0, sizeof(key));
            /* setup connection */
            ret = etsi_client_get(keyFile, &key);
            if (ret < 0) {
                printf("Error connecting to ETSI server: %s\n", keyFile);
            }
            else {
                byte* keyBuf = NULL;
                word32 keySz = 0;
                wolfEtsiKeyGetPtr(&key, &keyBuf, &keySz);
            #ifdef HAVE_SNI
                ret = ssl_SetNamedEphemeralKeyBuffer(name, server, port,
                    (char*)keyBuf, keySz, FILETYPE_DER, passwd, err);
            #else
                ret = ssl_SetEphemeralKeyBuffer(server, port,
                    (char*)keyBuf, keySz, FILETYPE_DER, passwd, err);
            #endif
            }
        }
        else {
        #ifdef HAVE_SNI
            ret = ssl_SetNamedEphemeralKey(name, server, port, keyFile,
                                FILETYPE_PEM, passwd, err);
        #else
            ret = ssl_SetEphemeralKey(server, port, keyFile,
                                FILETYPE_PEM, passwd, err);
        #endif
            if (ret == 0)
                loadCount++;
        }
        if (ret == 0)
            loadCount++;
        
        if (loadCount == 0) {
            printf("Failed loading private key %s: ret %d\n", keyFile, ret);
            ret = -1;
        }
        else {
            printf("Loaded key for %s:%d\n", server, port);
            ret = 0;
        }

        keyFile = strtok_r(NULL, ",", &ptr);
    }

    (void)name;
    return ret;
}

static void TrimNewLine(char* str)
{
    word32 strSz = 0;
    if (str)
        strSz = (word32)strlen(str);
    if (strSz > 0 && (str[strSz-1] == '\n' || str[strSz-1] == '\r'))
        str[strSz-1] = '\0';
}

int middlebox_decrypt_test(int argc, char** argv)
{
    int          ret = 0;
    int          hadBadPacket = 0;
    int          inum = 0;
    int          port = 0, portDef = HTTPS_TEST_PORT;
    int          i = 0, defDev = 0;
    int          frame = ETHER_IF_FRAME_LEN;
    char         err[PCAP_ERRBUF_SIZE];
    char         filter[32];
    const char  *keyFilesSrc = "https://" ETSI_TEST_HOST ":" ETSI_TEST_PORT_STR;
    char         keyFilesBuf[MAX_FILENAME_SZ];
    char         keyFilesUser[MAX_FILENAME_SZ];
    const char  *server = NULL;
    const char  *sniName = NULL;
    struct       bpf_program fp;
    pcap_if_t   *d;
    pcap_addr_t *a;

    signal(SIGINT, sig_handler);

#ifndef _WIN32
    ssl_InitSniffer();   /* dll load on Windows */
#endif
#ifdef DEBUG_WOLFSSL
    /* log setup */
    wolfSSL_Debugging_ON();
    wolfKeyMgr_SetLogFile(NULL, 0, WOLFKM_LOG_DEBUG);
#endif
    ssl_Trace("./tracefile.txt", err);
    ssl_EnableRecovery(1, -1, err);
#ifdef WOLFSSL_SNIFFER_KEY_CALLBACK
    ssl_SetKeyCallback(myKeyCb, NULL);
#endif

    if (argc == 1) {
        char cmdLineArg[128];
        /* normal case, user chooses device and port */

        if (pcap_findalldevs(&alldevs, err) == -1)
            err_sys("Error in pcap_findalldevs");

        for (d = alldevs; d; d=d->next) {
            printf("%d. %s", ++i, d->name);
            if (strcmp(d->name, "lo") == 0 || strcmp(d->name, "lo0") == 0) {
                defDev = i;
            }
            if (d->description)
                printf(" (%s)\n", d->description);
            else
                printf(" (No description available)\n");
        }

        if (i == 0)
            err_sys("No interfaces found! Make sure pcap or WinPcap is"
                    " installed correctly and you have sufficient permissions");

        printf("Enter the interface number (1-%d) [default: %d]: ", i, defDev);
        memset(cmdLineArg, 0, sizeof(cmdLineArg));
        if (fgets(cmdLineArg, sizeof(cmdLineArg), stdin))
            inum = atoi(cmdLineArg);
        if (inum == 0) {
            if (defDev == 0) defDev = 1;
            inum = defDev;
        }
        if (inum < 1 || inum > i) {
            err_sys("Interface number out of range");
        }

        /* Jump to the selected adapter */
        for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

        pcap = pcap_create(d->name, err);

        if (pcap == NULL) printf("pcap_create failed %s\n", err);

        /* print out addresses for selected interface */
        for (a = d->addresses; a; a = a->next) {
            if (a->addr->sa_family == AF_INET) {
                server =
                    iptos(&((struct sockaddr_in *)a->addr)->sin_addr);
                printf("server = %s\n", server);
            }
            else if (a->addr->sa_family == AF_INET6) {
                server =
                    ip6tos(&((struct sockaddr_in6 *)a->addr)->sin6_addr);
                printf("server = %s\n", server);
            }
        }
        if (server == NULL)
            err_sys("Unable to get device IPv4 or IPv6 address");

        ret = pcap_set_snaplen(pcap, 65536);
        if (ret != 0) printf("pcap_set_snaplen failed %s\n", pcap_geterr(pcap));

        ret = pcap_set_timeout(pcap, 1000);
        if (ret != 0) printf("pcap_set_timeout failed %s\n", pcap_geterr(pcap));

        ret = pcap_set_buffer_size(pcap, 1000000);
        if (ret != 0)
            printf("pcap_set_buffer_size failed %s\n", pcap_geterr(pcap));

        ret = pcap_set_promisc(pcap, 1);
        if (ret != 0) printf("pcap_set_promisc failed %s\n", pcap_geterr(pcap));


        ret = pcap_activate(pcap);
        if (ret != 0) printf("pcap_activate failed %s\n", pcap_geterr(pcap));

        printf("Enter the port to scan [default: %d]: ", portDef);
        memset(cmdLineArg, 0, sizeof(cmdLineArg));
        if (fgets(cmdLineArg, sizeof(cmdLineArg), stdin)) {
            port = atoi(cmdLineArg);
        }
        if (port <= 0) {
            port = portDef;
        }

        SNPRINTF(filter, sizeof(filter), "tcp and port %d", port);

        ret = pcap_compile(pcap, &fp, filter, 0, 0);
        if (ret != 0) {
            printf("pcap_compile failed %s\n", pcap_geterr(pcap));
            printf("Try using `sudo` permissions with middlebox/decrypt\n");
            exit(EXIT_FAILURE);
        }

        ret = pcap_setfilter(pcap, &fp);
        if (ret != 0) printf("pcap_setfilter failed %s\n", pcap_geterr(pcap));

        /* specify the key file or URL for ETSI key manager */
        printf("Enter the server key [default: %s]: ", keyFilesSrc);
        memset(keyFilesBuf, 0, sizeof(keyFilesBuf));
        memset(keyFilesUser, 0, sizeof(keyFilesUser));
        if (fgets(keyFilesUser, sizeof(keyFilesUser), stdin)) {
            TrimNewLine(keyFilesUser);
            if (strlen(keyFilesUser) > 0) {
                keyFilesSrc = keyFilesUser;
            }
        }
        strncpy(keyFilesBuf, keyFilesSrc, sizeof(keyFilesBuf));

        /* optionally enter a named key (SNI) */
    #if !defined(WOLFSSL_SNIFFER_WATCH) && defined(HAVE_SNI)
        printf("Enter alternate SNI [default: none]: ");
        memset(cmdLineArg, 0, sizeof(cmdLineArg));
        if (fgets(cmdLineArg, sizeof(cmdLineArg), stdin)) {
            TrimNewLine(cmdLineArg);
            if (strlen(cmdLineArg) > 0) {
                sniName = cmdLineArg;
            }
        }
    #endif /* !WOLFSSL_SNIFFER_WATCH && HAVE_SNI */

        /* get IPv4 or IPv6 addresses for selected interface */
        for (a = d->addresses; a; a = a->next) {
            server = NULL;
            if (a->addr->sa_family == AF_INET) {
                server =
                    iptos(&((struct sockaddr_in *)a->addr)->sin_addr);
            }
            else if (a->addr->sa_family == AF_INET6) {
                server =
                    ip6tos(&((struct sockaddr_in6 *)a->addr)->sin6_addr);
            }

            if (server) {
                strncpy(keyFilesBuf, keyFilesSrc, sizeof(keyFilesBuf));
                ret = load_key(sniName, server, port, keyFilesBuf, NULL, err);
                if (ret != 0) {
                    exit(EXIT_FAILURE);
                }
            }
        }
    }
    else if (argc >= 2) {
        isOfflinePcap = 1;
        pcap = pcap_open_offline(argv[1], err);
        if (pcap == NULL) {
            printf("pcap_open_offline failed %s\n", err);
            ret = -1;
        }
        else {
            const char* passwd = NULL;

            /* defaults for server and port */
            port = portDef;
            server = "127.0.0.1";

            if (argc >= 3)
                keyFilesSrc = argv[2];
            if (argc >= 4)
                server = argv[3];
            if (argc >= 5)
                port = atoi(argv[4]);
            if (argc >= 6)
                passwd = argv[5];

            ret = load_key(NULL, server, port, keyFilesSrc, passwd, err);
            if (ret != 0) {
                exit(EXIT_FAILURE);
            }

            /* Only let through TCP/IP packets */
            ret = pcap_compile(pcap, &fp, "(ip6 or ip) and tcp", 0, 0);
            if (ret != 0) {
                printf("pcap_compile failed %s\n", pcap_geterr(pcap));
                exit(EXIT_FAILURE);
            }

            ret = pcap_setfilter(pcap, &fp);
            if (ret != 0) {
                printf("pcap_setfilter failed %s\n", pcap_geterr(pcap));
                exit(EXIT_FAILURE);
            }
        }
    }
    else {
        /* usage error */
        printf( "usage: ./decrypt or ./decrypt dumpFile keyServerURL"
                " [server] [port] [password]\n");
        exit(EXIT_FAILURE);
    }

    if (ret != 0)
        err_sys(err);

    if (pcap_datalink(pcap) == DLT_NULL)
        frame = NULL_IF_FRAME_LEN;

    while (1) {
        static int packetNumber = 0;
        struct pcap_pkthdr header;
        const unsigned char* packet = pcap_next(pcap, &header);
        SSLInfo sslInfo;
        packetNumber++;
        if (packet) {

            byte* data = NULL;

            if (header.caplen > 40)  { /* min ip(20) + min tcp(20) */
                packet        += frame;
                header.caplen -= frame;
            }
            else
                continue;

            ret = ssl_DecodePacketWithSessionInfo(packet, header.caplen, &data,
                                                  &sslInfo, err);
            if (ret < 0) {
                printf("ssl_Decode ret = %d, %s\n", ret, err);
                hadBadPacket = 1;
            }
            if (ret > 0) {
                int j;
                /* Convert non-printable data to periods. */
                for (j = 0; j < ret; j++) {
                    if (isprint(data[j]) || isspace(data[j])) continue;
                    data[j] = '.';
                }
                data[ret] = 0;
                printf("SSL App Data(%d:%d):%s\n", packetNumber, ret, data);
                ssl_FreeZeroDecodeBuffer(&data, ret, err);
            }
        }
        else if (isOfflinePcap)
            break;      /* we're done reading file */
    }
    FreeAll();

    return hadBadPacket ? EXIT_FAILURE : EXIT_SUCCESS;
}
#endif /* WOLFKM_SNIFFER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char** argv)
{
#ifdef WOLFKM_SNIFFER
    return middlebox_decrypt_test(argc, argv);
#else
    printf("To enable sniffer use ./configure --enable-sniffer with wolfKeyMgr and wolfSSL\n");
    (void)argc;
    (void)argv;
    return EXIT_SUCCESS;
#endif
}
#endif /* !NO_MAIN_DRIVER */
