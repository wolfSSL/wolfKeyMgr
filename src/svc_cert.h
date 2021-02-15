/* svc_cert.h
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

#ifndef WOLFKM_SVC_CERT_H
#define WOLFKM_SVC_CERT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "keymanager.h"

#define WOLFKM_CERTSVC_PORT         "8118"
#define WOLFKM_CERTSVC_KEY_PASSWORD "wolfssl"
#define WOLFKM_CERTSVC_KEY          "./certs/test-key.pem"
#define WOLFKM_CERTSVC_CERT         "./certs/test-cert.pem"

enum CertServiceMisc {
    CERT_HEADER_SZ             =     4,        /* version (1), type(1), len(2) */
    CERT_VERSION               =     1,        /* current version */
    CERT_HEADER_VERSION_OFFSET =     0,        /* at front */
    CERT_HEADER_TYPE_OFFSET    =     1,        /* version (1) */
    CERT_HEADER_SZ_OFFSET      =     2,        /* version (1), type(1) */
    WORD16_LEN                 =     2,        /* sizeof word16 */
    MAX_PASSWORD_SZ            =   160,        /* max password size */

    WOLFKM_DEFAULT_MAX_SIGNS   = 5000          /* default max signs b4 re-init */
                                               /* 1,600,000 max / 32 (seed) /
                                                * 10 (our safety) */
};

enum CertMessageTypes {
    ERROR_RESPONSE      =     0,             /* error response type */
    CERT_REQUEST        =     1,             /* cert request type */
    CERT_RESPONSE       =     2,             /* cert response type */
    SIGN_REQUEST        =     3,             /* sign request type */
    SIGN_RESPONSE       =     4,             /* sign response type */
    VERIFY_REQUEST      =     5,             /* verify request type */
    VERIFY_RESPONSE     =     6              /* verify response type */
};



svcInfo* wolfCertSvc_Init(struct event_base* mainBase, word32 timeoutSec);
void wolfCertSvc_Cleanup(svcInfo* svc);

int wolfCertSvc_WorkerInit(svcInfo* svc, void** svcCtx);
void wolfCertSvc_WorkerFree(svcInfo* svc, void* svcCtx);

int wolfCertSvc_DoRequest(svcConn* conn);


#ifdef __cplusplus
}
#endif

#endif /* WOLFKM_SVC_CERT_H */
