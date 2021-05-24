/* svc_etsi.h
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

#ifndef WOLFKM_SVC_ETSI_H
#define WOLFKM_SVC_ETSI_H

#ifdef __cplusplus
extern "C" {
#endif

#define WOLFKM_ETSISVC_PORT         "8119"
#define WOLFKM_ETSISVC_KEY_PASSWORD "wolfssl"
#define WOLFKM_ETSISVC_CA           "./certs/ca-cert.pem"
#define WOLFKM_ETSISVC_KEY          "./certs/server-key.pem"
#define WOLFKM_ETSISVC_CERT         "./certs/server-cert.pem"


WOLFKM_LOCAL SvcInfo* wolfEtsiSvc_Init(struct event_base* mainBase, int renewSec);
WOLFKM_LOCAL void wolfEtsiSvc_Cleanup(SvcInfo* svc);

WOLFKM_LOCAL int wolfEtsiSvc_WorkerInit(SvcInfo* svc, void** svcThreadCtx);
WOLFKM_LOCAL void wolfEtsiSvc_WorkerFree(SvcInfo* svc, void* svcThreadCtx);

WOLFKM_LOCAL int wolfEtsiSvc_DoRequest(SvcConn* conn);
WOLFKM_LOCAL int wolfEtsiSvc_HandleTimeout(SvcConn* conn);
WOLFKM_LOCAL int wolfEtsiSvc_DoNotify(SvcConn* conn);
WOLFKM_LOCAL void wolfEtsiSvc_ConnClose(SvcConn* conn);

#ifdef __cplusplus
}
#endif

#endif /* WOLFKM_SVC_ETSI_H */
