/*
  Copyright (C) 2010 - 2026 Proxmox Server Solutions GmbH

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Affero General Public License for more details.

  You should have received a copy of the GNU Affero General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.

  Author: Dietmar Maurer <dietmar@proxmox.com>

*/

#ifndef _PVE_DFSM_H_
#define _PVE_DFSM_H_

#include <corosync/corotypes.h>
#include <corosync/cpg.h>

#include "loop.h"

typedef struct dfsm dfsm_t;

typedef struct {
    uint32_t nodeid;
    uint32_t pid;
    gpointer state;
    unsigned int state_len;
    gboolean synced;
} dfsm_node_info_t;

typedef struct {
    int node_count;
    gpointer data; /* app can use that */
    dfsm_node_info_t *local;
    dfsm_node_info_t nodes[];
} dfsm_sync_info_t;

/* return values:
 * res <= 0    ... serious error, leave group
 * res > 0    ... OK, continue
 */
typedef int (*dfsm_deliver_fn_t)(
    dfsm_t *dfsm,
    gpointer data,
    int *res_ptr,
    uint32_t nodeid,
    uint32_t pid,
    uint16_t msgtype,
    uint32_t msg_time,
    const void *msg,
    size_t msg_len
);

typedef void (*dfsm_confchg_fn_t)(
    dfsm_t *dfsm, gpointer data, const struct cpg_address *member_list, size_t member_list_entries
);

/* return values:
 * res == NULL ... serious error, leave group
 * res != NULL ... OK, continue
 */
typedef gpointer (*dfsm_get_state_fn_t)(dfsm_t *dfsm, gpointer data, unsigned int *res_len);

typedef gboolean (*dfsm_checksum_fn_t)(
    dfsm_t *dfsm, gpointer data, unsigned char *csum, size_t csum_len
);

typedef int (*dfsm_process_state_update_fn_t)(
    dfsm_t *dfsm, gpointer data, dfsm_sync_info_t *syncinfo
);

typedef void (*dfsm_synced_fn_t)(dfsm_t *dfsm);

typedef void (*dfsm_in_sync_fn_t)(dfsm_t *dfsm, gpointer data);

/* return values:
 * res < 0    ... serious error, leave group
 * res >=  0  ... OK
 */
typedef int (*dfsm_process_update_fn_t)(
    dfsm_t *dfsm,
    gpointer data,
    dfsm_sync_info_t *syncinfo,
    uint32_t nodeid,
    uint32_t pid,
    const void *msg,
    size_t msg_len
);

typedef struct {
    dfsm_deliver_fn_t dfsm_deliver_fn;
    dfsm_confchg_fn_t dfsm_confchg_fn;
    dfsm_get_state_fn_t dfsm_get_state_fn;
    dfsm_process_state_update_fn_t dfsm_process_state_update_fn;
    dfsm_process_state_update_fn_t dfsm_commit_fn;
    dfsm_process_state_update_fn_t dfsm_cleanup_fn;
    dfsm_process_update_fn_t dfsm_process_update_fn;
    dfsm_checksum_fn_t dfsm_checksum_fn;
    dfsm_synced_fn_t dfsm_synced_fn;
    /* Called whenever this node has marked all members as synced and delivered the messages queued
     * meanwhile, so that the local state matches the one of all members: first right after a sync,
     * then again on every service timer tick while that holds. dfsm_synced_fn runs earlier, when
     * the local node enters the synced mode and before the queued messages are delivered. */
    dfsm_in_sync_fn_t dfsm_in_sync_fn;
} dfsm_callbacks_t;

/* what became of a message sent with dfsm_send_message_sync */
typedef enum {
    DFSM_OUTCOME_PENDING = 0,
    /* this member processed it, the result is valid */
    DFSM_OUTCOME_PROCESSED,
    /* no member processed it, and none will, with one rare exception described at
     * dfsm_cpg_send_failed_early */
    DFSM_OUTCOME_NOT_APPLIED,
    /* this member could not confirm it, while others might process it */
    DFSM_OUTCOME_UNKNOWN,
} dfsm_outcome_t;

typedef struct {
    uint64_t msgcount;
    int result; /* we only have integer results for now */
    dfsm_outcome_t outcome;
    /* internal: came back while this member waited for updates, so synced members processed it */
    gboolean delivered_unsynced;
} dfsm_result_t;

dfsm_t *dfsm_new(
    gpointer data,
    const char *group_name,
    const char *log_domain,
    guint32 protocol_version,
    dfsm_callbacks_t *callbacks
);

void dfsm_destroy(dfsm_t *dfsm);

cs_error_t dfsm_initialize(dfsm_t *dfsm, int *fd);

gboolean dfsm_finalize(dfsm_t *dfsm);

cs_error_t dfsm_join(dfsm_t *dfsm);

cs_error_t dfsm_leave(dfsm_t *dfsm);

cs_error_t dfsm_dispatch(dfsm_t *dfsm, cs_dispatch_flags_t dispatch_types);

gboolean dfsm_restartable(dfsm_t *dfsm);

gboolean dfsm_is_initialized(dfsm_t *dfsm);

void dfsm_set_errormode(dfsm_t *dfsm);

cs_error_t dfsm_send_message(dfsm_t *dfsm, uint16_t msgtype, struct iovec *iov, int len);

/* only call this from another thread - else you get blocked forever
 *
 * Without rp, CS_OK only means that the message was sent. With rp, it returns CS_OK once this
 * member processed the message, with its result in rp. Otherwise rp->outcome tells whether other
 * members might still process it. */
cs_error_t dfsm_send_message_sync(
    dfsm_t *dfsm, uint16_t msgtype, struct iovec *iov, int len, dfsm_result_t *rp
);

/* Like dfsm_send_message, but returns CS_ERR_TRY_AGAIN at once if corosync applies flow control,
 * instead of retrying for up to ten seconds. For callers that try again later anyway. */
cs_error_t dfsm_send_message_once(dfsm_t *dfsm, uint16_t msgtype, struct iovec *iov, int len);

cs_error_t dfsm_send_update(dfsm_t *dfsm, struct iovec *iov, unsigned int len);

cs_error_t dfsm_send_update_complete(dfsm_t *dfsm);

gboolean dfsm_lowest_nodeid(dfsm_t *dfsm);

/* whether a process of that node is a member of the current group, loop thread only */
gboolean dfsm_nodeid_is_member(dfsm_t *dfsm, uint32_t nodeid);

gboolean dfsm_nodeid_is_local(dfsm_t *dfsm, uint32_t nodeid, uint32_t pid);

cs_error_t dfsm_verify_request(dfsm_t *dfsm);

cfs_service_t *service_dfsm_new(dfsm_t *dfsm);

void service_dfsm_destroy(cfs_service_t *service);

#endif /* _PVE_DFSM_H_ */
