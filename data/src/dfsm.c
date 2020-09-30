/*
  Copyright (C) 2010 Proxmox Server Solutions GmbH

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


/* NOTE: we try to keep the CPG handle as long as possible, because
 * calling cpg_initialize/cpg_finalize multiple times from the 
 * same process confuses corosync.
 * Note: CS_ERR_LIBRARY is returned when corosync died
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>
#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <corosync/corotypes.h>
#include <corosync/cpg.h>
#include <glib.h>

#include "cfs-utils.h"
#include "dfsm.h"

static cpg_callbacks_t cpg_callbacks;

typedef enum {
	DFSM_MODE_START = 0,
	DFSM_MODE_START_SYNC = 1,
	DFSM_MODE_SYNCED = 2,
	DFSM_MODE_UPDATE = 3,

	/* values >= 128 indicates abnormal/error conditions */
	DFSM_ERROR_MODE_START = 128,
	DFSM_MODE_LEAVE = 253,
	DFSM_MODE_VERSION_ERROR = 254,
	DFSM_MODE_ERROR = 255,
} dfsm_mode_t;

typedef enum {
	DFSM_MESSAGE_NORMAL = 0,
	DFSM_MESSAGE_SYNC_START = 1,
	DFSM_MESSAGE_STATE = 2,
	DFSM_MESSAGE_UPDATE = 3,
	DFSM_MESSAGE_UPDATE_COMPLETE = 4,
	DFSM_MESSAGE_VERIFY_REQUEST = 5,
	DFSM_MESSAGE_VERIFY = 6,
} dfsm_message_t;

#define DFSM_VALID_STATE_MESSAGE(mt) (mt >= DFSM_MESSAGE_SYNC_START && mt <= DFSM_MESSAGE_VERIFY)

typedef struct {
	uint16_t type;
	uint16_t subtype;
	uint32_t protocol_version;
	uint32_t time;
	uint32_t reserved;
} dfsm_message_header_t;

typedef struct {
	uint32_t epoch; // per process (not globally unique) 
	uint32_t time;
	uint32_t nodeid;
	uint32_t pid;
} dfsm_sync_epoch_t;

typedef struct {
	dfsm_message_header_t base;
	dfsm_sync_epoch_t epoch;
} dfsm_message_state_header_t;

typedef struct {
	dfsm_message_header_t base;
	uint64_t count;
} dfsm_message_normal_header_t;

typedef struct {
	uint32_t nodeid;
	uint32_t pid;
	uint64_t msg_count;
	void *msg;
	int msg_len; // fixme: unsigned?
} dfsm_queued_message_t;

struct dfsm {
	const char *log_domain;
	cpg_callbacks_t *cpg_callbacks;
	dfsm_callbacks_t *dfsm_callbacks;
	cpg_handle_t cpg_handle;
	GMutex cpg_mutex;
	struct cpg_name cpg_group_name;
	uint32_t nodeid;
	uint32_t pid;
	int we_are_member;

	guint32 protocol_version;
	gpointer data;

	gboolean joined;

	/* mode is protected with mode_mutex */
	GMutex mode_mutex;
	dfsm_mode_t mode;

	GHashTable *members; /* contains dfsm_node_info_t pointers  */
	dfsm_sync_info_t *sync_info;
	uint32_t local_epoch_counter;
	dfsm_sync_epoch_t sync_epoch;
	uint32_t lowest_nodeid; 
	GSequence *msg_queue; 
	GList *sync_queue;

	/* synchrounous message transmission, protected with sync_mutex */
	GMutex sync_mutex;
	GCond sync_cond;
	GHashTable *results;
	uint64_t msgcount;
	uint64_t msgcount_rcvd;

	/* state verification */
	guchar csum[32];
	dfsm_sync_epoch_t csum_epoch;
	uint64_t csum_id;
	uint64_t csum_counter;
};

static gboolean dfsm_deliver_queue(dfsm_t *dfsm);
static gboolean dfsm_deliver_sync_queue(dfsm_t *dfsm);

gboolean 
dfsm_nodeid_is_local(
	dfsm_t *dfsm, 
	uint32_t nodeid, 
	uint32_t pid)
{
	g_return_val_if_fail(dfsm != NULL, FALSE);

	return (nodeid == dfsm->nodeid && pid == dfsm->pid); 
}


static void 
dfsm_send_sync_message_abort(dfsm_t *dfsm)
{
	g_return_if_fail(dfsm != NULL);

	g_mutex_lock (&dfsm->sync_mutex);
	dfsm->msgcount_rcvd = dfsm->msgcount;
	g_cond_broadcast (&dfsm->sync_cond);
	g_mutex_unlock (&dfsm->sync_mutex);
}

static void 
dfsm_record_local_result(
	dfsm_t *dfsm,
	uint64_t msg_count,
	int msg_result,
	gboolean processed)
{
	g_return_if_fail(dfsm != NULL);
	g_return_if_fail(dfsm->results != NULL);

	g_mutex_lock (&dfsm->sync_mutex);
	dfsm_result_t *rp = (dfsm_result_t *)g_hash_table_lookup(dfsm->results, &msg_count);
	if (rp) {
		rp->result = msg_result;
		rp->processed = processed;
	}
	dfsm->msgcount_rcvd = msg_count;
	g_cond_broadcast (&dfsm->sync_cond);
	g_mutex_unlock (&dfsm->sync_mutex);
}

static cs_error_t 
dfsm_send_message_full(
	dfsm_t *dfsm,
	struct iovec *iov, 
	unsigned int len,
	int retry)
{
	g_return_val_if_fail(dfsm != NULL, CS_ERR_INVALID_PARAM);
	g_return_val_if_fail(!len || iov != NULL, CS_ERR_INVALID_PARAM);

	struct timespec tvreq = { .tv_sec = 0, .tv_nsec = 100000000 };
	cs_error_t result;
	int retries = 0;
loop:
	g_mutex_lock (&dfsm->cpg_mutex);
	result = cpg_mcast_joined(dfsm->cpg_handle, CPG_TYPE_AGREED, iov, len);
	g_mutex_unlock (&dfsm->cpg_mutex);
	if (retry && result == CS_ERR_TRY_AGAIN) {
		nanosleep(&tvreq, NULL);
		++retries;
		if ((retries % 10) == 0)
			cfs_dom_message(dfsm->log_domain, "cpg_send_message retry %d", retries);
		if (retries < 100)
			goto loop;
	}

	if (retries)
		cfs_dom_message(dfsm->log_domain, "cpg_send_message retried %d times", retries);

	if (result != CS_OK &&
	    (!retry || result != CS_ERR_TRY_AGAIN))
		cfs_dom_critical(dfsm->log_domain, "cpg_send_message failed: %d", result);

	return result;
}

static cs_error_t 
dfsm_send_state_message_full(
	dfsm_t *dfsm,
	uint16_t type,
	struct iovec *iov, 
	unsigned int len) 
{
	g_return_val_if_fail(dfsm != NULL, CS_ERR_INVALID_PARAM);
	g_return_val_if_fail(DFSM_VALID_STATE_MESSAGE(type), CS_ERR_INVALID_PARAM);
	g_return_val_if_fail(!len || iov != NULL, CS_ERR_INVALID_PARAM);

	dfsm_message_state_header_t header;
	header.base.type = type;
	header.base.subtype = 0;
	header.base.protocol_version = dfsm->protocol_version;
	header.base.time = time(NULL);
	header.base.reserved = 0;

	header.epoch = dfsm->sync_epoch;

	struct iovec real_iov[len + 1];

	real_iov[0].iov_base = (char *)&header;
	real_iov[0].iov_len = sizeof(header);

	for (int i = 0; i < len; i++)
		real_iov[i + 1] = iov[i];

	return dfsm_send_message_full(dfsm, real_iov, len + 1, 1);
}

cs_error_t 
dfsm_send_update(
	dfsm_t *dfsm,
	struct iovec *iov, 
	unsigned int len)
{
	return dfsm_send_state_message_full(dfsm, DFSM_MESSAGE_UPDATE, iov, len);
}

cs_error_t 
dfsm_send_update_complete(dfsm_t *dfsm)
{
	return dfsm_send_state_message_full(dfsm, DFSM_MESSAGE_UPDATE_COMPLETE, NULL, 0);
}


cs_error_t 
dfsm_send_message(
	dfsm_t *dfsm,
	uint16_t msgtype,
	struct iovec *iov, 
	int len)
{
	return dfsm_send_message_sync(dfsm, msgtype, iov, len, NULL);
}

cs_error_t 
dfsm_send_message_sync(
	dfsm_t *dfsm,
	uint16_t msgtype,
	struct iovec *iov, 
	int len,
	dfsm_result_t *rp)
{
	g_return_val_if_fail(dfsm != NULL, CS_ERR_INVALID_PARAM);
	g_return_val_if_fail(!len || iov != NULL, CS_ERR_INVALID_PARAM);

	g_mutex_lock (&dfsm->sync_mutex);
	/* note: hold lock until message is sent - to guarantee ordering */
	uint64_t msgcount = ++dfsm->msgcount;
	if (rp) {
		rp->msgcount = msgcount;
		rp->processed = 0;
		g_hash_table_replace(dfsm->results, &rp->msgcount, rp);
	}

	dfsm_message_normal_header_t header;
	header.base.type = DFSM_MESSAGE_NORMAL;
	header.base.subtype = msgtype;
	header.base.protocol_version = dfsm->protocol_version;
	header.base.time = time(NULL);
	header.base.reserved = 0;
	header.count = msgcount;

	struct iovec real_iov[len + 1];

	real_iov[0].iov_base = (char *)&header;
	real_iov[0].iov_len = sizeof(header);

	for (int i = 0; i < len; i++)
		real_iov[i + 1] = iov[i];

	cs_error_t result = dfsm_send_message_full(dfsm, real_iov, len + 1, 1);

	g_mutex_unlock (&dfsm->sync_mutex);

	if (result != CS_OK) {
		cfs_dom_critical(dfsm->log_domain, "cpg_send_message failed: %d", result);

		if (rp) {
			g_mutex_lock (&dfsm->sync_mutex);
			g_hash_table_remove(dfsm->results, &rp->msgcount);
			g_mutex_unlock (&dfsm->sync_mutex);
		}
		return result;
	}

	if (rp) {
		g_mutex_lock (&dfsm->sync_mutex);

		while (dfsm->msgcount_rcvd < msgcount)
			g_cond_wait (&dfsm->sync_cond, &dfsm->sync_mutex);

      
		g_hash_table_remove(dfsm->results, &rp->msgcount);
		
		g_mutex_unlock (&dfsm->sync_mutex);

		return rp->processed ? CS_OK : CS_ERR_FAILED_OPERATION;
	}

	return CS_OK;
}

static gboolean 
dfsm_send_checksum(dfsm_t *dfsm)
{
	g_return_val_if_fail(dfsm != NULL, FALSE);

	int len = 2;
	struct iovec iov[len];

	iov[0].iov_base = (char *)&dfsm->csum_id;
	iov[0].iov_len = sizeof(dfsm->csum_id);
	iov[1].iov_base = dfsm->csum;
	iov[1].iov_len = sizeof(dfsm->csum);
	
	gboolean res = (dfsm_send_state_message_full(dfsm, DFSM_MESSAGE_VERIFY, iov, len) == CS_OK);

	return res;
}

static void 
dfsm_free_queue_entry(gpointer data)
{
	dfsm_queued_message_t *qm = (dfsm_queued_message_t *)data;
	g_free (qm->msg);
	g_free (qm);
}

static void 
dfsm_free_message_queue(dfsm_t *dfsm) 
{
	g_return_if_fail(dfsm != NULL);
	g_return_if_fail(dfsm->msg_queue != NULL);

	GSequenceIter *iter = g_sequence_get_begin_iter(dfsm->msg_queue);
	GSequenceIter *end = g_sequence_get_end_iter(dfsm->msg_queue);
	while (iter != end) {
		GSequenceIter *cur = iter; 
		iter = g_sequence_iter_next(iter);
		dfsm_queued_message_t *qm = (dfsm_queued_message_t *)
			g_sequence_get(cur);
		dfsm_free_queue_entry(qm);
		g_sequence_remove(cur);
	}
}

static void 
dfsm_free_sync_queue(dfsm_t *dfsm) 
{
	g_return_if_fail(dfsm != NULL);

	GList *iter = dfsm->sync_queue;
	while (iter) {
		dfsm_queued_message_t *qm = (dfsm_queued_message_t *)iter->data;
		iter = g_list_next(iter);
		dfsm_free_queue_entry(qm);
	}

	g_list_free(dfsm->sync_queue);
	dfsm->sync_queue = NULL;
}

static gint 
message_queue_sort_fn(
	gconstpointer a,
	gconstpointer b,
	gpointer user_data)
{
	return ((dfsm_queued_message_t *)a)->msg_count - 
		((dfsm_queued_message_t *)b)->msg_count;
}

static dfsm_node_info_t *
dfsm_node_info_lookup(
	dfsm_t *dfsm,
	uint32_t nodeid, 
	uint32_t pid)
{
	g_return_val_if_fail(dfsm != NULL, NULL);
	g_return_val_if_fail(dfsm->members != NULL, NULL);

	dfsm_node_info_t info = { .nodeid = nodeid, .pid = pid };

	return (dfsm_node_info_t *)g_hash_table_lookup(dfsm->members, &info);
}

static dfsm_queued_message_t *
dfsm_queue_add_message(
	dfsm_t *dfsm,
	uint32_t nodeid,
	uint32_t pid,
	uint64_t msg_count,
	const void *msg,
	size_t msg_len)
{
	g_return_val_if_fail(dfsm != NULL, NULL);
	g_return_val_if_fail(msg != NULL, NULL);
	g_return_val_if_fail(msg_len != 0, NULL);

	dfsm_node_info_t *ni = dfsm_node_info_lookup(dfsm, nodeid, pid);
	if (!ni) {
		cfs_dom_critical(dfsm->log_domain, "dfsm_node_info_lookup failed");
		return NULL;
	}

	dfsm_queued_message_t *qm = g_new0(dfsm_queued_message_t, 1);
	g_return_val_if_fail(qm != NULL, NULL);
		
	qm->nodeid = nodeid;
	qm->pid = pid;
	qm->msg = g_memdup (msg, msg_len);
	qm->msg_len = msg_len;
	qm->msg_count =  msg_count;

	if (dfsm->mode == DFSM_MODE_UPDATE && ni->synced) {
		dfsm->sync_queue = g_list_append(dfsm->sync_queue, qm);
	} else {
		/* NOTE: we only need to sort the queue because we resend all
		 * queued messages sometimes.   
		 */
		g_sequence_insert_sorted(dfsm->msg_queue, qm, message_queue_sort_fn, NULL);
	}

	return qm;
}

static guint 
dfsm_sync_info_hash(gconstpointer key)
{
	dfsm_node_info_t *info = (dfsm_node_info_t *)key;

	return g_int_hash(&info->nodeid) + g_int_hash(&info->pid);
}

static gboolean 
dfsm_sync_info_equal(
	gconstpointer v1, 
	gconstpointer v2)
{
	dfsm_node_info_t *info1 = (dfsm_node_info_t *)v1;
	dfsm_node_info_t *info2 = (dfsm_node_info_t *)v2;

	if (info1->nodeid == info2->nodeid &&
	    info1->pid == info2->pid)
		return TRUE;

	return FALSE;
}

static int 
dfsm_sync_info_compare(
	gconstpointer v1, 
	gconstpointer v2)
{
	dfsm_node_info_t *info1 = (dfsm_node_info_t *)v1;
	dfsm_node_info_t *info2 = (dfsm_node_info_t *)v2;

	if (info1->nodeid != info2->nodeid)
		return info1->nodeid - info2->nodeid;

	return info1->pid - info2->pid;
}

static void 
dfsm_set_mode(
	dfsm_t *dfsm, 
	dfsm_mode_t new_mode)
{
	g_return_if_fail(dfsm != NULL);

	cfs_debug("dfsm_set_mode - set mode to %d", new_mode);

	int changed = 0;
	g_mutex_lock (&dfsm->mode_mutex);
	if (dfsm->mode != new_mode) {
		if (new_mode < DFSM_ERROR_MODE_START ||
		    (dfsm->mode < DFSM_ERROR_MODE_START || new_mode >= dfsm->mode)) {
			dfsm->mode = new_mode;
			changed = 1;
		}
	}
	g_mutex_unlock (&dfsm->mode_mutex);

	if (!changed)
		return;

	if (new_mode == DFSM_MODE_START) {
		cfs_dom_message(dfsm->log_domain, "start cluster connection");
	} else if (new_mode == DFSM_MODE_START_SYNC) {
		cfs_dom_message(dfsm->log_domain, "starting data syncronisation");
	} else if (new_mode == DFSM_MODE_SYNCED) {
		cfs_dom_message(dfsm->log_domain, "all data is up to date");
		if (dfsm->dfsm_callbacks->dfsm_synced_fn)
			dfsm->dfsm_callbacks->dfsm_synced_fn(dfsm);
	} else if (new_mode == DFSM_MODE_UPDATE) {
		cfs_dom_message(dfsm->log_domain, "waiting for updates from leader");	
	} else if (new_mode == DFSM_MODE_LEAVE) {
		cfs_dom_critical(dfsm->log_domain, "leaving CPG group");	
	} else if (new_mode == DFSM_MODE_ERROR) {
		cfs_dom_critical(dfsm->log_domain, "serious internal error - stop cluster connection"); 
	} else if (new_mode == DFSM_MODE_VERSION_ERROR) {
		cfs_dom_critical(dfsm->log_domain, "detected newer protocol - please update this node"); 
	}
}

static dfsm_mode_t 
dfsm_get_mode(dfsm_t *dfsm)
{
	g_return_val_if_fail(dfsm != NULL, DFSM_MODE_ERROR);

	g_mutex_lock (&dfsm->mode_mutex);
	dfsm_mode_t mode = dfsm->mode;
	g_mutex_unlock (&dfsm->mode_mutex);

	return mode;
}

gboolean 
dfsm_restartable(dfsm_t *dfsm)
{
	dfsm_mode_t mode = dfsm_get_mode(dfsm);

	return !(mode == DFSM_MODE_ERROR || 
		 mode == DFSM_MODE_VERSION_ERROR);
}

void
dfsm_set_errormode(dfsm_t *dfsm)
{
	dfsm_set_mode(dfsm, DFSM_MODE_ERROR);
}

static void 
dfsm_release_sync_resources(
	dfsm_t *dfsm,
	const struct cpg_address *member_list, 
	size_t member_list_entries)
{
	g_return_if_fail(dfsm != NULL);
	g_return_if_fail(dfsm->members != NULL);
	g_return_if_fail(!member_list_entries || member_list != NULL);

	cfs_debug("enter dfsm_release_sync_resources");

	if (dfsm->sync_info) {

		if (dfsm->sync_info->data && dfsm->dfsm_callbacks->dfsm_cleanup_fn) {
			dfsm->dfsm_callbacks->dfsm_cleanup_fn(dfsm, dfsm->data, dfsm->sync_info);
			dfsm->sync_info->data = NULL;
		}
		
		for (int i = 0; i < dfsm->sync_info->node_count; i++) {
			if (dfsm->sync_info->nodes[i].state) {
				g_free(dfsm->sync_info->nodes[i].state);
				dfsm->sync_info->nodes[i].state = NULL;
				dfsm->sync_info->nodes[i].state_len = 0;
			}			
		}
	}

	if (member_list) {

		g_hash_table_remove_all(dfsm->members);

		if (dfsm->sync_info)
			g_free(dfsm->sync_info);

		int size = sizeof(dfsm_sync_info_t) + 
			member_list_entries*sizeof(dfsm_sync_info_t);
		dfsm_sync_info_t *sync_info = dfsm->sync_info = g_malloc0(size); 
		sync_info->node_count = member_list_entries;

		for (int i = 0; i < member_list_entries; i++) {
			sync_info->nodes[i].nodeid = member_list[i].nodeid;
			sync_info->nodes[i].pid = member_list[i].pid;
		}

		qsort(sync_info->nodes, member_list_entries, sizeof(dfsm_node_info_t),
		      dfsm_sync_info_compare);

		for (int i = 0; i < member_list_entries; i++) {
			dfsm_node_info_t *info = &sync_info->nodes[i];
			g_hash_table_insert(dfsm->members, info, info);
			if (info->nodeid == dfsm->nodeid && info->pid == dfsm->pid)
				sync_info->local = info;
		}
	} 
}

static void 
dfsm_cpg_deliver_callback(
	cpg_handle_t handle,
	const struct cpg_name *group_name,
	uint32_t nodeid,
	uint32_t pid,
	void *msg,
	size_t msg_len)
{
	cs_error_t result;

	dfsm_t *dfsm = NULL;
	result = cpg_context_get(handle, (gpointer *)&dfsm);
	if (result != CS_OK || !dfsm || dfsm->cpg_callbacks != &cpg_callbacks) {
		cfs_critical("cpg_context_get error: %d (%p)", result, (void *) dfsm);
		return; /* we have no valid dfsm pointer, so we can just ignore this */
	}
	dfsm_mode_t mode = dfsm_get_mode(dfsm);

	cfs_dom_debug(dfsm->log_domain, "dfsm mode is %d", mode);

	if (mode >= DFSM_ERROR_MODE_START) {
		cfs_dom_debug(dfsm->log_domain, "error mode - ignoring message");
		goto leave;
	}

	if (!dfsm->sync_info) {
		cfs_dom_critical(dfsm->log_domain, "no dfsm_sync_info - internal error");
		goto leave;
	}

	if (msg_len < sizeof(dfsm_message_header_t)) {
		cfs_dom_critical(dfsm->log_domain, "received short message (%zd bytes)", msg_len);
		goto leave;
	}

	dfsm_message_header_t *base_header = (dfsm_message_header_t *)msg;
	
	if (base_header->protocol_version > dfsm->protocol_version) {
		cfs_dom_critical(dfsm->log_domain, "received message with protocol version %d", 
				 base_header->protocol_version);
		dfsm_set_mode(dfsm, DFSM_MODE_VERSION_ERROR);
		return;
	} else if (base_header->protocol_version < dfsm->protocol_version) {
		cfs_dom_message(dfsm->log_domain, "ignore message with wrong protocol version %d", 
				base_header->protocol_version);
		return;
	}

	if (base_header->type == DFSM_MESSAGE_NORMAL) {

		dfsm_message_normal_header_t *header = (dfsm_message_normal_header_t *)msg;

		if (msg_len < sizeof(dfsm_message_normal_header_t)) {
			cfs_dom_critical(dfsm->log_domain, "received short message (type = %d, subtype = %d, %zd bytes)",
					 base_header->type, base_header->subtype, msg_len);
			goto leave;
		}

		if (mode != DFSM_MODE_SYNCED) {
			cfs_dom_debug(dfsm->log_domain, "queue message %" PRIu64 " (subtype = %d, length = %zd)",
				      header->count, base_header->subtype, msg_len); 

			if (!dfsm_queue_add_message(dfsm, nodeid, pid, header->count, msg, msg_len))
				goto leave;
		} else {

			int msg_res = -1;
			int res = dfsm->dfsm_callbacks->dfsm_deliver_fn(
				dfsm, dfsm->data, &msg_res, nodeid, pid, base_header->subtype, 
				base_header->time, (uint8_t *)msg + sizeof(dfsm_message_normal_header_t),
				msg_len - sizeof(dfsm_message_normal_header_t));

			if (nodeid == dfsm->nodeid && pid == dfsm->pid)
				dfsm_record_local_result(dfsm, header->count, msg_res, res);

			if (res < 0)
				goto leave;
		}

		return;
	} 

	/* state related messages
	 * we needs right epoch - else we simply discard the message 
	 */

	dfsm_message_state_header_t *header = (dfsm_message_state_header_t *)msg;

	if (msg_len < sizeof(dfsm_message_state_header_t)) {
		cfs_dom_critical(dfsm->log_domain, "received short state message (type = %d, subtype = %d, %zd bytes)",
				 base_header->type, base_header->subtype, msg_len);
		goto leave;
	}

	if (base_header->type != DFSM_MESSAGE_SYNC_START && 
	    (memcmp(&header->epoch, &dfsm->sync_epoch, sizeof(dfsm_sync_epoch_t)) != 0)) {
		cfs_dom_debug(dfsm->log_domain, "ignore message (msg_type == %d) with "
			      "wrong epoch (epoch %d/%d/%08X)", base_header->type, 
			      header->epoch.nodeid, header->epoch.pid, header->epoch.epoch);
		return;
	}

	msg = (uint8_t *) msg + sizeof(dfsm_message_state_header_t);
	msg_len -= sizeof(dfsm_message_state_header_t);

	if (mode == DFSM_MODE_SYNCED) {
		if (base_header->type == DFSM_MESSAGE_UPDATE_COMPLETE) {

			for (int i = 0; i < dfsm->sync_info->node_count; i++)
				dfsm->sync_info->nodes[i].synced = 1;

			if (!dfsm_deliver_queue(dfsm))
				goto leave;

			return;

		} else if (base_header->type == DFSM_MESSAGE_VERIFY_REQUEST) {

			if (msg_len != sizeof(dfsm->csum_counter)) {
				cfs_dom_critical(dfsm->log_domain, "cpg received verify request with wrong length (%zd bytes) form node %d/%d", msg_len, nodeid, pid);
				goto leave;
			}

			uint64_t csum_id = *((uint64_t *)msg);
			msg = (uint8_t *) msg + 8; msg_len -= 8;

			cfs_dom_debug(dfsm->log_domain, "got verify request from node %d %016" PRIX64, nodeid, csum_id);

			if (dfsm->dfsm_callbacks->dfsm_checksum_fn) {
				if (!dfsm->dfsm_callbacks->dfsm_checksum_fn(
					    dfsm, dfsm->data, dfsm->csum, sizeof(dfsm->csum))) {
					cfs_dom_critical(dfsm->log_domain, "unable to compute data checksum");
					goto leave;
				}

				dfsm->csum_epoch = header->epoch;
				dfsm->csum_id = csum_id;

				if (nodeid == dfsm->nodeid && pid == dfsm->pid) {
					if (!dfsm_send_checksum(dfsm)) 
						goto leave;
				}
			}

			return;

		} else if (base_header->type == DFSM_MESSAGE_VERIFY) {
		
			cfs_dom_debug(dfsm->log_domain, "received verify message");
			
			if (dfsm->dfsm_callbacks->dfsm_checksum_fn) {

				if (msg_len != (sizeof(dfsm->csum_id) + sizeof(dfsm->csum))) {
					cfs_dom_critical(dfsm->log_domain, "cpg received verify message with wrong length (%zd bytes)", msg_len);
					goto leave;
				}

				uint64_t csum_id = *((uint64_t *)msg);
				msg = (uint8_t *) msg + 8; msg_len -= 8;
				
				if (dfsm->csum_id == csum_id &&
				    (memcmp(&dfsm->csum_epoch, &header->epoch, sizeof(dfsm_sync_epoch_t)) == 0)) {
					if (memcmp(msg, dfsm->csum, sizeof(dfsm->csum)) != 0) {
						cfs_dom_critical(dfsm->log_domain, "wrong checksum %016" PRIX64 " != %016" PRIX64 " - restarting",
								 *(uint64_t *)msg, *(uint64_t *)dfsm->csum);
						goto leave;
					} else {
						cfs_dom_message(dfsm->log_domain, "data verification successful");
					}
				} else {
					cfs_dom_message(dfsm->log_domain, "skip verification - no checksum saved");
				}
			}

			return;

		} else {
			/* ignore (we already got all required updates, or we are leader) */
			cfs_dom_debug(dfsm->log_domain, "ignore state sync message %d", 
				      base_header->type);
			return;
		}
		
	} else if (mode == DFSM_MODE_START_SYNC) {

		if (base_header->type == DFSM_MESSAGE_SYNC_START) {

			if (nodeid != dfsm->lowest_nodeid) {
				cfs_dom_critical(dfsm->log_domain, "ignore sync request from wrong member %d/%d",
						 nodeid, pid);
			}

			cfs_dom_message(dfsm->log_domain, "received sync request (epoch %d/%d/%08X)",
					header->epoch.nodeid, header->epoch.pid, header->epoch.epoch);

			dfsm->sync_epoch = header->epoch;

			dfsm_release_sync_resources(dfsm, NULL, 0);

			unsigned int state_len = 0;
			gpointer state = NULL;
			
			state = dfsm->dfsm_callbacks->dfsm_get_state_fn(dfsm, dfsm->data, &state_len);

			if (!(state && state_len)) {
				cfs_dom_critical(dfsm->log_domain, "dfsm_get_state_fn failed");
				goto leave;
			}

			struct iovec iov[1];
			iov[0].iov_base = state;
			iov[0].iov_len = state_len;

			result = dfsm_send_state_message_full(dfsm, DFSM_MESSAGE_STATE, iov, 1);

			if (state)
				g_free(state);

			if (result != CS_OK)
				goto leave;

			return;

		} else if (base_header->type == DFSM_MESSAGE_STATE) {

			dfsm_node_info_t *ni;
			
			if (!(ni = dfsm_node_info_lookup(dfsm, nodeid, pid))) {
				cfs_dom_critical(dfsm->log_domain, "received state for non-member %d/%d", nodeid, pid);
				goto leave;
			}

			if (ni->state) {
				cfs_dom_critical(dfsm->log_domain, "received duplicate state for member %d/%d", nodeid, pid);
				goto leave;
			}

			ni->state = g_memdup(msg, msg_len);
			ni->state_len = msg_len;

			int received_all = 1;
			for (int i = 0; i < dfsm->sync_info->node_count; i++) {
				if (!dfsm->sync_info->nodes[i].state) {
					received_all = 0;
					break;
				}
			}

			if (received_all) {
				cfs_dom_message(dfsm->log_domain, "received all states");

				int res = dfsm->dfsm_callbacks->dfsm_process_state_update_fn(dfsm, dfsm->data, dfsm->sync_info);
				if (res < 0)
					goto leave;

				if (dfsm->sync_info->local->synced)  {
					dfsm_set_mode(dfsm, DFSM_MODE_SYNCED);
					dfsm_release_sync_resources(dfsm, NULL, 0);

					if (!dfsm_deliver_queue(dfsm))
						goto leave;
					
				} else {
					dfsm_set_mode(dfsm, DFSM_MODE_UPDATE);

					if (!dfsm_deliver_queue(dfsm))
						goto leave;
				}

			}

			return;
		}

	} else if (mode == DFSM_MODE_UPDATE) {

		if (base_header->type == DFSM_MESSAGE_UPDATE) {
				
			int res = dfsm->dfsm_callbacks->dfsm_process_update_fn(
				dfsm, dfsm->data, dfsm->sync_info, nodeid, pid, msg, msg_len);

			if (res < 0)
				goto leave;

			return;

		} else if (base_header->type == DFSM_MESSAGE_UPDATE_COMPLETE) {


			int res = dfsm->dfsm_callbacks->dfsm_commit_fn(dfsm, dfsm->data, dfsm->sync_info);

			if (res < 0)
				goto leave;

			for (int i = 0; i < dfsm->sync_info->node_count; i++)
				dfsm->sync_info->nodes[i].synced = 1;

			dfsm_set_mode(dfsm, DFSM_MODE_SYNCED);

			if (!dfsm_deliver_sync_queue(dfsm))
				goto leave;

			if (!dfsm_deliver_queue(dfsm))
				goto leave;

			dfsm_release_sync_resources(dfsm, NULL, 0);

			return;
		}

	} else {
		cfs_dom_critical(dfsm->log_domain, "internal error - unknown mode %d", mode);
		goto leave;
	}

	if (base_header->type == DFSM_MESSAGE_VERIFY_REQUEST ||
	    base_header->type == DFSM_MESSAGE_VERIFY) {

		cfs_dom_debug(dfsm->log_domain, "ignore verify message %d while not synced", base_header->type);
    
	} else {
		cfs_dom_critical(dfsm->log_domain, "received unknown state message type (type = %d, %zd bytes)",
				 base_header->type, msg_len);
		goto leave;
	}

leave:
	dfsm_set_mode(dfsm, DFSM_MODE_LEAVE);
	dfsm_release_sync_resources(dfsm, NULL, 0);
	return;
}

static gboolean 
dfsm_resend_queue(dfsm_t *dfsm)
{
	g_return_val_if_fail(dfsm != NULL, FALSE);
	g_return_val_if_fail(dfsm->msg_queue != NULL, FALSE);

	GSequenceIter *iter = g_sequence_get_begin_iter(dfsm->msg_queue);
	GSequenceIter *end = g_sequence_get_end_iter(dfsm->msg_queue);
	gboolean res = TRUE;

	while (iter != end) {
		GSequenceIter *cur = iter; 
		iter = g_sequence_iter_next(iter);

		dfsm_queued_message_t *qm = (dfsm_queued_message_t *)
			g_sequence_get(cur);

		if (qm->nodeid == dfsm->nodeid && qm->pid == dfsm->pid) {
			cs_error_t result;
			struct iovec iov[1];
			iov[0].iov_base = qm->msg;
			iov[0].iov_len = qm->msg_len;

			if ((result = dfsm_send_message_full(dfsm, iov, 1, 1)) != CS_OK) {
				res = FALSE;			
				break;
			}
		}
	}

	dfsm_free_message_queue(dfsm);

	return res;
}

static gboolean
dfsm_deliver_sync_queue(dfsm_t *dfsm) 
{
	g_return_val_if_fail(dfsm != NULL, FALSE);

	if (!dfsm->sync_queue)
		return TRUE;

	gboolean res = TRUE;

	// fixme: cfs_debug
	cfs_dom_message(dfsm->log_domain, "%s: queue length %d", __func__, 
			g_list_length(dfsm->sync_queue));

	GList *iter = dfsm->sync_queue;
	while (iter) {
		dfsm_queued_message_t *qm = (dfsm_queued_message_t *)iter->data;
		iter = g_list_next(iter);

		if (res && dfsm->mode == DFSM_MODE_SYNCED) {		
			dfsm_cpg_deliver_callback(dfsm->cpg_handle, &dfsm->cpg_group_name,
						  qm->nodeid, qm->pid, qm->msg, qm->msg_len);
		} else {
			res = FALSE;
		}

		dfsm_free_queue_entry(qm);
	}
	g_list_free(dfsm->sync_queue);
	dfsm->sync_queue = NULL;

	return res;
}

static gboolean 
dfsm_deliver_queue(dfsm_t *dfsm)
{
	g_return_val_if_fail(dfsm != NULL, FALSE);
	g_return_val_if_fail(dfsm->msg_queue != NULL, FALSE);

	int qlen = g_sequence_get_length(dfsm->msg_queue);
	if (!qlen)
		return TRUE;

	GSequenceIter *iter = g_sequence_get_begin_iter(dfsm->msg_queue);
	GSequenceIter *end = g_sequence_get_end_iter(dfsm->msg_queue);
	gboolean res = TRUE;

	// fixme: cfs_debug
	cfs_dom_message(dfsm->log_domain, "%s: queue length %d", __func__, qlen);

	while (iter != end) {
		GSequenceIter *cur = iter; 
		iter = g_sequence_iter_next(iter);

		dfsm_queued_message_t *qm = (dfsm_queued_message_t *)
			g_sequence_get(cur);
	
		dfsm_node_info_t *ni = dfsm_node_info_lookup(dfsm, qm->nodeid, qm->pid);
		if (!ni) {
			cfs_dom_message(dfsm->log_domain, "remove message from non-member %d/%d", 
					qm->nodeid, qm->pid);
			dfsm_free_queue_entry(qm);
			g_sequence_remove(cur);
			continue;
		}

		if (dfsm->mode == DFSM_MODE_SYNCED) {
			if (ni->synced) {
				dfsm_cpg_deliver_callback(dfsm->cpg_handle, &dfsm->cpg_group_name,
							  qm->nodeid, qm->pid, qm->msg, qm->msg_len);
				dfsm_free_queue_entry(qm);
				g_sequence_remove(cur);
			}
		} else if (dfsm->mode == DFSM_MODE_UPDATE) {
			if (ni->synced) {
				dfsm->sync_queue = g_list_append(dfsm->sync_queue, qm);
				g_sequence_remove(cur);
			}
		} else {
			res = FALSE;
			break;
		}
	}

	return res;
}

static void 
dfsm_cpg_confchg_callback(
	cpg_handle_t handle,
	const struct cpg_name *group_name,
	const struct cpg_address *member_list, 
	size_t member_list_entries,
	const struct cpg_address *left_list, 
	size_t left_list_entries,
	const struct cpg_address *joined_list, 
	size_t joined_list_entries)
{
	cs_error_t result;

	dfsm_t *dfsm = NULL;
	result = cpg_context_get(handle, (gpointer *)&dfsm);
	if (result != CS_OK || !dfsm || dfsm->cpg_callbacks != &cpg_callbacks) {
		cfs_critical("cpg_context_get error: %d (%p)", result, (void *) dfsm);
		return; /* we have no valid dfsm pointer, so we can just ignore this */
	}

	dfsm->we_are_member = 0;

	/* create new epoch */
	dfsm->local_epoch_counter++;
	dfsm->sync_epoch.epoch = dfsm->local_epoch_counter;
	dfsm->sync_epoch.nodeid = dfsm->nodeid;
	dfsm->sync_epoch.pid = dfsm->pid;
	dfsm->sync_epoch.time = time(NULL);

	/* invalidate saved checksum */
	dfsm->csum_id = dfsm->csum_counter;
	memset(&dfsm->csum_epoch, 0, sizeof(dfsm->csum_epoch));

	dfsm_free_sync_queue(dfsm);

	dfsm_mode_t mode = dfsm_get_mode(dfsm);

	cfs_dom_debug(dfsm->log_domain, "dfsm mode is %d", mode);

	if (mode >= DFSM_ERROR_MODE_START) {
		cfs_dom_debug(dfsm->log_domain, "already left group - ignore message");
		return;
	}

	int lowest_nodeid = 0;
	GString *member_ids = g_string_new(NULL);
	for (int i = 0; i < member_list_entries; i++) {

		g_string_append_printf(member_ids, i ? ", %d/%d" : "%d/%d",
				       member_list[i].nodeid, member_list[i].pid);

		if (lowest_nodeid == 0 || lowest_nodeid > member_list[i].nodeid)
			lowest_nodeid =  member_list[i].nodeid;

		if (member_list[i].nodeid == dfsm->nodeid &&
		    member_list[i].pid == dfsm->pid)
			dfsm->we_are_member = 1;
	}


	if ((dfsm->we_are_member || mode != DFSM_MODE_START))
		cfs_dom_message(dfsm->log_domain, "members: %s",  member_ids->str);

	g_string_free(member_ids, 1);

	dfsm->lowest_nodeid = lowest_nodeid;

	/* NOTE: one node can be in left and joined list at the same time,
	   so it is better to query member list. Also JOIN/LEAVE list are
	   different on different nodes!
	*/

	dfsm_release_sync_resources(dfsm, member_list, member_list_entries);

	if (!dfsm->we_are_member) {
		if (mode == DFSM_MODE_START) {
			cfs_dom_debug(dfsm->log_domain, "ignore leave message");
			return;
		}
		cfs_dom_message(dfsm->log_domain, "we (%d/%d) left the process group", 
				dfsm->nodeid, dfsm->pid);
		goto leave;
	}

	if (member_list_entries > 1) {

		int qlen = g_sequence_get_length(dfsm->msg_queue);
		if (joined_list_entries && qlen) {
			/* we need to make sure that all members have the same queue. */
			cfs_dom_message(dfsm->log_domain, "queue not emtpy - resening %d messages", qlen);
			if (!dfsm_resend_queue(dfsm)) {
				cfs_dom_critical(dfsm->log_domain, "dfsm_resend_queue failed");
				goto leave;
			}
		}

		dfsm_set_mode(dfsm, DFSM_MODE_START_SYNC);
		if (lowest_nodeid == dfsm->nodeid) {
			if (dfsm_send_state_message_full(dfsm, DFSM_MESSAGE_SYNC_START, NULL, 0) != CS_OK) {
				cfs_dom_critical(dfsm->log_domain, "failed to send SYNC_START message");
				goto leave;
			}
		}
	} else {
		dfsm_set_mode(dfsm, DFSM_MODE_SYNCED);
		dfsm->sync_info->local->synced = 1;
		if (!dfsm_deliver_queue(dfsm))
			goto leave;
	}

	if (dfsm->dfsm_callbacks->dfsm_confchg_fn) 
		dfsm->dfsm_callbacks->dfsm_confchg_fn(dfsm, dfsm->data, member_list, member_list_entries);

	return;
leave:
	dfsm_set_mode(dfsm, DFSM_MODE_LEAVE);
	return;
}

static cpg_callbacks_t cpg_callbacks = {
	.cpg_deliver_fn = dfsm_cpg_deliver_callback,
	.cpg_confchg_fn = dfsm_cpg_confchg_callback,
};

dfsm_t *
dfsm_new(
	gpointer data, 
	const char *group_name, 
	const char *log_domain,
	guint32 protocol_version, 
	dfsm_callbacks_t *callbacks)
{
	g_return_val_if_fail(sizeof(dfsm_message_header_t) == 16, NULL);
	g_return_val_if_fail(sizeof(dfsm_message_state_header_t) == 32, NULL);
	g_return_val_if_fail(sizeof(dfsm_message_normal_header_t) == 24, NULL);	

	g_return_val_if_fail(callbacks != NULL, NULL);
	g_return_val_if_fail(callbacks->dfsm_deliver_fn != NULL, NULL);

	g_return_val_if_fail(callbacks->dfsm_get_state_fn != NULL, NULL);
	g_return_val_if_fail(callbacks->dfsm_process_state_update_fn != NULL, NULL);
	g_return_val_if_fail(callbacks->dfsm_process_update_fn != NULL, NULL);
	g_return_val_if_fail(callbacks->dfsm_commit_fn != NULL, NULL);
  
	dfsm_t *dfsm;

	if ((dfsm = g_new0(dfsm_t, 1)) == NULL)
		return NULL;

	g_mutex_init(&dfsm->sync_mutex);
	
	g_cond_init(&dfsm->sync_cond);

	if (!(dfsm->results = g_hash_table_new(g_int64_hash, g_int64_equal)))
		goto err;

	if (!(dfsm->msg_queue = g_sequence_new(NULL))) 
		goto err;

	g_mutex_init(&dfsm->cpg_mutex);

	dfsm->log_domain = log_domain;
	dfsm->data = data;
	dfsm->mode = DFSM_MODE_START;
	dfsm->protocol_version = protocol_version;
	strcpy (dfsm->cpg_group_name.value, group_name);
	dfsm->cpg_group_name.length = strlen (group_name) + 1;

	dfsm->cpg_callbacks = &cpg_callbacks;
	dfsm->dfsm_callbacks = callbacks;

	dfsm->members = g_hash_table_new(dfsm_sync_info_hash, dfsm_sync_info_equal);
	if (!dfsm->members)
		goto err;

	g_mutex_init(&dfsm->mode_mutex);

	return dfsm;

err:
	dfsm_destroy(dfsm);
	return NULL;
}

gboolean
dfsm_is_initialized(dfsm_t *dfsm)
{
	g_return_val_if_fail(dfsm != NULL, FALSE);

	return (dfsm->cpg_handle != 0) ? TRUE : FALSE;
}

gboolean 
dfsm_lowest_nodeid(dfsm_t *dfsm)
{
	g_return_val_if_fail(dfsm != NULL, FALSE);

	if (dfsm->lowest_nodeid && (dfsm->lowest_nodeid == dfsm->nodeid))
		return TRUE;

	return FALSE;
}

cs_error_t 
dfsm_verify_request(dfsm_t *dfsm)
{
	g_return_val_if_fail(dfsm != NULL, CS_ERR_INVALID_PARAM);

	/* only do when we have lowest nodeid */
	if (!dfsm->lowest_nodeid || (dfsm->lowest_nodeid != dfsm->nodeid))
		return CS_OK;

	dfsm_mode_t mode = dfsm_get_mode(dfsm);
	if (mode != DFSM_MODE_SYNCED)
		return CS_OK;		

	int len = 1;
	struct iovec iov[len];

	if (dfsm->csum_counter != dfsm->csum_id) {
		g_message("delay verify request %016" PRIX64, dfsm->csum_counter + 1);
		return CS_OK;
	};

	dfsm->csum_counter++;
	iov[0].iov_base = (char *)&dfsm->csum_counter;
	iov[0].iov_len = sizeof(dfsm->csum_counter);
	
	cfs_debug("send verify request %016" PRIX64, dfsm->csum_counter);

	cs_error_t result;
	result = dfsm_send_state_message_full(dfsm, DFSM_MESSAGE_VERIFY_REQUEST, iov, len);

	if (result != CS_OK)
		cfs_dom_critical(dfsm->log_domain, "failed to send VERIFY_REQUEST message");

	return result;
}


cs_error_t
dfsm_dispatch(
	dfsm_t *dfsm, 
	cs_dispatch_flags_t dispatch_types) 
{
	g_return_val_if_fail(dfsm != NULL, CS_ERR_INVALID_PARAM);
	g_return_val_if_fail(dfsm->cpg_handle != 0, CS_ERR_INVALID_PARAM);

	cs_error_t result;

	struct timespec tvreq = { .tv_sec = 0, .tv_nsec = 100000000 };
	int retries = 0;
loop:
	result = cpg_dispatch(dfsm->cpg_handle, dispatch_types);
	if (result == CS_ERR_TRY_AGAIN) {
		nanosleep(&tvreq, NULL);
		++retries;
		if ((retries % 10) == 0)
			cfs_dom_message(dfsm->log_domain, "cpg_dispatch retry %d", retries);
		goto loop;
	}

	if (!(result == CS_OK || result == CS_ERR_TRY_AGAIN)) {
		cfs_dom_critical(dfsm->log_domain, "cpg_dispatch failed: %d", result);
	}

	return result;
}


cs_error_t
dfsm_initialize(dfsm_t *dfsm, int *fd) 
{
	g_return_val_if_fail(dfsm != NULL, CS_ERR_INVALID_PARAM);
	g_return_val_if_fail(fd != NULL, CS_ERR_INVALID_PARAM);

	/* remove old messages */
	dfsm_free_message_queue(dfsm);
	dfsm_send_sync_message_abort(dfsm);

	dfsm->joined = FALSE;
	dfsm->we_are_member = 0;

	dfsm_set_mode(dfsm, DFSM_MODE_START);

	cs_error_t result;

	if (dfsm->cpg_handle == 0) {
		if ((result = cpg_initialize(&dfsm->cpg_handle, dfsm->cpg_callbacks)) != CS_OK) {
			cfs_dom_critical(dfsm->log_domain, "cpg_initialize failed: %d", result);
			goto err_no_finalize;
		}

		if ((result = cpg_local_get(dfsm->cpg_handle, &dfsm->nodeid)) != CS_OK) {
			cfs_dom_critical(dfsm->log_domain, "cpg_local_get failed: %d", result);
			goto err_finalize;
		}

		dfsm->pid = getpid();

		result = cpg_context_set(dfsm->cpg_handle, dfsm);
		if (result != CS_OK) {
			cfs_dom_critical(dfsm->log_domain, "cpg_context_set failed: %d", result);
			goto err_finalize;
		}
	}

	result = cpg_fd_get(dfsm->cpg_handle, fd);
	if (result != CS_OK) {
		cfs_dom_critical(dfsm->log_domain, "cpg_fd_get failed: %d", result);
		goto err_finalize;
	}
       
	return CS_OK;

 err_finalize:
	cpg_finalize(dfsm->cpg_handle);
 err_no_finalize:
	dfsm->cpg_handle = 0;
	return result;
}

cs_error_t
dfsm_join(dfsm_t *dfsm) 
{
	g_return_val_if_fail(dfsm != NULL, CS_ERR_INVALID_PARAM);
	g_return_val_if_fail(dfsm->cpg_handle != 0, CS_ERR_LIBRARY);
	g_return_val_if_fail(dfsm->joined == 0, CS_ERR_EXIST);

	cs_error_t result;

	struct timespec tvreq = { .tv_sec = 0, .tv_nsec = 100000000 };
	int retries = 0;
loop:
	g_mutex_lock (&dfsm->cpg_mutex);
	result = cpg_join(dfsm->cpg_handle, &dfsm->cpg_group_name); 
	g_mutex_unlock (&dfsm->cpg_mutex);
	if (result == CS_ERR_TRY_AGAIN) {
		nanosleep(&tvreq, NULL);
		++retries;
		if ((retries % 10) == 0)
			cfs_dom_message(dfsm->log_domain, "cpg_join retry %d", retries);
		goto loop;
	}

	if (result != CS_OK) {
		cfs_dom_critical(dfsm->log_domain, "cpg_join failed: %d", result);
		return result;
	}

	dfsm->joined = TRUE;
	return TRUE;
}

cs_error_t
dfsm_leave (dfsm_t *dfsm)
{
	g_return_val_if_fail(dfsm != NULL, CS_ERR_INVALID_PARAM);
	g_return_val_if_fail(dfsm->joined, CS_ERR_NOT_EXIST);

	cs_error_t result;

	struct timespec tvreq = { .tv_sec = 0, .tv_nsec = 100000000 };
	int retries = 0;
loop:
	g_mutex_lock (&dfsm->cpg_mutex);
	result = cpg_leave(dfsm->cpg_handle, &dfsm->cpg_group_name);
	g_mutex_unlock (&dfsm->cpg_mutex);
	if (result == CS_ERR_TRY_AGAIN) {
		nanosleep(&tvreq, NULL);
		++retries;
		if ((retries % 10) == 0)
			cfs_dom_message(dfsm->log_domain, "cpg_leave retry %d", retries);
		goto loop;
	}

	if (result != CS_OK) {
		cfs_dom_critical(dfsm->log_domain, "cpg_leave failed: %d", result);
		return result;
	}

	dfsm->joined = FALSE;

	return TRUE;		
}

gboolean 
dfsm_finalize(dfsm_t *dfsm)
{
	g_return_val_if_fail(dfsm != NULL, FALSE);

	dfsm_send_sync_message_abort(dfsm);

	if (dfsm->joined)
		dfsm_leave(dfsm);

	if (dfsm->cpg_handle) {
		cpg_finalize(dfsm->cpg_handle);
		dfsm->cpg_handle = 0;
		dfsm->joined = FALSE;
		dfsm->we_are_member = 0;
	}

	return TRUE;
}

void 
dfsm_destroy(dfsm_t *dfsm)
{
	g_return_if_fail(dfsm != NULL);

	dfsm_finalize(dfsm);

	if (dfsm->sync_info && dfsm->sync_info->data && dfsm->dfsm_callbacks->dfsm_cleanup_fn)
		dfsm->dfsm_callbacks->dfsm_cleanup_fn(dfsm, dfsm->data, dfsm->sync_info);

	dfsm_free_sync_queue(dfsm);

	g_mutex_clear (&dfsm->mode_mutex);

	g_mutex_clear (&dfsm->sync_mutex);

	g_cond_clear (&dfsm->sync_cond);

	g_mutex_clear (&dfsm->cpg_mutex);
 
	if (dfsm->results)
		g_hash_table_destroy(dfsm->results);

	if (dfsm->msg_queue) {
		dfsm_free_message_queue(dfsm);
		g_sequence_free(dfsm->msg_queue);
	}

	if (dfsm->sync_info)
		g_free(dfsm->sync_info);

	if (dfsm->cpg_handle)
		cpg_finalize(dfsm->cpg_handle);

	if (dfsm->members)
		g_hash_table_destroy(dfsm->members);

	g_free(dfsm);
}

typedef struct {
	dfsm_t *dfsm;
} service_dfsm_private_t;

static gboolean 
service_dfsm_finalize(
	cfs_service_t *service,
	gpointer context)
{
	g_return_val_if_fail(service != NULL, FALSE);
	g_return_val_if_fail(context != NULL, FALSE);

	service_dfsm_private_t *private = (service_dfsm_private_t *)context;
	dfsm_t *dfsm = private->dfsm;

	g_return_val_if_fail(dfsm != NULL, FALSE);

	return dfsm_finalize(dfsm);
}

static int 
service_dfsm_initialize(
	cfs_service_t *service,
	gpointer context)
{
	g_return_val_if_fail(service != NULL, -1);
	g_return_val_if_fail(context != NULL, -1);

	service_dfsm_private_t *private = (service_dfsm_private_t *)context;
	dfsm_t *dfsm = private->dfsm;

	g_return_val_if_fail(dfsm != NULL, -1);

	/* serious internal error - don't try to recover */
	if (!dfsm_restartable(dfsm))
		return -1;
	
	int fd = -1;

	cs_error_t result;
	if ((result = dfsm_initialize(dfsm, &fd)) != CS_OK)
		return -1;
       
	result = dfsm_join(dfsm);
	if (result != CS_OK) {
		/* we can't dispatch if not joined, so we need to finalize */
		dfsm_finalize(dfsm);
		return -1;
	}

	return fd;
}

static gboolean 
service_dfsm_dispatch(
	cfs_service_t *service,
	gpointer context)
{
	g_return_val_if_fail(service != NULL, FALSE);
	g_return_val_if_fail(context != NULL, FALSE);

	service_dfsm_private_t *private = (service_dfsm_private_t *)context;
	dfsm_t *dfsm = private->dfsm;

	g_return_val_if_fail(dfsm != NULL, FALSE);
	g_return_val_if_fail(dfsm->cpg_handle != 0, FALSE);

	cs_error_t result;

	result = dfsm_dispatch(dfsm, CS_DISPATCH_ONE);
	if (result == CS_ERR_LIBRARY || result == CS_ERR_BAD_HANDLE)
		goto finalize;
	if (result != CS_OK)
		goto fail;

	dfsm_mode_t mode = dfsm_get_mode(dfsm);
	if (mode >= DFSM_ERROR_MODE_START) {
		if (dfsm->joined) {
			result = dfsm_leave(dfsm);
			if (result == CS_ERR_LIBRARY || result == CS_ERR_BAD_HANDLE)
				goto finalize;
			if (result != CS_OK)
				goto finalize;
		} else {
			if (!dfsm->we_are_member)
				return FALSE;
		}
	}

	return TRUE;

finalize:
	dfsm_finalize(dfsm);
fail:
	cfs_service_set_restartable(service, dfsm_restartable(dfsm));
	return FALSE;
}

static void 
service_dfsm_timer(
	cfs_service_t *service,
	gpointer context)
{
	g_return_if_fail(service != NULL);
	g_return_if_fail(context != NULL);

	service_dfsm_private_t *private = (service_dfsm_private_t *)context;
	dfsm_t *dfsm = private->dfsm;

	g_return_if_fail(dfsm != NULL);

	dfsm_verify_request(dfsm);
}

static cfs_service_callbacks_t cfs_dfsm_callbacks = {
	.cfs_service_initialize_fn =  service_dfsm_initialize,
	.cfs_service_finalize_fn = service_dfsm_finalize,
	.cfs_service_dispatch_fn = service_dfsm_dispatch,
	.cfs_service_timer_fn = service_dfsm_timer,
};

cfs_service_t *
service_dfsm_new(dfsm_t *dfsm)
{
	cfs_service_t *service;

	g_return_val_if_fail(dfsm != NULL, NULL);

	service_dfsm_private_t *private = g_new0(service_dfsm_private_t, 1);
	if (!private)
		return NULL;

	private->dfsm = dfsm;

	service = cfs_service_new(&cfs_dfsm_callbacks, dfsm->log_domain, private); 

	return service;
}

void 
service_dfsm_destroy(cfs_service_t *service) 
{
	g_return_if_fail(service != NULL);

	service_dfsm_private_t *private = 
		(service_dfsm_private_t *)cfs_service_get_context(service);

	g_free(private);
	g_free(service);
}




