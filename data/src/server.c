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

#define G_LOG_DOMAIN "ipcs"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <sys/syslog.h>
#include <sys/uio.h>

#include <qb/qbdefs.h>
#include <qb/qbutil.h>
#include <qb/qbloop.h>
#include <qb/qbipcs.h>

#include <glib.h>

#include "cfs-utils.h"
#include "cfs-ipc-ops.h"
#include "status.h"
#include "memdb.h"
#include "logger.h"

static GThread *worker;
static qb_loop_t *loop;
static qb_ipcs_service_t* s1;
static GString *outbuf;
static memdb_t *memdb;

static int server_started = 0;   /* protect with server_started_mutex */
static int terminate_server = 0; /* protect with server_started_mutex */
static GCond server_started_cond;
static GCond server_stopped_cond;
static GMutex server_started_mutex;


typedef struct {
	struct qb_ipc_request_header req_header;
	char name[256];
} cfs_status_update_request_header_t;

typedef struct {
	struct qb_ipc_request_header req_header;
	char name[256];
	char nodename[256];
} cfs_status_get_request_header_t;

typedef struct {
	struct qb_ipc_request_header req_header;
	uint8_t priority;
	uint8_t ident_len;
	uint8_t tag_len;
	char data[];
} cfs_log_msg_request_header_t;

typedef struct {
	struct qb_ipc_request_header req_header;
	uint32_t max_entries;
	uint32_t res1;
	uint32_t res2;
	uint32_t res3;
} cfs_log_get_request_header_t;

typedef struct {
	struct qb_ipc_request_header req_header;
	uint32_t vmid;
	char property[];
} cfs_guest_config_propery_get_request_header_t;

struct s1_context {
	int32_t client_pid;
	uid_t uid;
	gid_t gid;	
	gboolean read_only;
};
 
static int32_t s1_connection_accept_fn(
	qb_ipcs_connection_t *c, 
	uid_t uid, 
	gid_t gid)
{
	if ((uid == 0 && gid == 0) || (gid == cfs.gid)) {
		cfs_debug("authenticated connection %d/%d", uid, gid);
		struct s1_context *ctx = g_new0(struct s1_context, 1);
		ctx->uid = uid;
		ctx->gid = gid;
		ctx->read_only = (gid == cfs.gid);

		struct qb_ipcs_connection_stats stats;
		qb_ipcs_connection_stats_get(c, &stats, QB_FALSE);
		ctx->client_pid = stats.client_pid;

		qb_ipcs_context_set(c, ctx);
		return 0;
	}
	cfs_critical("connection from bad user %d! - rejected", uid);
	return 1;
}

static void s1_connection_created_fn(
	qb_ipcs_connection_t *c)
{
	struct qb_ipcs_stats srv_stats;

	qb_ipcs_stats_get(s1, &srv_stats, QB_FALSE);

	cfs_debug("Connection created > active:%d > closed:%d",
		    srv_stats.active_connections,
		    srv_stats.closed_connections);
}

static void s1_connection_destroyed_fn(
	qb_ipcs_connection_t *c)
{
	cfs_debug("connection about to be freed");
	
	gpointer ctx;
	if ((ctx = qb_ipcs_context_get(c)))
		g_free(ctx);

}

static int32_t s1_connection_closed_fn(
	qb_ipcs_connection_t *c)
{
	struct qb_ipcs_connection_stats stats;

	qb_ipcs_connection_stats_get(c, &stats, QB_FALSE);

	cfs_debug("Connection to pid:%d destroyed", stats.client_pid);

	return 0;
}

static int32_t s1_msg_process_fn(
	qb_ipcs_connection_t *c,
	void *data,
	size_t size)
{
	struct qb_ipc_request_header *req_pt = 
		(struct qb_ipc_request_header *)data;

	struct s1_context *ctx = (struct s1_context *)qb_ipcs_context_get(c);

	if (!ctx) {
		cfs_critical("qb_ipcs_context_get failed");
		qb_ipcs_disconnect(c);
		return 0;
	}

	int32_t request_id __attribute__ ((aligned(8))) = req_pt->id;
	int32_t request_size __attribute__ ((aligned(8))) = req_pt->size;
	cfs_debug("process msg:%d, size:%d", request_id, request_size);

	char *resp = NULL;

	g_string_truncate(outbuf, 0);

	int32_t result = -ECHRNG;
	if (request_id == CFS_IPC_GET_FS_VERSION) {

		if (request_size != sizeof(struct qb_ipc_request_header)) {
			result = -EINVAL;
		} else {
			result = cfs_create_version_msg(outbuf);
		}

	} else if (request_id == CFS_IPC_GET_CLUSTER_INFO) {

		if (request_size != sizeof(struct qb_ipc_request_header)) {
			result = -EINVAL;
		} else {
			result = cfs_create_memberlist_msg(outbuf);
		}

	} else if (request_id == CFS_IPC_GET_GUEST_LIST) {
		
		if (request_size != sizeof(struct qb_ipc_request_header)) {
			result = -EINVAL;
		} else {
			result = cfs_create_vmlist_msg(outbuf);
		}
	} else if (request_id == CFS_IPC_SET_STATUS) {

		cfs_status_update_request_header_t *rh = 
			(cfs_status_update_request_header_t *)data;

		int datasize = request_size - sizeof(cfs_status_update_request_header_t);

		if (ctx->read_only) {
			result = -EPERM;
		} else if (datasize < 0) {
			result = -EINVAL;
		} else {	
			/* make sure name is 0 terminated */
			rh->name[sizeof(rh->name) - 1] = 0;

			char *dataptr = (char*) data + sizeof(cfs_status_update_request_header_t);

			result = cfs_status_set(rh->name, dataptr, datasize);
		}
	} else if (request_id == CFS_IPC_GET_STATUS) {

		cfs_status_get_request_header_t *rh =
			(cfs_status_get_request_header_t *)data;

		int datasize = request_size - sizeof(cfs_status_get_request_header_t);

		if (datasize < 0) {
			result = -EINVAL;
		} else {	
			/* make sure all names are 0 terminated */
			rh->name[sizeof(rh->name) - 1] = 0;
			rh->nodename[sizeof(rh->nodename) - 1] = 0;

			result = cfs_create_status_msg(outbuf, rh->nodename, rh->name);
		}
	} else if (request_id == CFS_IPC_GET_CONFIG) {

		int pathlen = request_size - sizeof(struct qb_ipc_request_header);

		if (pathlen <= 0) {
			result = -EINVAL;
		} else {
			/* make sure path is 0 terminated */
			((char *)data)[request_size - 1] = 0;
			char *path = (char*) data + sizeof(struct qb_ipc_request_header);

			if (ctx->read_only &&  path_is_private(path)) {
				result = -EPERM;
			} else {
				gpointer tmp = NULL;
				result = memdb_read(memdb, path, &tmp);
				if (result > 0) {
					g_string_append_len(outbuf, tmp, result);
					g_free(tmp);
				}
			}
		}			
	} else if (request_id == CFS_IPC_LOG_CLUSTER_MSG) {

		cfs_log_msg_request_header_t *rh = 
			(cfs_log_msg_request_header_t *)data;

		int datasize = request_size - G_STRUCT_OFFSET(cfs_log_msg_request_header_t, data);
		int msg_len = datasize - rh->ident_len - rh->tag_len;

		if (ctx->read_only) {
			result = -EPERM;
		} else if (msg_len  < 1) {
			result = -EINVAL;
		} else {
			char *msg = rh->data;
			if ((msg[rh->ident_len - 1] == 0) &&
			    (msg[rh->ident_len + rh->tag_len - 1] == 0) &&
			    (((char *)data)[request_size] == 0)) {

				char *ident = msg;
				char *tag = msg + rh->ident_len;
				msg = msg + rh->ident_len + rh->tag_len;

				time_t ctime = time(NULL);
				clog_entry_t *entry = (clog_entry_t *)alloca(CLOG_MAX_ENTRY_SIZE);
				if (clog_pack(entry, cfs.nodename, ident, tag, ctx->client_pid,
					      ctime, rh->priority, msg)) {
					cfs_cluster_log(entry);
				}

				result = 0;

			} else {
				result = -EINVAL;
			}
		}
	} else if (request_id == CFS_IPC_GET_CLUSTER_LOG) {

		cfs_log_get_request_header_t *rh = 
			(cfs_log_get_request_header_t *)data;

		int userlen = request_size - sizeof(cfs_log_get_request_header_t);

		if (userlen <= 0) {
			result = -EINVAL;
		} else {
			/* make sure user string is 0 terminated */
			((char *)data)[request_size - 1] = 0;
			char *user = (char*) data + sizeof(cfs_log_get_request_header_t);

			uint32_t max = rh->max_entries ?  rh->max_entries : 50;
			cfs_cluster_log_dump(outbuf, user, max);
			result = 0;
		}
	} else if (request_id == CFS_IPC_GET_RRD_DUMP) {
	
		if (request_size != sizeof(struct qb_ipc_request_header)) {
			result = -EINVAL;
		} else {
			cfs_rrd_dump(outbuf);
			result = 0;
		}
	} else if (request_id == CFS_IPC_GET_GUEST_CONFIG_PROPERTY) {

		cfs_guest_config_propery_get_request_header_t *rh =
			(cfs_guest_config_propery_get_request_header_t *) data;

		int proplen = request_size - G_STRUCT_OFFSET(cfs_guest_config_propery_get_request_header_t, property);

		result = 0;
		if (rh->vmid < 100 && rh->vmid != 0) {
			cfs_debug("vmid out of range %u", rh->vmid);
			result = -EINVAL;
		} else if (rh->vmid >= 100 && !vmlist_vm_exists(rh->vmid)) {
			result = -ENOENT;
		} else if (proplen <= 0) {
			cfs_debug("proplen <= 0, %d", proplen);
			result = -EINVAL;
		} else {
			((char *)data)[request_size - 1] = 0; // ensure property is 0 terminated

			cfs_debug("cfs_get_guest_config_property: basic valid checked, do request");

			result = cfs_create_guest_conf_property_msg(outbuf, memdb, rh->property, rh->vmid);
		}
	}

	cfs_debug("process result %d", result);

	if (result >= 0) {
		resp = outbuf->str;
		result = 0;
	}

	int iov_len = 2;
	struct iovec iov[iov_len];
	struct qb_ipc_response_header res_header;

	int resp_data_len = resp ? outbuf->len : 0;

	res_header.id = request_id;
	res_header.size = sizeof(res_header) + resp_data_len;
	res_header.error = result;

	iov[0].iov_base = (char *)&res_header;
	iov[0].iov_len = sizeof(res_header);
	iov[1].iov_base = resp;
	iov[1].iov_len = resp_data_len;

	ssize_t res = qb_ipcs_response_sendv(c, iov, iov_len);
	if (res < 0) {
		cfs_critical("qb_ipcs_response_send: %s", strerror(errno));
		qb_ipcs_disconnect(c);
	}

	return 0;
}

static int32_t my_job_add(
	enum qb_loop_priority p, 
	void *data, 
	qb_loop_job_dispatch_fn fn)
{
	return qb_loop_job_add(loop, p, data, fn);
}

static int32_t my_dispatch_add(
	enum qb_loop_priority p, 
	int32_t fd, 
	int32_t evts,
	void *data, 
	qb_ipcs_dispatch_fn_t fn)
{
	return qb_loop_poll_add(loop, p, fd, evts, data, fn);
}

static int32_t my_dispatch_mod(
	enum qb_loop_priority p, 
	int32_t fd, 
	int32_t evts,
	void *data, 
	qb_ipcs_dispatch_fn_t fn)
{
	return qb_loop_poll_mod(loop, p, fd, evts, data, fn);
}

static int32_t my_dispatch_del(
	int32_t fd)
{
	return qb_loop_poll_del(loop, fd);
}

static struct qb_ipcs_service_handlers service_handlers = {
	.connection_accept = s1_connection_accept_fn,
	.connection_created = s1_connection_created_fn,
	.msg_process = s1_msg_process_fn,
	.connection_destroyed = s1_connection_destroyed_fn,
	.connection_closed = s1_connection_closed_fn,
};

static struct qb_ipcs_poll_handlers poll_handlers = {
	.job_add = my_job_add,
	.dispatch_add = my_dispatch_add,
	.dispatch_mod = my_dispatch_mod,
	.dispatch_del = my_dispatch_del,
};

static void timer_job(void *data)
{
	gboolean terminate = FALSE;

	g_mutex_lock (&server_started_mutex);

	if (terminate_server) {
		cfs_debug ("got terminate request");

		if (loop)
			qb_loop_stop (loop);
		
		if (s1) {
			qb_ipcs_destroy (s1);
			s1 = 0;
		}
		server_started = 0;

		g_cond_signal (&server_stopped_cond);
		
		terminate = TRUE;
	} else if (!server_started) {
		server_started = 1;
		g_cond_signal (&server_started_cond);
	}
	
	g_mutex_unlock (&server_started_mutex);

	if (terminate)
		return;
			       
	qb_loop_timer_handle th;
	qb_loop_timer_add(loop, QB_LOOP_LOW, 1000000000, NULL, timer_job, &th);
}

static gpointer worker_thread(gpointer data)
{
	g_return_val_if_fail(loop != NULL, NULL);

	cfs_debug("start event loop");

	qb_ipcs_run(s1);

	qb_loop_timer_handle th;
	qb_loop_timer_add(loop, QB_LOOP_LOW, 1000, NULL, timer_job, &th);

	qb_loop_run(loop);

	cfs_debug("event loop finished - exit worker thread");
	
	return NULL;
}

gboolean server_start(memdb_t *db)
{
	g_return_val_if_fail(loop == NULL, FALSE);
	g_return_val_if_fail(worker == NULL, FALSE);
	g_return_val_if_fail(db != NULL, FALSE);

	terminate_server = 0;
	server_started = 0;
	
	memdb = db;

	outbuf = g_string_sized_new(8192*8);

	if (!(loop = qb_loop_create())) {
		cfs_critical("cant create event loop");
		return FALSE;
	}
	
	s1 = qb_ipcs_create("pve2", 1, QB_IPC_SHM, &service_handlers);
	if (s1 == 0) {
		cfs_critical("qb_ipcs_create failed: %s", strerror(errno));
		return FALSE;
	}
	qb_ipcs_poll_handlers_set(s1, &poll_handlers);

	worker = g_thread_new ("server", worker_thread, NULL);

	g_mutex_lock (&server_started_mutex);
	while (!server_started)
		g_cond_wait (&server_started_cond, &server_started_mutex);
	g_mutex_unlock (&server_started_mutex);
	
	cfs_debug("server started");
	
	return TRUE;
}

void server_stop(void)
{
	cfs_debug("server stop");

	g_mutex_lock (&server_started_mutex);
	terminate_server = 1;
	while (server_started)
		g_cond_wait (&server_stopped_cond, &server_started_mutex);
	g_mutex_unlock (&server_started_mutex);

	if (worker) {
		g_thread_join(worker);
		worker = NULL;
	}
	
	cfs_debug("worker thread finished");

	if (loop) {
		qb_loop_destroy(loop);

		loop = NULL;
	}

	if (outbuf) {
		g_string_free(outbuf, TRUE);
		outbuf = NULL;
	}
}
