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

#define G_LOG_DOMAIN "dcdb"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <dirent.h>
#include <errno.h>

#include "cfs-utils.h"
#include "loop.h"
#include "dcdb.h"
#include "status.h"

typedef struct {
	memdb_index_t *master;
	memdb_index_t *idx;
	GList *updates;
} dcdb_sync_info_t;

void
dcdb_send_unlock(
	dfsm_t *dfsm,
	const char *path,
	const guchar csum[32],
	gboolean request)
{
	g_return_if_fail(dfsm != NULL);
	g_return_if_fail(path != NULL);
	g_return_if_fail(csum != NULL);

	struct iovec iov[2];

	iov[0].iov_base = (char *)csum;
	iov[0].iov_len = 32;

	iov[1].iov_base = (char *)path;
	iov[1].iov_len = strlen(path) + 1;

	if (!cfs_is_quorate())
		return;

	dcdb_message_t msg_type = request ? 
		DCDB_MESSAGE_CFS_UNLOCK_REQUEST : DCDB_MESSAGE_CFS_UNLOCK;
	
	dfsm_send_message_sync(dfsm, msg_type, iov, 2, NULL);
}

static gboolean 
dcdb_parse_unlock_request(
	const void *msg,
	size_t msg_len,
	const char **path,
	const guchar **csum)

{
	g_return_val_if_fail(msg != NULL, FALSE);
	g_return_val_if_fail(path != NULL, FALSE);
	g_return_val_if_fail(csum != NULL, FALSE);

	if (msg_len < 33) {
		cfs_critical("received short unlock message (%zu < 33)", msg_len);
		return FALSE;
	}

	*csum = msg;
	msg = (char *)msg + 32; msg_len -= 32;

	*path = msg;
	if ((*path)[msg_len - 1] != 0) {
		cfs_critical("received mailformed unlock message - 'path' not terminated");
		*path = NULL;
		return FALSE;
	}

	return TRUE;
}

int 
dcdb_send_fuse_message(
	dfsm_t *dfsm,
	dcdb_message_t msg_type,
	const char *path,
	const char *to,
	const char *buf,
	guint32 size,
	guint32 offset,
	guint32 flags)
{
	struct iovec iov[8];

	iov[0].iov_base = (char *)&size;
	iov[0].iov_len = sizeof(size);

	iov[1].iov_base = (char *)&offset;
	iov[1].iov_len = sizeof(offset);

	guint32 pathlen = path ? strlen(path) + 1 : 0;
	iov[2].iov_base = (char *)&pathlen;
	iov[2].iov_len = sizeof(pathlen);

	guint32 tolen = to ? strlen(to) + 1 : 0;
	iov[3].iov_base = (char *)&tolen;
	iov[3].iov_len = sizeof(tolen);

	iov[4].iov_base = (char *)&flags;
	iov[4].iov_len = sizeof(flags);

	iov[5].iov_base = (char *)path;
	iov[5].iov_len = pathlen;

	iov[6].iov_base = (char *)to;
	iov[6].iov_len = tolen;

	iov[7].iov_base = (char *)buf;
	iov[7].iov_len = size;

	dfsm_result_t rc;
	memset(&rc, 0, sizeof(rc));
	rc.result = -EBUSY;

	if (!cfs_is_quorate())
		return -EACCES;

	if (dfsm_send_message_sync(dfsm, msg_type, iov, 8, &rc))
		return rc.result;

	return -EACCES;
}

static gboolean 
dcdb_parse_fuse_message(
	const void *msg,
	size_t msg_len,
	const char **path,
	const char **to,
	const char **buf,
	guint32 *size,
	guint32 *offset,
	guint32 *flags)

{
	g_return_val_if_fail(msg != NULL, FALSE);
	g_return_val_if_fail(path != NULL, FALSE);
	g_return_val_if_fail(to != NULL, FALSE);
	g_return_val_if_fail(buf != NULL, FALSE);
	g_return_val_if_fail(size != NULL, FALSE);
	g_return_val_if_fail(offset != NULL, FALSE);
	g_return_val_if_fail(flags != NULL, FALSE);

	if (msg_len < 20) {
		cfs_critical("received short fuse message (%zu < 20)", msg_len);
		return FALSE;
	}

	uint8_t *msg_ptr = (uint8_t *) msg;

	*size = *((guint32 *)msg_ptr);
	msg_ptr += 4; msg_len -= 4;

	*offset = *((guint32 *)msg_ptr);
	msg_ptr += 4; msg_len -= 4;

	guint32 pathlen = *((guint32 *)msg_ptr);
	msg_ptr += 4; msg_len -= 4;

	guint32 tolen = *((guint32 *)msg_ptr);
	msg_ptr += 4; msg_len -= 4;

	*flags = *((guint32 *)msg_ptr);
	msg_ptr += 4; msg_len -= 4;

	if (msg_len != ((*size) + pathlen + tolen)) {
		cfs_critical("received mailformed fuse message");
		return FALSE;
	}

	*path = (char *)msg_ptr;
	msg_ptr += pathlen; msg_len -= pathlen;

	if (pathlen) {
		if ((*path)[pathlen - 1] != 0) {
			cfs_critical("received mailformed fuse message - 'path' not terminated");
			*path = NULL;
			return FALSE;
		}
	} else {
		*path = NULL;
	}

	*to = (char *)msg_ptr;
	msg_ptr += tolen; msg_len -= tolen;

	if (tolen) {
		if ((*to)[tolen - 1] != 0) {
			cfs_critical("received mailformed fuse message - 'to' not terminated");
			*to = NULL;
			return FALSE;
		}
	} else {
		*to = NULL;
	}

	*buf = (*size) ? msg : NULL;

	return TRUE;
}

static gboolean 
dcdb_send_update_inode(
	dfsm_t *dfsm, 
	memdb_tree_entry_t *te)
{
	g_return_val_if_fail(dfsm != NULL, FALSE);
	g_return_val_if_fail(te != NULL, FALSE);

	int len;
	struct iovec iov[20];

	uint32_t namelen = strlen(te->name) + 1;

	iov[0].iov_base = (char *)&te->parent;
	iov[0].iov_len = sizeof(te->parent);
	iov[1].iov_base = (char *)&te->inode;
	iov[1].iov_len = sizeof(te->inode);
	iov[2].iov_base = (char *)&te->version;
	iov[2].iov_len = sizeof(te->version);
	iov[3].iov_base = (char *)&te->writer;
	iov[3].iov_len = sizeof(te->writer);
	iov[4].iov_base = (char *)&te->mtime;
	iov[4].iov_len = sizeof(te->mtime);
	iov[5].iov_base = (char *)&te->size;
	iov[5].iov_len = sizeof(te->size);
	iov[6].iov_base = (char *)&namelen;
	iov[6].iov_len = sizeof(namelen);
	iov[7].iov_base = (char *)&te->type;
	iov[7].iov_len = sizeof(te->type);
	iov[8].iov_base = (char *)te->name;
	iov[8].iov_len = namelen;

	len = 9;
	if (te->type == DT_REG && te->size) {
		iov[9].iov_base = (char *)te->data.value;
		iov[9].iov_len = te->size;
		len++;
	}

	if (dfsm_send_update(dfsm, iov, len) != CS_OK)
		return FALSE;

	return TRUE;
}

memdb_tree_entry_t *
dcdb_parse_update_inode(
	const void *msg, 
	size_t msg_len)
{
	if (msg_len < 40) {
		cfs_critical("received short message (msg_len < 40)");
		return NULL;
	}

	uint8_t *msg_ptr = (uint8_t *) msg;

	guint64 parent = *((guint64 *)msg_ptr);
	msg_ptr += 8; msg_len -= 8;
	guint64 inode = *((guint64 *)msg_ptr);
	msg_ptr += 8; msg_len -= 8;
	guint64 version = *((guint64 *)msg_ptr);
	msg_ptr += 8; msg_len -= 8;

	guint32 writer = *((guint32 *)msg_ptr);
	msg_ptr += 4; msg_len -= 4;
	guint32 mtime = *((guint32 *)msg_ptr);
	msg_ptr += 4; msg_len -= 4;
	guint32 size = *((guint32 *)msg_ptr);
	msg_ptr += 4; msg_len -= 4;
	guint32 namelen = *((guint32 *)msg_ptr);
	msg_ptr += 4; msg_len -= 4;

	char type = *((char *)msg_ptr);
	msg_ptr += 1; msg_len -= 1;

	if (!(type == DT_REG || type == DT_DIR)) {
		cfs_critical("received mailformed message (unknown inode type %d)", type);
		return NULL;
	}

	if (msg_len != (size + namelen)) {
		cfs_critical("received mailformed message (msg_len != (size + namelen))");
		return NULL;
	}

	char *name = (char *)msg;
	msg = (char *) msg + namelen; msg_len -= namelen;

	const void *data = msg;
	
	if (name[namelen - 1] != 0) {
		cfs_critical("received mailformed message (name[namelen-1] != 0)");
		return NULL;
	}

	memdb_tree_entry_t *te = memdb_tree_entry_new(name);
	if (!te)
		return NULL;

	te->parent = parent;
	te->version = version;
	te->inode = inode;
	te->writer = writer;
	te->mtime = mtime;
	te->size = size;
	te->type = type;

	if (te->type == DT_REG && te->size) {
		te->data.value = g_memdup(data, te->size);
		if (!te->data.value) {
			memdb_tree_entry_free(te);
			return NULL;
		}
	}

	return te;
}

void 
dcdb_sync_corosync_conf(
	memdb_t *memdb, 
	gboolean notify_corosync)
{
	g_return_if_fail(memdb != NULL);

	int len;
	gpointer data = NULL;

	len = memdb_read(memdb, "corosync.conf", &data);
	if (len <= 0)
		return;

	guint64 new_version = cluster_config_version(data, len);
	if (!new_version) {
		cfs_critical("unable to parse cluster config_version");
		return;
	}

	char *old_data = NULL;
	gsize old_length = 0;
	guint64 old_version = 0;

	GError *err = NULL;
	if (!g_file_get_contents(HOST_CLUSTER_CONF_FN, &old_data, &old_length, &err)) {
		if (!g_error_matches(err, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
			cfs_critical("unable to read cluster config file '%s' - %s", 
				     HOST_CLUSTER_CONF_FN, err->message);
		}
		g_error_free (err);
	} else {
		if (old_length)
			old_version = cluster_config_version(old_data, old_length);
	}

	/* test if something changed - return if no changes */
	if (data && old_data && (old_length == len) && 
	    !memcmp(data, old_data, len))
		goto ret;

	if (new_version < old_version) {
		cfs_critical("local corosync.conf is newer");
		goto ret;
	}

	if (!atomic_write_file(HOST_CLUSTER_CONF_FN, data, len, 0644, 0))
		goto ret;

	cfs_message("wrote new corosync config '%s' (version = %" G_GUINT64_FORMAT ")",
		    HOST_CLUSTER_CONF_FN, new_version);
	
	if (notify_corosync && old_version) {
		/* tell corosync that there is a new config file */
		cfs_debug ("run corosync-cfgtool -R");
		int status = system("corosync-cfgtool -R >/dev/null 2>&1");
		if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
			cfs_critical("corosync-cfgtool -R failed with exit code %d\n", WEXITSTATUS(status));
		}
		cfs_debug ("end corosync-cfgtool -R");
	}

ret:

	if (data)
		g_free(data);
	
	if (old_data)
		g_free(old_data);
}

static gpointer
dcdb_get_state(	
	dfsm_t *dfsm, 
	gpointer data,
	unsigned int *res_len)
{
	g_return_val_if_fail(dfsm != NULL, FALSE);
	g_return_val_if_fail(data != NULL, FALSE);

	memdb_t *memdb = (memdb_t *)data;

	g_return_val_if_fail(memdb->root != NULL, FALSE);

	cfs_debug("enter %s %016" PRIX64 " %08X", __func__, (uint64_t) memdb->root->version, memdb->root->mtime);

	g_mutex_lock (&memdb->mutex);
	memdb_index_t *idx = memdb_encode_index(memdb->index, memdb->root);
	g_mutex_unlock (&memdb->mutex);

	if (idx) {
		*res_len = idx->bytes;
	}

	return idx;
}

static int
dcdb_select_leader(
	int node_count,
	memdb_index_t *idx[])
{
	g_return_val_if_fail(idx != NULL, -1);

	cfs_debug("enter %s", __func__);

	int leader = -1;

	/* try select most actual data - compare 'version' an 'time of last write'
	 * NOTE: syncinfo members are sorted 
	 */
	for (int i = 0; i < node_count; i++) {
		if (leader < 0) {
			leader = i;
		} else {
			memdb_index_t *leaderidx = idx[leader];
				
			if (idx[i]->version == leaderidx->version &&
			    idx[i]->mtime > leaderidx->mtime) {
				leader = i;
			} else if (idx[i]->version > leaderidx->version) {
				leader = i;
			}
		}
	}

	cfs_debug ("leave %s (%d)", __func__, leader);

	return leader;
}

static gboolean 
dcdb_create_and_send_updates(
	dfsm_t *dfsm,
	memdb_t *memdb, 
	memdb_index_t *master,
	int node_count,
	memdb_index_t *idx[])
{
	g_return_val_if_fail(dfsm != NULL, FALSE);
	g_return_val_if_fail(memdb != NULL, FALSE);
	g_return_val_if_fail(master != NULL, FALSE);

	cfs_debug("enter %s", __func__);

	gboolean res = FALSE;

	GHashTable *updates = g_hash_table_new(g_int64_hash, g_int64_equal);
	if (!updates)
		goto ret;

	g_mutex_lock (&memdb->mutex);

	for (int n = 0; n < node_count; n++) {
		memdb_index_t *slave = idx[n];

		if (slave == master)
			continue;

		int j = 0;

		for (int i = 0; i < master->size; i++) {
			guint64 inode =  master->entries[i].inode;
			while (j < slave->size && slave->entries[j].inode < inode)
				j++;

			if (memcmp(&slave->entries[j], &master->entries[i], 
				    sizeof(memdb_index_extry_t)) == 0) {
				continue;
			}

			if (g_hash_table_lookup(updates, &inode))
				continue;
			
			cfs_debug("found different inode %d %016" PRIX64, i, (uint64_t) inode);
			
			memdb_tree_entry_t *te, *cpy;

			if (!(te = g_hash_table_lookup(memdb->index, &inode))) {
				cfs_critical("can get inode data for inode %016" PRIX64, (uint64_t) inode);
				goto ret;
			}
			
			cpy = memdb_tree_entry_copy(te, 1);
			g_hash_table_replace(updates, &cpy->inode, cpy);
		}
	}

	g_mutex_unlock (&memdb->mutex);

	/* send updates */

	GHashTableIter iter;
	gpointer key, value;
	int count = 0;

	cfs_message("start sending inode updates");

	g_hash_table_iter_init (&iter, updates);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		memdb_tree_entry_t *te = (memdb_tree_entry_t *)value;
		count++;

		if (!dcdb_send_update_inode(dfsm, te)) {
			/* tolerate error here */
			cfs_critical("sending update inode failed %016" PRIX64, (uint64_t) te->inode);
		} else {
			cfs_debug("sent update inode %016" PRIX64, (uint64_t) te->inode);
		}
			
		memdb_tree_entry_free(te);
	}

	cfs_message("sent all (%d) updates", count);

	if (dfsm_send_update_complete(dfsm) != CS_OK) {
		cfs_critical("failed to send UPDATE_COMPLETE message");
		goto ret;
	}

	res = TRUE;

 ret:
	if (updates)
		g_hash_table_destroy(updates);

	cfs_debug("leave %s (%d)", __func__, res);

	return res;
}

static int
dcdb_process_state_update(
	dfsm_t *dfsm, 
	gpointer data,
	dfsm_sync_info_t *syncinfo)
{
	g_return_val_if_fail(dfsm != NULL, -1);
	g_return_val_if_fail(data != NULL, -1);
	g_return_val_if_fail(syncinfo != NULL, -1);

	memdb_t *memdb = (memdb_t *)data;

	cfs_debug("enter %s", __func__);

	dcdb_sync_info_t *localsi = g_new0(dcdb_sync_info_t, 1);
	if (!localsi)
		return -1;

	syncinfo->data = localsi;

	memdb_index_t *idx[syncinfo->node_count];

	for (int i = 0; i < syncinfo->node_count; i++) {
		dfsm_node_info_t *ni = &syncinfo->nodes[i];

		if (ni->state_len < sizeof(memdb_index_t)) {
			cfs_critical("received short memdb index (len < sizeof(memdb_index_t))");
			return -1;
		}

		idx[i] = (memdb_index_t *)ni->state;

		if (ni->state_len != idx[i]->bytes) {
			cfs_critical("received mailformed memdb index (len != idx->bytes)");
			return -1;
		}
	}
	
	/* select leader - set mode */
	int leader = dcdb_select_leader(syncinfo->node_count, idx);
	if (leader < 0) {
		cfs_critical("unable to select leader failed");
		return -1;
	}

	cfs_message("leader is %d/%d", syncinfo->nodes[leader].nodeid, syncinfo->nodes[leader].pid);

	memdb_index_t *leaderidx = idx[leader];
	localsi->master = leaderidx;

	GString *synced_member_ids = g_string_new(NULL);
	g_string_append_printf(synced_member_ids, "%d/%d", syncinfo->nodes[leader].nodeid, syncinfo->nodes[leader].pid);

	for (int i = 0; i < syncinfo->node_count; i++) {
		dfsm_node_info_t *ni = &syncinfo->nodes[i];
		if (i == leader) {
			ni->synced = 1;
		} else {
			if (leaderidx->bytes == idx[i]->bytes &&
			    memcmp(leaderidx, idx[i], leaderidx->bytes) == 0) {
				ni->synced = 1;
				g_string_append_printf(synced_member_ids, ", %d/%d", ni->nodeid, ni->pid);
			}
		}
		if (dfsm_nodeid_is_local(dfsm, ni->nodeid, ni->pid)) 
			localsi->idx = idx[i];
	}
	cfs_message("synced members: %s", synced_member_ids->str);
	g_string_free(synced_member_ids, 1);

	/* send update */
	if (dfsm_nodeid_is_local(dfsm, syncinfo->nodes[leader].nodeid, syncinfo->nodes[leader].pid)) {
		if (!dcdb_create_and_send_updates(dfsm, memdb, leaderidx, syncinfo->node_count, idx))
			return -1;
	}

	return 0;
}

static int 
dcdb_process_update(
	dfsm_t *dfsm, 
	gpointer data,
	dfsm_sync_info_t *syncinfo,
	uint32_t nodeid,
	uint32_t pid,
	const void *msg,
	size_t msg_len)
{
	g_return_val_if_fail(dfsm != NULL, -1);
	g_return_val_if_fail(data != NULL, -1);
	g_return_val_if_fail(msg != NULL, -1);
	g_return_val_if_fail(syncinfo != NULL, -1);
	g_return_val_if_fail(syncinfo->data != NULL, -1);
	
	cfs_debug("enter %s", __func__);

	memdb_tree_entry_t *te;

	if (!(te = dcdb_parse_update_inode(msg, msg_len)))
		return -1;

	cfs_debug("received inode update %016" PRIX64 " from node %d",
		  (uint64_t) te->inode, nodeid);

	dcdb_sync_info_t *localsi = (dcdb_sync_info_t *)syncinfo->data;

	localsi->updates = g_list_append(localsi->updates, te);

	return 0;
}

static int
dcdb_commit(
	dfsm_t *dfsm, 
	gpointer data,
	dfsm_sync_info_t *syncinfo)
{
	g_return_val_if_fail(dfsm != NULL, -1);
	g_return_val_if_fail(data != NULL, -1);
	g_return_val_if_fail(syncinfo != NULL, -1);
	g_return_val_if_fail(syncinfo->data != NULL, -1);
	
	memdb_t *memdb = (memdb_t *)data;

	cfs_debug("enter %s", __func__);

	dcdb_sync_info_t *localsi = (dcdb_sync_info_t *)syncinfo->data;

	guint count = g_list_length(localsi->updates); 

	cfs_message("update complete - trying to commit (got %u inode updates)", count);

	if (!bdb_backend_commit_update(memdb, localsi->master, localsi->idx, localsi->updates)) 
		return -1;

	dcdb_sync_corosync_conf(memdb, FALSE);

	return 0;
}

static int 
dcdb_cleanup(
	dfsm_t *dfsm, 
	gpointer data,
	dfsm_sync_info_t *syncinfo)
{
	g_return_val_if_fail(dfsm != NULL, -1);
	g_return_val_if_fail(data != NULL, -1);
	g_return_val_if_fail(syncinfo != NULL, -1);
	g_return_val_if_fail(syncinfo->data != NULL, -1);

	cfs_debug("enter %s", __func__);

	dcdb_sync_info_t *localsi = (dcdb_sync_info_t *)syncinfo->data;

	GList *iter = localsi->updates;
	while (iter) {
		memdb_tree_entry_t *te = (memdb_tree_entry_t *)iter->data;
		memdb_tree_entry_free(te);
		iter = g_list_next(iter);
	}
	g_list_free(localsi->updates);

	g_free(localsi);

	return 0;
}

gboolean 
dcdb_checksum(
	dfsm_t *dfsm, 
	gpointer data,
	unsigned char *csum,
	size_t csum_len)
{
	g_return_val_if_fail(dfsm != NULL, FALSE);
	g_return_val_if_fail(csum != NULL, FALSE);

	memdb_t *memdb = (memdb_t *)data;

	g_return_val_if_fail(memdb != NULL, FALSE);

	cfs_debug("enter %s %016" PRIX64 " %08X", __func__, memdb->root->version, memdb->root->mtime);

	g_mutex_lock (&memdb->mutex);
	gboolean res = memdb_compute_checksum(memdb->index, memdb->root, csum, csum_len);
	g_mutex_unlock (&memdb->mutex);

	cfs_debug("leave %s %016" PRIX64 " (%d)", __func__, *( (uint64_t *) csum), res);

	return res;
}

static int
dcdb_deliver(
	dfsm_t *dfsm,
	gpointer data,
	int *res_ptr,
	uint32_t nodeid,
	uint32_t pid,
	uint16_t msg_type,
	uint32_t msg_time,
	const void *msg,
	size_t msg_len)
{
	g_return_val_if_fail(dfsm != NULL, -1);
	g_return_val_if_fail(msg != NULL, -1);

	memdb_t *memdb = (memdb_t *)data;

	g_return_val_if_fail(memdb != NULL, -1);
	g_return_val_if_fail(res_ptr != NULL, -1);

	int res = 1;

	int msg_result = -ENOTSUP;

	if (!DCDB_VALID_MESSAGE_TYPE(msg_type)) 
		goto unknown;

	cfs_debug("process message %u (length = %zd)", msg_type, msg_len);
	
	if (!cfs_is_quorate()) {
		cfs_critical("received write while not quorate - trigger resync");
		msg_result = -EACCES;
		goto leave;
	}

	const char *path, *to, *buf; 
	guint32 size, offset, flags;
	const guchar *csum;

	if (msg_type == DCDB_MESSAGE_CFS_UNLOCK_REQUEST ||
	    msg_type == DCDB_MESSAGE_CFS_UNLOCK) {
		msg_result = 0; /* ignored anyways */ 
		
		if (!dcdb_parse_unlock_request(msg, msg_len, &path, &csum))
			goto leave;

		guchar cur_csum[32];
		memdb_tree_entry_t *te = memdb_getattr(memdb, path);

		if (te &&  te->type == DT_DIR &&
		    path_is_lockdir(path) && memdb_tree_entry_csum(te, cur_csum) &&
		    (memcmp(csum, cur_csum, 32) == 0)) {

			if (msg_type == DCDB_MESSAGE_CFS_UNLOCK) {

				cfs_debug("got valid unlock message");

				msg_result = memdb_delete(memdb, path, nodeid, msg_time);

			} else if (dfsm_lowest_nodeid(dfsm)) {

				cfs_debug("got valid unlock request message");
			
				if (memdb_lock_expired(memdb, path, csum)) {
					cfs_debug("sending unlock message");
					dcdb_send_unlock(dfsm, path, csum, FALSE);
				}
			}
		}
		memdb_tree_entry_free(te);

	} else if (msg_type == DCDB_MESSAGE_CFS_WRITE) {

		if (!dcdb_parse_fuse_message(msg, msg_len, &path, &to, &buf, 
					     &size, &offset, &flags))
			goto leave;

		msg_result = memdb_write(memdb, path, nodeid, msg_time,
					 buf, size, offset, flags);

		if ((msg_result >= 0) && !strcmp(path, "corosync.conf"))
			dcdb_sync_corosync_conf(memdb, dfsm_nodeid_is_local(dfsm, nodeid, pid));

	} else if (msg_type == DCDB_MESSAGE_CFS_CREATE) {

		if (!dcdb_parse_fuse_message(msg, msg_len, &path, &to, &buf, 
					     &size, &offset, &flags))
			goto leave;
		
		msg_result = memdb_create(memdb, path, nodeid, msg_time);

		if ((msg_result >= 0) && !strcmp(path, "corosync.conf"))
			dcdb_sync_corosync_conf(memdb, dfsm_nodeid_is_local(dfsm, nodeid, pid));
		
	} else if (msg_type == DCDB_MESSAGE_CFS_MKDIR) {

		if (!dcdb_parse_fuse_message(msg, msg_len, &path, &to, &buf, 
					     &size, &offset, &flags))
			goto leave;
		
		msg_result = memdb_mkdir(memdb, path, nodeid, msg_time);
		
	} else if (msg_type == DCDB_MESSAGE_CFS_DELETE) {

		if (!dcdb_parse_fuse_message(msg, msg_len, &path, &to, &buf, 
					     &size, &offset, &flags))
			goto leave;

		msg_result = memdb_delete(memdb, path, nodeid, msg_time);
						
	} else if (msg_type == DCDB_MESSAGE_CFS_RENAME) {

		if (!dcdb_parse_fuse_message(msg, msg_len, &path, &to, &buf, 
					     &size, &offset, &flags))
			goto leave;

		msg_result = memdb_rename(memdb, path, to, nodeid, msg_time);
		
		if ((msg_result >= 0) && !strcmp(to, "corosync.conf"))
			dcdb_sync_corosync_conf(memdb, dfsm_nodeid_is_local(dfsm, nodeid, pid));
			
	} else if (msg_type == DCDB_MESSAGE_CFS_MTIME) {

		if (!dcdb_parse_fuse_message(msg, msg_len, &path, &to, &buf, 
					     &size, &offset, &flags))
			goto leave;
		
		/* Note: mtime is sent via offset field */
		msg_result = memdb_mtime(memdb, path, nodeid, offset);
		
	} else {
		goto unknown;
	}

	*res_ptr = msg_result;
ret:
	if (memdb->errors) {
		dfsm_set_errormode(dfsm);
		res = -1;
	}

	cfs_debug("leave %s (%d)", __func__, res);

	return res;

unknown:
	cfs_critical("received unknown message type (msg_type == %u)", msg_type);
leave:
	res = -1;
	goto ret;

}

static dfsm_callbacks_t dcdb_dfsm_callbacks = {
	.dfsm_deliver_fn = dcdb_deliver,
	.dfsm_get_state_fn = dcdb_get_state,
	.dfsm_process_state_update_fn = dcdb_process_state_update,
	.dfsm_process_update_fn = dcdb_process_update,
	.dfsm_commit_fn = dcdb_commit,
	.dfsm_cleanup_fn = dcdb_cleanup,
	.dfsm_checksum_fn = dcdb_checksum,
};

dfsm_t *dcdb_new(memdb_t *memdb)
{
	g_return_val_if_fail(memdb != NULL, NULL);
 
	return dfsm_new(memdb, DCDB_CPG_GROUP_NAME, G_LOG_DOMAIN, 
			DCDB_PROTOCOL_VERSION, &dcdb_dfsm_callbacks);
}
