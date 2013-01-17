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

#define G_LOG_DOMAIN "status"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <glib.h>
#include <sys/syslog.h>
#include <rrd.h>
#include <rrd_client.h>
#include <time.h>

#include "cfs-utils.h"
#include "status.h"
#include "logger.h"

#define KVSTORE_CPG_GROUP_NAME "pve_kvstore_v1"

typedef enum {
	KVSTORE_MESSAGE_UPDATE = 1,
	KVSTORE_MESSAGE_UPDATE_COMPLETE = 2,
	KVSTORE_MESSAGE_LOG = 3,
} kvstore_message_t;

static uint32_t vminfo_version_counter;

typedef struct {
	uint32_t vmid;
	char *nodename;
	int vmtype;
	uint32_t version;
} vminfo_t;

typedef struct {
	char *key;
	gpointer data;
	size_t len;
	uint32_t version;
} kventry_t;

typedef struct {
	char *key;
	gpointer data;
	size_t len;
	uint32_t time;
} rrdentry_t;

typedef struct {
	char *path;
	uint32_t version;
} memdb_change_t;

static memdb_change_t memdb_change_array[] = {
	{ .path = "cluster.conf" },
	{ .path = "cluster.conf.new" },
	{ .path = "storage.cfg" },
	{ .path = "user.cfg" },
	{ .path = "domains.cfg" },
	{ .path = "priv/shadow.cfg" },
	{ .path = "datacenter.cfg" },
	{ .path = "vzdump.cron" },
};

static GStaticMutex mutex = G_STATIC_MUTEX_INIT;

typedef struct {
	time_t start_time;

	uint32_t quorate;

	cfs_clinfo_t *clinfo;
	uint32_t clinfo_version;

	GHashTable *vmlist;
	uint32_t vmlist_version;

	dfsm_t *kvstore;
	GHashTable *kvhash;
	GHashTable *rrdhash;
	GHashTable *iphash;

	GHashTable *memdb_changes;

	clusterlog_t *clusterlog;
} cfs_status_t;

static cfs_status_t cfs_status;

struct cfs_clnode {
	char *name;
	uint32_t nodeid;
	uint32_t votes;
	gboolean online;
	GHashTable *kvhash;
};

struct cfs_clinfo {
	char *cluster_name;
	uint32_t cman_version;

	GHashTable *nodes_byid;
	GHashTable *nodes_byname;
};

static guint
g_int32_hash (gconstpointer v)
{
	return *(const uint32_t *) v;
}

static gboolean
g_int32_equal (gconstpointer v1,
	       gconstpointer v2)
{
	return *((const uint32_t*) v1) == *((const uint32_t*) v2);
}

static void vminfo_free(vminfo_t *vminfo)
{
	g_return_if_fail(vminfo != NULL);

	if (vminfo->nodename)
		g_free(vminfo->nodename);


	g_free(vminfo);
}

void cfs_clnode_destroy(
	cfs_clnode_t *clnode)
{
	g_return_if_fail(clnode != NULL);

	if (clnode->kvhash)
		g_hash_table_destroy(clnode->kvhash);

	if (clnode->name)
		g_free(clnode->name);

	g_free(clnode);
}

cfs_clnode_t *cfs_clnode_new(
	const char *name,
	uint32_t nodeid,
	uint32_t votes)
{
	g_return_val_if_fail(name != NULL, NULL);

	cfs_clnode_t *clnode = g_new0(cfs_clnode_t, 1);
	if (!clnode)
		return NULL;

	clnode->name = g_strdup(name);
	clnode->nodeid = nodeid;
	clnode->votes = votes;

	return clnode;
}

gboolean cfs_clinfo_destroy(
	cfs_clinfo_t *clinfo)
{
	g_return_val_if_fail(clinfo != NULL, FALSE);

	if (clinfo->cluster_name)
		g_free(clinfo->cluster_name);

	if (clinfo->nodes_byname)
		g_hash_table_destroy(clinfo->nodes_byname);

	if (clinfo->nodes_byid)
		g_hash_table_destroy(clinfo->nodes_byid);

	g_free(clinfo);

	return TRUE;
}

cfs_clinfo_t *cfs_clinfo_new(
	const char *cluster_name,
	uint32_t cman_version)
{
	g_return_val_if_fail(cluster_name != NULL, NULL);

	cfs_clinfo_t *clinfo = g_new0(cfs_clinfo_t, 1);
	if (!clinfo)
		return NULL;

	clinfo->cluster_name = g_strdup(cluster_name);
	clinfo->cman_version = cman_version;

	if (!(clinfo->nodes_byid = g_hash_table_new_full(
		      g_int32_hash, g_int32_equal, NULL,
		      (GDestroyNotify)cfs_clnode_destroy)))
		goto fail;

	if (!(clinfo->nodes_byname = g_hash_table_new(g_str_hash, g_str_equal)))
		goto fail;

	return clinfo;

fail:
	cfs_clinfo_destroy(clinfo);

	return NULL;
}

gboolean cfs_clinfo_add_node(
	cfs_clinfo_t *clinfo,
	cfs_clnode_t *clnode)
{
	g_return_val_if_fail(clinfo != NULL, FALSE);
	g_return_val_if_fail(clnode != NULL, FALSE);

	g_hash_table_replace(clinfo->nodes_byid, &clnode->nodeid, clnode);
	g_hash_table_replace(clinfo->nodes_byname, clnode->name, clnode);

	return TRUE;
}

int
cfs_create_memberlist_msg(
	GString *str)
{
	g_return_val_if_fail(str != NULL, -EINVAL);

	g_static_mutex_lock(&mutex);

	g_string_append_printf(str,"{\n");

	guint nodecount = 0;

	cfs_clinfo_t *clinfo = cfs_status.clinfo;

	if (clinfo && clinfo->nodes_byid)
		nodecount = g_hash_table_size(clinfo->nodes_byid);

	if (nodecount) {
		g_string_append_printf(str, "\"nodename\": \"%s\",\n", cfs.nodename);
		g_string_append_printf(str, "\"version\": %u,\n", cfs_status.clinfo_version);

		g_string_append_printf(str, "\"cluster\": { ");
		g_string_append_printf(str, "\"name\": \"%s\", \"version\": %d, "
				       "\"nodes\": %d, \"quorate\": %d ",
				       clinfo->cluster_name, clinfo->cman_version,
				       nodecount, cfs_status.quorate);

		g_string_append_printf(str,"},\n");
		g_string_append_printf(str,"\"nodelist\": {\n");

		GHashTable *ht = clinfo->nodes_byid;
		GHashTableIter iter;
		gpointer key, value;

		g_hash_table_iter_init (&iter, ht);

		int i = 0;
		while (g_hash_table_iter_next (&iter, &key, &value)) {
			cfs_clnode_t *node = (cfs_clnode_t *)value;
			if (i) g_string_append_printf(str, ",\n");
			i++;

			g_string_append_printf(str, "  \"%s\": { \"id\": %d, \"online\": %d",
					       node->name, node->nodeid, node->online);


			char *ip = (char *)g_hash_table_lookup(cfs_status.iphash, node->name);
			if (ip) {
				g_string_append_printf(str, ", \"ip\": \"%s\"", ip);
			}

			g_string_append_printf(str, "}");

		}
		g_string_append_printf(str,"\n  }\n");
	} else {
		g_string_append_printf(str, "\"nodename\": \"%s\",\n", cfs.nodename);
		g_string_append_printf(str, "\"version\": %u\n", cfs_status.clinfo_version);
	}

	g_string_append_printf(str,"}\n");

	g_static_mutex_unlock (&mutex);

	return 0;
}

static void
kventry_free(kventry_t *entry)
{
	g_return_if_fail(entry != NULL);

	g_free(entry->key);
	g_free(entry->data);
	g_free(entry);
}

static GHashTable *
kventry_hash_new(void)
{
	return g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
				     (GDestroyNotify)kventry_free);
}

static void
rrdentry_free(rrdentry_t *entry)
{
	g_return_if_fail(entry != NULL);

	g_free(entry->key);
	g_free(entry->data);
	g_free(entry);
}

static GHashTable *
rrdentry_hash_new(void)
{
	return g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
				     (GDestroyNotify)rrdentry_free);
}

void
cfs_cluster_log_dump(GString *str, const char *user, guint max_entries)
{
	clusterlog_dump(cfs_status.clusterlog, str, user, max_entries);
}

void
cfs_cluster_log(clog_entry_t *entry)
{
	g_return_if_fail(entry != NULL);

	clusterlog_insert(cfs_status.clusterlog, entry);

	if (cfs_status.kvstore) {
		struct iovec iov[1];
		iov[0].iov_base = (char *)entry;
		iov[0].iov_len = clog_entry_size(entry);

		dfsm_send_message(cfs_status.kvstore, KVSTORE_MESSAGE_LOG, iov, 1);
	}
}

void cfs_status_init(void)
{
	g_static_mutex_lock (&mutex);

	cfs_status.start_time = time(NULL);

	cfs_status.vmlist = vmlist_hash_new();

	cfs_status.kvhash = kventry_hash_new();

	cfs_status.rrdhash = rrdentry_hash_new();

	cfs_status.iphash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	cfs_status.memdb_changes = g_hash_table_new(g_str_hash, g_str_equal);

	for (int i = 0; i < G_N_ELEMENTS(memdb_change_array); i++) {
		g_hash_table_replace(cfs_status.memdb_changes,
				     memdb_change_array[i].path,
				     &memdb_change_array[i]);
	}

	cfs_status.clusterlog = clusterlog_new();

	// fixme:
	clusterlog_add(cfs_status.clusterlog, "root", "cluster", getpid(),
		       LOG_INFO, "starting cluster log");

	g_static_mutex_unlock (&mutex);
}

void cfs_status_cleanup(void)
{
	g_static_mutex_lock (&mutex);

	cfs_status.clinfo_version++;

	if (cfs_status.clinfo) {
		cfs_clinfo_destroy(cfs_status.clinfo);
		cfs_status.clinfo = NULL;
	}

	if (cfs_status.vmlist) {
		g_hash_table_destroy(cfs_status.vmlist);
		cfs_status.vmlist = NULL;
	}

	if (cfs_status.kvhash) {
		g_hash_table_destroy(cfs_status.kvhash);
		cfs_status.kvhash = NULL;
	}

	if (cfs_status.rrdhash) {
		g_hash_table_destroy(cfs_status.rrdhash);
		cfs_status.rrdhash = NULL;
	}

	if (cfs_status.iphash) {
		g_hash_table_destroy(cfs_status.iphash);
		cfs_status.iphash = NULL;
	}

	if (cfs_status.clusterlog)
		clusterlog_destroy(cfs_status.clusterlog);

	g_static_mutex_unlock (&mutex);
}

void cfs_status_set_clinfo(
	cfs_clinfo_t *clinfo)
{
	g_return_if_fail(clinfo != NULL);

	g_static_mutex_lock (&mutex);

	cfs_status.clinfo_version++;

	cfs_clinfo_t *old = cfs_status.clinfo;

	cfs_status.clinfo = clinfo;

	cfs_message("update cluster info (cluster name  %s, version = %d)",
		    clinfo->cluster_name, clinfo->cman_version);


	if (old && old->nodes_byid && clinfo->nodes_byid) {
		/* copy kvstore */
		GHashTable *ht = clinfo->nodes_byid;
		GHashTableIter iter;
		gpointer key, value;

		g_hash_table_iter_init (&iter, ht);

		while (g_hash_table_iter_next (&iter, &key, &value)) {
			cfs_clnode_t *node = (cfs_clnode_t *)value;
			cfs_clnode_t *oldnode;
			if ((oldnode = g_hash_table_lookup(old->nodes_byid, key))) {
				node->online = oldnode->online;
				node->kvhash = oldnode->kvhash;
				oldnode->kvhash = NULL;
			}
		}

	}

	if (old)
		cfs_clinfo_destroy(old);


	g_static_mutex_unlock (&mutex);
}

static void
dump_kvstore_versions(
	GString *str,
	GHashTable *kvhash,
	const char *nodename)
{
	g_return_if_fail(kvhash != NULL);
	g_return_if_fail(str != NULL);
	g_return_if_fail(nodename != NULL);

	GHashTable *ht = kvhash;
	GHashTableIter iter;
	gpointer key, value;

	g_string_append_printf(str, "\"%s\": {\n", nodename);

	g_hash_table_iter_init (&iter, ht);

	int i = 0;
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		kventry_t *entry = (kventry_t *)value;
		if (i) g_string_append_printf(str, ",\n");
		i++;
		g_string_append_printf(str,"\"%s\": %u", entry->key, entry->version);
	}

	g_string_append_printf(str, "}\n");
}

int
cfs_create_version_msg(GString *str)
{
	g_return_val_if_fail(str != NULL, -EINVAL);

	g_static_mutex_lock (&mutex);

	g_string_append_printf(str,"{\n");

	g_string_append_printf(str, "\"starttime\": %lu,\n", (unsigned long)cfs_status.start_time);

	g_string_append_printf(str, "\"clinfo\": %u,\n", cfs_status.clinfo_version);

	g_string_append_printf(str, "\"vmlist\": %u,\n", cfs_status.vmlist_version);

	for (int i = 0; i < G_N_ELEMENTS(memdb_change_array); i++) {
		g_string_append_printf(str, "\"%s\": %u,\n",
				       memdb_change_array[i].path,
				       memdb_change_array[i].version);
	}

	g_string_append_printf(str, "\"kvstore\": {\n");

	dump_kvstore_versions(str, cfs_status.kvhash, cfs.nodename);

	cfs_clinfo_t *clinfo = cfs_status.clinfo;

	if (clinfo && clinfo->nodes_byid) {
		GHashTable *ht = clinfo->nodes_byid;
		GHashTableIter iter;
		gpointer key, value;

		g_hash_table_iter_init (&iter, ht);

		while (g_hash_table_iter_next (&iter, &key, &value)) {
			cfs_clnode_t *node = (cfs_clnode_t *)value;
			if (!node->kvhash)
				continue;
			g_string_append_printf(str, ",\n");
			dump_kvstore_versions(str, node->kvhash, node->name);
		}
	}

	g_string_append_printf(str,"}\n");

	g_string_append_printf(str,"}\n");

	g_static_mutex_unlock (&mutex);

	return 0;
}

GHashTable *
vmlist_hash_new(void)
{
	return g_hash_table_new_full(g_int_hash, g_int_equal, NULL,
				     (GDestroyNotify)vminfo_free);
}

gboolean
vmlist_hash_insert_vm(
	GHashTable *vmlist,
	int vmtype,
	guint32 vmid,
	const char *nodename,
	gboolean replace)
{
	g_return_val_if_fail(vmlist != NULL, FALSE);
	g_return_val_if_fail(nodename != NULL, FALSE);
	g_return_val_if_fail(vmid != 0, FALSE);
	g_return_val_if_fail(vmtype == VMTYPE_QEMU || vmtype == VMTYPE_OPENVZ, FALSE);

	if (!replace && g_hash_table_lookup(vmlist, &vmid)) {
		cfs_critical("detected duplicate VMID %d", vmid);
		return FALSE;
	}

	vminfo_t *vminfo = g_new0(vminfo_t, 1);

	vminfo->vmid = vmid;
	vminfo->vmtype = vmtype;
	vminfo->nodename = g_strdup(nodename);

	vminfo->version = ++vminfo_version_counter;

	g_hash_table_replace(vmlist, &vminfo->vmid, vminfo);

	return TRUE;
}

void
vmlist_register_vm(
	int vmtype,
	guint32 vmid,
	const char *nodename)
{
	g_return_if_fail(cfs_status.vmlist != NULL);
	g_return_if_fail(nodename != NULL);
	g_return_if_fail(vmid != 0);
	g_return_if_fail(vmtype == VMTYPE_QEMU || vmtype == VMTYPE_OPENVZ);

	cfs_debug("vmlist_register_vm: %s/%u %d", nodename, vmid, vmtype);

	g_static_mutex_lock (&mutex);

	cfs_status.vmlist_version++;

	vmlist_hash_insert_vm(cfs_status.vmlist, vmtype, vmid, nodename, TRUE);

	g_static_mutex_unlock (&mutex);
}

gboolean
vmlist_different_vm_exists(
	int vmtype,
	guint32 vmid,
	const char *nodename)
{
	g_return_val_if_fail(cfs_status.vmlist != NULL, FALSE);
	g_return_val_if_fail(vmid != 0, FALSE);

	gboolean res = FALSE;

	g_static_mutex_lock (&mutex);

	vminfo_t *vminfo;
	if ((vminfo = (vminfo_t *)g_hash_table_lookup(cfs_status.vmlist, &vmid))) {
		if (!(vminfo->vmtype == vmtype && strcmp(vminfo->nodename, nodename) == 0))
			res = TRUE;
	}
	g_static_mutex_unlock (&mutex);

	return res;
}

gboolean
vmlist_vm_exists(
	guint32 vmid)
{
	g_return_val_if_fail(cfs_status.vmlist != NULL, FALSE);
	g_return_val_if_fail(vmid != 0, FALSE);

	g_static_mutex_lock (&mutex);

	gpointer res = g_hash_table_lookup(cfs_status.vmlist, &vmid);

	g_static_mutex_unlock (&mutex);

	return res != NULL;
}

void
vmlist_delete_vm(
	guint32 vmid)
{
	g_return_if_fail(cfs_status.vmlist != NULL);
	g_return_if_fail(vmid != 0);

	g_static_mutex_lock (&mutex);

	cfs_status.vmlist_version++;

	g_hash_table_remove(cfs_status.vmlist, &vmid);

	g_static_mutex_unlock (&mutex);
}

void cfs_status_set_vmlist(
	GHashTable *vmlist)
{
	g_return_if_fail(vmlist != NULL);

	g_static_mutex_lock (&mutex);

	cfs_status.vmlist_version++;

	if (cfs_status.vmlist)
		g_hash_table_destroy(cfs_status.vmlist);

	cfs_status.vmlist = vmlist;

	g_static_mutex_unlock (&mutex);
}

int
cfs_create_vmlist_msg(GString *str)
{
	g_return_val_if_fail(cfs_status.vmlist != NULL, -EINVAL);
	g_return_val_if_fail(str != NULL, -EINVAL);

	g_static_mutex_lock (&mutex);

	g_string_append_printf(str,"{\n");

	GHashTable *ht = cfs_status.vmlist;

	guint count = g_hash_table_size(ht);

	if (!count) {
		g_string_append_printf(str,"\"version\": %u\n", cfs_status.vmlist_version);
	} else {
		g_string_append_printf(str,"\"version\": %u,\n", cfs_status.vmlist_version);

		g_string_append_printf(str,"\"ids\": {\n");

		GHashTableIter iter;
		gpointer key, value;

		g_hash_table_iter_init (&iter, ht);

		int first = 1;
		while (g_hash_table_iter_next (&iter, &key, &value)) {
			vminfo_t *vminfo = (vminfo_t *)value;
			char *type;
			if (vminfo->vmtype == VMTYPE_QEMU) {
				type = "qemu";
			} else if (vminfo->vmtype == VMTYPE_OPENVZ) {
				type = "openvz";
			} else {
				type = "unknown";
			}

			if (!first)
				g_string_append_printf(str, ",\n");
			first = 0;

			g_string_append_printf(str,"\"%u\": { \"node\": \"%s\", \"type\": \"%s\", \"version\": %u }",
					       vminfo->vmid, vminfo->nodename, type, vminfo->version);
		}

		g_string_append_printf(str,"}\n");
	}
	g_string_append_printf(str,"\n}\n");

	g_static_mutex_unlock (&mutex);

	return 0;
}

void
record_memdb_change(const char *path)
{
	g_return_if_fail(cfs_status.memdb_changes != 0);

	memdb_change_t *ce;

	if ((ce = (memdb_change_t *)g_hash_table_lookup(cfs_status.memdb_changes, path))) {
		ce->version++;
	}
}

void
record_memdb_reload(void)
{
	for (int i = 0; i < G_N_ELEMENTS(memdb_change_array); i++) {
		memdb_change_array[i].version++;
	}
}

static gboolean
kventry_hash_set(
	GHashTable *kvhash,
	const char *key,
	gconstpointer data,
	size_t len)
{
	g_return_val_if_fail(kvhash != NULL, FALSE);
	g_return_val_if_fail(key != NULL, FALSE);
	g_return_val_if_fail(data != NULL, FALSE);

	kventry_t *entry;
	if ((entry = (kventry_t *)g_hash_table_lookup(kvhash, key))) {
		g_free(entry->data);
		entry->data = g_memdup(data, len);
		entry->len = len;
		entry->version++;
	} else {
		kventry_t *entry = g_new0(kventry_t, 1);

		entry->key = g_strdup(key);
		entry->data = g_memdup(data, len);
		entry->len = len;

		g_hash_table_replace(kvhash, entry->key, entry);
	}

	return TRUE;
}

static const char *rrd_def_node[] = {
	"DS:loadavg:GAUGE:120:0:U",
	"DS:maxcpu:GAUGE:120:0:U",
	"DS:cpu:GAUGE:120:0:U",
	"DS:iowait:GAUGE:120:0:U",
	"DS:memtotal:GAUGE:120:0:U",
	"DS:memused:GAUGE:120:0:U",
	"DS:swaptotal:GAUGE:120:0:U",
	"DS:swapused:GAUGE:120:0:U",
	"DS:roottotal:GAUGE:120:0:U",
	"DS:rootused:GAUGE:120:0:U",
	"DS:netin:COUNTER:120:0:U",
	"DS:netout:COUNTER:120:0:U",

	"RRA:AVERAGE:0.5:1:70", // 1 min avg - one hour
	"RRA:AVERAGE:0.5:30:70", // 30 min avg - one day
	"RRA:AVERAGE:0.5:180:70", // 3 hour avg - one week
	"RRA:AVERAGE:0.5:720:70", // 12 hour avg - one month
	"RRA:AVERAGE:0.5:10080:70", // 7 day avg - ony year

	"RRA:MAX:0.5:1:70", // 1 min max - one hour
	"RRA:MAX:0.5:30:70", // 30 min max - one day
	"RRA:MAX:0.5:180:70",  // 3 hour max - one week
	"RRA:MAX:0.5:720:70", // 12 hour max - one month
	"RRA:MAX:0.5:10080:70", // 7 day max - ony year
	NULL,
};

static const char *rrd_def_vm[] = {
	"DS:maxcpu:GAUGE:120:0:U",
	"DS:cpu:GAUGE:120:0:U",
	"DS:maxmem:GAUGE:120:0:U",
	"DS:mem:GAUGE:120:0:U",
	"DS:maxdisk:GAUGE:120:0:U",
	"DS:disk:GAUGE:120:0:U",
	"DS:netin:COUNTER:120:0:U",
	"DS:netout:COUNTER:120:0:U",
	"DS:diskread:COUNTER:120:0:U",
	"DS:diskwrite:COUNTER:120:0:U",

	"RRA:AVERAGE:0.5:1:70", // 1 min avg - one hour
	"RRA:AVERAGE:0.5:30:70", // 30 min avg - one day
	"RRA:AVERAGE:0.5:180:70", // 3 hour avg - one week
	"RRA:AVERAGE:0.5:720:70", // 12 hour avg - one month
	"RRA:AVERAGE:0.5:10080:70", // 7 day avg - ony year

	"RRA:MAX:0.5:1:70", // 1 min max - one hour
	"RRA:MAX:0.5:30:70", // 30 min max - one day
	"RRA:MAX:0.5:180:70",  // 3 hour max - one week
	"RRA:MAX:0.5:720:70", // 12 hour max - one month
	"RRA:MAX:0.5:10080:70", // 7 day max - ony year
	NULL,
};

static const char *rrd_def_storage[] = {
	"DS:total:GAUGE:120:0:U",
	"DS:used:GAUGE:120:0:U",

	"RRA:AVERAGE:0.5:1:70", // 1 min avg - one hour
	"RRA:AVERAGE:0.5:30:70", // 30 min avg - one day
	"RRA:AVERAGE:0.5:180:70", // 3 hour avg - one week
	"RRA:AVERAGE:0.5:720:70", // 12 hour avg - one month
	"RRA:AVERAGE:0.5:10080:70", // 7 day avg - ony year

	"RRA:MAX:0.5:1:70", // 1 min max - one hour
	"RRA:MAX:0.5:30:70", // 30 min max - one day
	"RRA:MAX:0.5:180:70",  // 3 hour max - one week
	"RRA:MAX:0.5:720:70", // 12 hour max - one month
	"RRA:MAX:0.5:10080:70", // 7 day max - ony year
	NULL,
};

#define RRDDIR "/var/lib/rrdcached/db"

static void
create_rrd_file(
	const char *filename,
	int argcount,
	const char *rrddef[])
{
	/* start at day boundary */
	time_t ctime;
	time(&ctime);
	struct tm *ltm = localtime(&ctime);
	ltm->tm_sec = 0;
	ltm->tm_min = 0;
	ltm->tm_hour = 0;

	rrd_clear_error();
	if (rrd_create_r(filename, 60, timelocal(ltm), argcount, rrddef)) {
		cfs_message("RRD create error %s: %s", filename, rrd_get_error());
	}
}

static inline const char *
rrd_skip_data(
	const char *data,
	int count)
{
	int found = 0;
	while (*data && found < count) {
		if (*data++ == ':')
			found++;
	}
	return data;
}

static void
update_rrd_data(
	const char *key,
	gconstpointer data,
	size_t len)
{
	g_return_if_fail(key != NULL);
	g_return_if_fail(data != NULL);
	g_return_if_fail(len > 0);
	g_return_if_fail(len < 4096);

	static const char *rrdcsock = "unix:/var/run/rrdcached.sock";

	int use_daemon = 1;
        if (rrdc_connect(rrdcsock) != 0)
		use_daemon = 0;

	char *filename = NULL;

	int skip = 0;

	if (strncmp(key, "pve2-node/", 10) == 0) {
		const char *node = key + 10;

		skip = 2;

		if (strchr(node, '/') != NULL)
			goto keyerror;

		if (strlen(node) < 1)
			goto keyerror;

		filename = g_strdup_printf(RRDDIR "/%s", key);

		if (!g_file_test(filename, G_FILE_TEST_EXISTS)) {

			mkdir(RRDDIR "/pve2-node", 0755);
			int argcount = sizeof(rrd_def_node)/sizeof(void*) - 1;
			create_rrd_file(filename, argcount, rrd_def_node);
		}

	} else if ((strncmp(key, "pve2-vm/", 8) == 0) ||
		   (strncmp(key, "pve2.3-vm/", 10) == 0)) {
		const char *vmid;

		if (strncmp(key, "pve2-vm/", 8) == 0) {
			vmid = key + 8;
			skip = 2;
		} else {
			vmid = key + 10;
			skip = 4;
		}

		if (strchr(vmid, '/') != NULL)
			goto keyerror;

		if (strlen(vmid) < 1)
			goto keyerror;

		filename = g_strdup_printf(RRDDIR "/%s/%s", "pve2-vm", vmid);

		if (!g_file_test(filename, G_FILE_TEST_EXISTS)) {

			mkdir(RRDDIR "/pve2-vm", 0755);
			int argcount = sizeof(rrd_def_vm)/sizeof(void*) - 1;
			create_rrd_file(filename, argcount, rrd_def_vm);
		}

	} else if (strncmp(key, "pve2-storage/", 13) == 0) {
		const char *node = key + 13;

		const char *storage = node;
		while (*storage && *storage != '/')
			storage++;

		if (*storage != '/' || ((storage - node) < 1))
			goto keyerror;

		storage++;

		if (strchr(storage, '/') != NULL)
			goto keyerror;

		if (strlen(storage) < 1)
			goto keyerror;

		filename = g_strdup_printf(RRDDIR "/%s", key);

		if (!g_file_test(filename, G_FILE_TEST_EXISTS)) {

			mkdir(RRDDIR "/pve2-storage", 0755);

			char *dir = g_path_get_dirname(filename);
			mkdir(dir, 0755);
			g_free(dir);

			int argcount = sizeof(rrd_def_storage)/sizeof(void*) - 1;
			create_rrd_file(filename, argcount, rrd_def_storage);
		}

	} else {
		goto keyerror;
	}

	const char *dp = skip ? rrd_skip_data(data, skip) : data;

	const char *update_args[] = { dp, NULL };

	if (use_daemon) {
		int status;
		if ((status = rrdc_update(filename, 1, update_args)) != 0) {
			cfs_message("RRDC update error %s: %d", filename, status);
			rrdc_disconnect();
			rrd_clear_error();
			if (rrd_update_r(filename, NULL, 1, update_args) != 0) {
				cfs_message("RRD update error %s: %s", filename, rrd_get_error());
			}
		}

	} else {
		rrd_clear_error();
		if (rrd_update_r(filename, NULL, 1, update_args) != 0) {
			cfs_message("RRD update error %s: %s", filename, rrd_get_error());
		}
	}

ret:
	if (filename) 
		g_free(filename);

	return;

keyerror:
	cfs_critical("RRD update error: unknown/wrong key %s", key);
	goto ret;
}

static gboolean
rrd_entry_is_old(
	gpointer key,
	gpointer value,
	gpointer user_data)
{
	rrdentry_t *entry = (rrdentry_t *)value;
	uint32_t ctime = GPOINTER_TO_UINT(user_data);

	int diff = ctime - entry->time;

	/* remove everything older than 5 minutes */
	int expire = 60*5;

	return (diff > expire) ? TRUE : FALSE;
}

static char *rrd_dump_buf = NULL;
static time_t rrd_dump_last = 0;

void
cfs_rrd_dump(GString *str)
{
	time_t ctime;
	time(&ctime);

	if (rrd_dump_buf && (ctime - rrd_dump_last) < 2) {
		g_string_assign(str, rrd_dump_buf);
		return;
	}

	/* remove old data */
	g_hash_table_foreach_remove(cfs_status.rrdhash, rrd_entry_is_old,
				    GUINT_TO_POINTER(ctime));

	g_string_set_size(str, 0);

	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init (&iter, cfs_status.rrdhash);

	while (g_hash_table_iter_next (&iter, &key, &value)) {
		rrdentry_t *entry = (rrdentry_t *)value;
		g_string_append(str, key);
		g_string_append(str, ":");
		g_string_append(str, entry->data);
		g_string_append(str, "\n");
	}

	g_string_append_c(str, 0); // never return undef

	rrd_dump_last = ctime;
	if (rrd_dump_buf)
		g_free(rrd_dump_buf);
	rrd_dump_buf = g_strdup(str->str);
}

static gboolean
nodeip_hash_set(
	GHashTable *iphash,
	const char *nodename,
	const char *ip,
	size_t len)
{
	g_return_val_if_fail(iphash != NULL, FALSE);
	g_return_val_if_fail(nodename != NULL, FALSE);
	g_return_val_if_fail(ip != NULL, FALSE);
	g_return_val_if_fail(len > 0, FALSE);
	g_return_val_if_fail(len < 256, FALSE);
	g_return_val_if_fail(ip[len-1] == 0, FALSE);

	char *oldip = (char *)g_hash_table_lookup(iphash, nodename);

	if (!oldip || (strcmp(oldip, ip) != 0)) {
		cfs_status.clinfo_version++;
		g_hash_table_replace(iphash, g_strdup(nodename), g_strdup(ip));
	}

	return TRUE;
}

static gboolean
rrdentry_hash_set(
	GHashTable *rrdhash,
	const char *key,
	const char *data,
	size_t len)
{
	g_return_val_if_fail(rrdhash != NULL, FALSE);
	g_return_val_if_fail(key != NULL, FALSE);
	g_return_val_if_fail(data != NULL, FALSE);
	g_return_val_if_fail(len > 0, FALSE);
	g_return_val_if_fail(len < 4096, FALSE);
	g_return_val_if_fail(data[len-1] == 0, FALSE);

	rrdentry_t *entry;
	if ((entry = (rrdentry_t *)g_hash_table_lookup(rrdhash, key))) {
		g_free(entry->data);
		entry->data = g_memdup(data, len);
		entry->len = len;
		entry->time = time(NULL);
	} else {
		rrdentry_t *entry = g_new0(rrdentry_t, 1);

		entry->key = g_strdup(key);
		entry->data = g_memdup(data, len);
		entry->len = len;
		entry->time = time(NULL);

		g_hash_table_replace(rrdhash, entry->key, entry);
	}

	update_rrd_data(key, data, len);

	return TRUE;
}

static int
kvstore_send_update_message(
	dfsm_t *dfsm,
	const char *key,
	gpointer data,
	guint32 len)
{

	struct iovec iov[2];

	char name[256];
	g_strlcpy(name, key, sizeof(name));

	iov[0].iov_base = &name;
	iov[0].iov_len = sizeof(name);

	iov[1].iov_base = (char *)data;
	iov[1].iov_len = len;

	if (dfsm_send_message(dfsm, KVSTORE_MESSAGE_UPDATE, iov, 2) == CS_OK)
		return 0;

	return -EACCES;
}

static clog_entry_t *
kvstore_parse_log_message(
	const void *msg,
	size_t msg_len)
{
	g_return_val_if_fail(msg != NULL, NULL);

	if (msg_len < sizeof(clog_entry_t)) {
		cfs_critical("received short log message (%lu < %lu)", msg_len, sizeof(clog_entry_t));
		return NULL;
	}

	clog_entry_t *entry = (clog_entry_t *)msg;

	uint32_t size = sizeof(clog_entry_t) + entry->node_len +
		entry->ident_len + entry->tag_len + entry->msg_len;

	if (msg_len != size) {
		cfs_critical("received log message with wrong size (%lu != %u)", msg_len, size);
		return NULL;
	}

	msg = entry->data;

	if (*((char *)msg + entry->node_len - 1)) {
		cfs_critical("unterminated string in log message");
		return NULL;
	}
	msg += entry->node_len;

	if (*((char *)msg + entry->ident_len - 1)) {
		cfs_critical("unterminated string in log message");
		return NULL;
	}
	msg += entry->ident_len;

	if (*((char *)msg + entry->tag_len - 1)) {
		cfs_critical("unterminated string in log message");
		return NULL;
	}
	msg += entry->tag_len;

	if (*((char *)msg + entry->msg_len - 1)) {
		cfs_critical("unterminated string in log message");
		return NULL;
	}

	return entry;
}

static gboolean
kvstore_parse_update_message(
	const void *msg,
	size_t msg_len,
	const char **key,
	gconstpointer *data,
	guint32 *len)
{
	g_return_val_if_fail(msg != NULL, FALSE);
	g_return_val_if_fail(key != NULL, FALSE);
	g_return_val_if_fail(data != NULL, FALSE);
	g_return_val_if_fail(len != NULL, FALSE);

	if (msg_len < 256) {
		cfs_critical("received short kvstore message (%lu < 256)", msg_len);
		return FALSE;
	}

	/* test if key is null terminated */
	int i = 0;
	for (i = 0; i < 256; i++)
		if (((char *)msg)[i] == 0)
			break;

	if (i == 256)
		return FALSE;


	*len = msg_len - 256;
	*key = msg;
	*data = msg + 256;

	return TRUE;
}

int
cfs_create_status_msg(
	GString *str,
	const char *nodename,
	const char *key)
{
	g_return_val_if_fail(str != NULL, -EINVAL);
	g_return_val_if_fail(key != NULL, -EINVAL);

	int res = -ENOENT;

	GHashTable *kvhash = NULL;

	g_static_mutex_lock (&mutex);

	if (!nodename || !nodename[0] || !strcmp(nodename, cfs.nodename)) {
		kvhash = cfs_status.kvhash;
	} else {
		cfs_clnode_t *clnode;
		if ((clnode = g_hash_table_lookup(cfs_status.clinfo->nodes_byname, nodename)))
			kvhash = clnode->kvhash;
	}

	kventry_t *entry;
	if (kvhash && (entry = (kventry_t *)g_hash_table_lookup(kvhash, key))) {
		g_string_append_len(str, entry->data, entry->len);
		res = 0;
	}

	g_static_mutex_unlock (&mutex);

	return res;
}

int
cfs_status_set(
	const char *key,
	gpointer data,
	size_t len)
{
	g_return_val_if_fail(key != NULL, FALSE);
	g_return_val_if_fail(data != NULL, FALSE);
	g_return_val_if_fail(cfs_status.kvhash != NULL, FALSE);

	if (len > CFS_MAX_STATUS_SIZE)
		return -EFBIG;

	g_static_mutex_lock (&mutex);

	gboolean res;

	if (strncmp(key, "rrd/", 4) == 0) {
		res = rrdentry_hash_set(cfs_status.rrdhash, key + 4, data, len);
	} else if (!strcmp(key, "nodeip")) {
		res = nodeip_hash_set(cfs_status.iphash, cfs.nodename, data, len);
	} else {
		res = kventry_hash_set(cfs_status.kvhash, key, data, len);
	}
	g_static_mutex_unlock (&mutex);

	if (cfs_status.kvstore)
		kvstore_send_update_message(cfs_status.kvstore, key, data, len);

	return res ? 0 : -ENOMEM;
}

gboolean
cfs_kvstore_node_set(
	uint32_t nodeid,
	const char *key,
	gconstpointer data,
	size_t len)
{
	g_return_val_if_fail(nodeid != 0, FALSE);
	g_return_val_if_fail(key != NULL, FALSE);
	g_return_val_if_fail(data != NULL, FALSE);

	g_static_mutex_lock (&mutex);

	if (!cfs_status.clinfo || !cfs_status.clinfo->nodes_byid)
		goto ret; /* ignore */

	cfs_clnode_t *clnode = g_hash_table_lookup(cfs_status.clinfo->nodes_byid, &nodeid);
	if (!clnode)
		goto ret; /* ignore */

	cfs_debug("got node %d status update %s", nodeid, key);

	if (strncmp(key, "rrd/", 4) == 0) {
		rrdentry_hash_set(cfs_status.rrdhash, key + 4, data, len);
	} else if (!strcmp(key, "nodeip")) {
		nodeip_hash_set(cfs_status.iphash, clnode->name, data, len);
	} else {
		if (!clnode->kvhash) {
			if (!(clnode->kvhash = kventry_hash_new())) {
				goto ret; /*ignore */
			}
		}

		kventry_hash_set(clnode->kvhash, key, data, len);

	}
ret:
	g_static_mutex_unlock (&mutex);

	return TRUE;
}

static gboolean
cfs_kvstore_sync(void)
{
	g_return_val_if_fail(cfs_status.kvhash != NULL, FALSE);
	g_return_val_if_fail(cfs_status.kvstore != NULL, FALSE);

	gboolean res = TRUE;

	g_static_mutex_lock (&mutex);

	GHashTable *ht = cfs_status.kvhash;
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init (&iter, ht);

	while (g_hash_table_iter_next (&iter, &key, &value)) {
		kventry_t *entry = (kventry_t *)value;
		kvstore_send_update_message(cfs_status.kvstore, entry->key, entry->data, entry->len);
	}

	g_static_mutex_unlock (&mutex);

	return res;
}

static int
dfsm_deliver(
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
	g_return_val_if_fail(res_ptr != NULL, -1);

	/* ignore message for ourself */
	if (dfsm_nodeid_is_local(dfsm, nodeid, pid))
		goto ret;

	if (msg_type == KVSTORE_MESSAGE_UPDATE) {
		const char *key;
		gconstpointer data;
		guint32 len;
		if (kvstore_parse_update_message(msg, msg_len, &key, &data, &len)) {
			cfs_kvstore_node_set(nodeid, key, data, len);
		} else {
			cfs_critical("cant parse update message");
		}
	} else if (msg_type == KVSTORE_MESSAGE_LOG) {
		cfs_message("received log"); // fixme: remove
		const clog_entry_t *entry;
		if ((entry = kvstore_parse_log_message(msg, msg_len))) {
			clusterlog_insert(cfs_status.clusterlog, entry);
		} else {
			cfs_critical("cant parse log message");
		}
	} else {
		cfs_critical("received unknown message type %d\n", msg_type);
		goto fail;
	}

ret:
	*res_ptr = 0;
	return 1;

fail:
	*res_ptr = -EACCES;
	return 1;
}

static void
dfsm_confchg(
	dfsm_t *dfsm,
	gpointer data,
	const struct cpg_address *member_list,
	size_t member_list_entries)
{
	g_return_if_fail(dfsm != NULL);
	g_return_if_fail(member_list != NULL);

	cfs_debug("enter %s", __func__);

	g_static_mutex_lock (&mutex);

	cfs_clinfo_t *clinfo = cfs_status.clinfo;

	if (clinfo && clinfo->nodes_byid) {

		GHashTable *ht = clinfo->nodes_byid;
		GHashTableIter iter;
		gpointer key, value;

		g_hash_table_iter_init (&iter, ht);

		while (g_hash_table_iter_next (&iter, &key, &value)) {
			cfs_clnode_t *node = (cfs_clnode_t *)value;
			node->online = FALSE;
		}

		for (int i = 0; i < member_list_entries; i++) {
			cfs_clnode_t *node;
			if ((node = g_hash_table_lookup(clinfo->nodes_byid, &member_list[i].nodeid))) {
				node->online = TRUE;
			}
		}

		cfs_status.clinfo_version++;
	}

	g_static_mutex_unlock (&mutex);
}

static gpointer
dfsm_get_state(
	dfsm_t *dfsm,
	gpointer data,
	unsigned int *res_len)
{
	g_return_val_if_fail(dfsm != NULL, NULL);

	gpointer msg = clusterlog_get_state(cfs_status.clusterlog, res_len);

	return msg;
}

static int
dfsm_process_update(
	dfsm_t *dfsm,
	gpointer data,
	dfsm_sync_info_t *syncinfo,
	uint32_t nodeid,
	uint32_t pid,
	const void *msg,
	size_t msg_len)
{
	cfs_critical("%s: received unexpected update message", __func__);

	return -1;
}

static int
dfsm_process_state_update(
	dfsm_t *dfsm,
	gpointer data,
	dfsm_sync_info_t *syncinfo)
{
	g_return_val_if_fail(dfsm != NULL, -1);
	g_return_val_if_fail(syncinfo != NULL, -1);

	clog_base_t *clog[syncinfo->node_count];

	int local_index = -1;
	for (int i = 0; i < syncinfo->node_count; i++) {
		dfsm_node_info_t *ni = &syncinfo->nodes[i];
		ni->synced = 1;

		if (syncinfo->local == ni)
			local_index = i;

		clog_base_t *base = (clog_base_t *)ni->state;
		if (ni->state_len > 8 && ni->state_len == clog_size(base)) {
			clog[i] = ni->state;
		} else {
			cfs_critical("received log with wrong size %u", ni->state_len);
			clog[i] = NULL;
		}
	}

	if (!clusterlog_merge(cfs_status.clusterlog, clog, syncinfo->node_count, local_index)) {
		cfs_critical("unable to merge log files");
	}

	cfs_kvstore_sync();

	return 1;
}

static int
dfsm_commit(
	dfsm_t *dfsm,
	gpointer data,
	dfsm_sync_info_t *syncinfo)
{
	g_return_val_if_fail(dfsm != NULL, -1);
	g_return_val_if_fail(syncinfo != NULL, -1);

	return 1;
}

static void
dfsm_synced(dfsm_t *dfsm)
{
	g_return_if_fail(dfsm != NULL);

	char *ip = (char *)g_hash_table_lookup(cfs_status.iphash, cfs.nodename);
	if (!ip) 
		ip = cfs.ip;

	cfs_status_set("nodeip", ip, strlen(ip) + 1);
}

static int
dfsm_cleanup(
	dfsm_t *dfsm,
	gpointer data,
	dfsm_sync_info_t *syncinfo)
{
	return 1;
}

static dfsm_callbacks_t kvstore_dfsm_callbacks = {
	.dfsm_deliver_fn = dfsm_deliver,
	.dfsm_confchg_fn = dfsm_confchg,

	.dfsm_get_state_fn = dfsm_get_state,
	.dfsm_process_state_update_fn = dfsm_process_state_update,
	.dfsm_process_update_fn = dfsm_process_update,
	.dfsm_commit_fn = dfsm_commit,
	.dfsm_cleanup_fn = dfsm_cleanup,
	.dfsm_synced_fn = dfsm_synced,
};

dfsm_t *
cfs_status_dfsm_new(void)
{
	g_static_mutex_lock (&mutex);

	cfs_status.kvstore = dfsm_new(NULL, KVSTORE_CPG_GROUP_NAME, G_LOG_DOMAIN,
				      0, &kvstore_dfsm_callbacks);
	g_static_mutex_unlock (&mutex);

	return cfs_status.kvstore;
}

gboolean
cfs_is_quorate(void)
{
	g_static_mutex_lock (&mutex);
	gboolean res =  cfs_status.quorate;
	g_static_mutex_unlock (&mutex);

	return res;
}

void
cfs_set_quorate(
	uint32_t quorate,
	gboolean quiet)
{
	g_static_mutex_lock (&mutex);

	uint32_t prev_quorate =	cfs_status.quorate;
	cfs_status.quorate = quorate;

	if (!prev_quorate && cfs_status.quorate) {
		if (!quiet)
			cfs_message("node has quorum");
	}

	if (prev_quorate && !cfs_status.quorate) {
		if (!quiet)
			cfs_message("node lost quorum");
	}

	g_static_mutex_unlock (&mutex);
}

