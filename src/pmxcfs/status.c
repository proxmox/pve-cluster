/*
  Copyright (C) 2010 - 2020 Proxmox Server Solutions GmbH

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

#include <ctype.h>
#include <errno.h>
#include <glib.h>
#include <rrd.h>
#include <rrd_client.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syslog.h>
#include <time.h>

#include "cfs-utils.h"
#include "logger.h"
#include "memdb.h"
#include "status.h"

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
    {.path = "corosync.conf"},
    {.path = "corosync.conf.new"},
    {.path = "storage.cfg"},
    {.path = "user.cfg"},
    {.path = "domains.cfg"},
    {.path = "notifications.cfg"},
    {.path = "priv/notifications.cfg"},
    {.path = "priv/shadow.cfg"},
    {.path = "priv/acme/plugins.cfg"},
    {.path = "priv/tfa.cfg"},
    {.path = "priv/token.cfg"},
    {.path = "priv/ipam.db"}, // TODO: replaced by sdn/ipam-pve-db.json remove with PVE 9 or later
    {.path = "priv/macs.db"}, // TODO: replaced by sdn/mac-cache.json remove with PVE 9 or later
    {.path = "datacenter.cfg"},
    {.path = "vzdump.cron"},
    {.path = "vzdump.conf"},
    {.path = "jobs.cfg"},
    {.path = "ha/crm_commands"},
    {.path = "ha/manager_status"},
    {.path = "ha/resources.cfg"},
    {.path = "ha/rules.cfg"},
    {.path = "ha/groups.cfg"},
    {.path = "ha/fence.cfg"},
    {.path = "status.cfg"},
    {.path = "replication.cfg"},
    {.path = "ceph.conf"},
    {.path = "sdn/vnets.cfg"},
    {.path = "sdn/zones.cfg"},
    {.path = "sdn/controllers.cfg"},
    {.path = "sdn/subnets.cfg"},
    {.path = "sdn/ipams.cfg"},
    {.path = "sdn/mac-cache.json"},
    {.path = "sdn/pve-ipam-state.json"},
    {.path = "sdn/dns.cfg"},
    {.path = "sdn/fabrics.cfg"},
    {.path = "sdn/.running-config"},
    {.path = "virtual-guest/cpu-models.conf"},
    {.path = "virtual-guest/profiles.cfg"},
    {.path = "firewall/cluster.fw"},
    {.path = "mapping/directory.cfg"},
    {.path = "mapping/pci.cfg"},
    {.path = "mapping/usb.cfg"},
};

static GMutex mutex;

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

static guint g_int32_hash(gconstpointer v) { return *(const uint32_t *)v; }

static gboolean g_int32_equal(gconstpointer v1, gconstpointer v2) {
    return *((const uint32_t *)v1) == *((const uint32_t *)v2);
}

static void vminfo_free(vminfo_t *vminfo) {
    g_return_if_fail(vminfo != NULL);

    if (vminfo->nodename) {
        g_free(vminfo->nodename);
    }

    g_free(vminfo);
}

static const char *vminfo_type_to_string(vminfo_t *vminfo) {
    if (vminfo->vmtype == VMTYPE_QEMU) {
        return "qemu";
    } else if (vminfo->vmtype == VMTYPE_OPENVZ) {
        // FIXME: remove openvz stuff for 7.x
        return "openvz";
    } else if (vminfo->vmtype == VMTYPE_LXC) {
        return "lxc";
    } else {
        return "unknown";
    }
}

static const char *vminfo_type_to_path_type(vminfo_t *vminfo) {
    if (vminfo->vmtype == VMTYPE_QEMU) {
        return "qemu-server"; // special case..
    } else {
        return vminfo_type_to_string(vminfo);
    }
}

int vminfo_to_path(vminfo_t *vminfo, GString *path) {
    g_return_val_if_fail(vminfo != NULL, -1);
    g_return_val_if_fail(path != NULL, -1);

    if (!vminfo->nodename) {
        return 0;
    }

    const char *type = vminfo_type_to_path_type(vminfo);
    g_string_printf(path, "/nodes/%s/%s/%u.conf", vminfo->nodename, type, vminfo->vmid);

    return 1;
}

void cfs_clnode_destroy(cfs_clnode_t *clnode) {
    g_return_if_fail(clnode != NULL);

    if (clnode->kvhash) {
        g_hash_table_destroy(clnode->kvhash);
    }

    if (clnode->name) {
        g_free(clnode->name);
    }

    g_free(clnode);
}

cfs_clnode_t *cfs_clnode_new(const char *name, uint32_t nodeid, uint32_t votes) {
    g_return_val_if_fail(name != NULL, NULL);

    cfs_clnode_t *clnode = g_new0(cfs_clnode_t, 1);
    if (!clnode) {
        return NULL;
    }

    clnode->name = g_strdup(name);
    clnode->nodeid = nodeid;
    clnode->votes = votes;

    return clnode;
}

gboolean cfs_clinfo_destroy(cfs_clinfo_t *clinfo) {
    g_return_val_if_fail(clinfo != NULL, FALSE);

    if (clinfo->cluster_name) {
        g_free(clinfo->cluster_name);
    }

    if (clinfo->nodes_byname) {
        g_hash_table_destroy(clinfo->nodes_byname);
    }

    if (clinfo->nodes_byid) {
        g_hash_table_destroy(clinfo->nodes_byid);
    }

    g_free(clinfo);

    return TRUE;
}

cfs_clinfo_t *cfs_clinfo_new(const char *cluster_name, uint32_t cman_version) {
    g_return_val_if_fail(cluster_name != NULL, NULL);

    cfs_clinfo_t *clinfo = g_new0(cfs_clinfo_t, 1);
    if (!clinfo) {
        return NULL;
    }

    clinfo->cluster_name = g_strdup(cluster_name);
    clinfo->cman_version = cman_version;

    if (!(clinfo->nodes_byid = g_hash_table_new_full(
              g_int32_hash, g_int32_equal, NULL, (GDestroyNotify)cfs_clnode_destroy
          ))) {
        goto fail;
    }

    if (!(clinfo->nodes_byname = g_hash_table_new(g_str_hash, g_str_equal))) {
        goto fail;
    }

    return clinfo;

fail:
    cfs_clinfo_destroy(clinfo);

    return NULL;
}

gboolean cfs_clinfo_add_node(cfs_clinfo_t *clinfo, cfs_clnode_t *clnode) {
    g_return_val_if_fail(clinfo != NULL, FALSE);
    g_return_val_if_fail(clnode != NULL, FALSE);

    g_hash_table_replace(clinfo->nodes_byid, &clnode->nodeid, clnode);
    g_hash_table_replace(clinfo->nodes_byname, clnode->name, clnode);

    return TRUE;
}

int cfs_create_memberlist_msg(GString *str) {
    g_return_val_if_fail(str != NULL, -EINVAL);

    g_mutex_lock(&mutex);

    g_string_append_printf(str, "{\n");

    guint nodecount = 0;

    cfs_clinfo_t *clinfo = cfs_status.clinfo;

    if (clinfo && clinfo->nodes_byid) {
        nodecount = g_hash_table_size(clinfo->nodes_byid);
    }

    if (nodecount) {
        g_string_append_printf(str, "\"nodename\": \"%s\",\n", cfs.nodename);
        g_string_append_printf(str, "\"version\": %u,\n", cfs_status.clinfo_version);

        g_string_append_printf(str, "\"cluster\": { ");
        g_string_append_printf(
            str,
            "\"name\": \"%s\", \"version\": %d, "
            "\"nodes\": %d, \"quorate\": %d ",
            clinfo->cluster_name, clinfo->cman_version, nodecount, cfs_status.quorate
        );

        g_string_append_printf(str, "},\n");
        g_string_append_printf(str, "\"nodelist\": {\n");

        GHashTable *ht = clinfo->nodes_byid;
        GHashTableIter iter;
        gpointer key, value;

        g_hash_table_iter_init(&iter, ht);

        int i = 0;
        while (g_hash_table_iter_next(&iter, &key, &value)) {
            cfs_clnode_t *node = (cfs_clnode_t *)value;
            if (i) {
                g_string_append_printf(str, ",\n");
            }
            i++;

            g_string_append_printf(
                str, "  \"%s\": { \"id\": %d, \"online\": %d", node->name, node->nodeid,
                node->online
            );

            char *ip = (char *)g_hash_table_lookup(cfs_status.iphash, node->name);
            if (ip) {
                g_string_append_printf(str, ", \"ip\": \"%s\"", ip);
            }

            g_string_append_printf(str, "}");
        }
        g_string_append_printf(str, "\n  }\n");
    } else {
        g_string_append_printf(str, "\"nodename\": \"%s\",\n", cfs.nodename);
        g_string_append_printf(str, "\"version\": %u\n", cfs_status.clinfo_version);
    }

    g_string_append_printf(str, "}\n");

    g_mutex_unlock(&mutex);

    return 0;
}

static void kventry_free(kventry_t *entry) {
    g_return_if_fail(entry != NULL);

    g_free(entry->key);
    g_free(entry->data);
    g_free(entry);
}

static GHashTable *kventry_hash_new(void) {
    return g_hash_table_new_full(g_str_hash, g_str_equal, NULL, (GDestroyNotify)kventry_free);
}

static void rrdentry_free(rrdentry_t *entry) {
    g_return_if_fail(entry != NULL);

    g_free(entry->key);
    g_free(entry->data);
    g_free(entry);
}

static GHashTable *rrdentry_hash_new(void) {
    return g_hash_table_new_full(g_str_hash, g_str_equal, NULL, (GDestroyNotify)rrdentry_free);
}

void cfs_cluster_log_dump(GString *str, const char *user, guint max_entries) {
    clusterlog_dump(cfs_status.clusterlog, str, user, max_entries);
}

void cfs_cluster_log(clog_entry_t *entry) {
    g_return_if_fail(entry != NULL);

    clusterlog_insert(cfs_status.clusterlog, entry);

    if (cfs_status.kvstore) {
        struct iovec iov[1];
        iov[0].iov_base = (char *)entry;
        iov[0].iov_len = clog_entry_size(entry);

        if (dfsm_is_initialized(cfs_status.kvstore)) {
            dfsm_send_message(cfs_status.kvstore, KVSTORE_MESSAGE_LOG, iov, 1);
        }
    }
}

void cfs_status_init(void) {
    g_mutex_lock(&mutex);

    cfs_status.start_time = time(NULL);

    cfs_status.vmlist = vmlist_hash_new();

    cfs_status.kvhash = kventry_hash_new();

    cfs_status.rrdhash = rrdentry_hash_new();

    cfs_status.iphash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

    cfs_status.memdb_changes = g_hash_table_new(g_str_hash, g_str_equal);

    for (int i = 0; i < G_N_ELEMENTS(memdb_change_array); i++) {
        g_hash_table_replace(
            cfs_status.memdb_changes, memdb_change_array[i].path, &memdb_change_array[i]
        );
    }

    cfs_status.clusterlog = clusterlog_new();

    // fixme:
    clusterlog_add(
        cfs_status.clusterlog, "root", "cluster", getpid(), LOG_INFO, "starting cluster log"
    );

    g_mutex_unlock(&mutex);
}

void cfs_status_cleanup(void) {
    g_mutex_lock(&mutex);

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

    if (cfs_status.clusterlog) {
        clusterlog_destroy(cfs_status.clusterlog);
    }

    g_mutex_unlock(&mutex);
}

void cfs_status_set_clinfo(cfs_clinfo_t *clinfo) {
    g_return_if_fail(clinfo != NULL);

    g_mutex_lock(&mutex);

    cfs_status.clinfo_version++;

    cfs_clinfo_t *old = cfs_status.clinfo;

    cfs_status.clinfo = clinfo;

    cfs_message(
        "update cluster info (cluster name  %s, version = %d)", clinfo->cluster_name,
        clinfo->cman_version
    );

    if (old && old->nodes_byid && clinfo->nodes_byid) {
        /* copy kvstore */
        GHashTable *ht = clinfo->nodes_byid;
        GHashTableIter iter;
        gpointer key, value;

        g_hash_table_iter_init(&iter, ht);

        while (g_hash_table_iter_next(&iter, &key, &value)) {
            cfs_clnode_t *node = (cfs_clnode_t *)value;
            cfs_clnode_t *oldnode;
            if ((oldnode = g_hash_table_lookup(old->nodes_byid, key))) {
                node->online = oldnode->online;
                node->kvhash = oldnode->kvhash;
                oldnode->kvhash = NULL;
            }
        }
    }

    if (old) {
        cfs_clinfo_destroy(old);
    }

    g_mutex_unlock(&mutex);
}

static void dump_kvstore_versions(GString *str, GHashTable *kvhash, const char *nodename) {
    g_return_if_fail(kvhash != NULL);
    g_return_if_fail(str != NULL);
    g_return_if_fail(nodename != NULL);

    GHashTable *ht = kvhash;
    GHashTableIter iter;
    gpointer key, value;

    g_string_append_printf(str, "\"%s\": {\n", nodename);

    g_hash_table_iter_init(&iter, ht);

    int i = 0;
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        kventry_t *entry = (kventry_t *)value;
        if (i) {
            g_string_append_printf(str, ",\n");
        }
        i++;
        g_string_append_printf(str, "\"%s\": %u", entry->key, entry->version);
    }

    g_string_append_printf(str, "}\n");
}

int cfs_create_version_msg(GString *str) {
    g_return_val_if_fail(str != NULL, -EINVAL);

    g_mutex_lock(&mutex);

    g_string_append_printf(str, "{\n");

    g_string_append_printf(str, "\"starttime\": %lu,\n", (unsigned long)cfs_status.start_time);

    g_string_append_printf(str, "\"clinfo\": %u,\n", cfs_status.clinfo_version);

    g_string_append_printf(str, "\"vmlist\": %u,\n", cfs_status.vmlist_version);

    for (int i = 0; i < G_N_ELEMENTS(memdb_change_array); i++) {
        g_string_append_printf(
            str, "\"%s\": %u,\n", memdb_change_array[i].path, memdb_change_array[i].version
        );
    }

    g_string_append_printf(str, "\"kvstore\": {\n");

    dump_kvstore_versions(str, cfs_status.kvhash, cfs.nodename);

    cfs_clinfo_t *clinfo = cfs_status.clinfo;

    if (clinfo && clinfo->nodes_byid) {
        GHashTable *ht = clinfo->nodes_byid;
        GHashTableIter iter;
        gpointer key, value;

        g_hash_table_iter_init(&iter, ht);

        while (g_hash_table_iter_next(&iter, &key, &value)) {
            cfs_clnode_t *node = (cfs_clnode_t *)value;
            if (!node->kvhash) {
                continue;
            }
            g_string_append_printf(str, ",\n");
            dump_kvstore_versions(str, node->kvhash, node->name);
        }
    }

    g_string_append_printf(str, "}\n");

    g_string_append_printf(str, "}\n");

    g_mutex_unlock(&mutex);

    return 0;
}

GHashTable *vmlist_hash_new(void) {
    return g_hash_table_new_full(g_int_hash, g_int_equal, NULL, (GDestroyNotify)vminfo_free);
}

gboolean vmlist_hash_insert_vm(
    GHashTable *vmlist, int vmtype, guint32 vmid, const char *nodename, gboolean replace
) {
    g_return_val_if_fail(vmlist != NULL, FALSE);
    g_return_val_if_fail(nodename != NULL, FALSE);
    g_return_val_if_fail(vmid != 0, FALSE);
    // FIXME: remove openvz stuff for 7.x
    g_return_val_if_fail(
        vmtype == VMTYPE_QEMU || vmtype == VMTYPE_OPENVZ || vmtype == VMTYPE_LXC, FALSE
    );

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

void vmlist_register_vm(int vmtype, guint32 vmid, const char *nodename) {
    g_return_if_fail(cfs_status.vmlist != NULL);
    g_return_if_fail(nodename != NULL);
    g_return_if_fail(vmid != 0);
    // FIXME: remove openvz stuff for 7.x
    g_return_if_fail(vmtype == VMTYPE_QEMU || vmtype == VMTYPE_OPENVZ || vmtype == VMTYPE_LXC);

    cfs_debug("vmlist_register_vm: %s/%u %d", nodename, vmid, vmtype);

    g_mutex_lock(&mutex);

    cfs_status.vmlist_version++;

    vmlist_hash_insert_vm(cfs_status.vmlist, vmtype, vmid, nodename, TRUE);

    g_mutex_unlock(&mutex);
}

gboolean vmlist_different_vm_exists(int vmtype, guint32 vmid, const char *nodename) {
    g_return_val_if_fail(cfs_status.vmlist != NULL, FALSE);
    g_return_val_if_fail(vmid != 0, FALSE);

    gboolean res = FALSE;

    g_mutex_lock(&mutex);

    vminfo_t *vminfo;
    if ((vminfo = (vminfo_t *)g_hash_table_lookup(cfs_status.vmlist, &vmid))) {
        if (!(vminfo->vmtype == vmtype && strcmp(vminfo->nodename, nodename) == 0)) {
            res = TRUE;
        }
    }
    g_mutex_unlock(&mutex);

    return res;
}

gboolean vmlist_vm_exists(guint32 vmid) {
    g_return_val_if_fail(cfs_status.vmlist != NULL, FALSE);
    g_return_val_if_fail(vmid != 0, FALSE);

    g_mutex_lock(&mutex);

    gpointer res = g_hash_table_lookup(cfs_status.vmlist, &vmid);

    g_mutex_unlock(&mutex);

    return res != NULL;
}

void vmlist_delete_vm(guint32 vmid) {
    g_return_if_fail(cfs_status.vmlist != NULL);
    g_return_if_fail(vmid != 0);

    g_mutex_lock(&mutex);

    cfs_status.vmlist_version++;

    g_hash_table_remove(cfs_status.vmlist, &vmid);

    g_mutex_unlock(&mutex);
}

void cfs_status_set_vmlist(GHashTable *vmlist) {
    g_return_if_fail(vmlist != NULL);

    g_mutex_lock(&mutex);

    cfs_status.vmlist_version++;

    if (cfs_status.vmlist) {
        g_hash_table_destroy(cfs_status.vmlist);
    }

    cfs_status.vmlist = vmlist;

    g_mutex_unlock(&mutex);
}

int cfs_create_vmlist_msg(GString *str) {
    g_return_val_if_fail(cfs_status.vmlist != NULL, -EINVAL);
    g_return_val_if_fail(str != NULL, -EINVAL);

    g_mutex_lock(&mutex);

    g_string_append_printf(str, "{\n");

    GHashTable *ht = cfs_status.vmlist;

    guint count = g_hash_table_size(ht);

    if (!count) {
        g_string_append_printf(str, "\"version\": %u\n", cfs_status.vmlist_version);
    } else {
        g_string_append_printf(str, "\"version\": %u,\n", cfs_status.vmlist_version);

        g_string_append_printf(str, "\"ids\": {\n");

        GHashTableIter iter;
        gpointer key, value;

        g_hash_table_iter_init(&iter, ht);

        int first = 1;
        while (g_hash_table_iter_next(&iter, &key, &value)) {
            vminfo_t *vminfo = (vminfo_t *)value;
            const char *type = vminfo_type_to_string(vminfo);

            if (!first) {
                g_string_append_printf(str, ",\n");
            }
            first = 0;

            g_string_append_printf(
                str, "\"%u\": { \"node\": \"%s\", \"type\": \"%s\", \"version\": %u }",
                vminfo->vmid, vminfo->nodename, type, vminfo->version
            );
        }

        g_string_append_printf(str, "}\n");
    }
    g_string_append_printf(str, "\n}\n");

    g_mutex_unlock(&mutex);

    return 0;
}

// checks if a config line starts with the given prop. if yes, writes a '\0'
// at the end of the value, and returns the pointer where the value starts
// note: line[line_end] needs to be guaranteed a null byte
char *
_get_property_value_from_line(char *line, size_t line_len, const char *prop, size_t prop_len) {
    if (line_len <= prop_len + 1) {
        return NULL;
    }

    if (line[prop_len] == ':' && memcmp(line, prop, prop_len) == 0) { // found
        char *v_start = &line[prop_len + 1];
        char *v_end = &line[line_len - 1];

        // drop initial value whitespaces here already
        while (v_start < v_end && *v_start && isspace(*v_start)) {
            v_start++;
        }

        if (!*v_start) {
            return NULL;
        }

        while (v_end > v_start && isspace(*v_end)) {
            v_end--;
        }
        if (v_end < &line[line_len - 1]) {
            v_end[1] = '\0';
        }

        return v_start;
    }

    return NULL;
}

// checks the conf for lines starting with the given props and
// writes the pointers into the correct positions into the 'found' array
// afterwards, without initial whitespace(s), we only deal with the format
// restriction imposed by our perl VM config parser, main reference is
// PVE::QemuServer::parse_vm_config this allows to be very fast and still
// relatively simple
// main restrictions used for our advantage is the properties match regex:
// ($line =~ m/^([a-z][a-z_]*\d*):\s*(.+?)\s*$/) from parse_vm_config
// currently we only look at the current configuration in place, i.e., *no*
// snapshot and *no* pending changes
//
// min..max is the char range of the first character of the given props,
// so that we can return early when checking the line
// note: conf must end with a newline
void _get_property_values(
    char **found,
    char *conf,
    int conf_size,
    const char **props,
    uint8_t num_props,
    char min,
    char max
) {
    const char *const conf_end = conf + conf_size;
    char *line = conf;
    size_t remaining_size = conf_size;
    uint8_t count = 0;

    if (conf_size == 0) {
        return;
    }

    char *next_newline = memchr(conf, '\n', conf_size);
    if (next_newline == NULL) {
        return; // valid property lines end with \n, but none in the config
    }
    *next_newline = '\0';

    while (line != NULL) {
        if (!line[0]) {
            goto next;
        }

        // snapshot or pending section start, but nothing found yet -> not found
        if (line[0] == '[') {
            return;
        }
        // continue early if line does not begin with the min/max char of the properties
        if (line[0] < min || line[0] > max) {
            goto next;
        }

        size_t line_len = next_newline - line;
        for (uint8_t i = 0; i < num_props; i++) {
            char *value = _get_property_value_from_line(line, line_len, props[i], strlen(props[i]));
            if (value != NULL) {
                count += (found[i] != NULL) & 0x1; // count newly found lines
                found[i] = value;
            }
        }
        if (count == num_props) {
            return; // found all
        }
    next:
        line = next_newline + 1;
        remaining_size = conf_end - line;
        next_newline = memchr(line, '\n', remaining_size);
        if (next_newline == NULL) {
            return; // valid property lines end with \n, but none in the config
        }
        *next_newline = '\0';
    }

    return;
}

static void _g_str_append_kv_jsonescaped(GString *str, const char *k, const char *v) {
    g_string_append_printf(str, "\"%s\": \"", k);

    for (; *v; v++) {
        if (*v == '\\' || *v == '"') {
            g_string_append_c(str, '\\');
        }
        g_string_append_c(str, *v);
    }

    g_string_append_c(str, '"');
}

int _print_found_properties(
    GString *str,
    gpointer conf,
    int size,
    const char **props,
    uint8_t num_props,
    uint32_t vmid,
    char **values,
    char min,
    char max,
    int first
) {
    _get_property_values(values, conf, size, props, num_props, min, max);

    uint8_t found = 0;
    for (uint8_t i = 0; i < num_props; i++) {
        if (values[i] == NULL) {
            continue;
        }
        if (found) {
            g_string_append_c(str, ',');
        } else {
            if (!first) {
                g_string_append_printf(str, ",\n");
            } else {
                first = 0;
            }
            g_string_append_printf(str, "\"%u\":{", vmid);
            found = 1;
        }
        _g_str_append_kv_jsonescaped(str, props[i], values[i]);
    }

    if (found) {
        g_string_append_c(str, '}');
    }

    return first;
}

int cfs_create_guest_conf_properties_msg(
    GString *str, memdb_t *memdb, const char **props, uint8_t num_props, uint32_t vmid
) {
    g_return_val_if_fail(cfs_status.vmlist != NULL, -EINVAL);
    g_return_val_if_fail(str != NULL, -EINVAL);

    // Prelock &memdb->mutex in order to enable the usage of memdb_read_nolock
    // to prevent Deadlocks as in #2553
    g_mutex_lock(&memdb->mutex);
    g_mutex_lock(&mutex);

    g_string_printf(str, "{\n");

    GHashTable *ht = cfs_status.vmlist;

    int res = 0;
    GString *path = NULL;
    gpointer tmp = NULL;
    char **values = calloc(num_props, sizeof(char *));
    char min = 'z', max = 'a';

    for (uint8_t i = 0; i < num_props; i++) {
        if (props[i][0] > max) {
            max = props[i][0];
        }

        if (props[i][0] < min) {
            min = props[i][0];
        }
    }

    if (!g_hash_table_size(ht)) {
        goto ret;
    }

    if ((path = g_string_sized_new(256)) == NULL) {
        res = -ENOMEM;
        goto ret;
    }

    if (vmid >= 100) {
        vminfo_t *vminfo = (vminfo_t *)g_hash_table_lookup(cfs_status.vmlist, &vmid);
        if (vminfo == NULL) {
            goto enoent;
        }

        if (!vminfo_to_path(vminfo, path)) {
            goto err;
        }

        // use memdb_read_nolock because lock is handled here
        int size = memdb_read_nolock(memdb, path->str, &tmp);
        if (tmp == NULL) {
            goto err;
        }

        // conf needs to be newline terminated
        if (((char *)tmp)[size - 1] != '\n') {
            gpointer new = realloc(tmp, size + 1);
            if (new == NULL) {
                goto err;
            }
            tmp = new;
            ((char *)tmp)[size++] = '\n';
        }
        _print_found_properties(str, tmp, size, props, num_props, vmid, values, min, max, 1);
    } else {
        GHashTableIter iter;
        g_hash_table_iter_init(&iter, ht);

        gpointer key, value;
        int first = 1;
        while (g_hash_table_iter_next(&iter, &key, &value)) {
            vminfo_t *vminfo = (vminfo_t *)value;

            if (!vminfo_to_path(vminfo, path)) {
                goto err;
            }

            g_free(tmp); // no-op if already null
            tmp = NULL;
            // use memdb_read_nolock because lock is handled here
            int size = memdb_read_nolock(memdb, path->str, &tmp);
            if (tmp == NULL) {
                continue;
            }

            // conf needs to be newline terminated
            if (((char *)tmp)[size - 1] != '\n') {
                gpointer new = realloc(tmp, size + 1);
                if (new == NULL) {
                    continue;
                }
                tmp = new;
                ((char *)tmp)[size++] = '\n';
            }

            memset(values, 0, sizeof(char *) * num_props); // reset array
            first = _print_found_properties(
                str, tmp, size, props, num_props, vminfo->vmid, values, min, max, first
            );
        }
    }
ret:
    g_free(tmp);
    free(values);
    if (path != NULL) {
        g_string_free(path, TRUE);
    }
    g_string_append_printf(str, "\n}\n");
    g_mutex_unlock(&mutex);
    g_mutex_unlock(&memdb->mutex);
    return res;
err:
    res = -EIO;
    goto ret;
enoent:
    res = -ENOENT;
    goto ret;
}

int cfs_create_guest_conf_property_msg(
    GString *str, memdb_t *memdb, const char *prop, uint32_t vmid
) {
    return cfs_create_guest_conf_properties_msg(str, memdb, &prop, 1, vmid);
}

void record_memdb_change(const char *path) {
    g_return_if_fail(cfs_status.memdb_changes != 0);

    memdb_change_t *ce;

    if ((ce = (memdb_change_t *)g_hash_table_lookup(cfs_status.memdb_changes, path))) {
        ce->version++;
    }
}

void record_memdb_reload(void) {
    for (int i = 0; i < G_N_ELEMENTS(memdb_change_array); i++) {
        memdb_change_array[i].version++;
    }
}

static gboolean
kventry_hash_set(GHashTable *kvhash, const char *key, gconstpointer data, size_t len) {
    g_return_val_if_fail(kvhash != NULL, FALSE);
    g_return_val_if_fail(key != NULL, FALSE);
    g_return_val_if_fail(data != NULL, FALSE);

    kventry_t *entry;
    if (!len) {
        g_hash_table_remove(kvhash, key);
    } else if ((entry = (kventry_t *)g_hash_table_lookup(kvhash, key))) {
        g_free(entry->data);
        entry->data = g_memdup2(data, len);
        entry->len = len;
        entry->version++;
    } else {
        kventry_t *entry = g_new0(kventry_t, 1);

        entry->key = g_strdup(key);
        entry->data = g_memdup2(data, len);
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
    "DS:netin:DERIVE:120:0:U",
    "DS:netout:DERIVE:120:0:U",

    "RRA:AVERAGE:0.5:1:70",     // 1 min avg - one hour
    "RRA:AVERAGE:0.5:30:70",    // 30 min avg - one day
    "RRA:AVERAGE:0.5:180:70",   // 3 hour avg - one week
    "RRA:AVERAGE:0.5:720:70",   // 12 hour avg - one month
    "RRA:AVERAGE:0.5:10080:70", // 7 day avg - ony year

    "RRA:MAX:0.5:1:70",     // 1 min max - one hour
    "RRA:MAX:0.5:30:70",    // 30 min max - one day
    "RRA:MAX:0.5:180:70",   // 3 hour max - one week
    "RRA:MAX:0.5:720:70",   // 12 hour max - one month
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
    "DS:netin:DERIVE:120:0:U",
    "DS:netout:DERIVE:120:0:U",
    "DS:diskread:DERIVE:120:0:U",
    "DS:diskwrite:DERIVE:120:0:U",

    "RRA:AVERAGE:0.5:1:70",     // 1 min avg - one hour
    "RRA:AVERAGE:0.5:30:70",    // 30 min avg - one day
    "RRA:AVERAGE:0.5:180:70",   // 3 hour avg - one week
    "RRA:AVERAGE:0.5:720:70",   // 12 hour avg - one month
    "RRA:AVERAGE:0.5:10080:70", // 7 day avg - ony year

    "RRA:MAX:0.5:1:70",     // 1 min max - one hour
    "RRA:MAX:0.5:30:70",    // 30 min max - one day
    "RRA:MAX:0.5:180:70",   // 3 hour max - one week
    "RRA:MAX:0.5:720:70",   // 12 hour max - one month
    "RRA:MAX:0.5:10080:70", // 7 day max - ony year
    NULL,
};

static const char *rrd_def_storage[] = {
    "DS:total:GAUGE:120:0:U",
    "DS:used:GAUGE:120:0:U",

    "RRA:AVERAGE:0.5:1:70",     // 1 min avg - one hour
    "RRA:AVERAGE:0.5:30:70",    // 30 min avg - one day
    "RRA:AVERAGE:0.5:180:70",   // 3 hour avg - one week
    "RRA:AVERAGE:0.5:720:70",   // 12 hour avg - one month
    "RRA:AVERAGE:0.5:10080:70", // 7 day avg - ony year

    "RRA:MAX:0.5:1:70",     // 1 min max - one hour
    "RRA:MAX:0.5:30:70",    // 30 min max - one day
    "RRA:MAX:0.5:180:70",   // 3 hour max - one week
    "RRA:MAX:0.5:720:70",   // 12 hour max - one month
    "RRA:MAX:0.5:10080:70", // 7 day max - ony year
    NULL,
};

#define RRDDIR "/var/lib/rrdcached/db"

static void create_rrd_file(const char *filename, int argcount, const char *rrddef[]) {
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

static inline const char *rrd_skip_data(const char *data, int count, char separator) {
    int found = 0;
    while (*data && found < count) {
        if (*data++ == separator) {
            found++;
        }
    }
    return data;
}

// The key and subdirectory format used up until PVE8 is 'pve{version}-{type}/{id}' with version
// being 2 or 2.3 for VMs. Starting with PVE9 'pve-{type}-{version}/{id}'. Newer versions are only
// allowed to append new columns to the data! Otherwise this would be a breaking change.
//
// Type can be: node, vm, storage
//
// Version is the version of PVE with which it was introduced, e.g.: 9.0, 9.2, 10.0.
//
// ID is the actual identifier of the item in question. E.g. node name, VMID or for storage it is
// '{node}/{storage name}'
//
// This way, we can handle unknown new formats gracefully and cut the data at the expected
// column for the currently understood format. Receiving older formats will still need special
// checks to determine how much padding is needed.
//
// Should we ever plan to change existing columns, we need to introduce this as a breaking
// change!
static void update_rrd_data(const char *key, gconstpointer data, size_t len) {
    g_return_if_fail(key != NULL);
    g_return_if_fail(data != NULL);
    g_return_if_fail(len > 0);
    g_return_if_fail(len < 4096);

    static const char *rrdcsock = "unix:/var/run/rrdcached.sock";

    int use_daemon = 1;
    if (rrdc_connect(rrdcsock) != 0) {
        use_daemon = 0;
    }

    char *filename = NULL;

    int skip = 0; // columns to skip at beginning. They contain non-archivable data, like uptime,
                  // status, is guest a template and such.
    int keep_columns = 0; // how many columns do we want to keep (after initial skip) in case we get
                          // more columns than needed from a newer format

    if (strncmp(key, "pve2-node/", 10) == 0 || strncmp(key, "pve-node-", 9) == 0) {
        const char *node = rrd_skip_data(key, 1, '/');

        if (strchr(node, '/') != NULL) {
            goto keyerror;
        }

        if (strlen(node) < 1) {
            goto keyerror;
        }

        skip = 2; // first two columns are live data that isn't archived

        if (strncmp(key, "pve-node-", 9) == 0) {
            keep_columns = 12; // pve2-node format uses 12 columns
        }

        filename = g_strdup_printf(RRDDIR "/pve2-node/%s", node);

        if (!g_file_test(filename, G_FILE_TEST_EXISTS)) {
            mkdir(RRDDIR "/pve2-node", 0755);
            int argcount = sizeof(rrd_def_node) / sizeof(void *) - 1;
            create_rrd_file(filename, argcount, rrd_def_node);
        }

    } else if (strncmp(key, "pve2.3-vm/", 10) == 0 || strncmp(key, "pve-vm-", 7) == 0) {

        const char *vmid = rrd_skip_data(key, 1, '/');

        if (strchr(vmid, '/') != NULL) {
            goto keyerror;
        }

        if (strlen(vmid) < 1) {
            goto keyerror;
        }

        skip = 4; // first 4 columns are live data that isn't archived

        if (strncmp(key, "pve-vm-", 7) == 0) {
            keep_columns = 10; // pve2.3-vm format uses 10 data columns
        }

        filename = g_strdup_printf(RRDDIR "/%s/%s", "pve2-vm", vmid);

        if (!g_file_test(filename, G_FILE_TEST_EXISTS)) {
            mkdir(RRDDIR "/pve2-vm", 0755);
            int argcount = sizeof(rrd_def_vm) / sizeof(void *) - 1;
            create_rrd_file(filename, argcount, rrd_def_vm);
        }

    } else if (strncmp(key, "pve2-storage/", 13) == 0 || strncmp(key, "pve-storage-", 12) == 0) {
        const char *node = rrd_skip_data(key, 1, '/'); // will contain {node}/{storage}

        const char *storage = rrd_skip_data(node, 1, '/');

        if ((storage - node) < 1) {
            goto keyerror;
        }

        if (strchr(storage, '/') != NULL) {
            goto keyerror;
        }

        if (strlen(storage) < 1) {
            goto keyerror;
        }

        filename = g_strdup_printf(RRDDIR "/pve2-storage/%s", node);

        if (!g_file_test(filename, G_FILE_TEST_EXISTS)) {
            mkdir(RRDDIR "/pve2-storage", 0755);
            char *dir = g_path_get_dirname(filename);
            mkdir(dir, 0755);
            g_free(dir);

            int argcount = sizeof(rrd_def_storage) / sizeof(void *) - 1;
            create_rrd_file(filename, argcount, rrd_def_storage);
        }

    } else {
        goto keyerror;
    }

    const char *dp = skip ? rrd_skip_data(data, skip, ':') : data;

    if (keep_columns) {
        keep_columns++; // We specify the number of columns we want earlier, but we also have the
                        // always present timestamp column, so we need to skip one more column
        char *cut = (char *)rrd_skip_data(dp, keep_columns, ':');
        *(cut - 1) = 0; // terminate string by replacing colon from field separator with zero.
    }

    const char *update_args[] = {dp, NULL};

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
    if (filename) {
        g_free(filename);
    }

    return;

keyerror:
    cfs_critical("RRD update error: unknown/wrong key %s", key);
    goto ret;
}

static gboolean rrd_entry_is_old(gpointer key, gpointer value, gpointer user_data) {
    rrdentry_t *entry = (rrdentry_t *)value;
    uint32_t ctime = GPOINTER_TO_UINT(user_data);

    int diff = ctime - entry->time;

    /* remove everything older than 5 minutes */
    int expire = 60 * 5;

    return (diff > expire) ? TRUE : FALSE;
}

static char *rrd_dump_buf = NULL;
static time_t rrd_dump_last = 0;

void cfs_rrd_dump(GString *str) {
    time_t ctime;

    g_mutex_lock(&mutex);

    time(&ctime);
    if (rrd_dump_buf && (ctime - rrd_dump_last) < 2) {
        g_string_assign(str, rrd_dump_buf);
        g_mutex_unlock(&mutex);
        return;
    }

    /* remove old data */
    g_hash_table_foreach_remove(cfs_status.rrdhash, rrd_entry_is_old, GUINT_TO_POINTER(ctime));

    g_string_set_size(str, 0);

    GHashTableIter iter;
    gpointer key, value;

    g_hash_table_iter_init(&iter, cfs_status.rrdhash);

    while (g_hash_table_iter_next(&iter, &key, &value)) {
        rrdentry_t *entry = (rrdentry_t *)value;
        g_string_append(str, key);
        g_string_append(str, ":");
        g_string_append(str, entry->data);
        g_string_append(str, "\n");
    }

    g_string_append_c(str, 0); // never return undef

    rrd_dump_last = ctime;
    if (rrd_dump_buf) {
        g_free(rrd_dump_buf);
    }
    rrd_dump_buf = g_strdup(str->str);

    g_mutex_unlock(&mutex);
}

static gboolean
nodeip_hash_set(GHashTable *iphash, const char *nodename, const char *ip, size_t len) {
    g_return_val_if_fail(iphash != NULL, FALSE);
    g_return_val_if_fail(nodename != NULL, FALSE);
    g_return_val_if_fail(ip != NULL, FALSE);
    g_return_val_if_fail(len > 0, FALSE);
    g_return_val_if_fail(len < 256, FALSE);
    g_return_val_if_fail(ip[len - 1] == 0, FALSE);

    char *oldip = (char *)g_hash_table_lookup(iphash, nodename);

    if (!oldip || (strcmp(oldip, ip) != 0)) {
        cfs_status.clinfo_version++;
        g_hash_table_replace(iphash, g_strdup(nodename), g_strdup(ip));
    }

    return TRUE;
}

static gboolean
rrdentry_hash_set(GHashTable *rrdhash, const char *key, const char *data, size_t len) {
    g_return_val_if_fail(rrdhash != NULL, FALSE);
    g_return_val_if_fail(key != NULL, FALSE);
    g_return_val_if_fail(data != NULL, FALSE);
    g_return_val_if_fail(len > 0, FALSE);
    g_return_val_if_fail(len < 4096, FALSE);
    g_return_val_if_fail(data[len - 1] == 0, FALSE);

    rrdentry_t *entry;
    if ((entry = (rrdentry_t *)g_hash_table_lookup(rrdhash, key))) {
        g_free(entry->data);
        entry->data = g_memdup2(data, len);
        entry->len = len;
        entry->time = time(NULL);
    } else {
        rrdentry_t *entry = g_new0(rrdentry_t, 1);

        entry->key = g_strdup(key);
        entry->data = g_memdup2(data, len);
        entry->len = len;
        entry->time = time(NULL);

        g_hash_table_replace(rrdhash, entry->key, entry);
    }

    update_rrd_data(key, data, len);

    return TRUE;
}

static int kvstore_send_update_message(dfsm_t *dfsm, const char *key, gpointer data, guint32 len) {
    if (!dfsm_is_initialized(dfsm)) {
        return -EACCES;
    }

    struct iovec iov[2];

    char name[256];
    g_strlcpy(name, key, sizeof(name));

    iov[0].iov_base = &name;
    iov[0].iov_len = sizeof(name);

    iov[1].iov_base = (char *)data;
    iov[1].iov_len = len;

    if (dfsm_send_message(dfsm, KVSTORE_MESSAGE_UPDATE, iov, 2) == CS_OK) {
        return 0;
    }

    return -EACCES;
}

static clog_entry_t *kvstore_parse_log_message(const void *msg, size_t msg_len) {
    g_return_val_if_fail(msg != NULL, NULL);

    if (msg_len < sizeof(clog_entry_t)) {
        cfs_critical("received short log message (%zu < %zu)", msg_len, sizeof(clog_entry_t));
        return NULL;
    }

    clog_entry_t *entry = (clog_entry_t *)msg;

    uint32_t size =
        sizeof(clog_entry_t) + entry->node_len + entry->ident_len + entry->tag_len + entry->msg_len;

    if (msg_len != size) {
        cfs_critical("received log message with wrong size (%zu != %u)", msg_len, size);
        return NULL;
    }

    char *msgptr = entry->data;

    if (*((char *)msgptr + entry->node_len - 1)) {
        cfs_critical("unterminated string in log message");
        return NULL;
    }
    msgptr += entry->node_len;

    if (*((char *)msgptr + entry->ident_len - 1)) {
        cfs_critical("unterminated string in log message");
        return NULL;
    }
    msgptr += entry->ident_len;

    if (*((char *)msgptr + entry->tag_len - 1)) {
        cfs_critical("unterminated string in log message");
        return NULL;
    }
    msgptr += entry->tag_len;

    if (*((char *)msgptr + entry->msg_len - 1)) {
        cfs_critical("unterminated string in log message");
        return NULL;
    }

    return entry;
}

static gboolean kvstore_parse_update_message(
    const void *msg, size_t msg_len, const char **key, gconstpointer *data, guint32 *len
) {
    g_return_val_if_fail(msg != NULL, FALSE);
    g_return_val_if_fail(key != NULL, FALSE);
    g_return_val_if_fail(data != NULL, FALSE);
    g_return_val_if_fail(len != NULL, FALSE);

    if (msg_len < 256) {
        cfs_critical("received short kvstore message (%zu < 256)", msg_len);
        return FALSE;
    }

    /* test if key is null terminated */
    int i = 0;
    for (i = 0; i < 256; i++) {
        if (((char *)msg)[i] == 0) {
            break;
        }
    }

    if (i == 256) {
        return FALSE;
    }

    *len = msg_len - 256;
    *key = msg;
    *data = (char *)msg + 256;

    return TRUE;
}

int cfs_create_status_msg(GString *str, const char *nodename, const char *key) {
    g_return_val_if_fail(str != NULL, -EINVAL);
    g_return_val_if_fail(key != NULL, -EINVAL);

    int res = -ENOENT;

    GHashTable *kvhash = NULL;

    g_mutex_lock(&mutex);

    if (!nodename || !nodename[0] || !strcmp(nodename, cfs.nodename)) {
        kvhash = cfs_status.kvhash;
    } else if (cfs_status.clinfo && cfs_status.clinfo->nodes_byname) {
        cfs_clnode_t *clnode;
        if ((clnode = g_hash_table_lookup(cfs_status.clinfo->nodes_byname, nodename))) {
            kvhash = clnode->kvhash;
        }
    }

    kventry_t *entry;
    if (kvhash && (entry = (kventry_t *)g_hash_table_lookup(kvhash, key))) {
        g_string_append_len(str, entry->data, entry->len);
        res = 0;
    }

    g_mutex_unlock(&mutex);

    return res;
}

int cfs_status_set(const char *key, gpointer data, size_t len) {
    g_return_val_if_fail(key != NULL, FALSE);
    g_return_val_if_fail(data != NULL, FALSE);
    g_return_val_if_fail(cfs_status.kvhash != NULL, FALSE);

    if (len > CFS_MAX_STATUS_SIZE) {
        return -EFBIG;
    }

    g_mutex_lock(&mutex);

    gboolean res;

    if (strncmp(key, "rrd/", 4) == 0) {
        res = rrdentry_hash_set(cfs_status.rrdhash, key + 4, data, len);
    } else if (!strcmp(key, "nodeip")) {
        res = nodeip_hash_set(cfs_status.iphash, cfs.nodename, data, len);
    } else {
        res = kventry_hash_set(cfs_status.kvhash, key, data, len);
    }
    g_mutex_unlock(&mutex);

    if (cfs_status.kvstore) {
        kvstore_send_update_message(cfs_status.kvstore, key, data, len);
    }

    return res ? 0 : -ENOMEM;
}

gboolean cfs_kvstore_node_set(uint32_t nodeid, const char *key, gconstpointer data, size_t len) {
    g_return_val_if_fail(nodeid != 0, FALSE);
    g_return_val_if_fail(key != NULL, FALSE);
    g_return_val_if_fail(data != NULL, FALSE);

    g_mutex_lock(&mutex);

    if (!cfs_status.clinfo || !cfs_status.clinfo->nodes_byid) {
        goto ret; /* ignore */
    }

    cfs_clnode_t *clnode = g_hash_table_lookup(cfs_status.clinfo->nodes_byid, &nodeid);
    if (!clnode) {
        goto ret; /* ignore */
    }

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
    g_mutex_unlock(&mutex);

    return TRUE;
}

static gboolean cfs_kvstore_sync(void) {
    g_return_val_if_fail(cfs_status.kvhash != NULL, FALSE);
    g_return_val_if_fail(cfs_status.kvstore != NULL, FALSE);

    gboolean res = TRUE;

    g_mutex_lock(&mutex);

    GHashTable *ht = cfs_status.kvhash;
    GHashTableIter iter;
    gpointer key, value;

    g_hash_table_iter_init(&iter, ht);

    while (g_hash_table_iter_next(&iter, &key, &value)) {
        kventry_t *entry = (kventry_t *)value;
        kvstore_send_update_message(cfs_status.kvstore, entry->key, entry->data, entry->len);
    }

    g_mutex_unlock(&mutex);

    return res;
}

static int dfsm_deliver(
    dfsm_t *dfsm,
    gpointer data,
    int *res_ptr,
    uint32_t nodeid,
    uint32_t pid,
    uint16_t msg_type,
    uint32_t msg_time,
    const void *msg,
    size_t msg_len
) {
    g_return_val_if_fail(dfsm != NULL, -1);
    g_return_val_if_fail(msg != NULL, -1);
    g_return_val_if_fail(res_ptr != NULL, -1);

    /* ignore message for ourself */
    if (dfsm_nodeid_is_local(dfsm, nodeid, pid)) {
        goto ret;
    }

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

static void dfsm_confchg(
    dfsm_t *dfsm, gpointer data, const struct cpg_address *member_list, size_t member_list_entries
) {
    g_return_if_fail(dfsm != NULL);
    g_return_if_fail(member_list != NULL);

    cfs_debug("enter %s", __func__);

    g_mutex_lock(&mutex);

    cfs_clinfo_t *clinfo = cfs_status.clinfo;

    if (clinfo && clinfo->nodes_byid) {

        GHashTable *ht = clinfo->nodes_byid;
        GHashTableIter iter;
        gpointer key, value;

        g_hash_table_iter_init(&iter, ht);

        while (g_hash_table_iter_next(&iter, &key, &value)) {
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

    g_mutex_unlock(&mutex);
}

static gpointer dfsm_get_state(dfsm_t *dfsm, gpointer data, unsigned int *res_len) {
    g_return_val_if_fail(dfsm != NULL, NULL);

    gpointer msg = clusterlog_get_state(cfs_status.clusterlog, res_len);

    return msg;
}

static int dfsm_process_update(
    dfsm_t *dfsm,
    gpointer data,
    dfsm_sync_info_t *syncinfo,
    uint32_t nodeid,
    uint32_t pid,
    const void *msg,
    size_t msg_len
) {
    cfs_critical("%s: received unexpected update message", __func__);

    return -1;
}

static int dfsm_process_state_update(dfsm_t *dfsm, gpointer data, dfsm_sync_info_t *syncinfo) {
    g_return_val_if_fail(dfsm != NULL, -1);
    g_return_val_if_fail(syncinfo != NULL, -1);

    clog_base_t *clog[syncinfo->node_count];

    int local_index = -1;
    for (int i = 0; i < syncinfo->node_count; i++) {
        dfsm_node_info_t *ni = &syncinfo->nodes[i];
        ni->synced = 1;

        if (syncinfo->local == ni) {
            local_index = i;
        }

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

static int dfsm_commit(dfsm_t *dfsm, gpointer data, dfsm_sync_info_t *syncinfo) {
    g_return_val_if_fail(dfsm != NULL, -1);
    g_return_val_if_fail(syncinfo != NULL, -1);

    return 1;
}

static void dfsm_synced(dfsm_t *dfsm) {
    g_return_if_fail(dfsm != NULL);

    char *ip = (char *)g_hash_table_lookup(cfs_status.iphash, cfs.nodename);
    if (!ip) {
        ip = cfs.ip;
    }

    cfs_status_set("nodeip", ip, strlen(ip) + 1);
}

static int dfsm_cleanup(dfsm_t *dfsm, gpointer data, dfsm_sync_info_t *syncinfo) { return 1; }

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

dfsm_t *cfs_status_dfsm_new(void) {
    g_mutex_lock(&mutex);

    cfs_status.kvstore =
        dfsm_new(NULL, KVSTORE_CPG_GROUP_NAME, G_LOG_DOMAIN, 0, &kvstore_dfsm_callbacks);
    g_mutex_unlock(&mutex);

    return cfs_status.kvstore;
}

gboolean cfs_is_quorate(void) {
    g_mutex_lock(&mutex);
    gboolean res = cfs_status.quorate;
    g_mutex_unlock(&mutex);

    return res;
}

void cfs_set_quorate(uint32_t quorate, gboolean quiet) {
    g_mutex_lock(&mutex);

    uint32_t prev_quorate = cfs_status.quorate;
    cfs_status.quorate = quorate;

    if (!prev_quorate && cfs_status.quorate) {
        if (!quiet) {
            cfs_message("node has quorum");
        }
    }

    if (prev_quorate && !cfs_status.quorate) {
        if (!quiet) {
            cfs_message("node lost quorum");
        }
    }

    g_mutex_unlock(&mutex);
}
