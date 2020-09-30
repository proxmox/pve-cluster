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

#ifndef _PVE_STATUS_H_
#define _PVE_STATUS_H_

#include <glib.h>

#include "dfsm.h"
#include "logger.h"
#include "memdb.h"

#define VMTYPE_QEMU 1
#define VMTYPE_OPENVZ 2
#define VMTYPE_LXC 3

#define CFS_MAX_STATUS_SIZE (32*1024)

typedef struct cfs_clnode cfs_clnode_t;
typedef struct cfs_clinfo cfs_clinfo_t;

void 
cfs_status_init(void);

void 
cfs_status_cleanup(void);

dfsm_t *
cfs_status_dfsm_new(void);

void
cfs_cluster_log(clog_entry_t *entry);

void 
cfs_cluster_log_dump(
	GString *str, 
	const char *user, 
	guint max_entries);

void
cfs_rrd_dump(GString *str); 

int
cfs_status_set(
	const char *key,
	gpointer data,
	size_t len);

void 
cfs_status_set_clinfo(
	cfs_clinfo_t *clinfo);

void 
cfs_status_set_vmlist(
	GHashTable *vmlist);

cfs_clnode_t *
cfs_clnode_new(
	const char *name, 
	uint32_t nodeid, 
	uint32_t votes);

void 
cfs_clnode_destroy(
	cfs_clnode_t *clnode);

cfs_clinfo_t *
cfs_clinfo_new(
	const char *cluster_name, 
	uint32_t cman_version);

gboolean 
cfs_clinfo_destroy(
	cfs_clinfo_t *clinfo);

gboolean 
cfs_clinfo_add_node(
	cfs_clinfo_t *clinfo,
	cfs_clnode_t *clnode);

void 
cfs_set_quorate(
	uint32_t quorate, 
	gboolean quiet);

gboolean
cfs_is_quorate(void);

GHashTable *
vmlist_hash_new(void);

gboolean 
vmlist_hash_insert_vm(
	GHashTable *vmlist,
	int vmtype, 
	guint32 vmid, 
	const char *nodename,
	gboolean replace);

void 
vmlist_register_vm(
	int vmtype, 
	guint32 vmid, 
	const char *nodename);

void
vmlist_delete_vm(
	guint32 vmid);

gboolean
vmlist_vm_exists(
	guint32 vmid);

gboolean
vmlist_different_vm_exists(
	int vmtype,
	guint32 vmid,
	const char *nodename);

void 
record_memdb_change(const char *path);

void 
record_memdb_reload(void);


int
cfs_create_status_msg(
	GString *str,
	const char *nodename,
	const char *key);

int
cfs_create_version_msg(
	GString *str);

int
cfs_create_vmlist_msg(
	GString *str);

int
cfs_create_memberlist_msg(
	GString *str);

int
cfs_create_guest_conf_property_msg(GString *str, memdb_t *memdb, const char *prop, uint32_t vmid);

#endif /* _PVE_STATUS_H_ */
