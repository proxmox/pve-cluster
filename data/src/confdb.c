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

#define G_LOG_DOMAIN "confdb"

#define CLUSTER_KEY "cluster"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>

#include <corosync/confdb.h>

#include "cfs-utils.h"
#include "loop.h"
#include "status.h"

typedef struct {
	confdb_handle_t handle;
	gboolean changes;
} cs_private_t;

static int 
confdb_get_int(
	confdb_handle_t handle,
	hdb_handle_t parent,
	const char *key, 
	unsigned int default_value)
{
	char value[512];
	value[0] = 0;
	size_t value_len = sizeof(value);
	if (confdb_key_get(handle, parent, key, strlen(key),
			   value, &value_len) == CS_OK) {
		return atoi(value);
	}

	return default_value;
}

static char *
confdb_get_string(
	confdb_handle_t handle,
	hdb_handle_t parent,
	const char *key, 
	const char *default_value)
{
	char value[512];
	value[0] = 0;

	size_t value_len = sizeof(value);
	if (confdb_key_get(handle, parent, key, strlen(key),
			   value, &value_len) == CS_OK) {
		return g_strdup(value);
	}

	if (default_value)
		return g_strdup(default_value);

	return NULL;
}

static cs_error_t 
cman_read_clusternodes(
	confdb_handle_t handle,
	hdb_handle_t nodes_handle,
	cfs_clinfo_t *clinfo)
{
	cs_error_t result;

	result = confdb_object_find_start(handle, nodes_handle);
	if (result != CS_OK) {
		cfs_critical("confdb_object_find_start failed %d", result);
		return result;
	}

	hdb_handle_t obj_handle = 0;
	while((result = confdb_object_find(handle, nodes_handle, "clusternode", 
					   strlen("clusternode"), &obj_handle)) == CS_OK) {
		uint32_t nodeid = confdb_get_int(handle, obj_handle, "nodeid", 0);
		uint32_t votes = confdb_get_int(handle, obj_handle, "votes", 0);
		char *name = confdb_get_string(handle, obj_handle, "name", NULL);

		if (name && nodeid) {
			cfs_clnode_t *clnode = cfs_clnode_new(name, nodeid, votes);
			cfs_clinfo_add_node(clinfo, clnode);
		}
		if (name)
			g_free(name);
	}

	if (result == CS_ERR_ACCESS)
		result = CS_OK;

	confdb_object_find_destroy(handle, nodes_handle);

	return result;
}

static cs_error_t 
cman_read_cluster(
	confdb_handle_t handle,
	hdb_handle_t cluster_parent_handle)
{
	cs_error_t result;

	
	uint32_t cman_version = confdb_get_int(handle, cluster_parent_handle, "config_version", 0);

	char *clustername = confdb_get_string(handle, cluster_parent_handle, "name", "unknown");

	cfs_clinfo_t *clinfo = cfs_clinfo_new(clustername, cman_version);

	g_free(clustername);

	result = confdb_object_find_start(handle, cluster_parent_handle);
	if (result != CS_OK) {
		cfs_critical("confdb_object_find_start failed %d", result);
		cfs_clinfo_destroy(clinfo);
		return result;
	}

	hdb_handle_t nodes_handle = 0;
	result = confdb_object_find(handle, cluster_parent_handle, "clusternodes", 
				    strlen("clusternodes"), &nodes_handle);
	if (result == CS_OK) {
		cman_read_clusternodes(handle, nodes_handle, clinfo);
		cfs_status_set_clinfo(clinfo);
	} else {
		cfs_clinfo_destroy(clinfo);
		cfs_critical("cant find clusternodes object %d", result);
	}

	confdb_object_find_destroy(handle, cluster_parent_handle);

	return result;
}

static cs_error_t 
cman_read_config(confdb_handle_t handle)
{
	cs_error_t result;

	result = confdb_object_find_start(handle, OBJECT_PARENT_HANDLE);
	if (result != CS_OK) {
		cfs_critical("confdb_object_find_start failed %d", result);
		return result;
	}

	hdb_handle_t cluster_parent_handle = 0;
	result = confdb_object_find(handle, OBJECT_PARENT_HANDLE, CLUSTER_KEY, 
				    strlen(CLUSTER_KEY), &cluster_parent_handle);
	if (result == CS_OK) {
		result = cman_read_cluster(handle, cluster_parent_handle);
	} else {
		cfs_critical("cant find cluster object %d", result);
	}

	confdb_object_find_destroy(handle, OBJECT_PARENT_HANDLE);

	return result;
}

static cs_error_t 
track_object(confdb_handle_t handle)
{

	hdb_handle_t obj_handle = 0;
	cs_error_t result;

	result = confdb_object_find_start(handle, OBJECT_PARENT_HANDLE);
	if (result != CS_OK) {
		cfs_critical("confdb_object_find_start failed %d", result);
		return result;
	}

	result = confdb_object_find(handle, OBJECT_PARENT_HANDLE, CLUSTER_KEY, 
				    strlen(CLUSTER_KEY), &obj_handle);
	if (result != CS_OK) {
		cfs_critical("cant find cluster object %d", result);
		return result;
	}

	result = confdb_object_find_destroy(handle, OBJECT_PARENT_HANDLE);
	if (result != CS_OK) {
		cfs_critical("confdb_object_find_destroy failed %d", result);
		return result;
	}

	result = confdb_track_changes(handle, obj_handle, CONFDB_TRACK_DEPTH_RECURSIVE);

	return result;
}

static void 
confdb_key_change_notify(
	confdb_handle_t handle,
	confdb_change_type_t change_type,
	hdb_handle_t parent_object_handle,
	hdb_handle_t object_handle,
	const void *object_name,
	size_t  object_name_len,
	const void *key_name,
	size_t key_name_len,
	const void *key_value,
	size_t key_value_len)
{
	cs_error_t result;
	cs_private_t *private = NULL;

	result = confdb_context_get(handle, (gconstpointer *)&private);
	if (result != CS_OK || !private) {
		cfs_critical("confdb_context_get error: %d (%p)", result, private);
		return;
	}

	private->changes = TRUE;
}

static void 
confdb_object_create_notify(
	confdb_handle_t handle,
	hdb_handle_t parent_object_handle,
	hdb_handle_t object_handle,
	const void *name_pt,
	size_t name_len)
{
	cs_error_t result;
	cs_private_t *private = NULL;

	result = confdb_context_get(handle, (gconstpointer *)&private);
	if (result != CS_OK || !private) {
		cfs_critical("confdb_context_get error: %d (%p)", result, private);
		return;
	}

	private->changes = TRUE;
}

static void 
confdb_object_delete_notify(
	confdb_handle_t handle,
	hdb_handle_t parent_object_handle,
	const void *name_pt,
	size_t name_len)
{
	cs_error_t result;
	cs_private_t *private = NULL;

	result = confdb_context_get(handle, (gconstpointer *)&private);
	if (result != CS_OK || !private) {
		cfs_critical("confdb_context_get error: %d (%p)", result, private);
		return;
	}

	if (name_len == strlen(CLUSTER_KEY) &&
	    !strncmp(name_pt, CLUSTER_KEY, name_len))
		track_object(handle);

	private->changes = TRUE;
}

/* this does not work with current corosync - seems a bug
 * that is why we listen to delete/change/create events instead
 */
static void 
confdb_reload_notify(
	confdb_handle_t handle,
	confdb_reload_type_t type)
{
	cs_error_t result;

	cs_private_t *private = NULL;

	result = confdb_context_get(handle, (gconstpointer *)&private);
	if (result != CS_OK || !private) {
		cfs_critical("confdb_context_get error: %d (%p)", result, private);
		return;
	}

	private->changes = TRUE;
}

static confdb_callbacks_t confdb_callbacks = {
	.confdb_key_change_notify_fn = confdb_key_change_notify,
	.confdb_object_create_change_notify_fn = confdb_object_create_notify,
	.confdb_object_delete_change_notify_fn = confdb_object_delete_notify,
	.confdb_reload_notify_fn = confdb_reload_notify,
};

static gboolean 
service_confdb_finalize(
	cfs_service_t *service,
	gpointer context)
{
	g_return_val_if_fail(service != NULL, FALSE);
	g_return_val_if_fail(context != NULL, FALSE);

	cs_private_t *private = (cs_private_t *)context;
	confdb_handle_t handle = private->handle;

	cs_error_t result;

	result = confdb_finalize(handle);
	private->handle = 0;
	if (result != CS_OK) {
		cfs_critical("confdb_finalize failed: %d", result);
		return FALSE;
	}

	return TRUE;
}

static int 
service_confdb_initialize(
	cfs_service_t *service,
	gpointer context)
{
	g_return_val_if_fail(service != NULL, FALSE);
	g_return_val_if_fail(context != NULL, FALSE);

	cs_private_t *private = (cs_private_t *)context;

	confdb_handle_t handle = private->handle;
	cs_error_t result;

	if (!private->handle) {

		result = confdb_initialize(&handle, &confdb_callbacks);
		if (result != CS_OK) {
			cfs_critical("confdb_initialize failed: %d", result);
			private->handle = 0;
			return -1;
		}

		result = confdb_context_set(handle, private);
		if (result != CS_OK) {
			cfs_critical("confdb_context_set failed: %d", result);
			confdb_finalize(handle);
			private->handle = 0;
			return -1;
		}

		private->handle = handle;
	}

	result = track_object(handle);
	if (result == CS_ERR_LIBRARY || result == CS_ERR_BAD_HANDLE) {
		cfs_critical("confdb_track_changes failed: %d - closing handle", result);
		confdb_finalize(handle);
		private->handle = 0;
		return -1;
	} else if (result != CS_OK) {
		cfs_critical("confdb_track_changes failed: %d - trying again", result);
		return -1;
	}
		
	int confdb_fd = -1;
	if ((result = confdb_fd_get(handle, &confdb_fd)) != CS_OK) {
		cfs_critical("confdb_fd_get failed %d - trying again", result);
		return -1;
	}

	cman_read_config(handle);

	return confdb_fd;
}

static gboolean 
service_confdb_dispatch(
	cfs_service_t *service,
	gpointer context)
{
	g_return_val_if_fail(service != NULL, FALSE);
	g_return_val_if_fail(context != NULL, FALSE);

	cs_private_t *private = (cs_private_t *)context;
	confdb_handle_t handle =  private->handle;

	cs_error_t result;

	private->changes = FALSE;
	int retries = 0;
loop:
	result = confdb_dispatch(handle, CS_DISPATCH_ALL);
	if (result == CS_ERR_TRY_AGAIN) {
		usleep(100000);
		++retries;
		if ((retries % 100) == 0)
			cfs_message("confdb_dispatch retry %d", retries);
		goto loop;
	}


	if (result == CS_OK || result == CS_ERR_TRY_AGAIN) {

		if (private->changes) {
			result = cman_read_config(handle);
			if (result == CS_OK)
				return TRUE;
		}
	} else {
		cfs_critical("confdb_dispatch failed: %d", result);
	}

	confdb_finalize(handle);
	private->handle = 0;
	return FALSE;
}

static cfs_service_callbacks_t cfs_confdb_callbacks = {
	.cfs_service_initialize_fn =  service_confdb_initialize,
	.cfs_service_finalize_fn = service_confdb_finalize,
	.cfs_service_dispatch_fn = service_confdb_dispatch,
};

cfs_service_t *
service_confdb_new(void)
{
	cfs_service_t *service;

	cs_private_t *private = g_new0(cs_private_t, 1);
	if (!private)
		return NULL;

	service = cfs_service_new(&cfs_confdb_callbacks, G_LOG_DOMAIN, private); 

	return service;
}

void 
service_confdb_destroy(cfs_service_t *service) 
{
	g_return_if_fail(service != NULL);

	cs_private_t *private = 
		(cs_private_t *)cfs_service_get_context(service);

	g_free(private);
	g_free(service);
}
