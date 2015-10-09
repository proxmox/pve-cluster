/*
  Copyright (C) 2010-2015 Proxmox Server Solutions GmbH

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


/* see "man cmap_overview" and "man cmap_keys" */

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

#include <corosync/cmap.h>

#include "cfs-utils.h"
#include "loop.h"
#include "status.h"

typedef struct {
	cmap_handle_t handle;
	cmap_track_handle_t track_nodelist_handle;
	cmap_track_handle_t track_version_handle;
	gboolean changes;
} cs_private_t;

static cs_error_t
cmap_read_clusternodes(
	cmap_handle_t handle,
	cfs_clinfo_t *clinfo)
{
	cs_error_t result;
        cmap_iter_handle_t iter;

	result = cmap_iter_init(handle, "nodelist.node.", &iter);
	if (result != CS_OK) {
		cfs_critical("cmap_iter_init failed %d", result);
		return result;
	}

 	cmap_value_types_t type;
 	char key_name[CMAP_KEYNAME_MAXLEN + 1];
	size_t value_len;

	int last_id = -1;
	uint32_t nodeid = 0;
	uint32_t votes = 0;
	char *name = NULL;

	while ((result = cmap_iter_next(handle, iter, key_name, &value_len, &type)) == CS_OK) {
		int id;
		char subkey[CMAP_KEYNAME_MAXLEN + 1];
		if (sscanf(key_name, "nodelist.node.%d.%s", &id, subkey) != 2) continue;

		if (id != last_id) {
			if (name && nodeid) {
				cfs_clnode_t *clnode = cfs_clnode_new(name, nodeid, votes);
				cfs_clinfo_add_node(clinfo, clnode);
			}
			last_id = id;
			if (name) free(name);
			name = NULL;
			nodeid = 0;
			votes = 0;
		}

		if (strcmp(subkey, "nodeid") == 0) {
			if ((result = cmap_get_uint32(handle, key_name, &nodeid)) != CS_OK) {
				cfs_critical("cmap_get %s failed %d", key_name, result);
			}
		} else if (strcmp(subkey, "quorum_votes") == 0) {
			if ((result = cmap_get_uint32(handle, key_name, &votes)) != CS_OK) {
				cfs_critical("cmap_get %s failed %d", key_name, result);
			}
		} else if (strcmp(subkey, "ring0_addr") == 0) {
			// prefering the 'name' subkey over 'ring0_addr', needed for RRP
			// and when using a IP address for ring0_addr
			if (name == NULL &&
			    (result = cmap_get_string(handle, key_name, &name)) != CS_OK) {
				cfs_critical("cmap_get %s failed %d", key_name, result);
			}
		} else if (strcmp(subkey, "name") == 0) {
			free(name);
			name = NULL;
			if ((result = cmap_get_string(handle, key_name, &name)) != CS_OK) {
				cfs_critical("cmap_get %s failed %d", key_name, result);
			}
		}
	}

	if (name && nodeid) {
		cfs_clnode_t *clnode = cfs_clnode_new(name, nodeid, votes);
		cfs_clinfo_add_node(clinfo, clnode);
	}
	if (name) free(name);

        result = cmap_iter_finalize(handle, iter);
 	if (result != CS_OK) {
		cfs_critical("cmap_iter_finalize failed %d", result);
		return result;
	}

	return result;
}

static cs_error_t
cmap_read_config(cmap_handle_t handle)
{
	cs_error_t result;

	uint64_t config_version = 0;

	result = cmap_get_uint64(handle, "totem.config_version", &config_version);
	if (result != CS_OK) {
		cfs_critical("cmap_get totem.config_version failed %d", result);
		// optional, do not throw error
	}

	char *clustername = NULL;
	result = cmap_get_string(handle, "totem.cluster_name", &clustername);
	if (result != CS_OK) {
		cfs_critical("cmap_get totem.cluster_name failed %d", result);
		return result;
	}

	cfs_clinfo_t *clinfo = cfs_clinfo_new(clustername, config_version);
	g_free(clustername);

	result = cmap_read_clusternodes(handle, clinfo);
	if (result == CS_OK) {
		cfs_status_set_clinfo(clinfo);
	} else {
		cfs_clinfo_destroy(clinfo);
	}

	return result;
}

static gboolean
service_cmap_finalize(
	cfs_service_t *service,
	gpointer context)
{
	g_return_val_if_fail(service != NULL, FALSE);
	g_return_val_if_fail(context != NULL, FALSE);

	cs_private_t *private = (cs_private_t *)context;
	cmap_handle_t handle = private->handle;
	cs_error_t result;

        if (private->track_nodelist_handle) {
            result = cmap_track_delete(handle, private->track_nodelist_handle);
            if (result != CS_OK) {
		cfs_critical("cmap_track_delete nodelist failed: %d", result);
            }
            private->track_nodelist_handle = 0;
        }
	
        if (private->track_version_handle) {
            result = cmap_track_delete(handle, private->track_version_handle);
            if (result != CS_OK) {
		cfs_critical("cmap_track_delete version failed: %d", result);
            }
            private->track_version_handle = 0;
        }

	result = cmap_finalize(handle);
	private->handle = 0;
	if (result != CS_OK) {
		cfs_critical("cmap_finalize failed: %d", result);
		return FALSE;
	}

	return TRUE;
}

static void
track_callback(
    cmap_handle_t cmap_handle,
    cmap_track_handle_t cmap_track_handle,
    int32_t event,
    const char *key_name,
    struct cmap_notify_value new_value,
    struct cmap_notify_value old_value,
    void *context)
{
	g_return_if_fail(context != NULL);

	cs_private_t *private = (cs_private_t *)context;

	cfs_debug("track_callback %s %d\n", key_name, event);

	private->changes = TRUE;
}


static int
service_cmap_initialize(
	cfs_service_t *service,
	gpointer context)
{
	g_return_val_if_fail(service != NULL, FALSE);
	g_return_val_if_fail(context != NULL, FALSE);

	cs_private_t *private = (cs_private_t *)context;

        // fixme: do not copy (use pointer)
	cmap_handle_t handle = private->handle;
	cs_error_t result;

	if (!private->handle) {

		result = cmap_initialize(&handle);
		if (result != CS_OK) {
			cfs_critical("cmap_initialize failed: %d", result);
			private->handle = 0;
			return -1;
		}

		result = cmap_context_set(handle, private);
		if (result != CS_OK) {
			cfs_critical("cmap_context_set failed: %d", result);
			cmap_finalize(handle);
			private->handle = 0;
			return -1;
		}

		private->handle = handle;
	}

	
        result = cmap_track_add(handle, "nodelist.node.",
				CMAP_TRACK_PREFIX|CMAP_TRACK_ADD|CMAP_TRACK_DELETE|CMAP_TRACK_MODIFY,
                                track_callback, context, &private->track_nodelist_handle);

	if (result == CS_OK) {
		result = cmap_track_add(handle, "totem.config_version",
					CMAP_TRACK_ADD|CMAP_TRACK_DELETE|CMAP_TRACK_MODIFY,
					track_callback, context, &private->track_version_handle);
	}

	if (result == CS_ERR_LIBRARY || result == CS_ERR_BAD_HANDLE) {
		cfs_critical("cmap_track_changes failed: %d - closing handle", result);
		cmap_finalize(handle);
		private->handle = 0;
		return -1;
	} else if (result != CS_OK) {
                cfs_critical("cmap_track_changes failed: %d - trying again", result);
		return -1;
	}

	int cmap_fd = -1;
	if ((result = cmap_fd_get(handle, &cmap_fd)) != CS_OK) {
		cfs_critical("confdb_fd_get failed %d - trying again", result);
		return -1;
	}

	cmap_read_config(handle);

	return cmap_fd;
}

static gboolean
service_cmap_dispatch(
	cfs_service_t *service,
	gpointer context)
{
	g_return_val_if_fail(service != NULL, FALSE);
	g_return_val_if_fail(context != NULL, FALSE);

	cs_private_t *private = (cs_private_t *)context;
	cmap_handle_t handle =  private->handle;

	cs_error_t result;

	private->changes = FALSE;
	int retries = 0;
loop:
	result = cmap_dispatch(handle, CS_DISPATCH_ALL);
	if (result == CS_ERR_TRY_AGAIN) {
		usleep(100000);
		++retries;
		if ((retries % 100) == 0)
			cfs_message("cmap_dispatch retry %d", retries);
		goto loop;
	}


	if (result == CS_OK || result == CS_ERR_TRY_AGAIN) {

		if (private->changes) {
			result = cmap_read_config(handle);

			private->changes = FALSE;

			if (result == CS_OK)
				return TRUE;
		}
	} else {
		cfs_critical("cmap_dispatch failed: %d", result);
	}

	cmap_finalize(handle);
	private->handle = 0;
	return FALSE;
}

static cfs_service_callbacks_t cfs_confdb_callbacks = {
	.cfs_service_initialize_fn =  service_cmap_initialize,
	.cfs_service_finalize_fn = service_cmap_finalize,
	.cfs_service_dispatch_fn = service_cmap_dispatch,
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
