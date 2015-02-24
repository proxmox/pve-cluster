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
	gboolean changes;
} cs_private_t;

static cs_error_t 
cmap_read_config(cmap_handle_t handle)
{
	cs_error_t result;

        cmap_iter_handle_t iter;

        result = cmap_iter_init(handle, "nodelist.node", &iter);
  	if (result != CS_OK) {
		cfs_critical("cmap_iter_init failed %d", result);
		return result;
	}

        // TODO 

        result = cmap_iter_finalize(handle, iter);
 	if (result != CS_OK) {
		cfs_critical("cmap_iter_finalize failed %d", result);
		return result;
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

	result = cmap_finalize(handle);
	private->handle = 0;
	if (result != CS_OK) {
		cfs_critical("cmap_finalize failed: %d", result);
		return FALSE;
	}

	return TRUE;
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

	result = CS_OK; // fixme: track_object(handle);
        
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
