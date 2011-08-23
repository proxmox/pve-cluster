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

#define G_LOG_DOMAIN "quorum"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>

#include <corosync/quorum.h>

#include "cfs-utils.h"
#include "loop.h"
#include "status.h"

typedef struct {
	quorum_handle_t handle;
} qs_private_t;

static void quorum_notification_fn(
	quorum_handle_t handle,
	uint32_t quorate,
	uint64_t ring_id,
	uint32_t view_list_entries,
	uint32_t *view_list)
{
	cs_error_t result;

	cfs_debug("quorum notification called, quorate = %d, "
		  "number of nodes = %d", quorate, view_list_entries);

	qs_private_t *private = NULL;

	result = quorum_context_get(handle, (gconstpointer *)&private);
	if (result != CS_OK || !private) {
		cfs_critical("quorum_context_get error: %d (%p)", result, private);
		return;
	}

	cfs_set_quorate(quorate, FALSE);
}

static quorum_callbacks_t quorum_callbacks = {
	.quorum_notify_fn = quorum_notification_fn,
};

static gboolean service_quorum_finalize(
	cfs_service_t *service,
	gpointer context)
{
	g_return_val_if_fail(service != NULL, FALSE);
	g_return_val_if_fail(context != NULL, FALSE);

	qs_private_t *private = (qs_private_t *)context;
	quorum_handle_t handle = private->handle;

	cs_error_t result;

	cfs_set_quorate(0, TRUE);

	result = quorum_finalize(handle);
	private->handle = 0;
	if (result != CS_OK) {
		cfs_critical("quorum_finalize failed: %d", result);
		return FALSE;
	}

	return TRUE;
}

static int service_quorum_initialize(
	cfs_service_t *service,
	gpointer context)
{
	g_return_val_if_fail(service != NULL, FALSE);
	g_return_val_if_fail(context != NULL, FALSE);

	qs_private_t *private = (qs_private_t *)context;

	quorum_handle_t handle = private->handle;
	cs_error_t result;

	if (!private->handle) {

		result = quorum_initialize(&handle, &quorum_callbacks);
		if (result != CS_OK) {
			cfs_critical("quorum_initialize failed: %d", result);
			private->handle = 0;
			return -1;
		}

		result = quorum_context_set(handle, private);
		if (result != CS_OK) {
			cfs_critical("quorum_context_set failed: %d", result);
			quorum_finalize(handle);
			private->handle = 0;
			return -1;
		}

		private->handle = handle;
	}
	

	result = quorum_trackstart(handle, CS_TRACK_CHANGES);
	if (result == CS_ERR_LIBRARY || result == CS_ERR_BAD_HANDLE) {
		cfs_critical("quorum_trackstart failed: %d - closing handle", result);
		quorum_finalize(handle);
		private->handle = 0;
		return -1;
	} else if (result != CS_OK) {
		cfs_critical("quorum_trackstart failed: %d - trying again", result);
		return -1;
	}
	
	int quorum_fd = -1;
	if ((result = quorum_fd_get(handle, &quorum_fd)) != CS_OK) {
		cfs_critical("quorum_fd_get failed %d - trying again", result);
		return -1;
	}

	return quorum_fd;
}

static gboolean service_quorum_dispatch(
	cfs_service_t *service,
	gpointer context)
{
	g_return_val_if_fail(service != NULL, FALSE);
	g_return_val_if_fail(context != NULL, FALSE);

	qs_private_t *private = (qs_private_t *)context;
	quorum_handle_t handle =  private->handle;

	cs_error_t result;

	int retries = 0;
loop:
	result = quorum_dispatch(handle, QUORUM_DISPATCH_ALL);
	if (result == QUORUM_ERR_TRY_AGAIN) {
		usleep(100000);
		++retries;
		if ((retries % 100) == 0)
			cfs_message("quorum_dispatch retry %d", retries);
		goto loop;
	}


	if (result == CS_OK || result == CS_ERR_TRY_AGAIN)
		return TRUE;

	cfs_critical("quorum_dispatch failed: %d", result);

	quorum_finalize(handle);
	private->handle = 0;
	return FALSE;
}

static cfs_service_callbacks_t cfs_quorum_callbacks = {
	.cfs_service_initialize_fn =  service_quorum_initialize,
	.cfs_service_finalize_fn = service_quorum_finalize,
	.cfs_service_dispatch_fn = service_quorum_dispatch,
};

cfs_service_t *service_quorum_new(void)
{
	cfs_service_t *service;

	qs_private_t *private = g_new0(qs_private_t, 1);
	if (!private)
		return NULL;

	service = cfs_service_new(&cfs_quorum_callbacks, G_LOG_DOMAIN, private); 

	return service;
}

void service_quorum_destroy(cfs_service_t *service) 
{
	g_return_if_fail(service != NULL);

	qs_private_t *private = 
		(qs_private_t *)cfs_service_get_context(service);

	g_free(private);
	g_free(service);
}
