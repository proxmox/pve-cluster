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

#ifndef _PVE_LOOP_H_
#define _PVE_LOOP_H_

#define FUSE_USE_VERSION 26

#include <glib.h>
#include <fuse.h>
#include <qb/qbdefs.h>
#include <qb/qbutil.h>
#include <qb/qbloop.h>

typedef struct cfs_loop cfs_loop_t;

typedef struct cfs_service cfs_service_t;

typedef int (*cfs_service_initialize_fn_t)(
	cfs_service_t *service, 
	gpointer context);

typedef	gboolean (*cfs_service_finalize_fn_t)(
	cfs_service_t *service, 
	gpointer context);

typedef gboolean (*cfs_service_dispatch_fn_t)(
	cfs_service_t *service, 
	gpointer context);

typedef void (*cfs_service_timer_fn_t)(
	cfs_service_t *service, 
	gpointer context);

typedef struct {
	cfs_service_initialize_fn_t cfs_service_initialize_fn;
	cfs_service_finalize_fn_t cfs_service_finalize_fn;
	cfs_service_dispatch_fn_t cfs_service_dispatch_fn;
	cfs_service_timer_fn_t cfs_service_timer_fn;
} cfs_service_callbacks_t;

cfs_service_t *cfs_service_new(
	cfs_service_callbacks_t *callbacks,
	const char *log_domain,
	gpointer context);

gpointer cfs_service_get_context(
	cfs_service_t *service);

gboolean cfs_service_set_timer(
	cfs_service_t *service,
	time_t period);

void cfs_service_set_restartable(
	cfs_service_t *service,
	gboolean restartable);

cfs_loop_t *cfs_loop_new(struct fuse *fuse);

void cfs_loop_destroy(
	cfs_loop_t *loop);

gboolean cfs_loop_add_service(
	cfs_loop_t *loop,
	cfs_service_t *service,
	enum qb_loop_priority priority);

gboolean cfs_loop_start_worker(
	cfs_loop_t *loop);

gpointer cfs_loop_stop_worker(
	cfs_loop_t *loop);


#endif /* _PVE_LOOP_H_ */
