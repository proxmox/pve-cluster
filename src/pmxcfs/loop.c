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

#define G_LOG_DOMAIN "loop"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <utime.h>
#include <sys/stat.h>
#include <glib.h>
#include <syslog.h>
#include <poll.h>

#include "cfs-utils.h"
#include "loop.h"

struct cfs_service {
	qb_loop_t *qbloop;	
	const char *log_domain;
	cfs_service_callbacks_t *callbacks;
	gboolean restartable;
	gpointer context;
	gboolean initialized;
	int errcount;
	time_t last_init;
	enum qb_loop_priority priority;
	time_t period;
	time_t last_timeout;
};

struct cfs_loop {
	GThread *worker;
	gboolean server_started;
	gboolean stop_worker_flag;
	GCond server_started_cond;
	GCond server_stopped_cond;
	GMutex server_started_mutex;
	qb_loop_t *qbloop;	
	struct fuse *fuse;
	GList *services;
};

gboolean 
cfs_service_set_timer(
	cfs_service_t *service,
	time_t period)
{
	g_return_val_if_fail(service != NULL, FALSE);

	service->period = period;

	return TRUE;
}

gpointer 
cfs_service_get_context(cfs_service_t *service)
{
	g_return_val_if_fail(service != NULL, NULL);

	return service->context;
}

void 
cfs_service_set_restartable(
	cfs_service_t *service,
	gboolean restartable)
{
	g_return_if_fail(service != NULL);

	service->restartable = restartable;
}

cfs_service_t *
cfs_service_new(
	cfs_service_callbacks_t *callbacks,
	const char *log_domain,
	gpointer context)
{
	g_return_val_if_fail(callbacks != NULL, NULL);
	g_return_val_if_fail(callbacks->cfs_service_initialize_fn != NULL, NULL);
	g_return_val_if_fail(callbacks->cfs_service_finalize_fn != NULL, NULL);
	g_return_val_if_fail(callbacks->cfs_service_dispatch_fn != NULL, NULL);

	cfs_service_t *service = g_new0(cfs_service_t, 1);
	if(!service)
		return NULL;
	
	if (log_domain)
		service->log_domain = log_domain;
	else
		service->log_domain = G_LOG_DOMAIN;

	service->callbacks = callbacks;

	service->restartable = TRUE;

	service->context = context;

	return service;
}

cfs_loop_t *
cfs_loop_new(struct fuse *fuse)
{
	cfs_loop_t *loop = g_new0(cfs_loop_t, 1);

	g_mutex_init(&loop->server_started_mutex);
	g_cond_init(&loop->server_started_cond);
	g_cond_init(&loop->server_stopped_cond);
	
	if (!(loop->qbloop = qb_loop_create())) {
		cfs_critical("cant create event loop");
		g_free(loop);
		return NULL;
	}

	loop->fuse = fuse;

	return loop;
}

void 
cfs_loop_destroy(cfs_loop_t *loop)
{
	g_return_if_fail(loop != NULL);

	if (loop->qbloop)
		qb_loop_destroy(loop->qbloop);

	if(loop->services)
		g_list_free(loop->services);

	g_mutex_clear(&loop->server_started_mutex);
	g_cond_clear(&loop->server_started_cond);
	g_cond_clear(&loop->server_stopped_cond);

	g_free(loop);
}

gboolean 
cfs_loop_add_service(
	cfs_loop_t *loop, 
	cfs_service_t *service, 
	enum qb_loop_priority priority)
{
	g_return_val_if_fail(loop != NULL, FALSE);
	g_return_val_if_fail(service != NULL, FALSE);
	g_return_val_if_fail(service->log_domain != NULL, FALSE);

	service->priority = priority;
	service->qbloop = loop->qbloop;

	loop->services = g_list_append(loop->services, service);

	return TRUE;
}

static int32_t 
poll_dispatch_fn(
	int32_t fd, 
	int32_t revents, 
	void *data)
{
	cfs_service_t *service = (cfs_service_t *)data;

	if (!service->callbacks->cfs_service_dispatch_fn(service, service->context)) {
		qb_loop_poll_del(service->qbloop, fd);
		service->initialized = FALSE;
		service->errcount = 0;

		if (!service->restartable)
			service->callbacks->cfs_service_finalize_fn(service, service->context);
			
		return -1;
	}

	return 0;
}

static void 
service_timer_job(void *data)
{
	g_return_if_fail(data != NULL);

	cfs_loop_t *loop = (cfs_loop_t *)data;
	qb_loop_t *qbloop = loop->qbloop;

	gboolean terminate = FALSE;
	
	g_mutex_lock (&loop->server_started_mutex);

	if (loop->stop_worker_flag) {
		cfs_debug ("got terminate request");
		qb_loop_stop(qbloop);
		loop->server_started = 0;
		g_cond_signal (&loop->server_stopped_cond);
		terminate = TRUE;
	} else if (!loop->server_started) {
		loop->server_started = 1;
		g_cond_signal (&loop->server_started_cond);
	}
	
	g_mutex_unlock (&loop->server_started_mutex);

	if (terminate)
		return;
	
	GList *l = loop->services;
	while (l) {
		cfs_service_t *service = (cfs_service_t *)l->data;
		l = g_list_next(l);

		if (!service->initialized)
			continue;

		time_t ctime = time(NULL);
		if (service->period && service->callbacks->cfs_service_timer_fn &&
		    ((ctime - service->last_timeout) >= service->period)) {
			service->last_timeout = ctime;
			service->callbacks->cfs_service_timer_fn(service, service->context);	
		}
	}

	qb_loop_timer_handle th;
	qb_loop_timer_add(qbloop, QB_LOOP_LOW, 1000000000, data, service_timer_job, &th);
}

static void 
service_start_job(void *data)
{
	g_return_if_fail(data != NULL);

	cfs_loop_t *loop = (cfs_loop_t *)data;
	qb_loop_t *qbloop = loop->qbloop;

	gboolean terminate = FALSE;
	g_mutex_lock (&loop->server_started_mutex);
	terminate = loop->stop_worker_flag;
	g_mutex_unlock (&loop->server_started_mutex);

	if (terminate)
		return;

	GList *l = loop->services;
	time_t ctime = time(NULL);

	while (l) {
		cfs_service_t *service = (cfs_service_t *)l->data;
		l = g_list_next(l);

		if (service->restartable && !service->initialized && 
		    ((ctime - service->last_init) > 5)) {
			int fd = service->callbacks->cfs_service_initialize_fn(service, service->context);
			service->last_init = ctime;

			if (fd >= 0) {
				service->initialized = TRUE;
				service->errcount = 0;

				int res;
				if ((res = qb_loop_poll_add(qbloop, service->priority, fd, POLLIN, 
							    service, poll_dispatch_fn)) != 0) {
					cfs_critical("qb_loop_poll_add failed: %s - disabling service", 
						     g_strerror(-res));
					service->initialized = FALSE;
					service->restartable = FALSE;
					service->callbacks->cfs_service_finalize_fn(service, service->context);
				}
			} else {
				if (!service->errcount) 
					cfs_dom_critical(service->log_domain, "can't initialize service");
				service->errcount++;
			}
		}
	}

	qb_loop_timer_handle th;
	qb_loop_timer_add(qbloop, QB_LOOP_LOW, 1000000000, data, service_start_job, &th);
}

static gpointer 
cfs_loop_worker_thread(gpointer data)
{
	g_return_val_if_fail(data != NULL, NULL);

	cfs_loop_t *loop = (cfs_loop_t *)data;
	qb_loop_t *qbloop = loop->qbloop;

	GList *l;
	time_t ctime = time(NULL);
	l = loop->services;
	while (l) {
		cfs_service_t *service = (cfs_service_t *)l->data;
		l = g_list_next(l);
		service->last_timeout = ctime;
	}

	qb_loop_timer_handle th;
	qb_loop_timer_add(qbloop, QB_LOOP_LOW, 10000000, loop, service_start_job, &th);

	qb_loop_timer_add(qbloop, QB_LOOP_LOW, 1000000000, loop, service_timer_job, &th);

	cfs_debug("start loop");
	
	qb_loop_run(qbloop);

	cfs_debug("end loop");

	l = loop->services;
	while (l) {
		cfs_service_t *service = (cfs_service_t *)l->data;
		l = g_list_next(l);
		service->callbacks->cfs_service_finalize_fn(service, service->context);
	}

	return NULL;
}

gboolean 
cfs_loop_start_worker(cfs_loop_t *loop)
{
	g_return_val_if_fail(loop != NULL, FALSE);

	loop->worker = g_thread_new("cfs_loop", cfs_loop_worker_thread, loop);
	
	g_mutex_lock (&loop->server_started_mutex);
	while (!loop->server_started)
		g_cond_wait (&loop->server_started_cond, &loop->server_started_mutex);
	g_mutex_unlock (&loop->server_started_mutex);
	
	cfs_debug("worker started");
	
	return TRUE;
}

void
cfs_loop_stop_worker(cfs_loop_t *loop)
{
	g_return_if_fail(loop != NULL);

	cfs_debug("cfs_loop_stop_worker");

	g_mutex_lock (&loop->server_started_mutex);
	loop->stop_worker_flag = TRUE;
	while (loop->server_started)
		g_cond_wait (&loop->server_stopped_cond, &loop->server_started_mutex);
	g_mutex_unlock (&loop->server_started_mutex);

	if (loop->worker) {
		g_thread_join(loop->worker);
		loop->worker = NULL;
	}
}
