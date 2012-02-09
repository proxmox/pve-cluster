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

#ifndef _PVE_CFS_UTILS_H_
#define _PVE_CFS_UTILS_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdint.h>
#include <glib.h>
#include <fcntl.h>

#define HOST_CLUSTER_CONF_FN "/etc/cluster/cluster.conf"
#define CFS_PID_FN "/var/run/pve-cluster.pid"
#define VARLIBDIR "/var/lib/pve-cluster"

#define CFS_MAX(a, b)		(((a) > (b)) ? (a) : (b))
#define CFS_MIN(a, b)		(((a) < (b)) ? (a) : (b))

typedef struct {
	char *nodename;
	char *ip;
	gid_t gid;
	int debug;
} cfs_t;

extern cfs_t cfs;

void
utf8_to_ascii(
	char *buf, 
	int bufsize, 
	const char *msg, 
	gboolean quotequote);

void 
cfs_log(
	const gchar *log_domain,
	GLogLevelFlags log_level,
	const char *file,
	int         line,
	const char  *func,
	const gchar    *format,
	...) G_GNUC_PRINTF (6, 7);

void ipc_log_fn(
	const char *file,
	int32_t line, 
	int32_t severity, 
	const char *msg);


#define cfs_debug(...)  G_STMT_START { \
	if (cfs.debug) \
		cfs_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, __FILE__, __LINE__, G_STRFUNC, __VA_ARGS__); \
	} G_STMT_END

#define cfs_dom_debug(domain, ...)  G_STMT_START {	\
	if (cfs.debug) \
		cfs_log(domain, G_LOG_LEVEL_DEBUG, __FILE__, __LINE__, G_STRFUNC, __VA_ARGS__); \
	} G_STMT_END

#define cfs_critical(...)  cfs_log(G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL, __FILE__, __LINE__, G_STRFUNC, __VA_ARGS__)
#define cfs_dom_critical(domain, ...)  cfs_log(domain, G_LOG_LEVEL_CRITICAL, __FILE__, __LINE__, G_STRFUNC, __VA_ARGS__)
#define cfs_message(...)  cfs_log(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE, __FILE__, __LINE__, G_STRFUNC, __VA_ARGS__)
#define cfs_dom_message(domain, ...)  cfs_log(domain, G_LOG_LEVEL_MESSAGE, __FILE__, __LINE__, G_STRFUNC, __VA_ARGS__)

guint64 
cluster_config_version(
	const gpointer config_data, 
	gsize config_length);

ssize_t 
safe_read(
	int fd, 
	char *buf, 
	size_t count);

gboolean 
full_write(
	int fd, 
	const char *buf, 
	size_t len);

gboolean 
atomic_write_file(
	const char *filename, 
	gconstpointer data, 
	size_t len, 
	mode_t mode, 
	gid_t gid);

gboolean
path_is_private(const char *path);

gboolean
path_is_lockdir(const char *path);

#endif /* _PVE_CFS_UTILS_H_ */
