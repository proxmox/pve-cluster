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
#include <sys/syslog.h>

#include "cfs-utils.h"

static const char * hexchar = "0123456789abcdef";

/* convert utf8 to json and syslog compatible ascii */
void
utf8_to_ascii(
	char *buf, 
	int bufsize, 
	const char *msg, 
	gboolean quotequote)
{
	g_return_if_fail(buf != NULL);

	*buf = 0;

	g_return_if_fail(bufsize > 10);

	const char *p = msg;
	char *d = buf;
	char *end = buf + bufsize - 7;

	if (!g_utf8_validate(msg, -1, NULL)) {
		while (*p && d < end) {
			char c = *p++;
			if (c == 34 && quotequote) {
				*d++ = '\\';
				*d++ = '"';
			} else if (c >= 0 && c < 32) {
				*d++ = '#';
				*d++ = '0';
				*(d+1) = hexchar[c % 10]; c = c / 10;
				*d = hexchar[c % 10];
				d += 2;
			} else if (c >= 32 && c < 127) {
				*d++ = c;	
			} else {
				*d++ = '?';
			}
		}
		*d = 0;
		return;
	}

	while (*p && d < end) {
		gunichar u = g_utf8_get_char(p);
		if (u == 34 && quotequote) {
			*d++ = '\\';
			*d++ = '"';
		} else if (u < 32 || u == 127) {
			*d++ = '#';
			*(d+2) = hexchar[u % 10]; u = u / 10;
			*(d+1) = hexchar[u % 10]; u = u / 10;
			*d = hexchar[u % 10];
			d += 3;
		} else if (u < 127) {
			*d++ = u;
		} else if (u < 65536) {
			*d++ = '\\';
			*d++ = 'u';
			*(d+3) = hexchar[u&0xf]; u = u >> 4;
			*(d+2) = hexchar[u&0xf]; u = u >> 4;
			*(d+1) = hexchar[u&0xf]; u = u >> 4;
			*d = hexchar[u&0xf];
			d += 4;
		} else {
			/* we simply ignore this */
		}
		p = g_utf8_next_char(p);
	}
	*d = 0;
}

void 
cfs_log(
	const gchar *log_domain,
	GLogLevelFlags log_level,
	const char *file,
	int         line,
	const char  *func,
	const gchar    *format,
	...)
{
	va_list args;

	va_start (args, format);
	char *orgmsg = g_strdup_vprintf (format, args);
	va_end (args);

	char msg[8192];
	utf8_to_ascii(msg, sizeof(msg), orgmsg, FALSE);

	gint level; 
	char *ltxt;

	switch (log_level & G_LOG_LEVEL_MASK) { 
	case G_LOG_LEVEL_ERROR: 
		level=LOG_ERR; 
		ltxt = "error";
		break; 
	case G_LOG_LEVEL_CRITICAL: 
		level=LOG_CRIT; 
		ltxt = "critical";
		break; 
	case G_LOG_LEVEL_WARNING: 
		level=LOG_WARNING; 
		ltxt = "warning";
 		break; 
	case G_LOG_LEVEL_MESSAGE: 
		level=LOG_NOTICE; 
		ltxt = "notice";
		break; 
	case G_LOG_LEVEL_INFO: 
		level=LOG_INFO; 
		ltxt = "info";
		break; 
	case G_LOG_LEVEL_DEBUG: 
		level=LOG_DEBUG;   
		ltxt = "debug";      
		if (!cfs.debug)
			return;
		break; 
	default:  
		level=LOG_INFO; 
		ltxt = "info";
	} 

	if (!file || (log_level == G_LOG_LEVEL_MESSAGE ||
		      log_level == G_LOG_LEVEL_INFO)) {

		if (log_domain) {
			syslog(level, "[%s] %s", log_domain, msg); 

			if (cfs.debug || cfs.print_to_console)
				printf("%s: [%s] %s\n", ltxt, log_domain, msg);
		} else {
			syslog(level, msg); 

			if (cfs.debug || cfs.print_to_console)
				printf("%s: %s\n", ltxt, msg);

		}

	} else {

		if (log_domain) {
			syslog(level, "[%s] %s (%s:%d:%s)", log_domain, msg, file, line, func); 

			if (cfs.debug || cfs.print_to_console)
				printf("%s: [%s] %s (%s:%d:%s)\n", ltxt, log_domain, msg, file, line, func);

		} else {
			syslog(level, "%s (%s:%d:%s)", msg, file, line, func); 

			if (cfs.debug || cfs.print_to_console)
				printf("%s: %s (%s:%d:%s)\n", ltxt, msg, file, line, func);
		}
	}

	g_free(orgmsg);
}

void ipc_log_fn(
	const char *file,
	int32_t line, 
	int32_t severity, 
	const char *msg)
{

	if (!cfs.debug && 
	    !(severity == LOG_ERR || severity == LOG_CRIT || severity == LOG_WARNING))
		return;

	GLogLevelFlags log_level;

	switch (severity) { 
	case LOG_ERR:
		log_level = G_LOG_LEVEL_ERROR;
		break; 
	case LOG_CRIT:
		log_level = G_LOG_LEVEL_CRITICAL; 
		break; 
	case LOG_WARNING:
		log_level = G_LOG_LEVEL_WARNING;
		break; 
	case LOG_NOTICE:
		log_level = G_LOG_LEVEL_MESSAGE;
		break; 
	case LOG_INFO:
		log_level = G_LOG_LEVEL_INFO;
		break; 
	case LOG_DEBUG:
		log_level = G_LOG_LEVEL_DEBUG;
		if (!cfs.debug)
			return;
		break; 
	default:  
		log_level = G_LOG_LEVEL_INFO;
	}

	cfs_log(G_LOG_DOMAIN, log_level, file, line, "", msg);
}

// xml parser for cluster.conf - just good enough to extract version

typedef struct
{
  guint64 version;
} PVEClusterConfig;

static void
parser_start_element (
	GMarkupParseContext  *context,
	const gchar          *element_name,
	const gchar         **attribute_names,
	const gchar         **attribute_values,
	gpointer              user_data,
	GError              **error)
{
	PVEClusterConfig *data = user_data;

	if (!data->version && !strcmp(element_name, "cluster")) { 
		const char **n = attribute_names;
		const char **v = attribute_values;

		while (n && v && *n) {
			if (!strcmp(*n, "config_version")) {
				char *e = NULL;
				guint64 ver = strtoull(*v, &e, 10);
				if (e) 
					data->version = ver;	  
			}
			++n;
			++v;
		}
	}
}

static GMarkupParser cluster_conf_parser = { 
	.start_element = parser_start_element 
};

guint64 
cluster_config_version(
	const gpointer config_data, 
	gsize config_length)
{
	GMarkupParseContext *ctx;

	GError *err = NULL;

	PVEClusterConfig cfg = { .version = 0 };
	if (!(ctx = g_markup_parse_context_new(&cluster_conf_parser, 0, &cfg, NULL))) {
		cfs_critical("g_markup_parse_context_new failed");
		return 0;
	}

	if (!g_markup_parse_context_parse(ctx, config_data, config_length, &err)) {
		cfs_critical("unable to parse cluster config - %s", err->message);
		g_error_free (err);
		g_markup_parse_context_free(ctx);
		return cfg.version;
	}

	if (!g_markup_parse_context_end_parse(ctx, &err)) {
		cfs_critical("unable to parse cluster config - %s", err->message);
		g_error_free (err);
		g_markup_parse_context_free(ctx);
		return cfg.version;
	}

	g_markup_parse_context_free(ctx);
	return cfg.version;
}

ssize_t 
safe_read(
	int fd, 
	char *buf, 
	size_t count)
{
  ssize_t n;

  do {
    n = read(fd, buf, count);
  } while (n < 0 && errno == EINTR);

  return n;
}

gboolean 
full_write(
	int fd, 
	const char *buf, 
	size_t len)
{
	size_t total;

	total = 0;

	while (len > 0) {
		ssize_t n;
		do {
			n = write(fd, buf, len);
		} while (n < 0 && errno == EINTR);
		
		if (n < 0)
			break;
		
		buf += n;
		total += n;
		len -= n;
	}

	return (len == 0);
}

gboolean 
atomic_write_file(
	const char *filename, 
	gconstpointer data, 
	size_t len, 
	mode_t mode, 
	gid_t gid)
{
	g_return_val_if_fail(filename != NULL, FALSE);
	g_return_val_if_fail(len == 0 || data != NULL, FALSE);

	gboolean res = TRUE;

	char *tmp_name = g_strdup_printf ("%s.XXXXXX", filename);
	int fd = mkstemp(tmp_name);
	if (fd == -1) {
		cfs_critical("Failed to create file '%s': %s", tmp_name, g_strerror(errno));
		res = FALSE;
		goto ret;
	}

	if (fchown(fd, 0, gid) == -1) {
		cfs_critical("Failed to change group of file '%s': %s", tmp_name, g_strerror(errno));
		close(fd);
		goto fail;
	}

	if (fchmod(fd, mode) == -1) {
		cfs_critical("Failed to change mode of file '%s': %s", tmp_name, g_strerror(errno));
		close(fd);
		goto fail;
	}

	if (len && !full_write(fd, data, len)) {
		cfs_critical("Failed to write file '%s': %s", tmp_name, g_strerror(errno));
		close(fd);
		goto fail;
	}

	if (close(fd) == -1) {
		cfs_critical("Failed to close file '%s': %s", tmp_name, g_strerror(errno));
		goto fail;
	}

	if (rename(tmp_name, filename) == -1) {
		cfs_critical("Failed to rename file from '%s' to '%s': %s", 
			   tmp_name, filename, g_strerror(errno));
		goto fail;
	}
ret:
	g_free (tmp_name);

	return res;

fail:
	unlink(tmp_name);

	res = FALSE;

	goto ret;
}

gboolean
path_is_private(const char *path)
{
	while (*path == '/') path++;

	if ((strncmp(path, "priv", 4) == 0) && (path[4] == 0 || path[4] == '/')) {
		return TRUE;
	} else {
		if (strncmp(path, "nodes/", 6) == 0) {
			const char *tmp = path + 6;
			while(*tmp && *tmp != '/') tmp++;
			if (*tmp == '/' && 
			    (strncmp(tmp, "/priv", 5) == 0) && 
			    (tmp[5] == 0 || tmp[5] == '/')) {
				return TRUE;
			}
		}
	}
	return FALSE;
}

gboolean
path_is_lockdir(const char *path)
{
	while (*path == '/') path++;

	return (strncmp(path, "priv/lock/", 10) == 0) && (strlen(path) > 10);
}
