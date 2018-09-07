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
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/file.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/utsname.h>
#include <grp.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <qb/qbdefs.h>
#include <qb/qbutil.h>
#include <qb/qblog.h>

#include "cfs-utils.h"
#include "cfs-plug.h"
#include "cfs-plug-memdb.h"
#include "status.h"
#include "dcdb.h"
#include "dfsm.h"
#include "quorum.h"
#include "confdb.h"
#include "server.h"

#define DBFILENAME VARLIBDIR "/config.db"
#define LOCKFILE VARLIBDIR "/.pmxcfs.lockfile"
#define RESTART_FLAG_FILE RUNDIR "/cfs-restart-flag"

#define CFSDIR "/etc/pve"

cfs_t cfs = {
	.debug = 0,
};

static struct fuse *fuse = NULL;

static cfs_plug_t *root_plug;

static void glib_print_handler(const gchar *string)
{
	printf("%s", string);
}

static void glib_log_handler(const gchar *log_domain,
			     GLogLevelFlags log_level,
			     const gchar *message,
			     gpointer user_data)
{

	cfs_log(log_domain, log_level, NULL, 0, NULL, "%s", message);
}

static gboolean write_pidfile(pid_t pid)
{
	char *strpid = g_strdup_printf("%d\n", pid);
	gboolean res = atomic_write_file(CFS_PID_FN, strpid, strlen(strpid), 0644, getgid());
	g_free(strpid);

	return res;
}

static cfs_plug_t *find_plug(const char *path, char **sub)
{
	g_return_val_if_fail(root_plug != NULL, NULL);
	g_return_val_if_fail(path != NULL, NULL);

	while(*path == '/') path++;

	cfs_debug("find_plug start %s", path);

	char *tmppath = g_strdup(path);
	char *subpath = tmppath;

	cfs_plug_t *plug = root_plug->lookup_plug(root_plug, &subpath);

	cfs_debug("find_plug end %s = %p (%s)", path, (void *) plug, subpath);

	if (subpath && subpath[0])
		*sub = g_strdup(subpath);

	g_free(tmppath);

	return plug;
}

void *cfs_fuse_init(struct fuse_conn_info *conn)
{
	return NULL;
}

static int cfs_fuse_getattr(const char *path, struct stat *stbuf)
{
	cfs_debug("enter cfs_fuse_getattr %s", path);

	int ret = -EACCES;

	char *subpath = NULL;
	cfs_plug_t *plug = find_plug(path, &subpath);

	if (plug && plug->ops && plug->ops->getattr) {
		ret = plug->ops->getattr(plug, subpath ? subpath : "", stbuf);

		stbuf->st_gid = cfs.gid;

		if (path_is_private(path)) {
			stbuf->st_mode &= 0777700;
		} else {
			if (S_ISDIR(stbuf->st_mode) || S_ISLNK(stbuf->st_mode)) {
				stbuf->st_mode &= 0777755; // access for other users
			} else {
				if (path_is_lxc_conf(path)) {
					stbuf->st_mode &= 0777755; // access for other users
				} else {
					stbuf->st_mode &= 0777750; // no access for other users
				}
			}
		}
	}

	cfs_debug("leave cfs_fuse_getattr %s (%d)", path, ret);

	if (subpath)
		g_free(subpath);

	return ret;

}

static int cfs_fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			    off_t offset, struct fuse_file_info *fi)
{
	(void) offset;
	(void) fi;

	cfs_debug("enter cfs_fuse_readdir %s", path);

	int ret = -EACCES;

	char *subpath = NULL;
	cfs_plug_t *plug = find_plug(path, &subpath);

	if (!plug)
		goto ret;

	if (plug->ops && plug->ops->readdir)
		ret = plug->ops->readdir(plug, subpath ? subpath : "", buf, filler, 0, fi);
ret:
	cfs_debug("leave cfs_fuse_readdir %s (%d)", path, ret);

	if (subpath)
		g_free(subpath);

	return ret;
}

static int cfs_fuse_chmod(const char *path, mode_t mode)
{
	int ret = -EPERM;

	cfs_debug("enter cfs_fuse_chmod %s", path);

	mode_t allowed_mode = (S_IRUSR | S_IWUSR);
	if (!path_is_private(path))
		allowed_mode |= (S_IRGRP);

	// allow only setting our supported modes (0600 for priv, 0640 for rest)
	// mode has additional bits set, which we ignore; see stat(2)
	if ((mode & ALLPERMS) == allowed_mode)
		ret = 0;

	cfs_debug("leave cfs_fuse_chmod %s (%d) mode: %o", path, ret, (int)mode);

	return ret;
}

static int cfs_fuse_chown(const char *path, uid_t user, gid_t group)
{
	int ret = -EPERM;

	cfs_debug("enter cfs_fuse_chown %s", path);

	// we get -1 if no change should be made
	if ((user == 0 || user == -1) && (group == cfs.gid || group == -1))
		ret = 0;

	cfs_debug("leave cfs_fuse_chown %s (%d) (uid: %d; gid: %d)", path, ret, user, group);

	return ret;
}

static int cfs_fuse_mkdir(const char *path, mode_t mode)
{
	cfs_debug("enter cfs_fuse_mkdir %s", path);

	int ret = -EACCES;

	char *subpath = NULL;
	cfs_plug_t *plug = find_plug(path, &subpath);

	if (!plug)
		goto ret;

	if (subpath && plug->ops && plug->ops->mkdir)
		ret = plug->ops->mkdir(plug, subpath, mode);

 ret:
	cfs_debug("leave cfs_fuse_mkdir %s (%d)", path, ret);

	if (subpath)
		g_free(subpath);

	return ret;
}

static int cfs_fuse_rmdir(const char *path)
{
	cfs_debug("enter cfs_fuse_rmdir %s", path);

	int ret = -EACCES;

	char *subpath = NULL;
	cfs_plug_t *plug = find_plug(path, &subpath);

	if (!plug)
		goto ret;

	if (subpath && plug->ops && plug->ops->rmdir)
		ret = plug->ops->rmdir(plug, subpath);

 ret:
	cfs_debug("leave cfs_fuse_rmdir %s (%d)", path, ret);

	if (subpath)
		g_free(subpath);

	return ret;
}

static int cfs_fuse_rename(const char *from, const char *to)
{
	cfs_debug("enter cfs_fuse_rename from %s to %s", from, to);

	int ret = -EACCES;

	char *sub_from = NULL;
	cfs_plug_t *plug_from = find_plug(from, &sub_from);

	char *sub_to = NULL;
	cfs_plug_t *plug_to = find_plug(to, &sub_to);

	if (!plug_from || !plug_to || plug_from != plug_to)
		goto ret;

	if (plug_from->ops && plug_from->ops->rename && sub_from && sub_to)
		ret = plug_from->ops->rename(plug_from, sub_from, sub_to);

 ret:
	cfs_debug("leave cfs_fuse_rename from %s to %s (%d)", from, to, ret);

	if (sub_from)
		g_free(sub_from);

	if (sub_to)
		g_free(sub_to);

	return ret;
}

static int cfs_fuse_open(const char *path, struct fuse_file_info *fi)
{
	cfs_debug("enter cfs_fuse_open %s", path);

	fi->direct_io = 1;
	fi->keep_cache = 0;

	int ret = -EACCES;

	char *subpath = NULL;
	cfs_plug_t *plug = find_plug(path, &subpath);

	if (plug && plug->ops) {
		if ((subpath || !plug->ops->readdir) && plug->ops->open) {
			ret = plug->ops->open(plug, subpath ? subpath : "", fi);
		}
	}

	cfs_debug("leave cfs_fuse_open %s (%d)", path, ret);

	if (subpath)
		g_free(subpath);

	return ret;
}

static int cfs_fuse_read(const char *path, char *buf, size_t size, off_t offset,
			 struct fuse_file_info *fi)
{
	(void) fi;

	cfs_debug("enter cfs_fuse_read %s %zu %jd", path, size, offset);

	int ret = -EACCES;

	char *subpath = NULL;
	cfs_plug_t *plug = find_plug(path, &subpath);

	if (plug && plug->ops) {
		if ((subpath || !plug->ops->readdir) && plug->ops->read)
			ret = plug->ops->read(plug, subpath ? subpath : "", buf, size, offset, fi);
	}

	cfs_debug("leave cfs_fuse_read %s (%d)", path, ret);

	if (subpath)
		g_free(subpath);

	return ret;
}

static int cfs_fuse_write(const char *path, const char *buf, size_t size,
			  off_t offset, struct fuse_file_info *fi)
{
	(void) fi;

	cfs_debug("enter cfs_fuse_write %s %zu %jd", path, size, offset);

	int ret = -EACCES;

	char *subpath = NULL;
	cfs_plug_t *plug = find_plug(path, &subpath);

	if (plug && plug->ops) {
		if ((subpath || !plug->ops->readdir) && plug->ops->write)
		ret = plug->ops->write(plug, subpath ? subpath : "",
				       buf, size, offset, fi);
	}

	cfs_debug("leave cfs_fuse_write %s (%d)", path, ret);

	if (subpath)
		g_free(subpath);

	return ret;
}

static int cfs_fuse_truncate(const char *path, off_t size)
{
	cfs_debug("enter cfs_fuse_truncate %s %jd", path, size);

	int ret = -EACCES;

	char *subpath = NULL;
	cfs_plug_t *plug = find_plug(path, &subpath);

	if (plug && plug->ops) {
		if ((subpath || !plug->ops->readdir) && plug->ops->truncate)
			ret = plug->ops->truncate(plug, subpath ? subpath : "", size);
	}

	cfs_debug("leave cfs_fuse_truncate %s (%d)", path, ret);

	if (subpath)
		g_free(subpath);

	return ret;
}

static int cfs_fuse_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	cfs_debug("enter cfs_fuse_create %s", path);

	int ret = -EACCES;

	char *subpath = NULL;
	cfs_plug_t *plug = find_plug(path, &subpath);

	if (!plug)
		goto ret;

	if (subpath && plug->ops && plug->ops->create)
		ret = plug->ops->create(plug, subpath, mode, fi);

ret:
	cfs_debug("leave cfs_fuse_create %s (%d)", path, ret);

	if (subpath)
		g_free(subpath);

	return ret;
}

static int cfs_fuse_unlink(const char *path)
{
	cfs_debug("enter cfs_fuse_unlink %s", path);

	int ret = -EACCES;

	char *subpath = NULL;
	cfs_plug_t *plug = find_plug(path, &subpath);

	if (!plug)
		goto ret;

	if (subpath && plug->ops && plug->ops->unlink)
		ret = plug->ops->unlink(plug, subpath);

ret:
	cfs_debug("leave cfs_fuse_unlink %s (%d)", path, ret);

	if (subpath)
		g_free(subpath);

	return ret;
}

static int cfs_fuse_readlink(const char *path, char *buf, size_t max)
{
	cfs_debug("enter cfs_fuse_readlink %s", path);

	int ret = -EACCES;

	char *subpath = NULL;
	cfs_plug_t *plug = find_plug(path, &subpath);

	if (!plug)
		goto ret;

	if (plug->ops && plug->ops->readlink)
		ret = plug->ops->readlink(plug, subpath ? subpath : "", buf, max);

ret:
	cfs_debug("leave cfs_fuse_readlink %s (%d)", path, ret);

	if (subpath)
		g_free(subpath);

	return ret;
}

static int cfs_fuse_utimens(const char *path, const struct timespec tv[2])
{
	cfs_debug("enter cfs_fuse_utimens %s", path);

	int ret = -EACCES;

	char *subpath = NULL;
	cfs_plug_t *plug = find_plug(path, &subpath);

	if (!plug)
		goto ret;

	if (plug->ops && plug->ops->utimens)
		ret = plug->ops->utimens(plug, subpath ? subpath : "", tv);

ret:
	cfs_debug("leave cfs_fuse_utimens %s (%d)", path, ret);

	if (subpath)
		g_free(subpath);

	return ret;
}

static int cfs_fuse_statfs(const char *path, struct statvfs *stbuf)
{
	g_return_val_if_fail(root_plug != NULL, PARAM_CHECK_ERRNO);

	cfs_debug("enter cfs_fuse_statfs %s", path);

	int ret = -EACCES;

	if (root_plug && root_plug->ops && root_plug->ops->statfs)
		ret = root_plug->ops->statfs(root_plug, "", stbuf);

	return ret;
}

static struct fuse_operations fuse_ops = {
	.getattr = cfs_fuse_getattr,
	.readdir = cfs_fuse_readdir,
	.mkdir = cfs_fuse_mkdir,
	.rmdir = cfs_fuse_rmdir,
	.rename = cfs_fuse_rename,
	.open = cfs_fuse_open,
	.read = cfs_fuse_read,
	.write = cfs_fuse_write,
	.truncate = cfs_fuse_truncate,
	.create = cfs_fuse_create,
	.unlink = cfs_fuse_unlink,
	.readlink = cfs_fuse_readlink,
	.utimens = cfs_fuse_utimens,
	.statfs = cfs_fuse_statfs,
	.init = cfs_fuse_init,
	.chown = cfs_fuse_chown,
	.chmod = cfs_fuse_chmod
};

static char *
create_dot_version_cb(cfs_plug_t *plug)
{
	GString *outbuf = g_string_new(NULL);
	char *data = NULL;

	if (cfs_create_version_msg(outbuf) == 0) {
		data = outbuf->str;
		g_string_free(outbuf, FALSE);
	} else {
		g_string_free(outbuf, TRUE);
	}

	return data;
}

static char *
create_dot_members_cb(cfs_plug_t *plug)
{
	GString *outbuf = g_string_new(NULL);
	char *data = NULL;

	if (cfs_create_memberlist_msg(outbuf) == 0) {
		data = outbuf->str;
		g_string_free(outbuf, FALSE);
	} else {
		g_string_free(outbuf, TRUE);
	}

	return data;
}

static char *
create_dot_vmlist_cb(cfs_plug_t *plug)
{
	GString *outbuf = g_string_new(NULL);
	char *data = NULL;

	if (cfs_create_vmlist_msg(outbuf) == 0) {
		data = outbuf->str;
		g_string_free(outbuf, FALSE);
	} else {
		g_string_free(outbuf, TRUE);
	}

	return data;
}

static char *
create_dot_rrd_cb(cfs_plug_t *plug)
{
	GString *outbuf = g_string_new(NULL);

	cfs_rrd_dump(outbuf);
	char *data = outbuf->str;
	g_string_free(outbuf, FALSE);

	return data;
}

static char *
create_dot_clusterlog_cb(cfs_plug_t *plug)
{
	GString *outbuf = g_string_new(NULL);

	cfs_cluster_log_dump(outbuf, NULL, 50);
	char *data = outbuf->str;
	g_string_free(outbuf, FALSE);

	return data;
}

static char *
read_debug_setting_cb(cfs_plug_t *plug)
{
	return g_strdup_printf("%d\n", !!cfs.debug);
}

static void
my_qb_log_filter(struct qb_log_callsite *cs)
{
	int32_t priority = cfs.debug ? LOG_DEBUG : LOG_INFO;

	if (qb_bit_is_set(cs->tags, QB_LOG_TAG_LIBQB_MSG_BIT)) {
		if (cs->priority <= (cfs.debug ? priority : LOG_WARNING)) {
			qb_bit_set(cs->targets, QB_LOG_SYSLOG);
		} else {
			qb_bit_clear(cs->targets, QB_LOG_SYSLOG);
		}
		if (cs->priority <= priority) {
			qb_bit_set(cs->targets, QB_LOG_STDERR);
		} else {
			qb_bit_clear(cs->targets, QB_LOG_STDERR);
		}
	} else {
		if (cs->priority <= priority) {
			qb_bit_set(cs->targets, QB_LOG_SYSLOG);
			qb_bit_set(cs->targets, QB_LOG_STDERR);
		} else {
			qb_bit_clear(cs->targets, QB_LOG_SYSLOG);
			qb_bit_clear(cs->targets, QB_LOG_STDERR);
		}
	}
}

static void
update_qb_log_settings(void)
{
	qb_log_filter_fn_set(my_qb_log_filter);

	if (cfs.debug) {
		qb_log_format_set(QB_LOG_SYSLOG, "[%g] %p: %b (%f:%l:%n)");
		qb_log_format_set(QB_LOG_STDERR, "[%g] %p: %b (%f:%l:%n)");
	} else {
		qb_log_format_set(QB_LOG_SYSLOG, "[%g] %p: %b");
		qb_log_format_set(QB_LOG_STDERR, "[%g] %p: %b");
	}
}

static int
write_debug_setting_cb(
	cfs_plug_t *plug,
	const char *buf,
	size_t size)
{
	int res = -EIO;

	if (size < 2)
		return res;

	if (strncmp(buf, "0\n", 2) == 0) {
		if (cfs.debug) {
			cfs_message("disable debug mode");
			cfs.debug = 0;
			update_qb_log_settings();
		}
		return 2;
	} else if (strncmp(buf, "1\n", 2) == 0) {
		if (!cfs.debug) {
			cfs.debug = 1;
			update_qb_log_settings();
			cfs_message("enable debug mode");
		}
		return 2;
	}

	return res;
}

static void
create_symlinks(cfs_plug_base_t *bplug, const char *nodename)
{
	g_return_if_fail(bplug != NULL);
	g_return_if_fail(nodename != NULL);

	char *lnktarget = g_strdup_printf("nodes/%s", nodename);
	cfs_plug_link_t *lnk = cfs_plug_link_new("local", lnktarget);
	g_free(lnktarget);
	cfs_plug_base_insert(bplug, (cfs_plug_t*)lnk);

	lnktarget = g_strdup_printf("nodes/%s/qemu-server", nodename);
	lnk = cfs_plug_link_new("qemu-server", lnktarget);
	g_free(lnktarget);
	cfs_plug_base_insert(bplug, (cfs_plug_t*)lnk);

	lnktarget = g_strdup_printf("nodes/%s/openvz", nodename);
	lnk = cfs_plug_link_new("openvz", lnktarget);
	g_free(lnktarget);
	cfs_plug_base_insert(bplug, (cfs_plug_t*)lnk);

	lnktarget = g_strdup_printf("nodes/%s/lxc", nodename);
	lnk = cfs_plug_link_new("lxc", lnktarget);
	g_free(lnktarget);
	cfs_plug_base_insert(bplug, (cfs_plug_t*)lnk);

	cfs_plug_func_t *fplug = cfs_plug_func_new(".version", 0440, create_dot_version_cb, NULL);
	cfs_plug_base_insert(bplug, (cfs_plug_t*)fplug);

	fplug = cfs_plug_func_new(".members", 0440, create_dot_members_cb, NULL);
	cfs_plug_base_insert(bplug, (cfs_plug_t*)fplug);

	fplug = cfs_plug_func_new(".vmlist", 0440, create_dot_vmlist_cb, NULL);
	cfs_plug_base_insert(bplug, (cfs_plug_t*)fplug);

	fplug = cfs_plug_func_new(".rrd", 0440, create_dot_rrd_cb, NULL);
	cfs_plug_base_insert(bplug, (cfs_plug_t*)fplug);

	fplug = cfs_plug_func_new(".clusterlog", 0440, create_dot_clusterlog_cb, NULL);
	cfs_plug_base_insert(bplug, (cfs_plug_t*)fplug);

	fplug = cfs_plug_func_new(".debug", 0640, read_debug_setting_cb, write_debug_setting_cb);
	cfs_plug_base_insert(bplug, (cfs_plug_t*)fplug);


}

static char *
lookup_node_ip(const char *nodename)
{
	char buf[INET6_ADDRSTRLEN];
	struct addrinfo *ainfo;
	struct addrinfo ahints;
	char *res = NULL;
	memset(&ahints, 0, sizeof(ahints));

	if (getaddrinfo(nodename, NULL, &ahints, &ainfo))
		return NULL;

	if (ainfo->ai_family == AF_INET) {
		struct sockaddr_in *sa = (struct sockaddr_in *)ainfo->ai_addr;
		inet_ntop(ainfo->ai_family, &sa->sin_addr, buf, sizeof(buf));
		if (strncmp(buf, "127.", 4) != 0) {
			res = g_strdup(buf);
		}
	} else if (ainfo->ai_family == AF_INET6) {
		struct sockaddr_in6 *sa = (struct sockaddr_in6 *)ainfo->ai_addr;
		inet_ntop(ainfo->ai_family, &sa->sin6_addr, buf, sizeof(buf));
		if (strcmp(buf, "::1") != 0) {
			res = g_strdup(buf);
		}
	}

	freeaddrinfo(ainfo);

	return res;
}

static const char*
log_tags_stringify(uint32_t tags) {
	if (qb_bit_is_set(tags, QB_LOG_TAG_LIBQB_MSG_BIT)) {
		return "libqb";
	} else {
		GQuark quark = tags;
		const char *domain = g_quark_to_string(quark);
		if (domain != NULL) {
			return domain;
		} else {
			return "main";
		}
 	}
}

int main(int argc, char *argv[])
{
	int ret = -1;
	int lockfd = -1;
	int pipefd[2];

	gboolean foreground = FALSE;
	gboolean force_local_mode = FALSE;
	gboolean wrote_pidfile = FALSE;
	memdb_t *memdb = NULL;
	dfsm_t *dcdb = NULL;
	dfsm_t *status_fsm = NULL;

	qb_log_init("pmxcfs", LOG_DAEMON, LOG_DEBUG);
	/* remove default filter */
	qb_log_filter_ctl(QB_LOG_SYSLOG, QB_LOG_FILTER_REMOVE,
			  QB_LOG_FILTER_FILE, "*", LOG_DEBUG);

 	qb_log_tags_stringify_fn_set(log_tags_stringify);

	qb_log_ctl(QB_LOG_STDERR, QB_LOG_CONF_ENABLED, QB_TRUE);

	update_qb_log_settings();

	g_set_print_handler(glib_print_handler);
	g_set_printerr_handler(glib_print_handler);
	g_log_set_default_handler(glib_log_handler, NULL);

	GOptionContext *context;

	GOptionEntry entries[] = {
		{ "debug", 'd', 0, G_OPTION_ARG_NONE, &cfs.debug, "Turn on debug messages", NULL },
		{ "foreground", 'f', 0, G_OPTION_ARG_NONE, &foreground, "Do not daemonize server", NULL },
		{ "local", 'l', 0, G_OPTION_ARG_NONE, &force_local_mode,
		  "Force local mode (ignore corosync.conf, force quorum)", NULL },
		{ NULL },
	};

	context = g_option_context_new ("");
	g_option_context_add_main_entries (context, entries, NULL);

	GError *err = NULL;
	if (!g_option_context_parse (context, &argc, &argv, &err))
	{
		cfs_critical("option parsing failed: %s", err->message);
		g_error_free (err);
		qb_log_fini();
		exit (1);
	}
	g_option_context_free(context);

	if (optind < argc) {
		cfs_critical("too many arguments");
		qb_log_fini();
		exit(-1);
	}

	if (cfs.debug) {
		update_qb_log_settings();
	}

	struct utsname utsname;
	if (uname(&utsname) != 0) {
		cfs_critical("Unable to read local node name");
		qb_log_fini();
		exit (-1);
	}

	char *dot = strchr(utsname.nodename, '.');
	if (dot)
		*dot = 0;

	cfs.nodename = g_strdup(utsname.nodename);

	if (!(cfs.ip = lookup_node_ip(cfs.nodename))) {
		cfs_critical("Unable to get local IP address");
		qb_log_fini();
		exit(-1);
	}

	struct group *www_data = getgrnam("www-data");
	if (!www_data) {
		cfs_critical("Unable to get www-data group ID");
		qb_log_fini();
		exit (-1);
	}
	cfs.gid = www_data->gr_gid;

	umask(027);

	mkdir(VARLIBDIR, 0755);
	mkdir(RUNDIR, 0755);

	if ((lockfd = open(LOCKFILE, O_RDWR|O_CREAT|O_APPEND, 0600)) == -1) {
		cfs_critical("unable to create lock '%s': %s", LOCKFILE, strerror (errno));
		goto err;
	}

	for (int i = 10; i >= 0; i--) {
		if (flock(lockfd, LOCK_EX|LOCK_NB) != 0) {
			if (!i) {
				cfs_critical("unable to acquire pmxcfs lock: %s", strerror (errno));
				goto err;
			}
			if (i == 10)
				cfs_message("unable to acquire pmxcfs lock - trying again");

			sleep(1);
		}
	}

	cfs_status_init();

	gboolean create = !g_file_test(DBFILENAME, G_FILE_TEST_EXISTS);

	if (!(memdb = memdb_open (DBFILENAME))) {
		cfs_critical("memdb_open failed - unable to open database '%s'", DBFILENAME);
		goto err;
	}

	// automatically import corosync.conf from host
	if (create && !force_local_mode) {
		char *cdata = NULL;
		gsize clen = 0;
		if (g_file_get_contents(HOST_CLUSTER_CONF_FN, &cdata, &clen, NULL)) {

			guint32 mtime = time(NULL);

			memdb_create(memdb, "/corosync.conf", 0, mtime);
			if (memdb_write(memdb, "/corosync.conf", 0, mtime, cdata, clen, 0, 1) < 0) {
				cfs_critical("memdb_write failed - unable to import corosync.conf");
				goto err;
			}
		}
	}

	// does corosync.conf exist?
	gpointer conf_data = NULL;
	int len = memdb_read(memdb, "corosync.conf", &conf_data);
	if (len >= 0) {
		if (force_local_mode) {
			cfs_message("forcing local mode (although corosync.conf exists)");
			cfs_set_quorate(1, TRUE);
		} else {
			if (!(dcdb = dcdb_new(memdb)))
				goto err;
			dcdb_sync_corosync_conf(memdb, 1);
		}
	} else {
		cfs_debug("using local mode (corosync.conf does not exist)");
		cfs_set_quorate(1, TRUE);
	}
	if (conf_data) g_free(conf_data);

	cfs_plug_memdb_t *config = cfs_plug_memdb_new("memdb", memdb, dcdb);

	cfs_plug_base_t *bplug = cfs_plug_base_new("", (cfs_plug_t *)config);

	create_symlinks(bplug, cfs.nodename);

	root_plug = (cfs_plug_t *)bplug;

	umount2(CFSDIR, MNT_FORCE);

	mkdir(CFSDIR, 0755);

	char *fa[] = { "-f", "-odefault_permissions", "-oallow_other", NULL};

	struct fuse_args fuse_args = FUSE_ARGS_INIT(sizeof (fa)/sizeof(gpointer) - 1, fa);

	struct fuse_chan *fuse_chan = fuse_mount(CFSDIR, &fuse_args);
	if (!fuse_chan) {
		cfs_critical("fuse_mount error: %s", strerror(errno));
		goto err;
	}

	if (!(fuse = fuse_new(fuse_chan, &fuse_args, &fuse_ops, sizeof(fuse_ops), NULL))) {
		cfs_critical("fuse_new error: %s", strerror(errno));
		goto err;
	}

	fuse_set_signal_handlers(fuse_get_session(fuse));

	if (!foreground) {
		if (pipe(pipefd) == -1) {
			cfs_critical("pipe error: %s", strerror(errno));
			goto err;
		}

		pid_t cpid = fork();

		if (cpid == -1) {
			cfs_critical("failed to daemonize program - %s", strerror (errno));
			goto err;
		} else if (cpid) {
			int readbytes, errno_tmp;
			char readbuffer;
			close(pipefd[1]);
			readbytes = read(pipefd[0], &readbuffer, sizeof(readbuffer));
			errno_tmp = errno;
			close(pipefd[0]);
			if (readbytes == -1) {
				cfs_critical("read error: %s", strerror(errno_tmp));
				kill(cpid, SIGKILL);
				goto err;
			} else if (readbytes != 1 || readbuffer != '1') {
				cfs_critical("child failed to send '1'");
				kill(cpid, SIGKILL);
				goto err;
			}
			/* child finished starting up */
			write_pidfile(cpid);
			qb_log_fini();
			_exit (0);
		} else {
			int nullfd;
			close(pipefd[0]);

			chroot("/");

			if ((nullfd = open("/dev/null", O_RDWR, 0)) != -1) {
				dup2(nullfd, 0);
				dup2(nullfd, 1);
				dup2(nullfd, 2);
				if (nullfd > 2)
					close (nullfd);
			}

			// do not print to the console after this point
			qb_log_ctl(QB_LOG_STDERR, QB_LOG_CONF_ENABLED, QB_FALSE);

			setsid();
		}
	} else {
		write_pidfile(getpid());
	}

	wrote_pidfile = TRUE;

	cfs_loop_t *corosync_loop = cfs_loop_new(fuse);

	cfs_service_t *service_quorum = NULL;
	cfs_service_t *service_confdb = NULL;
	cfs_service_t *service_dcdb = NULL;
	cfs_service_t *service_status = NULL;

	if (dcdb) {

		service_quorum = service_quorum_new();

		cfs_loop_add_service(corosync_loop, service_quorum, QB_LOOP_HIGH);

		service_confdb = service_confdb_new();

		cfs_loop_add_service(corosync_loop, service_confdb, QB_LOOP_MED);

		service_dcdb = service_dfsm_new(dcdb);
		cfs_service_set_timer(service_dcdb, DCDB_VERIFY_TIME);

		cfs_loop_add_service(corosync_loop, service_dcdb, QB_LOOP_MED);

		status_fsm = cfs_status_dfsm_new();
		service_status = service_dfsm_new(status_fsm);

		cfs_loop_add_service(corosync_loop, service_status, QB_LOOP_LOW);

	}

	cfs_loop_start_worker(corosync_loop);

	server_start(memdb);

	unlink(RESTART_FLAG_FILE);

	if (!foreground) {
		/* finished starting up, signaling parent */
		write(pipefd[1], "1", 1);
		close(pipefd[1]);
	}

	ret = fuse_loop_mt(fuse);

	open(RESTART_FLAG_FILE, O_CREAT|O_NOCTTY|O_NONBLOCK);

	cfs_message("teardown filesystem");

	server_stop();

	fuse_unmount(CFSDIR, fuse_chan);

	fuse_destroy(fuse);

	cfs_debug("set stop event loop flag");

	cfs_loop_stop_worker(corosync_loop);

	cfs_loop_destroy(corosync_loop);

	cfs_debug("worker finished");

	if (service_dcdb)
		service_dfsm_destroy(service_dcdb);

	if (service_confdb)
		service_confdb_destroy(service_confdb);

	if (service_quorum)
		service_quorum_destroy(service_quorum);

	if (service_status)
		service_dfsm_destroy(service_status);

 ret:

	if (status_fsm)
		dfsm_destroy(status_fsm);

	if (dcdb)
		dfsm_destroy(dcdb);

	if (memdb)
		memdb_close(memdb);

	if (wrote_pidfile)
		unlink(CFS_PID_FN);

	cfs_message("exit proxmox configuration filesystem (%d)", ret);

	cfs_status_cleanup();

	qb_log_fini();

	exit(ret);

 err:
	goto ret;
}
