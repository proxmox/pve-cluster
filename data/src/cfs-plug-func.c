/*
  Copyright (C) 2011 Proxmox Server Solutions GmbH

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
#include <sys/file.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>

#include "cfs-utils.h"
#include "cfs-plug.h"

static struct cfs_operations cfs_ops;

static cfs_plug_t *cfs_plug_func_lookup_plug(cfs_plug_t *plug, char **path)
{
	g_return_val_if_fail(plug != NULL, NULL);
	g_return_val_if_fail(plug->ops == &cfs_ops, NULL);

	return (!*path || !(*path)[0]) ? plug : NULL;
}

static void cfs_plug_func_destroy(cfs_plug_t *plug)
{
	g_return_if_fail(plug != NULL);
	g_return_if_fail(plug->ops == &cfs_ops);

	cfs_plug_func_t *fplug = (cfs_plug_func_t *)plug;

	cfs_debug("enter cfs_plug_func_destroy %s", plug->name);

	if (fplug->data)
		g_free(fplug->data);

	g_free(plug->name);

	g_free(plug);
}

static int 
cfs_plug_func_getattr(
	cfs_plug_t *plug, 
	const char *path, 
	struct stat *stbuf)
{
	g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(stbuf != NULL, PARAM_CHECK_ERRNO);

	cfs_debug("enter cfs_plug_func_getattr %s", path);

	cfs_plug_func_t *fplug = (cfs_plug_func_t *)plug;

	memset(stbuf, 0, sizeof(struct stat));

	g_rw_lock_writer_lock(&fplug->data_rw_lock);
	if (fplug->data)
		g_free(fplug->data);

	fplug->data = fplug->update_callback(plug);

	stbuf->st_size = fplug->data ? strlen(fplug->data) : 0;

	g_rw_lock_writer_unlock(&fplug->data_rw_lock);

	stbuf->st_mode = fplug->mode;
	stbuf->st_nlink = 1;

	return 0;
}

static int 
cfs_plug_func_read(
	cfs_plug_t *plug, 
	const char *path, 
	char *buf, 
	size_t size, 
	off_t offset,
	struct fuse_file_info *fi)
{
	(void) fi;

	g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(buf != NULL, PARAM_CHECK_ERRNO);

	cfs_plug_func_t *fplug = (cfs_plug_func_t *)plug;

	g_rw_lock_reader_lock(&fplug->data_rw_lock);
	char *data = fplug->data;

	cfs_debug("enter cfs_plug_func_read %s", data);

	if (!data) {
		g_rw_lock_reader_unlock(&fplug->data_rw_lock);
		return 0;
	}

	int len = strlen(data);

	if (offset < len) {
		if (offset + size > len)
			size = len - offset;
		memcpy(buf, data + offset, size);
	} else {
		size = 0;
	}
	g_rw_lock_reader_unlock(&fplug->data_rw_lock);

	return size;
}

static int 
cfs_plug_func_write(
	cfs_plug_t *plug, 
	const char *path, 
	const char *buf, 
	size_t size,
	off_t offset, 
	struct fuse_file_info *fi)
{
	(void) fi;

	g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(buf != NULL, PARAM_CHECK_ERRNO);

	cfs_debug("enter cfs_plug_func_write");

	cfs_plug_func_t *fplug = (cfs_plug_func_t *)plug;

	if (offset != 0 || !fplug->write_callback)
		return -EIO;

	return fplug->write_callback(plug, buf, size);
}

static int 
cfs_plug_func_truncate(
	cfs_plug_t *plug, 
	const char *path, 
	off_t size)
{
	g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);

	cfs_plug_func_t *fplug = (cfs_plug_func_t *)plug;

	if (fplug->write_callback)
		return 0;

	return -EIO;
}

static int 
cfs_plug_func_open(
	cfs_plug_t *plug, 
	const char *path, 
	struct fuse_file_info *fi)
{
	g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(fi != NULL, PARAM_CHECK_ERRNO);

	cfs_debug("enter cfs_plug_func_open %s", path);

	return 0;
}

static struct cfs_operations cfs_ops = {
	.getattr = cfs_plug_func_getattr,
	.read = cfs_plug_func_read,
	.write = cfs_plug_func_write,
	.truncate = cfs_plug_func_truncate,
	.open = cfs_plug_func_open,
};


cfs_plug_func_t *
cfs_plug_func_new(
	const char *name, 
	mode_t mode,
	cfs_plug_func_udpate_data_fn_t update_callback,
	cfs_plug_func_write_data_fn_t write_callback)
{
	g_return_val_if_fail(name != NULL, NULL);
	g_return_val_if_fail(update_callback != NULL, NULL);

	cfs_plug_func_t *fplug = g_new0(cfs_plug_func_t, 1);

	fplug->plug.ops = &cfs_ops;

	fplug->plug.lookup_plug = cfs_plug_func_lookup_plug;
	fplug->plug.destroy_plug = cfs_plug_func_destroy;

	fplug->plug.name = g_strdup(name);

	fplug->update_callback = update_callback;
	fplug->write_callback = write_callback;
	if (!write_callback)
		mode = mode & ~0222;

	fplug->mode = S_IFREG | mode;

	return fplug;
}

