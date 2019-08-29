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
#include <sys/file.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <arpa/inet.h>

#include "cfs-utils.h"
#include "cfs-plug-memdb.h"
#include "dcdb.h"
#include "status.h"

static struct cfs_operations cfs_ops;

static gboolean 
name_is_openvz_script(
	const char *name, 
	guint32 *vmid_ret)
{
	if (!name)
		return FALSE;

	guint32 vmid = 0;
	char *end = NULL;

	if (name[0] == 'v' && name[1] == 'p' && name[2] == 's') {
		end = (char *)name + 3;
	} else {
		if (name[0] < '1' || name[0] > '9')
			return FALSE;

		vmid = strtoul(name, &end, 10);
	}

	if (!end || end[0] != '.')
		return FALSE;

	end++;

	gboolean res = FALSE;

	if (end[0] == 'm' && strcmp(end, "mount") == 0)
		res = TRUE;

	if (end[0] == 'u' && strcmp(end, "umount") == 0)
		res = TRUE;

	if (end[0] == 's' && 
	    (strcmp(end, "start") == 0 || strcmp(end, "stop") == 0))
		res = TRUE;

	if (end[0] == 'p' && 
	    (strcmp(end, "premount") == 0 || strcmp(end, "postumount") == 0))
		res = TRUE;


	if (res && vmid_ret)
		*vmid_ret = vmid;

	return res;
}

static void tree_entry_stat(memdb_tree_entry_t *te, struct stat *stbuf, gboolean quorate)
{
	g_return_if_fail(te != NULL);
	g_return_if_fail(stbuf != NULL);

	if (te->type == DT_DIR) {
		stbuf->st_mode = S_IFDIR | (quorate ? 0777 : 0555);
		stbuf->st_nlink = 2;
	} else {
		stbuf->st_mode = S_IFREG | (quorate ? 0666 : 0444);
		stbuf->st_nlink = 1;
		if (name_is_openvz_script(te->name, NULL)) {
			stbuf->st_mode |= S_IXUSR;
		}
	} 
		
	stbuf->st_size = te->size;
	stbuf->st_blocks = 
		(stbuf->st_size + MEMDB_BLOCKSIZE -1)/MEMDB_BLOCKSIZE;
	stbuf->st_atime = te->mtime;
	stbuf->st_mtime = te->mtime;
	stbuf->st_ctime = te->mtime;
}

static int cfs_plug_memdb_getattr(cfs_plug_t *plug, const char *path, struct stat *stbuf)
{
	g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(stbuf != NULL, PARAM_CHECK_ERRNO);

	memset(stbuf, 0, sizeof(struct stat));

	cfs_plug_memdb_t *mdb = (cfs_plug_memdb_t *)plug;

	memdb_tree_entry_t *te = memdb_getattr(mdb->memdb, path);

	if (te) {
		tree_entry_stat(te, stbuf, cfs_is_quorate());
		memdb_tree_entry_free(te);
		return 0;
	}

	return  -ENOENT;
}

static int cfs_plug_memdb_readdir(
	cfs_plug_t *plug, 
	const char *path, 
	void *buf, 
	fuse_fill_dir_t filler, 
	off_t offset, 
	struct fuse_file_info *fi)
{
	(void) offset;
	(void) fi;

	g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(buf != NULL, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(filler != NULL, PARAM_CHECK_ERRNO);

	cfs_plug_memdb_t *mdb = (cfs_plug_memdb_t *)plug;

	GList *dirlist = memdb_readdir(mdb->memdb, path);

	if (dirlist) {

		filler(buf, ".", NULL, 0);
		filler(buf, "..", NULL, 0);

		struct stat stbuf;
		memset(&stbuf, 0, sizeof(struct stat));
	     
		GList *l = dirlist;
		while (l) {
			memdb_tree_entry_t *te = (memdb_tree_entry_t *)l->data;

			tree_entry_stat(te, &stbuf, 0);
			filler(buf, te->name, &stbuf, 0);
			l = g_list_next(l);
		}

		memdb_dirlist_free(dirlist);
	}

	return 0;
}

static int cfs_plug_memdb_open(cfs_plug_t *plug, const char *path, struct fuse_file_info *fi)
{
	g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(fi != NULL, PARAM_CHECK_ERRNO);

	memdb_tree_entry_t *te;

	cfs_plug_memdb_t *mdb = (cfs_plug_memdb_t *)plug;

	if ((te = memdb_getattr(mdb->memdb, path))) {
		memdb_tree_entry_free(te);
	} else 
		return -ENOENT;

	return 0;
}

static int cfs_plug_memdb_read(
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

	int len;
	gpointer data = NULL;

	cfs_plug_memdb_t *mdb = (cfs_plug_memdb_t *)plug;

	len = memdb_read(mdb->memdb, path, &data);
	if (len < 0)
		return len;

	if (offset < len) {
		if (offset + size > len)
			size = len - offset;
		memcpy(buf, (uint8_t *) data + offset, size);
	} else {
		size = 0;
	}

	if (data)
		g_free(data);

	return size;
}

static int cfs_plug_memdb_write(
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

	int res;

	cfs_plug_memdb_t *mdb = (cfs_plug_memdb_t *)plug;

	if (mdb->dfsm) {
		res = dcdb_send_fuse_message(mdb->dfsm, DCDB_MESSAGE_CFS_WRITE, path, NULL, buf,
					     size, offset, 0);
	} else {
		uint32_t ctime = time(NULL);
		res = memdb_write(mdb->memdb, path, 0, ctime, buf, size, offset, 0);
	}

	return res;
}

static int cfs_plug_memdb_truncate(cfs_plug_t *plug, const char *path, off_t size)
{
	g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);

	int res;

	cfs_plug_memdb_t *mdb = (cfs_plug_memdb_t *)plug;

	if (mdb->dfsm) {
		res = dcdb_send_fuse_message(mdb->dfsm, DCDB_MESSAGE_CFS_WRITE, path, NULL, NULL,
					     0, size, 1);
	} else {
		uint32_t ctime = time(NULL);
		res = memdb_write(mdb->memdb, path, 0, ctime, NULL, 0, size, 1);
	}

	return res;
}

static int cfs_plug_memdb_create (
	cfs_plug_t *plug, 
	const char *path, 
	mode_t mode, 
	struct fuse_file_info *fi)
{
	g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(fi != NULL, PARAM_CHECK_ERRNO);

	int res;

	cfs_plug_memdb_t *mdb = (cfs_plug_memdb_t *)plug;

	if (mdb->dfsm) {
		res = dcdb_send_fuse_message(mdb->dfsm, DCDB_MESSAGE_CFS_CREATE, path, 
					     NULL, NULL, 0, 0, 0);
	} else {
		uint32_t ctime = time(NULL);

		res = memdb_create(mdb->memdb, path, 0, ctime);
	}

	return res;
}

static int cfs_plug_memdb_mkdir(cfs_plug_t *plug, const char *path, mode_t mode)
{
	g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);

	int res;

	cfs_plug_memdb_t *mdb = (cfs_plug_memdb_t *)plug;

	if (mdb->dfsm) {
		res = dcdb_send_fuse_message(mdb->dfsm, DCDB_MESSAGE_CFS_MKDIR, path, 
					     NULL, NULL, 0, 0, 0);
	} else {
		uint32_t ctime = time(NULL);
		res = memdb_mkdir(mdb->memdb, path, 0, ctime);
	}

	return res;
}

static int cfs_plug_memdb_rmdir(cfs_plug_t *plug, const char *path)
{
	g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);

	int res;

	cfs_plug_memdb_t *mdb = (cfs_plug_memdb_t *)plug;

	if (mdb->dfsm) {
		res = dcdb_send_fuse_message(mdb->dfsm, DCDB_MESSAGE_CFS_DELETE, path, 
					     NULL, NULL, 0, 0, 0);
	} else {
		uint32_t ctime = time(NULL);
		res = memdb_delete(mdb->memdb, path, 0, ctime);
	}

	return res;
}

static int cfs_plug_memdb_rename(cfs_plug_t *plug, const char *from, const char *to)
{
	g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(from != NULL, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(to != NULL, PARAM_CHECK_ERRNO);

	int res;

	cfs_plug_memdb_t *mdb = (cfs_plug_memdb_t *)plug;

	if (mdb->dfsm) {
		res = dcdb_send_fuse_message(mdb->dfsm, DCDB_MESSAGE_CFS_RENAME, from, to, 
					     NULL, 0, 0, 0);
	} else {
		uint32_t ctime = time(NULL);
		res = memdb_rename(mdb->memdb, from, to, 0, ctime);
	}

	return res;
}

static int cfs_plug_memdb_unlink(cfs_plug_t *plug, const char *path)
{
	g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);

	int res;

	cfs_plug_memdb_t *mdb = (cfs_plug_memdb_t *)plug;

	if (mdb->dfsm) {
		res = dcdb_send_fuse_message(mdb->dfsm, DCDB_MESSAGE_CFS_DELETE, path, 
					     NULL, NULL, 0, 0, 0);
	} else {
		uint32_t ctime = time(NULL);
		res = memdb_delete(mdb->memdb, path, 0, ctime);
	}

	return res;
}

static int cfs_plug_memdb_utimens(
	cfs_plug_t *plug, 
	const char *path, 
	const struct timespec tv[2])
{
	g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(tv != NULL, PARAM_CHECK_ERRNO);

	int res;

	cfs_plug_memdb_t *mdb = (cfs_plug_memdb_t *)plug;

	res = -EIO;

	memdb_tree_entry_t *te = memdb_getattr(mdb->memdb, path);
	uint32_t mtime = tv[1].tv_sec;

	gboolean unlock_req = FALSE;
	guchar csum[32];

	if (te && mtime == 0 && te->type == DT_DIR &&
	    path_is_lockdir(path)) {
		unlock_req = TRUE;
	}

	if (mdb->dfsm) {
		if (unlock_req && memdb_tree_entry_csum(te, csum))
			dcdb_send_unlock(mdb->dfsm, path, csum, TRUE);
	    
		res = dcdb_send_fuse_message(mdb->dfsm, DCDB_MESSAGE_CFS_MTIME, path, 
					     NULL, NULL, 0, mtime, 0);
	} else {
		uint32_t ctime = time(NULL);
		if (unlock_req && memdb_tree_entry_csum(te, csum) &&
		    memdb_lock_expired(mdb->memdb, path, csum)) {
			res = memdb_delete(mdb->memdb, path, 0, ctime);
		} else {
			res = memdb_mtime(mdb->memdb, path, 0, mtime);
		}
	}

	memdb_tree_entry_free(te);

	return res;
}

static int cfs_plug_memdb_statfs(cfs_plug_t *plug, const char *path, struct statvfs *stbuf)
{
	g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);
	g_return_val_if_fail(stbuf != NULL, PARAM_CHECK_ERRNO);

	cfs_plug_memdb_t *mdb = (cfs_plug_memdb_t *)plug;

	return memdb_statfs(mdb->memdb, stbuf);
}

static void cfs_plug_memdb_destroy(cfs_plug_t *plug)
{
	g_return_if_fail(plug != NULL);
	g_return_if_fail(plug->ops == &cfs_ops);
	
	g_free(plug->name);

	g_free(plug);
}

static cfs_plug_t *cfs_plug_memdb_lookup_plug(cfs_plug_t *plug, char **path)
{
	g_return_val_if_fail(plug != NULL, NULL);
	g_return_val_if_fail(plug->ops == &cfs_ops, NULL);

	return plug;
}

static struct cfs_operations cfs_ops = {
	.getattr = cfs_plug_memdb_getattr,
	.readdir = cfs_plug_memdb_readdir,
	.open = cfs_plug_memdb_open,
	.create = cfs_plug_memdb_create,
	.read	= cfs_plug_memdb_read,
	.write = cfs_plug_memdb_write,
	.truncate = cfs_plug_memdb_truncate,
	.unlink = cfs_plug_memdb_unlink,
	.mkdir = cfs_plug_memdb_mkdir,
	.rmdir = cfs_plug_memdb_rmdir,
	.rename = cfs_plug_memdb_rename,
	.utimens = cfs_plug_memdb_utimens,
	.statfs = cfs_plug_memdb_statfs,
#ifdef HAS_CFS_PLUG_MEMDB_LOCK
	.lock = cfs_plug_memdb_lock,
#endif
};

cfs_plug_memdb_t *cfs_plug_memdb_new(
	const char *name, 
	memdb_t *memdb,
	dfsm_t *dfsm)
{
	g_return_val_if_fail(name != NULL, NULL);
	g_return_val_if_fail(memdb != NULL, NULL);

	cfs_plug_memdb_t *mdb = g_new0(cfs_plug_memdb_t, 1);

	g_return_val_if_fail(mdb != NULL, NULL);

	mdb->plug.ops = &cfs_ops;

	mdb->plug.lookup_plug = cfs_plug_memdb_lookup_plug;

	mdb->plug.destroy_plug = cfs_plug_memdb_destroy;

	mdb->plug.name = g_strdup(name);

	mdb->memdb = memdb;

	mdb->dfsm = dfsm;

	return mdb;
}
