/*
  Copyright (C) 2010 Proxmox Server Solutions GmbH

  This software is written by Proxmox Server Solutions GmbH <support@proxmox.com>

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

#ifndef _PVE_CFS_PLUG_H_
#define _PVE_CFS_PLUG_H_

#define FUSE_USE_VERSION 26

#include <errno.h>
#include <fuse.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define PARAM_CHECK_ERRNO -EREMOTEIO

typedef struct cfs_plug cfs_plug_t;

struct cfs_operations {
	int (*getattr) (cfs_plug_t *, const char *, struct stat *);
	int (*readlink) (cfs_plug_t *, const char *, char *, size_t);
	int (*mkdir) (cfs_plug_t *, const char *, mode_t);
	int (*unlink) (cfs_plug_t *, const char *);
	int (*rmdir) (cfs_plug_t *, const char *);
	int (*rename) (cfs_plug_t *, const char *, const char *);
	int (*truncate) (cfs_plug_t *, const char *, off_t);
	int (*open) (cfs_plug_t *, const char *, struct fuse_file_info *);
	int (*read) (cfs_plug_t *, const char *, char *, size_t, off_t,
		     struct fuse_file_info *);
	int (*write) (cfs_plug_t *, const char *, const char *, size_t, off_t,
		      struct fuse_file_info *);
	int (*readdir) (cfs_plug_t *, const char *, void *, fuse_fill_dir_t, off_t,
			struct fuse_file_info *);
	int (*create) (cfs_plug_t *, const char *, mode_t, struct fuse_file_info *);
	int (*utimens) (cfs_plug_t *, const char *, const struct timespec tv[2]);
	int (*statfs) (cfs_plug_t *, const char *, struct statvfs *);
};

struct cfs_plug {
	struct cfs_operations *ops;
	cfs_plug_t *(*lookup_plug)(cfs_plug_t *plug, char **path);
	void (*destroy_plug) (cfs_plug_t *plug);
	void (*start_workers) (cfs_plug_t *plug);
	void (*stop_workers) (cfs_plug_t *plug);

	char *name;
};

typedef struct {
	cfs_plug_t plug;
	cfs_plug_t *base;
	GHashTable *entries;
} cfs_plug_base_t;

typedef struct {
	cfs_plug_t plug;
	char *symlink;
} cfs_plug_link_t;

typedef char *(*cfs_plug_func_udpate_data_fn_t)(cfs_plug_t *plug);
typedef int (*cfs_plug_func_write_data_fn_t)(
	cfs_plug_t *plug, 
	const char *buf,
	size_t size);

typedef struct {
	cfs_plug_t plug;
	char *data;
	GRWLock data_rw_lock;
	mode_t mode;
	cfs_plug_func_udpate_data_fn_t update_callback;
	cfs_plug_func_write_data_fn_t write_callback;
} cfs_plug_func_t;

cfs_plug_base_t *cfs_plug_base_new(const char *name, cfs_plug_t *base);
void cfs_plug_base_insert(cfs_plug_base_t *base, cfs_plug_t *sub);

cfs_plug_link_t *cfs_plug_link_new(const char *name, const char *symlink);
cfs_plug_func_t *cfs_plug_func_new(
	const char *name, 
	mode_t mode,
	cfs_plug_func_udpate_data_fn_t update_callback,
	cfs_plug_func_write_data_fn_t write_callback);


#endif /* _PVE_CFS_PLUG_H_ */
