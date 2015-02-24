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

#ifndef _PVE_MEMDB_H_
#define _PVE_MEMDB_H_


#include <stdio.h>
#include <stdlib.h>

#include <glib.h>
#include <sys/statvfs.h>

#define MEMDB_MAX_FILE_SIZE (128*1024)
#define MEMDB_MAX_FSSIZE (30*1024*1024)
#define MEMDB_MAX_INODES 10000

#define MEMDB_BLOCKSIZE 4096
#define MEMDB_BLOCKS ((MEMDB_MAX_FSSIZE + MEMDB_BLOCKSIZE - 1)/MEMDB_BLOCKSIZE)

typedef struct memdb_tree_entry memdb_tree_entry_t;
struct memdb_tree_entry {
	guint64 parent;
	guint64 inode;
	guint64 version;
	guint32 writer;
	guint32 mtime;
	guint32 size;
	char type;       /* DT_REG .. regular file, DT_DIR ... directory */
	union {
		GHashTable *entries;
		gpointer value;
	} data;
	char name[0];
};

typedef struct {
	guint64 inode;
	char digest[32]; /* SHA256 digest */
} memdb_index_extry_t;

typedef struct {
	guint64 version;
	guint64 last_inode;
	guint32 writer;
	guint32 mtime;
	guint32 size;  /* number of entries */
	guint32 bytes; /* total bytes allocated */
	memdb_index_extry_t entries[0];
} memdb_index_t;

typedef struct db_backend db_backend_t;

typedef struct {
	char *path;
	guint32 ltime;
	guchar csum[32];
} memdb_lock_info_t;

typedef struct {
	char *dbfilename;
	gboolean errors;
	memdb_tree_entry_t *root;
	GHashTable *index; /* map version ==> memdb_tree_entry */
	GHashTable *locks; /* contains memdb_lock_info_t */
	GMutex mutex;
	db_backend_t *bdb;
} memdb_t;

memdb_t *
memdb_open(const char *dbfilename);

void
memdb_close(memdb_t *memdb);

gboolean
memdb_checkpoint(memdb_t *memdb);

gboolean
memdb_recreate_vmlist(memdb_t *memdb);

gboolean
memdb_lock_expired(
	memdb_t *memdb,
	const char *path,
	const guchar csum[32]);

void
memdb_update_locks(memdb_t *memdb);

int
memdb_statfs(
	memdb_t *memdb,
	struct statvfs *stbuf);

int
memdb_mkdir(
	memdb_t *memdb,
	const char *path,
	guint32 writer,
	guint32 mtime);

int
memdb_mtime(
	memdb_t *memdb,
	const char *path,
	guint32 writer,
	guint32 mtime);

GList *
memdb_readdir(
	memdb_t *memdb,
	const char *path);

void
memdb_dirlist_free(GList *dirlist);

void
tree_entry_debug(memdb_tree_entry_t *te);

void
tree_entry_print(memdb_tree_entry_t *te);

memdb_tree_entry_t *
memdb_tree_entry_new(const char *name);

memdb_tree_entry_t *
memdb_tree_entry_copy(
	memdb_tree_entry_t *te,
	gboolean with_data);

void
memdb_tree_entry_free(memdb_tree_entry_t *te);

int
memdb_delete(
	memdb_t *memdb,
	const char *path,
	guint32 writer,
	guint32 mtime);

int
memdb_read(
	memdb_t *memdb,
	const char *path,
	gpointer *data_ret);

int
memdb_create(
	memdb_t *memdb,
	const char *path,
	guint32 writer,
	guint32 mtime);

int
memdb_write(
	memdb_t *memdb,
	const char *path,
	guint32 writer,
	guint32 mtime,
	gconstpointer data,
	size_t count,
	off_t offset,
	gboolean truncate);

memdb_tree_entry_t *
memdb_getattr(
	memdb_t *memdb,
	const char *path);

int
memdb_rename(
	memdb_t *memdb,
	const char *from,
	const char *to,
	guint32 writer,
	guint32 mtime);

void
memdb_dump (
	memdb_t *memdb);

gboolean
memdb_compute_checksum(
	GHashTable *index,
	memdb_tree_entry_t *root,
	guchar *csum,
	size_t csum_len);

memdb_index_t *
memdb_encode_index(
	GHashTable *index,
	memdb_tree_entry_t *root);

void
memdb_dump_index (memdb_index_t *idx);

memdb_index_t *
memdb_index_copy(memdb_index_t *idx);

gboolean
memdb_tree_entry_csum(
	memdb_tree_entry_t *te,
	guchar csum[32]);

db_backend_t *
bdb_backend_open(
	const char *filename,
	memdb_tree_entry_t *root,
	GHashTable *index);

void
bdb_backend_close(db_backend_t *bdb);

int
bdb_backend_write(
	db_backend_t *bdb,
	guint64 inode,
	guint64 parent,
	guint64 version,
	guint32 writer,
	guint32 mtime,
	guint32 size,
	char type,
	char *name,
	gpointer value,
	guint64 delete_inode);

gboolean
bdb_backend_commit_update(
	memdb_t *memdb,
	memdb_index_t *master,
	memdb_index_t *slave,
	GList *inodes);


#endif /* _PVE_MEMDB_H_ */
