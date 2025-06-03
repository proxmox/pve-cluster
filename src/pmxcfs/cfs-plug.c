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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "cfs-plug.h"
#include "cfs-utils.h"

static struct cfs_operations cfs_ops;

static cfs_plug_t *cfs_plug_base_lookup_plug(cfs_plug_t *plug, char **path) {
    g_return_val_if_fail(plug != NULL, NULL);
    g_return_val_if_fail(plug->ops == &cfs_ops, NULL);
    g_return_val_if_fail(path != NULL, NULL);

    cfs_plug_base_t *bplug = (cfs_plug_base_t *)plug;

    g_return_val_if_fail(bplug->entries != NULL, NULL);

    cfs_debug("cfs_plug_base_lookup_plug %s", *path);

    if (!*path || !(*path)[0]) {
        return plug;
    }

    char *name = strsep(path, "/");

    cfs_debug("cfs_plug_base_lookup_plug name = %s new path = %s", name, *path);

    cfs_plug_t *sub;

    if (!(sub = (cfs_plug_t *)g_hash_table_lookup(bplug->entries, name))) {
        /* revert strsep modification */
        if (*path) {
            (*path)[-1] = '/';
        }
        *path = name;
        return plug;
    }

    if ((sub = sub->lookup_plug(sub, path))) {
        return sub;
    }

    *path = NULL;
    return NULL;
}

static int cfs_plug_base_getattr(cfs_plug_t *plug, const char *path, struct stat *stbuf) {
    g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(stbuf != NULL, PARAM_CHECK_ERRNO);

    cfs_debug("enter cfs_plug_base_getattr %s", path);

    int ret = -EACCES;

    memset(stbuf, 0, sizeof(struct stat));

    if (*path) {
        cfs_plug_t *base = ((cfs_plug_base_t *)plug)->base;

        if (base && base->ops && base->ops->getattr) {
            ret = base->ops->getattr(base, path, stbuf);
        }
        goto ret;
    }

    stbuf->st_mode = S_IFDIR | 0777;
    stbuf->st_nlink = 2;
    ret = 0;

ret:
    cfs_debug("leave cfs_plug_base_getattr %s", path);
    return ret;
}

struct hash_filler {
    void *buf;
    GHashTable *entries;
    fuse_fill_dir_t filler;
};

static int tmp_hash_filler(void *buf, const char *name, const struct stat *stbuf, off_t off) {

    struct hash_filler *hf = (struct hash_filler *)buf;

    if (hf->entries && g_hash_table_lookup(hf->entries, name)) {
        return 0;
    }

    if (name[0] == '.' && (name[1] == 0 || (name[1] == '.' && name[2] == 0))) {
        return 0;
    }

    hf->filler(hf->buf, name, stbuf, off);

    return 0;
}

static int cfs_plug_base_readdir(
    cfs_plug_t *plug,
    const char *path,
    void *buf,
    fuse_fill_dir_t filler,
    off_t offset,
    struct fuse_file_info *fi
) {
    (void)offset;
    (void)fi;

    g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(buf != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(filler != NULL, PARAM_CHECK_ERRNO);

    cfs_plug_base_t *bplug = (cfs_plug_base_t *)plug;

    cfs_debug("enter cfs_plug_base_readdir %s", path);

    int ret = -EACCES;

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    if (!path[0]) {
        GHashTableIter iter;
        gpointer key, value;

        g_hash_table_iter_init(&iter, bplug->entries);

        while (g_hash_table_iter_next(&iter, &key, &value)) {
            filler(buf, key, NULL, 0);
        }
    }

    cfs_plug_t *base = ((cfs_plug_base_t *)plug)->base;

    if (base && base->ops && base->ops->readdir) {
        struct hash_filler hf = {.buf = buf, .filler = filler, .entries = NULL};

        if (!path[0]) {
            hf.entries = bplug->entries;
        }

        ret = base->ops->readdir(base, path, &hf, tmp_hash_filler, 0, fi);

    } else {
        ret = 0;
    }

    return ret;
}

static int cfs_plug_base_mkdir(cfs_plug_t *plug, const char *path, mode_t mode) {
    g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);

    cfs_debug("enter cfs_plug_base_mkdir %s", path);

    int ret = -EACCES;

    cfs_plug_t *base = ((cfs_plug_base_t *)plug)->base;

    if (*path && base && base->ops && base->ops->mkdir) {
        ret = base->ops->mkdir(base, path, mode);
    }

    return ret;
}

static int cfs_plug_base_rmdir(cfs_plug_t *plug, const char *path) {
    g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);

    cfs_debug("enter cfs_plug_base_rmdir %s", path);

    int ret = -EACCES;

    cfs_plug_t *base = ((cfs_plug_base_t *)plug)->base;

    if (*path && base && base->ops && base->ops->rmdir) {
        ret = base->ops->rmdir(base, path);
    }

    return ret;
}

static int cfs_plug_base_rename(cfs_plug_t *plug, const char *from, const char *to) {
    g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(from != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(to != NULL, PARAM_CHECK_ERRNO);

    cfs_debug("enter cfs_plug_base_rename from %s to %s", from, to);

    int ret = -EACCES;

    cfs_plug_t *base = ((cfs_plug_base_t *)plug)->base;

    if (base && base->ops && base->ops->rename) {
        ret = base->ops->rename(base, from, to);
    }

    return ret;
}

static int cfs_plug_base_open(cfs_plug_t *plug, const char *path, struct fuse_file_info *fi) {
    g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(fi != NULL, PARAM_CHECK_ERRNO);

    cfs_debug("enter cfs_plug_base_open %s", path);

    int ret = -EACCES;

    cfs_plug_t *base = ((cfs_plug_base_t *)plug)->base;

    if (base && base->ops && base->ops->open) {
        ret = base->ops->open(base, path, fi);
    }

    return ret;
}

static int cfs_plug_base_read(
    cfs_plug_t *plug,
    const char *path,
    char *buf,
    size_t size,
    off_t offset,
    struct fuse_file_info *fi
) {
    (void)fi;

    g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(buf != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(fi != NULL, PARAM_CHECK_ERRNO);

    cfs_debug("enter cfs_plug_base_read %s %zu %jd", path, size, offset);

    int ret = -EACCES;

    cfs_plug_t *base = ((cfs_plug_base_t *)plug)->base;

    if (base && base->ops && base->ops->read) {
        ret = base->ops->read(base, path, buf, size, offset, fi);
    }

    return ret;
}

static int cfs_plug_base_write(
    cfs_plug_t *plug,
    const char *path,
    const char *buf,
    size_t size,
    off_t offset,
    struct fuse_file_info *fi
) {
    (void)fi;

    g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(buf != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(fi != NULL, PARAM_CHECK_ERRNO);

    cfs_debug("enter cfs_plug_base_write %s %zu %jd", path, size, offset);

    int ret = -EACCES;

    cfs_plug_t *base = ((cfs_plug_base_t *)plug)->base;

    if (base && base->ops && base->ops->write) {
        ret = base->ops->write(base, path, buf, size, offset, fi);
    }

    return ret;
}

static int cfs_plug_base_truncate(cfs_plug_t *plug, const char *path, off_t size) {
    g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);

    cfs_debug("enter cfs_plug_base_truncate %s %jd", path, size);

    int ret = -EACCES;

    cfs_plug_t *base = ((cfs_plug_base_t *)plug)->base;

    if (base && base->ops && base->ops->truncate) {
        ret = base->ops->truncate(base, path, size);
    }

    return ret;
}

static int
cfs_plug_base_create(cfs_plug_t *plug, const char *path, mode_t mode, struct fuse_file_info *fi) {
    g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(fi != NULL, PARAM_CHECK_ERRNO);

    cfs_debug("enter cfs_plug_base_create %s", path);

    int ret = -EACCES;

    cfs_plug_t *base = ((cfs_plug_base_t *)plug)->base;

    if (base && base->ops && base->ops->create) {
        ret = base->ops->create(base, path, mode, fi);
    }

    return ret;
}

static int cfs_plug_base_unlink(cfs_plug_t *plug, const char *path) {
    g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);

    cfs_debug("enter cfs_plug_base_unlink %s", path);

    int ret = -EACCES;

    cfs_plug_t *base = ((cfs_plug_base_t *)plug)->base;

    if (base && base->ops && base->ops->unlink) {
        ret = base->ops->unlink(base, path);
    }

    return ret;
}

static int cfs_plug_base_readlink(cfs_plug_t *plug, const char *path, char *buf, size_t max) {
    g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(buf != NULL, PARAM_CHECK_ERRNO);

    cfs_debug("enter cfs_plug_base_readlink %s", path);

    int ret = -EACCES;

    cfs_plug_t *base = ((cfs_plug_base_t *)plug)->base;

    if (base && base->ops && base->ops->readlink) {
        ret = base->ops->readlink(base, path, buf, max);
    }

    return ret;
}

static int cfs_plug_base_utimens(cfs_plug_t *plug, const char *path, const struct timespec tv[2]) {
    g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(tv != NULL, PARAM_CHECK_ERRNO);

    cfs_debug("enter cfs_plug_utimes %s", path);

    int ret = -EACCES;

    cfs_plug_t *base = ((cfs_plug_base_t *)plug)->base;

    if (base && base->ops && base->ops->utimens) {
        ret = base->ops->utimens(base, path, tv);
    }

    return ret;
}

static int cfs_plug_base_statfs(cfs_plug_t *plug, const char *path, struct statvfs *stbuf) {
    g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(stbuf != NULL, PARAM_CHECK_ERRNO);

    cfs_debug("enter cfs_plug_base_statfs %s", path);

    int ret = -EACCES;

    cfs_plug_t *base = ((cfs_plug_base_t *)plug)->base;

    if (base && base->ops && base->ops->statfs) {
        ret = base->ops->statfs(base, path, stbuf);
    }

    return ret;
}

static gboolean plug_remove_func(gpointer key, gpointer value, gpointer user_data) {
    cfs_plug_t *plug = (cfs_plug_t *)value;

    if (plug && plug->destroy_plug) {
        plug->destroy_plug(plug);
    }

    return TRUE;
}

static void cfs_plug_base_destroy(cfs_plug_t *plug) {
    g_return_if_fail(plug != NULL);
    g_return_if_fail(plug->ops == &cfs_ops);

    cfs_plug_base_t *bplug = (cfs_plug_base_t *)plug;

    cfs_debug("enter cfs_plug_base_destroy %s", plug->name);

    if (bplug->entries) {
        g_hash_table_foreach_remove(bplug->entries, plug_remove_func, NULL);
        g_hash_table_destroy(bplug->entries);
    }

    if (bplug->base && bplug->base->destroy_plug) {
        bplug->base->destroy_plug(bplug->base);
    }

    g_free(plug->name);

    g_free(plug);
}

static void cfs_plug_base_start_workers(cfs_plug_t *plug) {
    g_return_if_fail(plug != NULL);
    g_return_if_fail(plug->ops == &cfs_ops);

    cfs_plug_base_t *bplug = (cfs_plug_base_t *)plug;
    GHashTableIter iter;
    gpointer key, value;

    g_hash_table_iter_init(&iter, bplug->entries);

    while (g_hash_table_iter_next(&iter, &key, &value)) {

        cfs_plug_t *p = (cfs_plug_t *)value;

        if (p->start_workers) {
            p->start_workers(p);
        }
    }

    if (bplug->base && bplug->base->start_workers) {
        bplug->base->start_workers(bplug->base);
    }
}

static void cfs_plug_base_stop_workers(cfs_plug_t *plug) {
    g_return_if_fail(plug != NULL);
    g_return_if_fail(plug->ops == &cfs_ops);

    cfs_plug_base_t *bplug = (cfs_plug_base_t *)plug;
    GHashTableIter iter;
    gpointer key, value;

    g_hash_table_iter_init(&iter, bplug->entries);

    if (bplug->base && bplug->base->stop_workers) {
        bplug->base->stop_workers(bplug->base);
    }

    while (g_hash_table_iter_next(&iter, &key, &value)) {

        cfs_plug_t *p = (cfs_plug_t *)value;

        if (p->stop_workers) {
            p->stop_workers(p);
        }
    }
}

static struct cfs_operations cfs_ops = {
    .getattr = cfs_plug_base_getattr,
    .create = cfs_plug_base_create,
    .open = cfs_plug_base_open,
    .read = cfs_plug_base_read,
    .write = cfs_plug_base_write,
    .truncate = cfs_plug_base_truncate,
    .unlink = cfs_plug_base_unlink,
    .readdir = cfs_plug_base_readdir,
    .mkdir = cfs_plug_base_mkdir,
    .rmdir = cfs_plug_base_rmdir,
    .rename = cfs_plug_base_rename,
    .readlink = cfs_plug_base_readlink,
    .utimens = cfs_plug_base_utimens,
    .statfs = cfs_plug_base_statfs,
};

cfs_plug_base_t *cfs_plug_base_new(const char *name, cfs_plug_t *base) {
    g_return_val_if_fail(name != NULL, NULL);
    g_return_val_if_fail(base != NULL, NULL);

    cfs_plug_base_t *plug = g_new0(cfs_plug_base_t, 1);

    plug->plug.lookup_plug = cfs_plug_base_lookup_plug;
    plug->plug.destroy_plug = cfs_plug_base_destroy;
    plug->plug.start_workers = cfs_plug_base_start_workers;
    plug->plug.stop_workers = cfs_plug_base_stop_workers;

    plug->entries = g_hash_table_new(g_str_hash, g_str_equal);

    plug->plug.name = g_strdup(name);

    plug->plug.ops = &cfs_ops;

    plug->base = base;

    return plug;
}

void cfs_plug_base_insert(cfs_plug_base_t *bplug, cfs_plug_t *sub) {
    g_return_if_fail(bplug != NULL);
    g_return_if_fail(sub != NULL);
    g_return_if_fail(sub->name != NULL);

    g_hash_table_replace(bplug->entries, sub->name, sub);
}
