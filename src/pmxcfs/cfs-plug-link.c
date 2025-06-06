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
#include "status.h"

static struct cfs_operations cfs_ops;

static cfs_plug_t *cfs_plug_link_lookup_plug(cfs_plug_t *plug, char **path) {
    g_return_val_if_fail(plug != NULL, NULL);
    g_return_val_if_fail(plug->ops == &cfs_ops, NULL);

    return (!*path || !(*path)[0]) ? plug : NULL;
}

static int cfs_plug_link_getattr(cfs_plug_t *plug, const char *path, struct stat *stbuf) {
    g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(stbuf != NULL, PARAM_CHECK_ERRNO);

    cfs_debug("enter cfs_plug_link_getattr %s", path);

    int ret = -EACCES;

    cfs_plug_link_t *lnk = (cfs_plug_link_t *)plug;
    if (!lnk->symlink) {
        goto ret;
    }

    memset(stbuf, 0, sizeof(struct stat));

    stbuf->st_size = strlen(lnk->symlink);
    if (cfs_is_quorate()) {
        stbuf->st_mode = S_IFLNK | 0777;
    } else {
        stbuf->st_mode = S_IFLNK | 0555;
    }

    stbuf->st_nlink = 1;

    ret = 0;

ret:
    return ret;
}

static int cfs_plug_link_readlink(cfs_plug_t *plug, const char *path, char *buf, size_t max) {
    g_return_val_if_fail(plug != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(plug->ops == &cfs_ops, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(path != NULL, PARAM_CHECK_ERRNO);
    g_return_val_if_fail(buf != NULL, PARAM_CHECK_ERRNO);

    cfs_debug("enter cfs_plug_link_readlink %s", path);

    int ret = -EACCES;

    cfs_plug_link_t *lnk = (cfs_plug_link_t *)plug;

    if (!lnk->symlink) {
        goto ret;
    }

    strncpy(buf, lnk->symlink, max);
    if (max > 0) {
        buf[max - 1] = '\0';
    }
    ret = 0;

ret:
    return ret;
}

static void cfs_plug_link_destroy(cfs_plug_t *plug) {
    g_return_if_fail(plug != NULL);
    g_return_if_fail(plug->ops == &cfs_ops);

    cfs_plug_link_t *lnk = (cfs_plug_link_t *)plug;

    cfs_debug("enter cfs_plug_link_destroy %s", plug->name);

    g_free(plug->name);

    g_free(lnk->symlink);

    g_free(plug);
}

static struct cfs_operations cfs_ops = {
    .getattr = cfs_plug_link_getattr,
    .readlink = cfs_plug_link_readlink,
};

cfs_plug_link_t *cfs_plug_link_new(const char *name, const char *symlink) {
    g_return_val_if_fail(name != NULL, NULL);
    g_return_val_if_fail(symlink != NULL, NULL);

    cfs_plug_link_t *lnk = g_new0(cfs_plug_link_t, 1);

    lnk->plug.ops = &cfs_ops;

    lnk->plug.lookup_plug = cfs_plug_link_lookup_plug;
    lnk->plug.destroy_plug = cfs_plug_link_destroy;

    lnk->plug.name = g_strdup(name);

    lnk->symlink = g_strdup(symlink);

    return lnk;
}
