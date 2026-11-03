/*
  Copyright (C) 2026 Proxmox Server Solutions GmbH

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

  Author: Thomas Lamprecht <t.lamprecht@proxmox.com>

*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <time.h>
#include <unistd.h>

#include "cfs-utils.h"
#include "cluster-id.h"

static const char base32_alphabet[] = "abcdefghijklmnopqrstuvwxyz234567";

gboolean cluster_id_generate(char id[CLUSTER_ID_FILE_SIZE]) {
    guint8 raw[CLUSTER_ID_LEN];

    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        cfs_critical("unable to open /dev/urandom - %s", g_strerror(errno));
        return FALSE;
    }

    ssize_t res = safe_read(fd, (char *)raw, sizeof(raw));
    int saved_errno = errno;
    close(fd);

    if (res != (ssize_t)sizeof(raw)) {
        cfs_critical(
            "unable to read from /dev/urandom - %s",
            res < 0 ? g_strerror(saved_errno) : "short read"
        );
        return FALSE;
    }

    /* five bits of a random byte per character, so each one is uniformly distributed */
    for (int i = 0; i < CLUSTER_ID_LEN; i++) {
        id[i] = base32_alphabet[raw[i] & 0x1f];
    }
    id[CLUSTER_ID_LEN] = '\n';

    return TRUE;
}

gboolean cluster_id_is_valid(gconstpointer data, size_t len) {
    const char *id = data;

    if (!id ||
        !(len == CLUSTER_ID_LEN || (len == CLUSTER_ID_FILE_SIZE && id[CLUSTER_ID_LEN] == '\n'))) {
        return FALSE;
    }

    for (int i = 0; i < CLUSTER_ID_LEN; i++) {
        if (!((id[i] >= 'a' && id[i] <= 'z') || (id[i] >= '2' && id[i] <= '7'))) {
            return FALSE;
        }
    }

    return TRUE;
}

cluster_id_state_t cluster_id_state(memdb_t *memdb) {
    g_return_val_if_fail(memdb != NULL, CLUSTER_ID_NOT_A_FILE);

    memdb_tree_entry_t *te = memdb_getattr(memdb, CFS_CLUSTER_ID_FN);
    if (!te) {
        return CLUSTER_ID_MISSING;
    }

    gboolean is_file = te->type == DT_REG;
    memdb_tree_entry_free(te);
    if (!is_file) {
        return CLUSTER_ID_NOT_A_FILE;
    }

    gpointer data = NULL;
    int len = memdb_read(memdb, CFS_CLUSTER_ID_FN, &data);
    gboolean valid = len >= 0 && cluster_id_is_valid(data, len);
    g_free(data);

    return valid ? CLUSTER_ID_VALID : CLUSTER_ID_INVALID;
}

void cluster_id_ensure_standalone(memdb_t *memdb) {
    g_return_if_fail(memdb != NULL);

    cluster_id_state_t state = cluster_id_state(memdb);
    if (state == CLUSTER_ID_VALID) {
        return;
    }

    if (state == CLUSTER_ID_NOT_A_FILE) {
        cfs_message("not generating a cluster ID, '%s' is not a regular file", CFS_CLUSTER_ID_FN);
        return;
    }

    /* on failure nothing got written, so the start can go on and the next one tries again */
    char id[CLUSTER_ID_FILE_SIZE];
    if (!cluster_id_generate(id)) {
        return;
    }

    /* nothing is mounted yet, so no reader can see the file between creating and writing it, and
     * a crash in between leaves an empty file that the next start fills */
    guint32 mtime = time(NULL);
    int res = state == CLUSTER_ID_MISSING ? memdb_create(memdb, CFS_CLUSTER_ID_FN, 0, mtime) : 0;
    if (res == 0) {
        res = memdb_write(memdb, CFS_CLUSTER_ID_FN, 0, mtime, id, CLUSTER_ID_FILE_SIZE, 0, TRUE);
    }

    /* If storing the ID failed, the tree in memory can still have it, and the memdb refuses all
     * later writes. Empty the file, so that nothing uses an ID that the next start replaces. */
    if (res != CLUSTER_ID_FILE_SIZE) {
        memdb_clear_unstored(memdb, CFS_CLUSTER_ID_FN);
        cfs_critical("unable to store a cluster ID, starting without one - %s", g_strerror(-res));
        return;
    }

    cfs_message("generated cluster ID %.*s", CLUSTER_ID_LEN, id);
}
