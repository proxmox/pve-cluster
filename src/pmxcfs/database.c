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

#define G_LOG_DOMAIN "database"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <dirent.h>
#include <errno.h>
#include <glib.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sqlite3.h>

#include "cfs-utils.h"
#include "memdb.h"
#include "status.h"

struct db_backend {
    sqlite3 *db;
    sqlite3_stmt *stmt_insert_entry;
    sqlite3_stmt *stmt_update_entry;
    sqlite3_stmt *stmt_replace_entry;
    sqlite3_stmt *stmt_delete_entry;
    sqlite3_stmt *stmt_begin;
    sqlite3_stmt *stmt_commit;
    sqlite3_stmt *stmt_rollback;
    sqlite3_stmt *stmt_load_all;
};

#define VERSIONFILENAME "__version__"

/* colume type "INTEGER PRIMARY KEY" is a special case, because sqlite
 * uses the internal ROWID. So only real interger are allowed, and
 * there is no need to add an additionl check
 */
static const char *sql_create_db =
    "CREATE TABLE IF NOT EXISTS tree ("
    "  inode INTEGER PRIMARY KEY NOT NULL,"
    "  parent INTEGER NOT NULL CHECK(typeof(parent)=='integer'),"
    "  version INTEGER NOT NULL CHECK(typeof(version)=='integer'),"
    "  writer INTEGER NOT NULL CHECK(typeof(writer)=='integer'),"
    "  mtime INTEGER NOT NULL CHECK(typeof(mtime)=='integer'),"
    "  type INTEGER NOT NULL CHECK(typeof(type)=='integer'),"
    "  name TEXT NOT NULL,"
    "  data BLOB);";

static const char *sql_load_all =
    "SELECT inode, parent, version, writer, mtime, type, name, data FROM tree;";

static char *sql_insert_entry =
    "INSERT INTO tree ("
    "inode, parent, version, writer, mtime, type, name, data) "
    "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8);";

static char *sql_update_entry =
    "UPDATE tree SET parent = ?2, version = ?3, writer = ?4, mtime = ?5, "
    "type = ?6, name = ?7, data = ?8 WHERE inode = ?1;";

static char *sql_replace_entry =
    "REPLACE INTO tree (inode, parent, version, writer, mtime, type, "
    "name, data) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8);";

static char *sql_delete_entry = "DELETE FROM tree WHERE inode = ?1;";

static char *sql_begin = "BEGIN TRANSACTION;";
static char *sql_commit = "COMMIT TRANSACTION;";
static char *sql_rollback = "ROLLBACK TRANSACTION;";

static sqlite3 *bdb_create(const char *filename) {
    int rc;
    sqlite3 *db = NULL;

    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
    rc = sqlite3_open_v2(filename, &db, flags, NULL);
    if (rc != SQLITE_OK) {
        cfs_critical("splite3_open_v2 failed: %d\n", rc);
        sqlite3_close(db);
        return NULL;
    }

    if (chmod(filename, 0600) == -1) {
        cfs_critical("chmod failed: %s", strerror(errno));
        return NULL;
    }

    /* use WAL mode - to allow concurrent reads */
    rc = sqlite3_exec(db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        cfs_critical("unable to set WAL mode: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return NULL;
    }

    /* NORMAL is good enough when using WAL */
    rc = sqlite3_exec(db, "PRAGMA synchronous=NORMAL", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        cfs_critical("unable to set synchronous mode: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return NULL;
    }

    sqlite3_busy_timeout(db, 10000); /* 10 seconds */

    rc = sqlite3_exec(db, sql_create_db, NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        cfs_critical("init database failed: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return NULL;
    }

    return db;
}

static int backend_write_inode(
    sqlite3 *db,
    sqlite3_stmt *stmt,
    guint64 inode,
    guint64 parent,
    guint64 version,
    guint32 writer,
    guint32 mtime,
    guint32 size,
    char type,
    char *name,
    gpointer value
) {
    int rc;

    cfs_debug("enter backend_write_inode %016" PRIX64 " '%s', size %" PRIu32 "", inode, name, size);

    if ((rc = sqlite3_bind_int64(stmt, 1, inode)) != SQLITE_OK) {
        cfs_critical("sqlite3_bind failed: %s\n", sqlite3_errmsg(db));
        return rc;
    }
    if ((rc = sqlite3_bind_int64(stmt, 2, parent)) != SQLITE_OK) {
        cfs_critical("sqlite3_bind failed: %s\n", sqlite3_errmsg(db));
        return rc;
    }
    if ((rc = sqlite3_bind_int64(stmt, 3, version)) != SQLITE_OK) {
        cfs_critical("sqlite3_bind failed: %s\n", sqlite3_errmsg(db));
        return rc;
    }
    if ((rc = sqlite3_bind_int64(stmt, 4, writer)) != SQLITE_OK) {
        cfs_critical("sqlite3_bind failed: %s\n", sqlite3_errmsg(db));
        return rc;
    }
    if ((rc = sqlite3_bind_int64(stmt, 5, mtime)) != SQLITE_OK) {
        cfs_critical("sqlite3_bind failed: %s\n", sqlite3_errmsg(db));
        return rc;
    }
    if ((rc = sqlite3_bind_int64(stmt, 6, type)) != SQLITE_OK) {
        cfs_critical("sqlite3_bind failed: %s\n", sqlite3_errmsg(db));
        return rc;
    }
    if ((rc = sqlite3_bind_text(stmt, 7, name, -1, SQLITE_STATIC)) != SQLITE_OK) {
        cfs_critical("sqlite3_bind failed: %s\n", sqlite3_errmsg(db));
        return rc;
    }
    if ((rc = sqlite3_bind_blob(stmt, 8, value, size, SQLITE_STATIC)) != SQLITE_OK) {
        cfs_critical("sqlite3_bind failed: %s\n", sqlite3_errmsg(db));
        return rc;
    }

    if ((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
        cfs_critical("sqlite3_step failed: %s\n", sqlite3_errmsg(db));
        sqlite3_reset(stmt);
        return rc;
    }

    sqlite3_reset(stmt);

    return SQLITE_OK;
}

static int bdb_backend_delete_inode(db_backend_t *bdb, guint64 inode) {
    int rc;

    cfs_debug("enter dbd_backend_delete_inode");

    sqlite3_stmt *stmt = bdb->stmt_delete_entry;

    if ((rc = sqlite3_bind_int64(stmt, 1, inode)) != SQLITE_OK) {
        cfs_critical("delete_inode/sqlite3_bind failed: %s\n", sqlite3_errmsg(bdb->db));
        return rc;
    }

    if ((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
        cfs_critical("delete_inode failed: %s\n", sqlite3_errmsg(bdb->db));
        sqlite3_reset(stmt);
        return rc;
    }

    sqlite3_reset(stmt);

    return SQLITE_OK;
}

int bdb_backend_write(
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
    guint64 delete_inode
) {
    g_return_val_if_fail(bdb != NULL, SQLITE_PERM);
    g_return_val_if_fail(inode == 0 || (name != NULL && name[0]), SQLITE_PERM);
    g_return_val_if_fail(type == DT_REG || type == DT_DIR, SQLITE_PERM);
    int rc;

    gboolean need_txn = (inode != 0 || delete_inode != 0);

    if (need_txn) {
        rc = sqlite3_step(bdb->stmt_begin);
        sqlite3_reset(bdb->stmt_begin);
        if (rc != SQLITE_DONE) {
            cfs_critical("begin transaction failed: %s\n", sqlite3_errmsg(bdb->db));
            return rc;
        }
    }

    if (delete_inode != 0) {
        if ((rc = bdb_backend_delete_inode(bdb, delete_inode)) != SQLITE_OK) {
            goto rollback;
        }
    }

    if (inode != 0) {

        sqlite3_stmt *stmt = (inode > version) ? bdb->stmt_insert_entry : bdb->stmt_replace_entry;

        rc = backend_write_inode(
            bdb->db, stmt, inode, parent, version, writer, mtime, size, type, name, value
        );
        if (rc != SQLITE_OK) {
            goto rollback;
        }

        if (sqlite3_changes(bdb->db) != 1) {
            cfs_critical("no such inode %016" PRIX64, inode);
            goto rollback;
        }
    }

    rc = backend_write_inode(
        bdb->db, bdb->stmt_replace_entry, 0, 0, version, writer, mtime, 0, DT_REG, VERSIONFILENAME,
        NULL
    );

    if (rc != SQLITE_OK) {
        goto rollback;
    }

    if (need_txn) {
        rc = sqlite3_step(bdb->stmt_commit);
        sqlite3_reset(bdb->stmt_commit);
        if (rc != SQLITE_DONE) {
            cfs_critical("commit transaction failed: %s\n", sqlite3_errmsg(bdb->db));
            goto rollback;
        }
    }

    return SQLITE_OK;

rollback:

    if (!need_txn) {
        return rc;
    }

    int rbrc = sqlite3_step(bdb->stmt_rollback);
    sqlite3_reset(bdb->stmt_rollback);
    if (rbrc != SQLITE_DONE) {
        cfs_critical("rollback transaction failed: %s\n", sqlite3_errmsg(bdb->db));
        return rc;
    }

    return rc;
}

static gboolean
bdb_backend_load_index(db_backend_t *bdb, memdb_tree_entry_t *root, GHashTable *index) {
    g_return_val_if_fail(bdb != NULL, FALSE);
    g_return_val_if_fail(root != NULL, FALSE);
    g_return_val_if_fail(index != NULL, FALSE);
    g_return_val_if_fail(root->version == 0, FALSE);
    g_return_val_if_fail(g_hash_table_size(index) == 1, FALSE);

    sqlite3_stmt *stmt = bdb->stmt_load_all;

    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {

        memdb_tree_entry_t *te;

        guint64 inode = sqlite3_column_int64(stmt, 0);
        const char *name = (const char *)sqlite3_column_text(stmt, 6);
        int namelen = sqlite3_column_bytes(stmt, 6);
        if (name == NULL || namelen == 0) {
            cfs_critical("inode has no name (inode = %016" PRIX64 ")", inode);
            goto fail;
        }
        te = g_malloc0(sizeof(memdb_tree_entry_t) + namelen + 1);
        strcpy(te->name, name);

        te->inode = inode;
        te->parent = sqlite3_column_int64(stmt, 1);
        te->version = sqlite3_column_int64(stmt, 2);
        te->writer = sqlite3_column_int64(stmt, 3) & 0x0ffffffff;
        te->mtime = sqlite3_column_int64(stmt, 4) & 0x0ffffffff;
        te->type = sqlite3_column_int64(stmt, 5) & 255;

        gconstpointer value = sqlite3_column_blob(stmt, 7);

        int size = sqlite3_column_bytes(stmt, 7);
        te->size = size;

        if (te->type == DT_REG) {
            if (size > 0) {
                te->data.value = g_memdup2(value, size);
            }
        } else if (te->type == DT_DIR) {
            if (size) {
                cfs_critical("directory inode contains data (inode = %016" PRIX64 ")", te->inode);
                g_free(te);
                goto fail;
            }
            te->data.entries = NULL;
        } else {
            cfs_critical(
                "inode has unknown type (inode = %016" PRIX64 ", type = %d)", te->inode, te->type
            );
            g_free(te);
            goto fail;
        }

        cfs_debug(
            "name %s (inode = %016" PRIX64 ", parent = %016" PRIX64 ")", te->name, te->inode,
            te->parent
        );

        if (te->inode == 0) {
            if (!strcmp(te->name, VERSIONFILENAME)) {
                root->version = te->version;
                root->writer = te->writer;
                root->mtime = te->mtime;
                memdb_tree_entry_free(te);
            } else {
                cfs_critical("root inode has unexpected name '%s'", te->name);
                memdb_tree_entry_free(te);
                goto fail;
            }
        } else {
            memdb_tree_entry_t *pte;

            if (!(pte = g_hash_table_lookup(index, &te->parent))) {
                /* allocate placeholder (type == 0)
                 * this is simply replaced if we find a real inode later
                 */
                pte = g_malloc0(sizeof(memdb_tree_entry_t));
                pte->inode = te->parent;
                pte->data.entries = g_hash_table_new(g_str_hash, g_str_equal);
                g_hash_table_replace(index, &pte->inode, pte);

            } else if (!(pte->type == DT_DIR || pte->type == 0)) {
                cfs_critical(
                    "parent is not a directory "
                    "(inode = %016" PRIX64 ", parent = %016" PRIX64 ", name = '%s')",
                    te->inode, te->parent, te->name
                );
                memdb_tree_entry_free(te);
                goto fail;
            }

            if (te->type == DT_DIR) {
                memdb_tree_entry_t *tmpte;
                /* test if there is a placeholder entry */
                if ((tmpte = g_hash_table_lookup(index, &te->inode))) {
                    if (tmpte->type != 0) {
                        cfs_critical(
                            "found strange placeholder for "
                            "(inode = %016" PRIX64 ", parent = %016" PRIX64
                            ", name = '%s', type = '%d')",
                            te->inode, te->parent, te->name, tmpte->type
                        );
                        memdb_tree_entry_free(te);
                        goto fail;
                    }
                    /* copy entries from placeholder */
                    te->data.entries = tmpte->data.entries;
                    tmpte->data.entries = NULL;
                } else {
                    te->data.entries = g_hash_table_new(g_str_hash, g_str_equal);
                }
            }

            memdb_tree_entry_t *existing;
            if ((existing = g_hash_table_lookup(pte->data.entries, te->name))) {
                cfs_critical(
                    "found entry with duplicate name '%s' - "
                    "A:(inode = 0x%016" PRIX64 ", parent = 0x%016" PRIX64 ", v./mtime = 0x%" PRIX64
                    "/0x%" PRIi32
                    ")"
                    " vs. "
                    "B:(inode = 0x%016" PRIX64 ", parent = 0x%016" PRIX64 ", v./mtime = 0x%" PRIX64
                    "/0x%" PRIi32 ")",
                    te->name, existing->inode, existing->parent, existing->version, existing->mtime,
                    te->inode, te->parent, te->version, te->mtime
                );
                goto fail;
            }

            g_hash_table_replace(pte->data.entries, te->name, te);
            g_hash_table_replace(index, &te->inode, te);
        }
    }
    if (rc != SQLITE_DONE) {
        cfs_critical("select returned error: %s", sqlite3_errmsg(bdb->db));
        goto fail;
    }

    /* check if all inodes have parents (there must be no placeholders) */
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, index);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        memdb_tree_entry_t *te = (memdb_tree_entry_t *)value;
        if (te->type == 0) {
            cfs_critical("missing directory inode (inode = %016" PRIX64 ")", te->inode);
            goto fail;
        }
    }

    sqlite3_reset(stmt);

    return TRUE;

fail:
    sqlite3_reset(stmt);

    cfs_critical("DB load failed");

    return FALSE;
}

gboolean bdb_backend_commit_update(
    memdb_t *memdb, memdb_index_t *master, memdb_index_t *slave, GList *inodes
) {
    g_return_val_if_fail(memdb != NULL, FALSE);
    g_return_val_if_fail(memdb->bdb != NULL, FALSE);
    g_return_val_if_fail(master != NULL, FALSE);
    g_return_val_if_fail(slave != NULL, FALSE);

    cfs_debug("enter bdb_backend_commit_update");

    memdb_tree_entry_t *root = NULL;
    GHashTable *index = NULL;

    db_backend_t *bdb = (db_backend_t *)memdb->bdb;
    gboolean result = FALSE;

    int rc;

    rc = sqlite3_step(bdb->stmt_begin);
    sqlite3_reset(bdb->stmt_begin);
    if (rc != SQLITE_DONE) {
        cfs_critical("begin transaction failed: %s\n", sqlite3_errmsg(bdb->db));
        return rc;
    }

    g_mutex_lock(&memdb->mutex);

    /* first, delete anything not found in master index) */

    int i = 0;
    int j = 0;

    for (i = 0; i < master->size; i++) {
        guint64 inode = master->entries[i].inode;
        guint64 slave_inode;
        while (j < slave->size && (slave_inode = slave->entries[j].inode) <= inode) {

            if (slave_inode < inode) {
                if (bdb_backend_delete_inode(bdb, slave_inode) != SQLITE_OK) {
                    goto abort;
                }

                cfs_debug("deleted inode %016" PRIX64, slave_inode);
            }
            j++;
        }
        if (j >= slave->size) {
            break;
        }
    }

    while (j < slave->size) {
        guint64 slave_inode = slave->entries[j].inode;

        if (bdb_backend_delete_inode(bdb, slave_inode) != SQLITE_OK) {
            goto abort;
        }

        cfs_debug("deleted inode %016" PRIX64, slave_inode);

        j++;
    }

    /* now add all updates */

    GList *l = inodes;
    while (l) {
        memdb_tree_entry_t *te = (memdb_tree_entry_t *)l->data;

        tree_entry_debug(te);

        if (backend_write_inode(
                bdb->db, bdb->stmt_replace_entry, te->inode, te->parent, te->version, te->writer,
                te->mtime, te->size, te->type, te->inode ? te->name : VERSIONFILENAME,
                te->data.value
            ) != SQLITE_OK) {
            goto abort;
        }

        l = g_list_next(l);
    }

    /* now try to reload */
    root = memdb_tree_entry_new("");
    root->data.entries = g_hash_table_new(g_str_hash, g_str_equal);
    root->type = DT_DIR;

    index = g_hash_table_new_full(
        g_int64_hash, g_int64_equal, NULL, (GDestroyNotify)memdb_tree_entry_free
    );

    g_hash_table_replace(index, &root->inode, root);

    if (!bdb_backend_load_index(bdb, root, index)) {
        goto abort;
    }

    if (!memdb->root->version) {
        cfs_critical("new index has version 0 - internal error");
        goto abort;
    }

    memdb_index_t *new_idx = memdb_encode_index(index, root);
    if (!new_idx) {
        cfs_critical("cant encode new index - internal error");
        goto abort;
    }

    int idx_equal =
        (new_idx->bytes == master->bytes && (memcmp(master, new_idx, new_idx->bytes) == 0));

    g_free(new_idx);

    if (!idx_equal) {
        cfs_critical("new index does not match master index - internal error");
        goto abort;
    }

    rc = sqlite3_step(bdb->stmt_commit);
    sqlite3_reset(bdb->stmt_commit);
    if (rc != SQLITE_DONE) {
        cfs_critical("commit transaction failed: %s\n", sqlite3_errmsg(bdb->db));
        goto abort;
    }

    g_hash_table_destroy(memdb->index);
    memdb->index = index;
    memdb->root = root;
    index = NULL;
    root = NULL;

    record_memdb_reload();

    if (!memdb_recreate_vmlist(memdb)) {
        cfs_critical("memdb_recreate_vmlist failed");
        memdb->errors = 1;
        result = FALSE;
        goto ret;
    }

    memdb_update_locks(memdb);

    result = TRUE;

ret:
    g_mutex_unlock(&memdb->mutex);

    if (index) {
        g_hash_table_destroy(index);
    }

    cfs_debug("leave bdb_backend_commit_update (%d)", result);

    return result;

abort:

    memdb->errors = 1;

    rc = sqlite3_step(bdb->stmt_rollback);
    sqlite3_reset(bdb->stmt_rollback);
    if (rc != SQLITE_DONE) {
        cfs_critical("rollback transaction failed: %s\n", sqlite3_errmsg(bdb->db));
    }

    result = FALSE;

    goto ret;
}

void bdb_backend_close(db_backend_t *bdb) {
    g_return_if_fail(bdb != NULL);

    sqlite3_finalize(bdb->stmt_insert_entry);
    sqlite3_finalize(bdb->stmt_replace_entry);
    sqlite3_finalize(bdb->stmt_update_entry);
    sqlite3_finalize(bdb->stmt_delete_entry);
    sqlite3_finalize(bdb->stmt_begin);
    sqlite3_finalize(bdb->stmt_commit);
    sqlite3_finalize(bdb->stmt_rollback);
    sqlite3_finalize(bdb->stmt_load_all);

    int rc;
    if ((rc = sqlite3_close(bdb->db)) != SQLITE_OK) {
        cfs_critical("sqlite3_close failed: %d\n", rc);
    }

    sqlite3_shutdown();

    g_free(bdb);
}

db_backend_t *bdb_backend_open(const char *filename, memdb_tree_entry_t *root, GHashTable *index) {
    g_return_val_if_fail(filename != NULL, NULL);
    g_return_val_if_fail(root != NULL, NULL);
    g_return_val_if_fail(index != NULL, NULL);

    db_backend_t *bdb = g_new0(db_backend_t, 1);
    g_return_val_if_fail(bdb != NULL, NULL);

    int rc;

    sqlite3_initialize();

    if (!(bdb->db = bdb_create(filename))) {
        goto fail;
    }

    // tell the query planner that the prepared statement will be retained for a long time and
    // probably reused many times
    const unsigned int flags = SQLITE_PREPARE_PERSISTENT;

    rc = sqlite3_prepare_v3(bdb->db, sql_insert_entry, -1, flags, &bdb->stmt_insert_entry, NULL);
    if (rc != SQLITE_OK) {
        cfs_critical("sqlite3_prepare 'sql_insert_entry' failed: %s\n", sqlite3_errmsg(bdb->db));
        goto fail;
    }
    rc = sqlite3_prepare_v3(bdb->db, sql_update_entry, -1, flags, &bdb->stmt_update_entry, NULL);
    if (rc != SQLITE_OK) {
        cfs_critical("sqlite3_prepare 'sql_update_entry' failed: %s\n", sqlite3_errmsg(bdb->db));
        goto fail;
    }
    rc = sqlite3_prepare_v3(bdb->db, sql_replace_entry, -1, flags, &bdb->stmt_replace_entry, NULL);
    if (rc != SQLITE_OK) {
        cfs_critical("sqlite3_prepare 'sql_replace_entry' failed: %s\n", sqlite3_errmsg(bdb->db));
        goto fail;
    }
    rc = sqlite3_prepare_v3(bdb->db, sql_delete_entry, -1, flags, &bdb->stmt_delete_entry, NULL);
    if (rc != SQLITE_OK) {
        cfs_critical("sqlite3_prepare 'sql_delete_entry' failed: %s\n", sqlite3_errmsg(bdb->db));
        goto fail;
    }
    rc = sqlite3_prepare_v3(bdb->db, sql_begin, -1, flags, &bdb->stmt_begin, NULL);
    if (rc != SQLITE_OK) {
        cfs_critical("sqlite3_prepare 'sql_begin' failed: %s\n", sqlite3_errmsg(bdb->db));
        goto fail;
    }
    rc = sqlite3_prepare_v3(bdb->db, sql_commit, -1, flags, &bdb->stmt_commit, NULL);
    if (rc != SQLITE_OK) {
        cfs_critical("sqlite3_prepare 'sql_commit' failed: %s\n", sqlite3_errmsg(bdb->db));
        goto fail;
    }
    rc = sqlite3_prepare_v3(bdb->db, sql_rollback, -1, flags, &bdb->stmt_rollback, NULL);
    if (rc != SQLITE_OK) {
        cfs_critical("sqlite3_prepare 'sql_rollback' failed: %s\n", sqlite3_errmsg(bdb->db));
        goto fail;
    }
    rc = sqlite3_prepare_v3(bdb->db, sql_load_all, -1, flags, &bdb->stmt_load_all, NULL);
    if (rc != SQLITE_OK) {
        cfs_critical("sqlite3_prepare 'sql_load_all' failed: %s\n", sqlite3_errmsg(bdb->db));
        goto fail;
    }

    if (!bdb_backend_load_index(bdb, root, index)) {
        goto fail;
    }

    if (!root->version) {
        root->version++;

        guint32 mtime = time(NULL);

        if (bdb_backend_write(bdb, 0, 0, root->version, 0, mtime, 0, DT_REG, NULL, NULL, 0) !=
            SQLITE_OK) {
            goto fail;
        }
    }

    return bdb;

fail:
    bdb_backend_close(bdb);

    return NULL;
}
