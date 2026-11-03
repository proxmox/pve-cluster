/*
  Copyright (C) 2010 - 2026 Proxmox Server Solutions GmbH

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

#include <check.h>
#include <dirent.h>
#include <errno.h>
#include <glib.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cfs-plug-memdb.h"
#include "cfs-utils.h"
#include "cluster-id.h"
#include "memdb.h"
#include "status.h"

#if CHECK_MAJOR_VERSION == 0 && CHECK_MINOR_VERSION <= 10
#define _TEST_TYPE TFun
#else
#define _TEST_TYPE const TTest *
#endif

cfs_t cfs = {
    .debug = 0,
    .nodename = "testnode",
};

#define TESTDB "/tmp/test.db"

static memdb_t *memdb;

static void setup(void) {
    unlink(TESTDB);
    memdb = memdb_open(TESTDB);
    ck_assert(memdb != NULL);

    struct statvfs stbuf;
    ck_assert(memdb_statfs(memdb, &stbuf) == 0);

    int count = stbuf.f_files - stbuf.f_ffree;
    ck_assert(count == 1);
}

void teardown(void) {
    ck_assert(memdb != NULL);

    memdb_close(memdb);
}

START_TEST(test_path_is_private) {
    ck_assert(path_is_private("priv"));
    ck_assert(path_is_private("priv/lock/x"));
    ck_assert(path_is_private("/priv"));
    ck_assert(path_is_private("//priv//x"));
    ck_assert(path_is_private("nodes/n1/priv/pve-ssl.key"));
    ck_assert(path_is_private("nodes/n1//priv/x"));

    ck_assert(!path_is_private(""));
    ck_assert(!path_is_private("/"));
    ck_assert(!path_is_private("privileged"));
    ck_assert(!path_is_private("nodes/n1/qemu-server/100.conf"));
    /* a node may be named 'priv', its directory is not the private one */
    ck_assert(!path_is_private("nodes/priv/x"));
}
END_TEST

START_TEST(test_guest_config_properties_json) {
    time_t ctime = 1234;
    const char conf[] =
        "tab: a\tb\n"
        "cr: a\rb\n"
        "ctrl: a\001b\x1f"
        "c\n"
        "del: a\x7f"
        "b\n"
        "utf: caf\xc3\xa9 \xe2\x82\xac\n"
        "bad: a\xff"
        "b\xe2\x82"
        "c\xc0\xaf"
        "d\n"
        "quote: a\"b\\c\n";
    const char *props[] = {"tab", "cr", "ctrl", "del", "utf", "bad", "quote"};
    const char *expected =
        "{\n"
        "\"100\":{"
        "\"tab\": \"a\\tb\","
        "\"cr\": \"a\\rb\","
        "\"ctrl\": \"a\\u0001b\\u001fc\","
        "\"del\": \"a\x7f"
        "b\","
        "\"utf\": \"caf\xc3\xa9 \xe2\x82\xac\","
        "\"bad\": \"a\xef\xbf\xbd"
        "b\xef\xbf\xbd\xef\xbf\xbd"
        "c\xef\xbf\xbd\xef\xbf\xbd"
        "d\","
        "\"quote\": \"a\\\"b\\\\c\"}"
        "\n}\n";

    ck_assert(memdb_mkdir(memdb, "nodes", 0, ctime) == 0);
    ck_assert(memdb_mkdir(memdb, "nodes/testnode", 0, ctime) == 0);
    ck_assert(memdb_mkdir(memdb, "nodes/testnode/qemu-server", 0, ctime) == 0);
    ck_assert(memdb_create(memdb, "nodes/testnode/qemu-server/100.conf", 0, ctime) == 0);
    ck_assert(
        memdb_write(
            memdb, "nodes/testnode/qemu-server/100.conf", 0, ctime, conf, sizeof(conf) - 1, 0, 1
        ) == sizeof(conf) - 1
    );

    GString *str = g_string_new(NULL);
    ck_assert(
        cfs_create_guest_conf_properties_msg(str, memdb, props, G_N_ELEMENTS(props), 100) == 0
    );
    ck_assert_msg(strcmp(str->str, expected) == 0, "unexpected reply: %s", str->str);
    ck_assert(g_utf8_validate(str->str, str->len, NULL));
    g_string_free(str, TRUE);
}
END_TEST

static void write_guest_config(guint32 vmid, const char *conf) {
    char *path = g_strdup_printf("nodes/testnode/qemu-server/%u.conf", vmid);

    memdb_tree_entry_t *te = memdb_getattr(memdb, "nodes");
    if (!te) {
        ck_assert(memdb_mkdir(memdb, "nodes", 0, 1234) == 0);
        ck_assert(memdb_mkdir(memdb, "nodes/testnode", 0, 1234) == 0);
        ck_assert(memdb_mkdir(memdb, "nodes/testnode/qemu-server", 0, 1234) == 0);
    }
    memdb_tree_entry_free(te);

    ck_assert(memdb_create(memdb, path, 0, 1234) == 0);
    ck_assert(memdb_write(memdb, path, 0, 1234, conf, strlen(conf), 0, 1) == strlen(conf));
    g_free(path);
}

static void assert_guest_properties(guint32 vmid, const char **props, int count, const char *json) {
    GString *str = g_string_new(NULL);
    ck_assert(cfs_create_guest_conf_properties_msg(str, memdb, props, count, vmid) == 0);
    ck_assert_msg(strcmp(str->str, json) == 0, "unexpected reply: %s", str->str);
    g_string_free(str, TRUE);
}

/* the same values the Perl config parser sees: the last occurrence of the top-level section */
START_TEST(test_guest_config_properties_last_wins) {
    const char *meta[] = {"meta"};
    const char *lock_meta[] = {"lock", "meta"};

    write_guest_config(101, "meta: uid=1\nmeta: uid=2\nmeta: uid=3\n[snap]\nmeta: uid=4\n");
    assert_guest_properties(101, meta, 1, "{\n\"101\":{\"meta\": \"uid=3\"}\n}\n");

    /* another property repeating must not end the search early */
    write_guest_config(102, "lock: a\nlock: b\nlock: c\nmeta: uid=1\n");
    assert_guest_properties(
        102, lock_meta, 2, "{\n\"102\":{\"lock\": \"c\",\"meta\": \"uid=1\"}\n}\n"
    );

    /* the last line counts without a newline too */
    write_guest_config(103, "lock: a\nmeta: uid=1");
    assert_guest_properties(103, meta, 1, "{\n\"103\":{\"meta\": \"uid=1\"}\n}\n");
    write_guest_config(104, "meta: uid=1");
    assert_guest_properties(104, meta, 1, "{\n\"104\":{\"meta\": \"uid=1\"}\n}\n");
}
END_TEST

/* not in status.h, it is only called by the kvstore delivery */
gboolean cfs_kvstore_node_set(uint32_t nodeid, const char *key, gconstpointer data, size_t len);

/* a quote, a backslash, a control character and a byte that is not valid UTF-8 */
#define ODD "a\"b\\c\001d\xff"
#define ODD_JSON "a\\\"b\\\\c\\u0001d\xef\xbf\xbd"

static void assert_json_bytes(GString *str) {
    ck_assert(g_utf8_validate(str->str, str->len, NULL));
    for (gsize i = 0; i < str->len; i++) {
        ck_assert((unsigned char)str->str[i] >= 0x20 || str->str[i] == '\n');
    }
}

START_TEST(test_version_and_members_json) {
    cfs_clinfo_t *clinfo = cfs_clinfo_new("cl" ODD, 1);
    cfs_clinfo_add_node(clinfo, cfs_clnode_new("testnode", 1, 1));
    cfs_clinfo_add_node(clinfo, cfs_clnode_new("n" ODD, 2, 1));
    cfs_status_set_clinfo(clinfo);

    const char ip[] = "10.0.0.1" ODD;
    ck_assert(cfs_status_set("k" ODD, "x", 1) == 0);
    ck_assert(cfs_status_set("nodeip", (gpointer)ip, sizeof(ip)) == 0);
    ck_assert(cfs_kvstore_node_set(2, "r" ODD, "y", 1));

    GString *str = g_string_new(NULL);

    ck_assert(cfs_create_version_msg(str) == 0);
    assert_json_bytes(str);
    ck_assert(strstr(str->str, "\"k" ODD_JSON "\": 0") != NULL);
    ck_assert(strstr(str->str, "\"n" ODD_JSON "\": {\n\"r" ODD_JSON "\": 0") != NULL);

    g_string_truncate(str, 0);
    ck_assert(cfs_create_memberlist_msg(str) == 0);
    assert_json_bytes(str);
    ck_assert(strstr(str->str, "\"name\": \"cl" ODD_JSON "\"") != NULL);
    ck_assert(strstr(str->str, "\"n" ODD_JSON "\": { \"id\": 2") != NULL);
    ck_assert(strstr(str->str, "\"ip\": \"10.0.0.1" ODD_JSON "\"") != NULL);

    g_string_free(str, TRUE);
}
END_TEST

START_TEST(test_path_is_cluster_id) {
    ck_assert(path_is_cluster_id("cluster-id"));
    ck_assert(path_is_cluster_id("/cluster-id"));
    ck_assert(path_is_cluster_id("//cluster-id/"));

    ck_assert(!path_is_cluster_id(""));
    ck_assert(!path_is_cluster_id("/"));
    ck_assert(!path_is_cluster_id("cluster-i"));
    ck_assert(!path_is_cluster_id("cluster-id.new"));
    ck_assert(!path_is_cluster_id("cluster-id/x"));
    ck_assert(!path_is_cluster_id("nodes/n1/cluster-id"));
}
END_TEST

START_TEST(test_cluster_id_fuse_read_only) {
    time_t ctime = 1234;
    const char *id = "abcdefghijklmnopqrst\n";
    gpointer data;
    struct fuse_file_info fi = {0};
    struct fuse_file_info fi_write = {.flags = O_WRONLY};
    struct fuse_file_info fi_trunc = {.flags = O_RDONLY | O_TRUNC};
    struct fuse_file_info fi_append = {.flags = O_RDONLY | O_APPEND};
    struct timespec tv[2] = {{.tv_sec = 42}, {.tv_sec = 42}};
    struct stat stbuf;

    cfs_plug_t *plug = (cfs_plug_t *)cfs_plug_memdb_new("memdb", memdb, NULL);
    ck_assert(plug != NULL);

    ck_assert(plug->ops->create(plug, "cluster-id", 0644, &fi) == -EACCES);
    ck_assert(plug->ops->mkdir(plug, "cluster-id", 0755) == -EACCES);
    ck_assert(memdb_read(memdb, "cluster-id", &data) == -ENOENT);

    /* pmxcfs itself goes to the memdb directly */
    ck_assert(memdb_create(memdb, "cluster-id", 0, ctime) == 0);
    ck_assert(memdb_write(memdb, "cluster-id", 0, ctime, id, 21, 0, 1) == 21);

    memdb_tree_entry_t *before = memdb_getattr(memdb, "cluster-id");
    ck_assert(before != NULL);

    ck_assert(plug->ops->open(plug, "cluster-id", &fi) == 0);
    ck_assert(plug->ops->open(plug, "cluster-id", &fi_write) == -EACCES);
    ck_assert(plug->ops->open(plug, "cluster-id", &fi_trunc) == -EACCES);
    ck_assert(plug->ops->open(plug, "cluster-id", &fi_append) == -EACCES);
    ck_assert(plug->ops->write(plug, "cluster-id", "x", 1, 0, &fi) == -EACCES);
    ck_assert(plug->ops->truncate(plug, "cluster-id", 0) == -EACCES);
    ck_assert(plug->ops->unlink(plug, "cluster-id") == -EACCES);
    ck_assert(plug->ops->rename(plug, "cluster-id", "moved") == -EACCES);
    ck_assert(plug->ops->mkdir(plug, "cluster-id", 0755) == -EACCES);
    ck_assert(plug->ops->utimens(plug, "cluster-id", tv) == -EACCES);

    ck_assert(plug->ops->create(plug, "other", 0644, &fi) == 0);
    ck_assert(plug->ops->write(plug, "other", "x", 1, 0, &fi) == 1);
    ck_assert(plug->ops->rename(plug, "other", "cluster-id") == -EACCES);

    ck_assert(memdb_read(memdb, "cluster-id", &data) == 21);
    ck_assert(memcmp(data, id, 21) == 0);
    g_free(data);

    /* not even the metadata changed */
    memdb_tree_entry_t *after = memdb_getattr(memdb, "cluster-id");
    ck_assert(after != NULL);
    ck_assert(after->version == before->version);
    ck_assert(after->mtime == before->mtime);
    memdb_tree_entry_free(before);
    memdb_tree_entry_free(after);

    cfs_set_quorate(1, TRUE);
    ck_assert(plug->ops->getattr(plug, "cluster-id", &stbuf) == 0);
    ck_assert((stbuf.st_mode & 0777) == 0444);
    ck_assert(plug->ops->getattr(plug, "other", &stbuf) == 0);
    ck_assert((stbuf.st_mode & 0777) == 0666);

    /* a directory at the path, as a node without the check can create, stays removable */
    ck_assert(memdb_delete(memdb, "cluster-id", 0, ctime) == 0);
    ck_assert(memdb_mkdir(memdb, "cluster-id", 0, ctime) == 0);
    ck_assert(plug->ops->rmdir(plug, "cluster-id") == 0);

    plug->destroy_plug(plug);
}
END_TEST

START_TEST(test_cluster_id_is_valid) {
    ck_assert(cluster_id_is_valid("abcdefghijklmnopqrst\n", 21));
    ck_assert(cluster_id_is_valid("uvwxyz234567abcdefgh\n", 21));
    ck_assert(cluster_id_is_valid("abcdefghijklmnopqrst", 20));

    ck_assert(!cluster_id_is_valid(NULL, 21));
    ck_assert(!cluster_id_is_valid("", 0));
    ck_assert(!cluster_id_is_valid("abcdefghijklmno", 15));
    ck_assert(!cluster_id_is_valid("abcdefghijklmnop", 16));
    ck_assert(!cluster_id_is_valid("abcdefghijklmnop\n", 17));
    ck_assert(!cluster_id_is_valid("abcdefghijklmnopqrs\n", 20));
    ck_assert(!cluster_id_is_valid("abcdefghijklmnopqrstu", 21));
    ck_assert(!cluster_id_is_valid("abcdefghijklmnopqrstu\n", 22));
    ck_assert(!cluster_id_is_valid("abcdefghijklmnopqrst\n\n", 22));
    ck_assert(!cluster_id_is_valid("abcdefghijklmnopqrst ", 21));
    ck_assert(!cluster_id_is_valid("Abcdefghijklmnopqrst\n", 21));
    ck_assert(!cluster_id_is_valid("abcdefghijklmnopqrs1\n", 21));
    ck_assert(!cluster_id_is_valid("abcdefghijklmnopqrs8\n", 21));
    ck_assert(!cluster_id_is_valid("abcdefgh\0jklmnopqrst\n", 21));
}
END_TEST

START_TEST(test_cluster_id_generate) {
    char id1[CLUSTER_ID_FILE_SIZE], id2[CLUSTER_ID_FILE_SIZE];

    ck_assert(cluster_id_generate(id1));
    ck_assert(cluster_id_generate(id2));

    ck_assert(cluster_id_is_valid(id1, sizeof(id1)));
    ck_assert(cluster_id_is_valid(id2, sizeof(id2)));
    ck_assert(memcmp(id1, id2, sizeof(id1)) != 0);
}
END_TEST

START_TEST(test_cluster_id_state) {
    time_t ctime = 1234;

    ck_assert(cluster_id_state(memdb) == CLUSTER_ID_MISSING);

    ck_assert(memdb_create(memdb, "cluster-id", 0, ctime) == 0);
    ck_assert(cluster_id_state(memdb) == CLUSTER_ID_INVALID);

    ck_assert(memdb_write(memdb, "cluster-id", 0, ctime, "abcdefghijklmnopqrst\n", 21, 0, 1) == 21);
    ck_assert(cluster_id_state(memdb) == CLUSTER_ID_VALID);

    ck_assert(memdb_write(memdb, "cluster-id", 0, ctime, "foo", 3, 0, 1) == 3);
    ck_assert(cluster_id_state(memdb) == CLUSTER_ID_INVALID);

    ck_assert(memdb_delete(memdb, "cluster-id", 0, ctime) == 0);
    ck_assert(memdb_mkdir(memdb, "cluster-id", 0, ctime) == 0);
    ck_assert(cluster_id_state(memdb) == CLUSTER_ID_NOT_A_FILE);
}
END_TEST

START_TEST(test_cluster_id_standalone) {
    time_t ctime = 1234;
    gpointer data;
    int len;

    cluster_id_ensure_standalone(memdb);
    len = memdb_read(memdb, "cluster-id", &data);
    ck_assert(len == CLUSTER_ID_FILE_SIZE);
    ck_assert(cluster_id_is_valid(data, len));

    /* an existing ID is kept */
    char id[CLUSTER_ID_FILE_SIZE];
    memcpy(id, data, sizeof(id));
    g_free(data);

    cluster_id_ensure_standalone(memdb);
    ck_assert(memdb_read(memdb, "cluster-id", &data) == CLUSTER_ID_FILE_SIZE);
    ck_assert(memcmp(data, id, sizeof(id)) == 0);
    g_free(data);

    /* an empty file is what a crash between creating and writing leaves behind, it gets filled */
    ck_assert(memdb_delete(memdb, "cluster-id", 0, ctime) == 0);
    ck_assert(memdb_create(memdb, "cluster-id", 0, ctime) == 0);

    cluster_id_ensure_standalone(memdb);
    len = memdb_read(memdb, "cluster-id", &data);
    ck_assert(len == CLUSTER_ID_FILE_SIZE);
    ck_assert(cluster_id_is_valid(data, len));
    g_free(data);

    /* so is invalid content */
    ck_assert(memdb_write(memdb, "cluster-id", 0, ctime, "foo\n", 4, 0, 1) == 4);

    cluster_id_ensure_standalone(memdb);
    len = memdb_read(memdb, "cluster-id", &data);
    ck_assert(len == CLUSTER_ID_FILE_SIZE);
    ck_assert(cluster_id_is_valid(data, len));
    g_free(data);

    /* a valid ID without newline is kept as is */
    ck_assert(memdb_write(memdb, "cluster-id", 0, ctime, "abcdefghijklmnopqrst", 20, 0, 1) == 20);

    cluster_id_ensure_standalone(memdb);
    ck_assert(memdb_read(memdb, "cluster-id", &data) == 20);
    ck_assert(memcmp(data, "abcdefghijklmnopqrst", 20) == 0);
    g_free(data);

    /* an ID with only 16 characters is malformed like anything else and gets replaced */
    ck_assert(memdb_write(memdb, "cluster-id", 0, ctime, "abcdefghijklmnop\n", 17, 0, 1) == 17);

    cluster_id_ensure_standalone(memdb);
    len = memdb_read(memdb, "cluster-id", &data);
    ck_assert(len == CLUSTER_ID_FILE_SIZE);
    ck_assert(cluster_id_is_valid(data, len));
    g_free(data);

    /* a directory is left for the admin and does not stop the start */
    ck_assert(memdb_delete(memdb, "cluster-id", 0, ctime) == 0);
    ck_assert(memdb_mkdir(memdb, "cluster-id", 0, ctime) == 0);

    cluster_id_ensure_standalone(memdb);
    memdb_tree_entry_t *te = memdb_getattr(memdb, "cluster-id");
    ck_assert(te != NULL);
    ck_assert(te->type == DT_DIR);
    memdb_tree_entry_free(te);
}
END_TEST

static void sql_exec(const char *statement) {
    sqlite3 *db = NULL;
    ck_assert(sqlite3_open(TESTDB, &db) == SQLITE_OK);
    ck_assert(sqlite3_exec(db, statement, NULL, NULL, NULL) == SQLITE_OK);
    ck_assert(sqlite3_close(db) == SQLITE_OK);
}

/* Storing fails for the rows of the ID file that match the condition. The start goes on without a
 * readable ID, and the next start with a working database stores one. */
static void check_standalone_store_failure(const char *condition) {
    char *trigger = g_strdup_printf(
        "CREATE TRIGGER fail_cluster_id BEFORE INSERT ON tree WHEN NEW.name = 'cluster-id'%s "
        "BEGIN SELECT RAISE(FAIL, 'injected failure'); END;",
        condition
    );
    sql_exec(trigger);
    g_free(trigger);

    cluster_id_ensure_standalone(memdb);
    ck_assert(memdb->errors);
    ck_assert(cluster_id_state(memdb) != CLUSTER_ID_VALID);

    gpointer data = NULL;
    ck_assert(memdb_read(memdb, "cluster-id", &data) <= 0);
    g_free(data);

    memdb_close(memdb);
    sql_exec("DROP TRIGGER fail_cluster_id;");
    memdb = memdb_open(TESTDB);
    ck_assert(memdb != NULL);

    ck_assert(cluster_id_state(memdb) != CLUSTER_ID_VALID);
    cluster_id_ensure_standalone(memdb);
    ck_assert(cluster_id_state(memdb) == CLUSTER_ID_VALID);
}

START_TEST(test_cluster_id_standalone_create_failure) { check_standalone_store_failure(""); }
END_TEST

/* creating the empty file works, storing the ID fails */
START_TEST(test_cluster_id_standalone_write_failure) {
    check_standalone_store_failure(" AND length(NEW.data) > 0");
}
END_TEST

START_TEST(test_cluster_id_standalone_replace_failure) {
    ck_assert(memdb_create(memdb, "cluster-id", 0, 1234) == 0);
    ck_assert(memdb_write(memdb, "cluster-id", 0, 1234, "foo\n", 4, 0, 1) == 4);

    check_standalone_store_failure("");
}
END_TEST

START_TEST(test_truncate_grow) {
    const char *fn = "/f1";
    time_t ctime = 1234;
    gpointer data;

    ck_assert(memdb_create(memdb, fn, 0, ctime) == 0);

    /* growing without writing data, as a plain truncate does, still has to leave the entry
     * backed by an allocation */
    ck_assert(memdb_write(memdb, fn, 0, ctime, NULL, 0, 16, 1) == 0);

    ck_assert(memdb_read(memdb, fn, &data) == 16);
    ck_assert(data != NULL);
    g_free(data);
}
END_TEST

START_TEST(test_indextest1) {
    char namebuf[100];

    time_t ctime = 1234;
    int testsize = 1024 * 32;
    gchar *testdata = g_malloc0(testsize);

    for (int i = 0; i < 100; i++) {
        sprintf(namebuf, "testfile%d", i);

        ck_assert(memdb_create(memdb, namebuf, 0, ctime) == 0);
        ck_assert(memdb_write(memdb, namebuf, 0, ctime, testdata, testsize, 0, 0) == testsize);
    }

    struct statvfs stbuf;
    ck_assert(memdb_statfs(memdb, &stbuf) == 0);

    int count = stbuf.f_files - stbuf.f_ffree;
    ck_assert(count == 101);

    memdb_index_t *idx = memdb_encode_index(memdb->index, memdb->root);
    ck_assert(idx != NULL);

    ck_assert(idx->version == 201);
    ck_assert(idx->last_inode == 200);
    ck_assert(idx->writer == 0);
    ck_assert(idx->size == 101);
    ck_assert(idx->bytes == (101 * 40 + sizeof(memdb_index_t)));

    GChecksum *sha256 = g_checksum_new(G_CHECKSUM_SHA256);
    ck_assert(sha256 != NULL);
    g_checksum_update(sha256, (unsigned char *)idx, idx->bytes);
    const char *csum = g_checksum_get_string(sha256);
    ck_assert_msg(
        strcmp(csum, "913fd95015af9d93f10dd51ba2a7bb11351bcfe040be21e95fcba834adc3ec10") == 0,
        "wrong idx checksum %s", csum
    );
    g_free(idx);
    g_free(testdata);
}
END_TEST

START_TEST(test_dirtest1) {
    const char *dn = "/dir1";
    const char *sdn = "/dir1/sdir1";
    time_t ctime = 1234;

    ck_assert(memdb_mkdir(memdb, sdn, 0, ctime) == -ENOENT);
    ck_assert(memdb_delete(memdb, dn, 0, ctime) == -ENOENT);

    ck_assert(memdb_mkdir(memdb, dn, 0, ctime) == 0);
    ck_assert(memdb_mkdir(memdb, dn, 0, ctime) == -EEXIST);
    ck_assert(memdb_mkdir(memdb, sdn, 0, ctime) == 0);
    ck_assert(memdb_mkdir(memdb, sdn, 0, ctime) == -EEXIST);
    ck_assert(memdb_delete(memdb, dn, 0, ctime) == -ENOTEMPTY);
    ck_assert(memdb_delete(memdb, sdn, 0, ctime) == 0);
    ck_assert(memdb_delete(memdb, dn, 0, ctime) == 0);
}
END_TEST

START_TEST(test_filetest1) {
    const char *dn = "/dir1";
    const char *fn = "/dir1/f1";
    time_t ctime = 1234;
    gpointer data;

    char buf[1024];
    memset(buf, 0, sizeof(buf));

    ck_assert(memdb_read(memdb, fn, &data) == -ENOENT);

    ck_assert(memdb_mkdir(memdb, dn, 0, ctime) == 0);

    ck_assert(memdb_read(memdb, fn, &data) == -ENOENT);

    ck_assert(memdb_write(memdb, fn, 0, ctime, buf, sizeof(buf), 0, 0) == -ENOENT);

    ck_assert(memdb_create(memdb, fn, 0, ctime) == 0);

    ck_assert(memdb_write(memdb, fn, 0, ctime, buf, sizeof(buf), 0, 0) == sizeof(buf));

    ck_assert(memdb_read(memdb, fn, &data) == sizeof(buf));

    ck_assert(memcmp(buf, data, sizeof(buf)) == 0);

    g_free(data);

    ck_assert(memdb_write(memdb, fn, 0, ctime, "0123456789", 10, 0, 1) == 10);

    ck_assert(memdb_read(memdb, fn, &data) == 10);
    g_free(data);

    ck_assert(memdb_write(memdb, fn, 0, ctime, "X", 1, 3, 0) == 1);

    ck_assert(memdb_write(memdb, fn, 0, ctime, "X", 1, 6, 0) == 1);

    ck_assert(memdb_read(memdb, fn, &data) == 10);

    ck_assert(strncmp(data, "012X45X789", 10) == 0);
    g_free(data);

    ck_assert(memdb_delete(memdb, fn, 0, ctime) == 0);

    ck_assert(memdb_delete(memdb, fn, 0, ctime) == -ENOENT);

    ck_assert(memdb_delete(memdb, dn, 0, ctime) == 0);
}
END_TEST

/* Nornmaly, parent inode number is always less than contained inode,
 * but this is not allways the case. A simple move can destroy that
 * ordering. This code test the placeholder algorithm in
 * bdb_backend_load_index()
 */
START_TEST(test_loaddb1) {
    time_t ctime = 1234;

    ck_assert(memdb_mkdir(memdb, "dir1", 0, ctime) == 0);

    ck_assert(memdb_create(memdb, "dir1/file1", 0, ctime) == 0);

    ck_assert(memdb_create(memdb, "dir1/file2", 0, ctime) == 0);

    ck_assert(memdb_mkdir(memdb, "dir2", 0, ctime) == 0);

    ck_assert(memdb_rename(memdb, "dir1/file1", "dir2/file1", 0, ctime) == 0);

    ck_assert(memdb_rename(memdb, "dir1/file2", "dir2/file2", 0, ctime) == 0);

    ck_assert(memdb_create(memdb, "dir2/file1", 0, ctime) == -EEXIST);

    ck_assert(memdb_create(memdb, "dir2/file2", 0, ctime) == -EEXIST);

    // memdb_dump(memdb);

    memdb_close(memdb);

    memdb = memdb_open(TESTDB);
    ck_assert(memdb != NULL);

    ck_assert(memdb_create(memdb, "dir2/file1", 0, ctime) == -EEXIST);

    ck_assert(memdb_create(memdb, "dir2/file2", 0, ctime) == -EEXIST);

    // memdb_dump(memdb);
}
END_TEST

START_TEST(test_rename_same_entry) {
    time_t ctime = 1234;
    gpointer data;

    ck_assert(memdb_mkdir(memdb, "dir1", 0, ctime) == 0);
    ck_assert(memdb_create(memdb, "dir1/file1", 0, ctime) == 0);
    ck_assert(memdb_write(memdb, "dir1/file1", 0, ctime, "data", 4, 0, 0) == 4);

    /* both paths resolve to the same entry, so this has to be a no-op */
    ck_assert(memdb_rename(memdb, "dir1/file1", "dir1//file1", 0, ctime) == 0);

    ck_assert(memdb_read(memdb, "dir1/file1", &data) == 4);
    ck_assert(memcmp(data, "data", 4) == 0);
    g_free(data);
}
END_TEST

START_TEST(test_rename_keeps_destination_on_error) {
    time_t ctime = 1234;
    gpointer data;

    ck_assert(memdb_mkdir(memdb, "src", 0, ctime) == 0);
    ck_assert(memdb_create(memdb, "src/keep", 0, ctime) == 0);
    ck_assert(memdb_mkdir(memdb, "dst", 0, ctime) == 0);
    ck_assert(memdb_create(memdb, "dst/file", 0, ctime) == 0);
    ck_assert(memdb_write(memdb, "dst/file", 0, ctime, "keepme", 6, 0, 0) == 6);

    /* a non-empty source directory cannot be renamed, so the destination must survive */
    ck_assert(memdb_rename(memdb, "src", "dst/file", 0, ctime) == -ENOTEMPTY);

    ck_assert(memdb_read(memdb, "dst/file", &data) == 6);
    ck_assert(memcmp(data, "keepme", 6) == 0);
    g_free(data);

    ck_assert(memdb_read(memdb, "src/keep", &data) == 0);
}
END_TEST

START_TEST(test_lock_timestamp_preserved) {
    time_t ctime = 1234;
    const char *path = "priv/lock/test";

    ck_assert(memdb_mkdir(memdb, "priv", 0, ctime) == 0);
    ck_assert(memdb_mkdir(memdb, "priv/lock", 0, ctime) == 0);
    ck_assert(memdb_mkdir(memdb, path, 0, ctime) == 0);

    memdb_lock_info_t *lock = g_hash_table_lookup(memdb->locks, path);
    ck_assert(lock != NULL);
    lock->ltime = 42;

    /* an unchanged lock directory has to keep its age, else it never expires */
    memdb_update_locks(memdb);

    lock = g_hash_table_lookup(memdb->locks, path);
    ck_assert(lock != NULL);
    ck_assert(lock->ltime == 42);
}
END_TEST

START_TEST(test_loaddb2) {
    time_t ctime = 1234;

    ck_assert(memdb_mkdir(memdb, "dir1", 0, ctime) == 0);

    ck_assert(memdb_mkdir(memdb, "dir1/sd1", 0, ctime) == 0);

    ck_assert(memdb_create(memdb, "dir1/file1", 0, ctime) == 0);

    ck_assert(memdb_create(memdb, "dir1/file2", 0, ctime) == 0);

    ck_assert(memdb_mkdir(memdb, "dir2", 0, ctime) == 0);

    ck_assert(memdb_rename(memdb, "dir1/sd1", "dir2/sd1", 0, ctime) == 0);

    ck_assert(memdb_rename(memdb, "dir1/file1", "dir2/sd1/file1", 0, ctime) == 0);

    ck_assert(memdb_rename(memdb, "dir1/file2", "dir2/sd1/file2", 0, ctime) == 0);

    ck_assert(memdb_create(memdb, "dir2/file3", 0, ctime) == 0);

    ck_assert(memdb_mkdir(memdb, "dir2/sd1", 0, ctime) == -EEXIST);

    // memdb_dump(memdb);

    memdb_close(memdb);

    memdb = memdb_open(TESTDB);
    ck_assert(memdb != NULL);

    ck_assert(memdb_mkdir(memdb, "dir2/sd1", 0, ctime) == -EEXIST);

    // memdb_dump(memdb);
}
END_TEST

static void add_test(Suite *s, _TEST_TYPE tf, const char *name) {
    TCase *tc = tcase_create(name);
    tcase_add_checked_fixture(tc, setup, teardown);
    tcase_add_test(tc, tf);
    suite_add_tcase(s, tc);
}

static Suite *memdb_suite(void) {
    Suite *s = suite_create("memdb");

    add_test(s, test_dirtest1, "dirtest1");

    add_test(s, test_filetest1, "filetest1");

    add_test(s, test_truncate_grow, "truncate_grow");

    add_test(s, test_path_is_private, "path_is_private");

    add_test(s, test_guest_config_properties_json, "guest_config_properties_json");

    add_test(s, test_version_and_members_json, "version_and_members_json");

    add_test(s, test_guest_config_properties_last_wins, "guest_config_properties_last_wins");

    add_test(s, test_path_is_cluster_id, "path_is_cluster_id");

    add_test(s, test_cluster_id_fuse_read_only, "cluster_id_fuse_read_only");

    add_test(s, test_cluster_id_is_valid, "cluster_id_is_valid");

    add_test(s, test_cluster_id_generate, "cluster_id_generate");

    add_test(s, test_cluster_id_state, "cluster_id_state");

    add_test(s, test_cluster_id_standalone, "cluster_id_standalone");

    add_test(s, test_cluster_id_standalone_create_failure, "cluster_id_standalone_create_failure");

    add_test(s, test_cluster_id_standalone_write_failure, "cluster_id_standalone_write_failure");

    add_test(
        s, test_cluster_id_standalone_replace_failure, "cluster_id_standalone_replace_failure"
    );

    add_test(s, test_indextest1, "indextest1");

    add_test(s, test_loaddb1, "loaddb1");

    add_test(s, test_loaddb2, "loaddb2");

    add_test(s, test_lock_timestamp_preserved, "lock_timestamp_preserved");

    add_test(s, test_rename_same_entry, "rename_same_entry");

    add_test(s, test_rename_keeps_destination_on_error, "rename_keeps_destination_on_error");

    return s;
}

int main(void) {
    int number_failed;

    cfs_status_init();

    Suite *s = memdb_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
