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

/* Runs several dcdb instances in one process, each with its own memdb, and replaces the CPG
 * transport with an ordered in-process queue, so that membership changes, syncs and the cluster ID
 * generation can be tested without corosync. The sources are included to reach the static CPG
 * callbacks and the generation state of dcdb.c. That state exists once per pmxcfs process, so each
 * call into an instance swaps in a copy of its own. The quorate flag, the corosync membership and
 * the configured nodes of status.c stay common to all instances. */

#include <check.h>
#include <stdint.h>

#include "dfsm.c"
#undef G_LOG_DOMAIN
#include "dcdb.c"

#if CHECK_MAJOR_VERSION == 0 && CHECK_MINOR_VERSION <= 10
#define _TEST_TYPE TFun
#else
#define _TEST_TYPE const TTest *
#endif

cfs_t cfs = {
    .debug = 0,
    .nodename = "testnode",
};

typedef struct {
    uint32_t nodeid;
    uint32_t pid;
    size_t len;
    void *data;
} packet_t;

static GQueue packets = G_QUEUE_INIT;

/* the send with this number fails, counted from 1 since send_nr got reset, 0 for none */
static int fail_send_nr;
static int send_nr;

typedef struct {
    dfsm_t *dfsm;
    cluster_id_gen_t gen;
} member_state_t;

static member_state_t member_states[8];
/* the instance whose state the globals of dcdb.c hold */
static member_state_t *current_state;

static void save_state(member_state_t *state) { state->gen = cluster_id_gen; }

static void load_state(const member_state_t *state) { cluster_id_gen = state->gen; }

static member_state_t *find_state(dfsm_t *dfsm) {
    for (size_t i = 0; i < G_N_ELEMENTS(member_states); i++) {
        if (member_states[i].dfsm == dfsm) {
            return &member_states[i];
        }
    }

    ck_abort_msg("no state for this instance");
    return NULL;
}

/* to call before anything that can run code of dcdb.c for this instance */
static void enter(dfsm_t *dfsm) {
    member_state_t *state = find_state(dfsm);

    if (state != current_state) {
        if (current_state) {
            save_state(current_state);
        }
        load_state(state);
        current_state = state;
    }
}

/* the generation state of an instance as of its last call */
static const member_state_t *state_of(dfsm_t *dfsm) {
    if (current_state) {
        save_state(current_state);
    }

    return find_state(dfsm);
}

cs_error_t cpg_context_get(cpg_handle_t handle, void **context) {
    *context = (void *)(uintptr_t)handle;
    return CS_OK;
}

cs_error_t cpg_mcast_joined(
    cpg_handle_t handle, cpg_guarantee_t guarantee, const struct iovec *iov, unsigned int iov_len
) {
    dfsm_t *sender = (dfsm_t *)(uintptr_t)handle;

    if (++send_nr == fail_send_nr) {
        return CS_ERR_LIBRARY;
    }

    packet_t *p = g_new0(packet_t, 1);

    p->nodeid = sender->nodeid;
    p->pid = sender->pid;

    for (unsigned int i = 0; i < iov_len; i++) {
        p->len += iov[i].iov_len;
    }

    p->data = g_malloc(p->len);

    size_t pos = 0;
    for (unsigned int i = 0; i < iov_len; i++) {
        if (iov[i].iov_len) {
            memcpy((char *)p->data + pos, iov[i].iov_base, iov[i].iov_len);
        }
        pos += iov[i].iov_len;
    }

    g_queue_push_tail(&packets, p);

    return CS_OK;
}

/* delivers the next queued message to the given nodes, FALSE if there is none */
static gboolean deliver_next(dfsm_t **nodes, int count) {
    packet_t *p = g_queue_pop_head(&packets);
    if (!p) {
        return FALSE;
    }

    for (int i = 0; i < count; i++) {
        enter(nodes[i]);
        dfsm_cpg_deliver_callback(
            nodes[i]->cpg_handle, &nodes[i]->cpg_group_name, p->nodeid, p->pid, p->data, p->len
        );
        ck_assert(dfsm_get_mode(nodes[i]) < DFSM_ERROR_MODE_START);
    }

    g_free(p->data);
    g_free(p);

    return TRUE;
}

/* delivers all queued messages, including those sent meanwhile, to the given nodes in order */
static void pump(dfsm_t **nodes, int count) {
    int rounds = 0;

    while (deliver_next(nodes, count)) {
        ck_assert(++rounds < 1000);
    }
}

/* the messages of a node that left before they got delivered */
static void drop_packets(void) {
    packet_t *p;

    while ((p = g_queue_pop_head(&packets))) {
        g_free(p->data);
        g_free(p);
    }
}

/* the databases of all tests, removed at the end whatever the tests left behind */
static char *tmpdir;

static memdb_t *open_db(const char *name) {
    char *filename = g_build_filename(tmpdir, name, NULL);
    unlink(filename);
    memdb_t *memdb = memdb_open(filename);
    g_free(filename);
    ck_assert(memdb != NULL);

    /* a node in cluster mode always has a corosync.conf */
    ck_assert(memdb_create(memdb, "corosync.conf", 0, 100) == 0);

    return memdb;
}

static dfsm_t *start_node(memdb_t *memdb, uint32_t nodeid) {
    dfsm_t *dfsm = dcdb_new(memdb);
    ck_assert(dfsm != NULL);

    dfsm->cpg_handle = (uintptr_t)dfsm;
    dfsm->joined = TRUE; /* messages are only sent while joined */
    dfsm->nodeid = nodeid;
    dfsm->pid = 100 + nodeid;

    member_state_t *state = find_state(NULL); /* a free slot */
    state->dfsm = dfsm;

    return dfsm;
}

static void stop_nodes(dfsm_t **nodes, memdb_t **dbs, int count) {
    for (int i = 0; i < count; i++) {
        member_state_t *state = find_state(nodes[i]);
        if (state == current_state) {
            save_state(state);
            load_state(&(member_state_t){0});
            current_state = NULL;
        }
        g_free(state->gen.blocked_reason);
        memset(state, 0, sizeof(*state));

        nodes[i]->cpg_handle = 0;
        dfsm_destroy(nodes[i]);
        memdb_close(dbs[i]);
    }
}

/* the nodes in the corosync configuration, as the confdb service reads them */
static void set_config_node_ids(const uint32_t *ids, size_t count) {
    cfs_clinfo_t *clinfo = cfs_clinfo_new("test", 1);

    for (size_t i = 0; i < count; i++) {
        char *name = g_strdup_printf("node%u", ids[i]);
        cfs_clinfo_add_node(clinfo, cfs_clnode_new(name, ids[i], 1));
        g_free(name);
    }

    cfs_status_set_clinfo(clinfo);
}

/* nodes 1 to count */
static void set_config_nodes(uint32_t count) {
    uint32_t ids[count];

    for (uint32_t i = 0; i < count; i++) {
        ids[i] = i + 1;
    }

    set_config_node_ids(ids, count);
}

/* a timer tick of the dcdb service on each node, without delivering what it sends */
static void tick_only(dfsm_t **nodes, int count) {
    for (int i = 0; i < count; i++) {
        enter(nodes[i]);
        dfsm_check_in_sync(nodes[i]);
    }
}

static void tick(dfsm_t **nodes, int count) {
    tick_only(nodes, count);
    pump(nodes, count);
}

/* a change of the dcdb group, as seen by its members, without delivering what it causes */
static void change_group(dfsm_t **nodes, int count) {
    struct cpg_address members[count];

    for (int i = 0; i < count; i++) {
        members[i].nodeid = nodes[i]->nodeid;
        members[i].pid = nodes[i]->pid;
        members[i].reason = 0;
    }

    for (int i = 0; i < count; i++) {
        enter(nodes[i]);
        dfsm_cpg_confchg_callback(
            nodes[i]->cpg_handle, &nodes[i]->cpg_group_name, members, count, NULL, 0, members, count
        );
    }
}

static void set_group(dfsm_t **nodes, int count) {
    change_group(nodes, count);
    pump(nodes, count);
}

/* a change of the corosync membership, as the quorum service records it */
static void set_quorum(uint32_t quorate, uint32_t *view, size_t view_len) {
    cfs_set_quorate(quorate, TRUE);
    cfs_set_quorum_members(view, view_len);
}

static void read_id(memdb_t *memdb, char id[CLUSTER_ID_FILE_SIZE]) {
    gpointer data = NULL;

    ck_assert(memdb_read(memdb, "cluster-id", &data) == CLUSTER_ID_FILE_SIZE);
    ck_assert(cluster_id_is_valid(data, CLUSTER_ID_FILE_SIZE));
    memcpy(id, data, CLUSTER_ID_FILE_SIZE);

    g_free(data);
}

static void assert_id(memdb_t *memdb, const char *expected) {
    char id[CLUSTER_ID_FILE_SIZE];

    read_id(memdb, id);
    ck_assert(memcmp(id, expected, CLUSTER_ID_FILE_SIZE) == 0);
}

static void write_id(memdb_t *memdb, const char *id, guint32 writer, guint32 mtime) {
    ck_assert(memdb_create(memdb, "cluster-id", writer, mtime) == 0);
    ck_assert(memdb_write(memdb, "cluster-id", writer, mtime, id, strlen(id), 0, 1) == strlen(id));
}

static void other_writes(memdb_t *memdb, int count) {
    ck_assert(memdb_create(memdb, "other", 2, 100) == 0);
    for (int i = 0; i < count; i++) {
        ck_assert(memdb_write(memdb, "other", 2, 100, "x", 1, 0, 1) == 1);
    }
}

START_TEST(test_single_node_cluster) {
    memdb_t *dbs[] = {open_db("1.db")};
    dfsm_t *nodes[] = {start_node(dbs[0], 1)};
    uint32_t view[] = {1};
    char id[CLUSTER_ID_FILE_SIZE];

    /* without the configured nodes known, nothing happens */
    set_quorum(1, view, 1);
    set_group(nodes, 1);
    ck_assert(cluster_id_state(dbs[0]) == CLUSTER_ID_MISSING);

    set_config_nodes(1);
    tick(nodes, 1);
    read_id(dbs[0], id);

    stop_nodes(nodes, dbs, 1);
}
END_TEST

/* removing nodes from the configuration can lift the node majority blocker */
START_TEST(test_config_nodes_removed) {
    memdb_t *dbs[] = {open_db("1.db"), open_db("2.db")};
    dfsm_t *nodes[] = {start_node(dbs[0], 1), start_node(dbs[1], 2)};
    uint32_t view[] = {1, 2};
    char id[CLUSTER_ID_FILE_SIZE];

    set_config_nodes(4);
    set_quorum(1, view, 2);
    set_group(nodes, 2);
    tick(nodes, 2);
    ck_assert(cluster_id_state(dbs[0]) == CLUSTER_ID_MISSING);

    set_config_nodes(2);
    tick(nodes, 2);
    read_id(dbs[0], id);
    assert_id(dbs[1], id);

    stop_nodes(nodes, dbs, 2);
}
END_TEST

START_TEST(test_only_lowest_generates) {
    memdb_t *dbs[] = {open_db("1.db"), open_db("2.db")};
    dfsm_t *nodes[] = {start_node(dbs[0], 1), start_node(dbs[1], 2)};
    uint32_t view[] = {1, 2};
    char id1[CLUSTER_ID_FILE_SIZE], id2[CLUSTER_ID_FILE_SIZE];

    set_config_nodes(2);
    set_quorum(1, view, 2);
    set_group(nodes, 2);

    read_id(dbs[0], id1);
    read_id(dbs[1], id2);
    ck_assert(memcmp(id1, id2, CLUSTER_ID_FILE_SIZE) == 0);

    /* written by node 1, the lowest */
    memdb_tree_entry_t *te = memdb_getattr(dbs[1], "cluster-id");
    ck_assert(te != NULL);
    ck_assert(te->writer == 1);
    memdb_tree_entry_free(te);

    stop_nodes(nodes, dbs, 2);
}
END_TEST

/* A node with an outdated database starts first and is alone in the group, while corosync, with
 * the other node running, makes it quorate. It must not publish an ID of its own. */
START_TEST(test_stale_node_alone) {
    memdb_t *dbs[] = {open_db("1.db"), open_db("2.db")};
    write_id(dbs[1], "abcdefghijklmnopqrst\n", 2, 100);
    other_writes(dbs[1], 10);

    dfsm_t *nodes[] = {start_node(dbs[0], 1), start_node(dbs[1], 2)};
    uint32_t view[] = {1, 2};

    set_config_nodes(2);
    set_quorum(1, view, 2);
    set_group(nodes, 1);
    tick(nodes, 1);
    ck_assert(cluster_id_state(dbs[0]) == CLUSTER_ID_MISSING);

    set_group(nodes, 2);
    assert_id(dbs[0], "abcdefghijklmnopqrst\n");
    assert_id(dbs[1], "abcdefghijklmnopqrst\n");

    stop_nodes(nodes, dbs, 2);
}
END_TEST

/* Like above, but the outdated node holds the empty file of an interrupted creation. Filling it
 * would make its database the newest one, so its ID would replace the established one. */
START_TEST(test_stale_node_alone_with_empty_file) {
    memdb_t *dbs[] = {open_db("1.db"), open_db("2.db")};
    ck_assert(memdb_create(dbs[0], "cluster-id", 1, 100) == 0);
    write_id(dbs[1], "abcdefghijklmnopqrst\n", 1, 100);

    dfsm_t *nodes[] = {start_node(dbs[0], 1), start_node(dbs[1], 2)};
    uint32_t view[] = {1, 2};

    set_config_nodes(2);
    set_quorum(1, view, 2);
    set_group(nodes, 1);
    tick(nodes, 1);
    ck_assert(cluster_id_state(dbs[0]) == CLUSTER_ID_INVALID);

    set_group(nodes, 2);
    assert_id(dbs[0], "abcdefghijklmnopqrst\n");
    assert_id(dbs[1], "abcdefghijklmnopqrst\n");

    stop_nodes(nodes, dbs, 2);
}
END_TEST

/* Quorate through a QDevice, or two_node, last_man_standing or lowered expected votes, the
 * corosync membership of a lone outdated node is just itself. */
START_TEST(test_lone_node_without_node_majority) {
    memdb_t *dbs[] = {open_db("1.db"), open_db("2.db")};
    write_id(dbs[1], "abcdefghijklmnopqrst\n", 2, 100);

    dfsm_t *nodes[] = {start_node(dbs[0], 1), start_node(dbs[1], 2)};
    uint32_t view1[] = {1}, view12[] = {1, 2};

    set_config_nodes(2);
    set_quorum(1, view1, 1);
    set_group(nodes, 1);
    tick(nodes, 1);
    ck_assert(cluster_id_state(dbs[0]) == CLUSTER_ID_MISSING);

    set_quorum(1, view12, 2);
    set_group(nodes, 2);
    assert_id(dbs[0], "abcdefghijklmnopqrst\n");
    assert_id(dbs[1], "abcdefghijklmnopqrst\n");

    stop_nodes(nodes, dbs, 2);
}
END_TEST

START_TEST(test_half_of_the_nodes) {
    memdb_t *dbs[] = {open_db("1.db"), open_db("2.db")};
    dfsm_t *nodes[] = {start_node(dbs[0], 1), start_node(dbs[1], 2)};
    uint32_t view[] = {1, 2};

    set_config_nodes(4);
    set_quorum(1, view, 2);
    set_group(nodes, 2);
    tick(nodes, 2);
    ck_assert(cluster_id_state(dbs[0]) == CLUSTER_ID_MISSING);
    ck_assert(cluster_id_state(dbs[1]) == CLUSTER_ID_MISSING);

    stop_nodes(nodes, dbs, 2);
}
END_TEST

/* Right after node 4 got removed from the configuration, the corosync membership and the group can
 * still contain it. Of the configured nodes 1, 2 and 3, only node 1 is there. */
START_TEST(test_member_not_configured) {
    memdb_t *dbs[] = {open_db("1.db"), open_db("4.db")};
    dfsm_t *nodes[] = {start_node(dbs[0], 1), start_node(dbs[1], 4)};
    uint32_t view[] = {1, 4}, config[] = {1, 2, 3};

    set_config_nodes(5);
    set_quorum(1, view, 2);
    set_group(nodes, 2);
    ck_assert(cluster_id_state(dbs[0]) == CLUSTER_ID_MISSING);

    set_config_node_ids(config, 3);
    tick(nodes, 2);
    ck_assert(cluster_id_state(dbs[0]) == CLUSTER_ID_MISSING);

    stop_nodes(nodes, dbs, 2);
}
END_TEST

/* Neither gaining quorum nor a corosync membership change causes a sync of the group, the next
 * timer tick acts on them. */
START_TEST(test_quorum_change) {
    memdb_t *dbs[] = {open_db("1.db"), open_db("2.db")};
    dfsm_t *nodes[] = {start_node(dbs[0], 1), start_node(dbs[1], 2)};
    uint32_t view12[] = {1, 2}, view123[] = {1, 2, 3};
    char id[CLUSTER_ID_FILE_SIZE];

    set_config_nodes(3);
    set_quorum(0, view12, 2);
    set_group(nodes, 2);
    tick(nodes, 2);
    ck_assert(cluster_id_state(dbs[0]) == CLUSTER_ID_MISSING);

    /* node 3 only runs corosync */
    set_quorum(1, view123, 3);
    tick(nodes, 2);
    ck_assert(cluster_id_state(dbs[0]) == CLUSTER_ID_MISSING);

    /* node 3 left corosync again, the group did not change */
    set_quorum(1, view12, 2);
    tick(nodes, 2);
    read_id(dbs[0], id);
    assert_id(dbs[1], id);

    stop_nodes(nodes, dbs, 2);
}
END_TEST

/* node 3 joins corosync and the group, in both orders the notifications can arrive */
static void third_node_joins(gboolean quorum_first) {
    memdb_t *dbs[] = {open_db("1.db"), open_db("2.db"), open_db("3.db")};
    dfsm_t *nodes[] = {start_node(dbs[0], 1), start_node(dbs[1], 2), start_node(dbs[2], 3)};
    uint32_t view12[] = {1, 2}, view123[] = {1, 2, 3};
    char id[CLUSTER_ID_FILE_SIZE];

    set_config_nodes(5);
    set_quorum(0, view12, 2);
    set_group(nodes, 2);

    if (quorum_first) {
        set_quorum(1, view123, 3);
        tick(nodes, 2);
        ck_assert(cluster_id_state(dbs[0]) == CLUSTER_ID_MISSING);
        /* the sync runs the check right away */
        set_group(nodes, 3);
    } else {
        set_group(nodes, 3);
        set_quorum(1, view123, 3);
        ck_assert(cluster_id_state(dbs[0]) == CLUSTER_ID_MISSING);
        tick(nodes, 3);
    }

    read_id(dbs[0], id);
    assert_id(dbs[1], id);
    assert_id(dbs[2], id);

    stop_nodes(nodes, dbs, 3);
}

START_TEST(test_third_node_joins_quorum_first) { third_node_joins(TRUE); }
END_TEST

START_TEST(test_third_node_joins_group_first) { third_node_joins(FALSE); }
END_TEST

/* a timer tick during a sync does nothing, the databases might still differ */
START_TEST(test_tick_during_sync) {
    memdb_t *dbs[] = {open_db("1.db"), open_db("2.db")};
    write_id(dbs[1], "abcdefghijklmnopqrst\n", 2, 100);
    other_writes(dbs[1], 10);

    dfsm_t *nodes[] = {start_node(dbs[0], 1), start_node(dbs[1], 2)};
    uint32_t view[] = {1, 2};

    set_config_nodes(2);
    set_quorum(1, view, 2);

    change_group(nodes, 2);
    do {
        guint queued = g_queue_get_length(&packets);
        tick_only(nodes, 2);
        ck_assert(g_queue_get_length(&packets) == queued);
    } while (deliver_next(nodes, 2));

    assert_id(dbs[0], "abcdefghijklmnopqrst\n");
    assert_id(dbs[1], "abcdefghijklmnopqrst\n");

    stop_nodes(nodes, dbs, 2);
}
END_TEST

/* ticks before the messages of the first attempt got delivered must write the same ID */
START_TEST(test_pending_id_reused) {
    memdb_t *dbs[] = {open_db("1.db")};
    dfsm_t *nodes[] = {start_node(dbs[0], 1)};
    uint32_t view[] = {1};
    char first[CLUSTER_ID_FILE_SIZE];

    set_config_nodes(1);
    set_quorum(1, view, 1);

    change_group(nodes, 1);
    ck_assert(g_queue_get_length(&packets) == 2);
    ck_assert(state_of(nodes[0])->gen.have_pending_id);
    memcpy(first, state_of(nodes[0])->gen.pending_id, CLUSTER_ID_FILE_SIZE);

    tick_only(nodes, 1);
    tick_only(nodes, 1);
    ck_assert(g_queue_get_length(&packets) == 6);

    pump(nodes, 1);
    assert_id(dbs[0], first);

    /* once delivered, the next check finds it valid and forgets the pending one */
    tick_only(nodes, 1);
    ck_assert(g_queue_is_empty(&packets));
    ck_assert(!state_of(nodes[0])->gen.have_pending_id);

    stop_nodes(nodes, dbs, 1);
}
END_TEST

/* A failed send leaves no ID, or the empty file of an interrupted creation, and causes no event.
 * The next timer tick tries again. fail_nr is the send of the attempt that fails. */
static void send_fails(int fail_nr, gboolean with_empty_file) {
    memdb_t *dbs[] = {open_db("1.db"), open_db("2.db")};
    if (with_empty_file) {
        ck_assert(memdb_create(dbs[0], "cluster-id", 3, 100) == 0);
        ck_assert(memdb_create(dbs[1], "cluster-id", 3, 100) == 0);
    }

    dfsm_t *nodes[] = {start_node(dbs[0], 1), start_node(dbs[1], 2)};
    uint32_t view[] = {1, 2};
    char id[CLUSTER_ID_FILE_SIZE];

    set_config_nodes(2);
    set_quorum(0, view, 2);
    set_group(nodes, 2);

    set_quorum(1, view, 2);
    send_nr = 0;
    fail_send_nr = fail_nr;
    tick(nodes, 2);
    fail_send_nr = 0;
    ck_assert(send_nr == fail_nr);
    ck_assert(
        cluster_id_state(dbs[1]) ==
        (fail_nr == 1 && !with_empty_file ? CLUSTER_ID_MISSING : CLUSTER_ID_INVALID)
    );

    tick(nodes, 2);
    read_id(dbs[0], id);
    assert_id(dbs[1], id);

    stop_nodes(nodes, dbs, 2);
}

START_TEST(test_create_send_fails) { send_fails(1, FALSE); }
END_TEST

START_TEST(test_write_send_fails) { send_fails(2, FALSE); }
END_TEST

START_TEST(test_write_send_fails_with_empty_file) { send_fails(1, TRUE); }
END_TEST

/* The lowest node leaves after its CREATE got delivered, but before its WRITE. The remaining
 * majority fills the file with an ID of its own, which stays when the former generator rejoins with
 * its outdated database and its pending ID. */
START_TEST(test_generator_leaves_before_write) {
    memdb_t *dbs[] = {open_db("1.db"), open_db("2.db"), open_db("3.db")};
    dfsm_t *nodes[] = {start_node(dbs[0], 1), start_node(dbs[1], 2), start_node(dbs[2], 3)};
    dfsm_t **rest = nodes + 1;
    uint32_t view1[] = {1}, view23[] = {2, 3}, view123[] = {1, 2, 3};
    char first[CLUSTER_ID_FILE_SIZE], id[CLUSTER_ID_FILE_SIZE];

    set_config_nodes(3);
    set_quorum(1, view123, 3);
    change_group(nodes, 3);
    while (cluster_id_state(dbs[2]) == CLUSTER_ID_MISSING) {
        ck_assert(deliver_next(nodes, 3));
    }
    ck_assert(cluster_id_state(dbs[2]) == CLUSTER_ID_INVALID);
    ck_assert(g_queue_get_length(&packets) == 1);
    ck_assert(state_of(nodes[0])->gen.have_pending_id);
    memcpy(first, state_of(nodes[0])->gen.pending_id, CLUSTER_ID_FILE_SIZE);
    drop_packets();

    set_quorum(1, view23, 2);
    set_group(rest, 2);
    read_id(dbs[1], id);
    assert_id(dbs[2], id);
    ck_assert(memcmp(id, first, CLUSTER_ID_FILE_SIZE) != 0);

    /* node 1 meanwhile, alone and without quorum */
    set_quorum(0, view1, 1);
    set_group(nodes, 1);
    tick(nodes, 1);
    ck_assert(cluster_id_state(dbs[0]) == CLUSTER_ID_INVALID);

    /* it learns about the others from corosync before their group merges with its own */
    set_quorum(1, view123, 3);
    tick(nodes, 1);
    ck_assert(cluster_id_state(dbs[0]) == CLUSTER_ID_INVALID);
    set_group(nodes, 3);
    for (int i = 0; i < 3; i++) {
        assert_id(dbs[i], id);
    }
    ck_assert(!state_of(nodes[0])->gen.have_pending_id);

    stop_nodes(nodes, dbs, 3);
}
END_TEST

START_TEST(test_lowest_repairs_empty_file) {
    memdb_t *dbs[] = {open_db("1.db"), open_db("2.db")};
    ck_assert(memdb_create(dbs[0], "cluster-id", 3, 100) == 0);
    ck_assert(memdb_create(dbs[1], "cluster-id", 3, 100) == 0);

    dfsm_t *nodes[] = {start_node(dbs[0], 1), start_node(dbs[1], 2)};
    uint32_t view[] = {1, 2};
    char id[CLUSTER_ID_FILE_SIZE];

    set_config_nodes(2);
    set_quorum(1, view, 2);
    set_group(nodes, 2);

    read_id(dbs[0], id);
    assert_id(dbs[1], id);

    stop_nodes(nodes, dbs, 2);
}
END_TEST

/* an ID with only 16 characters is malformed like anything else */
START_TEST(test_lowest_replaces_short_id) {
    memdb_t *dbs[] = {open_db("1.db"), open_db("2.db")};
    write_id(dbs[0], "abcdefghijklmnop\n", 1, 100);
    write_id(dbs[1], "abcdefghijklmnop\n", 1, 100);

    dfsm_t *nodes[] = {start_node(dbs[0], 1), start_node(dbs[1], 2)};
    uint32_t view[] = {1, 2};
    char id[CLUSTER_ID_FILE_SIZE];

    set_config_nodes(2);
    set_quorum(1, view, 2);
    set_group(nodes, 2);

    read_id(dbs[0], id);
    assert_id(dbs[1], id);

    stop_nodes(nodes, dbs, 2);
}
END_TEST

/* after the removal of a directory at the path, the next timer tick generates the ID */
START_TEST(test_removed_directory) {
    memdb_t *dbs[] = {open_db("1.db")};
    ck_assert(memdb_mkdir(dbs[0], "cluster-id", 1, 100) == 0);
    dfsm_t *nodes[] = {start_node(dbs[0], 1)};
    uint32_t view[] = {1};

    set_config_nodes(1);
    set_quorum(1, view, 1);
    set_group(nodes, 1);
    tick(nodes, 1);
    ck_assert(cluster_id_state(dbs[0]) == CLUSTER_ID_NOT_A_FILE);

    enter(nodes[0]);
    ck_assert(
        dcdb_send_fuse_message_full(
            nodes[0], DCDB_MESSAGE_CFS_DELETE, "cluster-id", NULL, NULL, 0, 0, 0, NULL
        ) == CS_OK
    );
    pump(nodes, 1);
    ck_assert(cluster_id_state(dbs[0]) == CLUSTER_ID_MISSING);

    tick(nodes, 1);
    ck_assert(cluster_id_state(dbs[0]) == CLUSTER_ID_VALID);

    stop_nodes(nodes, dbs, 1);
}
END_TEST

/* content that an older node writes over the ID gets replaced on the next timer tick */
START_TEST(test_overwritten_id) {
    memdb_t *dbs[] = {open_db("1.db"), open_db("2.db")};
    dfsm_t *nodes[] = {start_node(dbs[0], 1), start_node(dbs[1], 2)};
    uint32_t view[] = {1, 2};
    char id[CLUSTER_ID_FILE_SIZE];

    set_config_nodes(2);
    set_quorum(1, view, 2);
    set_group(nodes, 2);
    tick(nodes, 2);
    read_id(dbs[0], id);

    enter(nodes[1]);
    ck_assert(
        dcdb_send_fuse_message_full(
            nodes[1], DCDB_MESSAGE_CFS_WRITE, "cluster-id", NULL, "bogus\n", 6, 0, 1, NULL
        ) == CS_OK
    );
    pump(nodes, 2);
    ck_assert(cluster_id_state(dbs[0]) == CLUSTER_ID_INVALID);

    tick(nodes, 2);
    read_id(dbs[0], id);
    assert_id(dbs[1], id);

    stop_nodes(nodes, dbs, 2);
}
END_TEST

static void add_test(Suite *s, _TEST_TYPE tf, const char *name) {
    TCase *tc = tcase_create(name);
    tcase_add_test(tc, tf);
    suite_add_tcase(s, tc);
}

static void remove_tmpdir(void) {
    GDir *dir = g_dir_open(tmpdir, 0, NULL);
    if (dir) {
        const char *name;
        while ((name = g_dir_read_name(dir))) {
            char *filename = g_build_filename(tmpdir, name, NULL);
            unlink(filename);
            g_free(filename);
        }
        g_dir_close(dir);
    }

    rmdir(tmpdir);
    g_free(tmpdir);
}

int main(void) {
    cfs_status_init();

    if (!(tmpdir = g_dir_make_tmp("check_dcdb-XXXXXX", NULL))) {
        fprintf(stderr, "unable to create a temporary directory\n");
        return EXIT_FAILURE;
    }

    Suite *s = suite_create("dcdb");

    add_test(s, test_single_node_cluster, "single_node_cluster");
    add_test(s, test_config_nodes_removed, "config_nodes_removed");
    add_test(s, test_only_lowest_generates, "only_lowest_generates");
    add_test(s, test_stale_node_alone, "stale_node_alone");
    add_test(s, test_stale_node_alone_with_empty_file, "stale_node_alone_with_empty_file");
    add_test(s, test_lone_node_without_node_majority, "lone_node_without_node_majority");
    add_test(s, test_half_of_the_nodes, "half_of_the_nodes");
    add_test(s, test_member_not_configured, "member_not_configured");
    add_test(s, test_quorum_change, "quorum_change");
    add_test(s, test_third_node_joins_quorum_first, "third_node_joins_quorum_first");
    add_test(s, test_third_node_joins_group_first, "third_node_joins_group_first");
    add_test(s, test_tick_during_sync, "tick_during_sync");
    add_test(s, test_pending_id_reused, "pending_id_reused");
    add_test(s, test_create_send_fails, "create_send_fails");
    add_test(s, test_write_send_fails, "write_send_fails");
    add_test(s, test_write_send_fails_with_empty_file, "write_send_fails_with_empty_file");
    add_test(s, test_generator_leaves_before_write, "generator_leaves_before_write");
    add_test(s, test_lowest_repairs_empty_file, "lowest_repairs_empty_file");
    add_test(s, test_lowest_replaces_short_id, "lowest_replaces_short_id");
    add_test(s, test_removed_directory, "removed_directory");
    add_test(s, test_overwritten_id, "overwritten_id");

    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    remove_tmpdir();

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
