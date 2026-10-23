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

#define G_LOG_DOMAIN "ipcs"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/syslog.h>
#include <sys/uio.h>

#include <qb/qbdefs.h>
#include <qb/qbipcs.h>
#include <qb/qbloop.h>
#include <qb/qbutil.h>

#include <glib.h>

#include "cfs-ipc-common.h"
#include "cfs-ipc-ops.h"
#include "cfs-utils.h"
#include "logger.h"
#include "memdb.h"
#include "status.h"

static GThread *worker;
static qb_loop_t *loop;
static qb_ipcs_service_t *s1;
/* initial size of the response buffer, it grows as needed */
#define OUTBUF_SIZE (8192 * 8)
static GString *outbuf;
static memdb_t *memdb;

static int server_started = 0;   /* protect with server_started_mutex */
static int terminate_server = 0; /* protect with server_started_mutex */
static GCond server_started_cond;
static GCond server_stopped_cond;
static GMutex server_started_mutex;

typedef struct {
    char name[256];
} cfs_status_update_request_header_t;

typedef struct {
    char name[256];
    char nodename[256];
} cfs_status_get_request_header_t;

typedef struct {
    uint8_t priority;
    uint8_t ident_len;
    uint8_t tag_len;
    char data[];
} cfs_log_msg_request_header_t;

typedef struct {
    uint32_t max_entries;
    uint32_t res1;
    uint32_t res2;
    uint32_t res3;
} cfs_log_get_request_header_t;

typedef struct {
    uint32_t vmid;
    char property[];
} cfs_guest_config_propery_get_request_header_t;

typedef struct {
    uint32_t vmid;
    uint8_t num_props;
    char props[]; /* list of \0 terminated properties */
} cfs_guest_config_properties_get_request_header_t;

struct s1_context {
    int32_t client_pid;
    uid_t uid;
    gid_t gid;
    gboolean read_only;
    gboolean logged_bad_request;
    gboolean logged_send_error;
    /* the rest of a chunked response, which the client did not fetch yet */
    GString *pending;
    size_t pending_offset;
    uint32_t pending_index;
};

static void s1_context_drop_pending(struct s1_context *ctx) {
    if (ctx->pending) {
        g_string_free(ctx->pending, TRUE);
        ctx->pending = NULL;
    }
}

static int32_t s1_connection_accept_fn(qb_ipcs_connection_t *c, uid_t uid, gid_t gid) {
    if ((uid == 0 && gid == 0) || (gid == cfs.gid)) {
        cfs_debug("authenticated connection %d/%d", uid, gid);
        struct s1_context *ctx = g_new0(struct s1_context, 1);
        ctx->uid = uid;
        ctx->gid = gid;
        ctx->read_only = (gid == cfs.gid);

        struct qb_ipcs_connection_stats stats;
        qb_ipcs_connection_stats_get(c, &stats, QB_FALSE);
        ctx->client_pid = stats.client_pid;

        qb_ipcs_context_set(c, ctx);
        return 0;
    }
    cfs_critical("connection from bad user %d! - rejected", uid);
    return 1;
}

static void s1_connection_created_fn(qb_ipcs_connection_t *c) {
    struct qb_ipcs_stats srv_stats;

    qb_ipcs_stats_get(s1, &srv_stats, QB_FALSE);

    cfs_debug(
        "Connection created > active:%d > closed:%d", srv_stats.active_connections,
        srv_stats.closed_connections
    );
}

static void s1_connection_destroyed_fn(qb_ipcs_connection_t *c) {
    cfs_debug("connection about to be freed");

    struct s1_context *ctx;
    if ((ctx = qb_ipcs_context_get(c))) {
        s1_context_drop_pending(ctx);
        g_free(ctx);
    }
}

static int32_t s1_connection_closed_fn(qb_ipcs_connection_t *c) {
    struct qb_ipcs_connection_stats stats;

    qb_ipcs_connection_stats_get(c, &stats, QB_FALSE);

    cfs_debug("Connection to pid:%d destroyed", stats.client_pid);

    return 0;
}

/* Compare in constant time, so that a caller cannot learn a valid token prefix from how long the
 * comparison takes. Both lengths are already known to the caller, only the contents are secret. */
static gboolean token_equal(const char *a, const char *b, size_t len) {
    unsigned char diff = 0;

    for (size_t i = 0; i < len; i++) {
        diff |= (unsigned char)a[i] ^ (unsigned char)b[i];
    }

    return diff == 0;
}

static int32_t s1_msg_handle_request(
    struct s1_context *ctx, void *data, int32_t request_id, int32_t request_size
) {
    g_string_truncate(outbuf, 0);

    int32_t result = -ECHRNG;
    if (request_id == CFS_IPC_GET_FS_VERSION) {

        if (request_size != 0) {
            result = -EINVAL;
        } else {
            result = cfs_create_version_msg(outbuf);
        }

    } else if (request_id == CFS_IPC_GET_CLUSTER_INFO) {

        if (request_size != 0) {
            result = -EINVAL;
        } else {
            result = cfs_create_memberlist_msg(outbuf);
        }

    } else if (request_id == CFS_IPC_GET_GUEST_LIST) {

        if (request_size != 0) {
            result = -EINVAL;
        } else {
            result = cfs_create_vmlist_msg(outbuf);
        }
    } else if (request_id == CFS_IPC_SET_STATUS) {

        cfs_status_update_request_header_t *rh = (cfs_status_update_request_header_t *)data;

        int datasize = request_size - sizeof(cfs_status_update_request_header_t);

        if (ctx->read_only) {
            result = -EPERM;
        } else if (datasize < 0) {
            result = -EINVAL;
        } else {
            /* make sure name is 0 terminated */
            rh->name[sizeof(rh->name) - 1] = 0;

            char *dataptr = (char *)data + sizeof(cfs_status_update_request_header_t);

            result = cfs_status_set(rh->name, dataptr, datasize);
        }
    } else if (request_id == CFS_IPC_GET_STATUS) {

        cfs_status_get_request_header_t *rh = (cfs_status_get_request_header_t *)data;

        int datasize = request_size - sizeof(cfs_status_get_request_header_t);

        if (datasize < 0) {
            result = -EINVAL;
        } else {
            /* make sure all names are 0 terminated */
            rh->name[sizeof(rh->name) - 1] = 0;
            rh->nodename[sizeof(rh->nodename) - 1] = 0;

            result = cfs_create_status_msg(outbuf, rh->nodename, rh->name);
        }
    } else if (request_id == CFS_IPC_GET_CONFIG) {

        int pathlen = request_size;

        if (pathlen <= 0) {
            result = -EINVAL;
        } else {
            /* make sure path is 0 terminated */
            ((char *)data)[request_size - 1] = 0;
            char *path = (char *)data;

            if (ctx->read_only && path_is_private(path)) {
                result = -EPERM;
            } else {
                gpointer tmp = NULL;
                result = memdb_read(memdb, path, &tmp);
                if (result > 0) {
                    g_string_append_len(outbuf, tmp, result);
                    g_free(tmp);
                    result = 0;
                }
            }
        }
    } else if (request_id == CFS_IPC_LOG_CLUSTER_MSG) {

        cfs_log_msg_request_header_t *rh = (cfs_log_msg_request_header_t *)data;

        int datasize = request_size - G_STRUCT_OFFSET(cfs_log_msg_request_header_t, data);

        if (ctx->read_only) {
            result = -EPERM;
        } else if (datasize < 1) {
            /* the ident and tag lengths are part of the request body, so do not read them
             * before the request is known to be long enough to carry them */
            result = -EINVAL;
        } else if (rh->ident_len < 1 || rh->tag_len < 1 ||
                   (datasize - rh->ident_len - rh->tag_len) < 1) {
            result = -EINVAL;
        } else {
            char *msg = rh->data;
            /* ident and tag have to bring their own terminator, the message text is terminated by
             * the extra zero byte that the request copy always has */
            if ((msg[rh->ident_len - 1] == 0) && (msg[rh->ident_len + rh->tag_len - 1] == 0)) {

                char *ident = msg;
                char *tag = msg + rh->ident_len;
                msg = msg + rh->ident_len + rh->tag_len;

                time_t ctime = time(NULL);
                clog_entry_t *entry = (clog_entry_t *)alloca(CLOG_MAX_ENTRY_SIZE);
                if (clog_pack(
                        entry, cfs.nodename, ident, tag, ctx->client_pid, ctime, rh->priority, msg
                    )) {
                    cfs_cluster_log(entry);
                }

                result = 0;

            } else {
                result = -EINVAL;
            }
        }
    } else if (request_id == CFS_IPC_GET_CLUSTER_LOG) {

        cfs_log_get_request_header_t *rh = (cfs_log_get_request_header_t *)data;

        int userlen = request_size - sizeof(cfs_log_get_request_header_t);

        if (userlen <= 0) {
            result = -EINVAL;
        } else {
            /* make sure user string is 0 terminated */
            ((char *)data)[request_size - 1] = 0;
            char *user = (char *)data + sizeof(cfs_log_get_request_header_t);

            uint32_t max = rh->max_entries ? rh->max_entries : 50;
            cfs_cluster_log_dump(outbuf, user, max);
            result = 0;
        }
    } else if (request_id == CFS_IPC_GET_RRD_DUMP) {

        if (request_size != 0) {
            result = -EINVAL;
        } else {
            cfs_rrd_dump(outbuf);
            result = 0;
        }
    } else if (request_id == CFS_IPC_GET_GUEST_CONFIG_PROPERTY) {

        cfs_guest_config_propery_get_request_header_t *rh =
            (cfs_guest_config_propery_get_request_header_t *)data;

        int proplen =
            request_size - G_STRUCT_OFFSET(cfs_guest_config_propery_get_request_header_t, property);

        result = 0;
        if (proplen <= 0) {
            /* vmid is part of the request body, so do not read it before the request is known
             * to be long enough to carry it */
            cfs_debug("proplen <= 0, %d", proplen);
            result = -EINVAL;
        } else if (rh->vmid < 100 && rh->vmid != 0) {
            cfs_debug("vmid out of range %u", rh->vmid);
            result = -EINVAL;
        } else if (rh->vmid >= 100 && !vmlist_vm_exists(rh->vmid)) {
            result = -ENOENT;
        } else {
            ((char *)data)[request_size - 1] = 0; // ensure property is 0 terminated

            cfs_debug("cfs_get_guest_config_property: basic valid checked, do request");

            result = cfs_create_guest_conf_property_msg(outbuf, memdb, rh->property, rh->vmid);
        }
    } else if (request_id == CFS_IPC_GET_GUEST_CONFIG_PROPERTIES) {

        cfs_guest_config_properties_get_request_header_t *rh =
            (cfs_guest_config_properties_get_request_header_t *)data;

        /* keep this signed, a short request must not wrap around into a huge length */
        ssize_t remaining =
            request_size - G_STRUCT_OFFSET(cfs_guest_config_properties_get_request_header_t, props);

        result = 0;
        if (remaining <= 1) {
            /* vmid and num_props are part of the request body, so do not read them before the
             * request is known to be long enough to carry them */
            cfs_debug("property length <= 1, %ld", remaining);
            result = -EINVAL;
        } else if (rh->vmid < 100 && rh->vmid != 0) {
            cfs_debug("vmid out of range %u", rh->vmid);
            result = -EINVAL;
        } else if (rh->vmid >= 100 && !vmlist_vm_exists(rh->vmid)) {
            result = -ENOENT;
        } else if (rh->num_props == 0) {
            cfs_debug("num_props == 0");
            result = -EINVAL;
        } else {
            const char **properties = malloc(sizeof(char *) * rh->num_props);
            char *current = (rh->props);
            for (uint8_t i = 0; i < rh->num_props; i++) {
                size_t proplen = strnlen(current, remaining);
                if (proplen == 0) {
                    cfs_debug("property length 0");
                    result = -EINVAL;
                    break;
                }
                if (proplen == (size_t)remaining || current[proplen] != '\0') {
                    cfs_debug("property not \\0 terminated");
                    result = -EINVAL;
                    break;
                }
                if (current[0] < 'a' || current[0] > 'z') {
                    cfs_debug("property does not start with [a-z]");
                    result = -EINVAL;
                    break;
                }
                properties[i] = current;
                remaining -= (proplen + 1);
                current += proplen + 1;
            }

            if (remaining != 0) {
                cfs_debug("leftover data after parsing %u properties", rh->num_props);
                result = -EINVAL;
            }

            if (result == 0) {
                cfs_debug("cfs_get_guest_config_properties: basic validity checked, do request");
                result = cfs_create_guest_conf_properties_msg(
                    outbuf, memdb, properties, rh->num_props, rh->vmid
                );
            }

            free(properties);
        }
    } else if (request_id == CFS_IPC_VERIFY_TOKEN) {

        /* the request body is the NUL-terminated token itself */
        const char *token = data;
        int tokenlen = request_size - 1;

        if (tokenlen <= 0) {
            cfs_debug("tokenlen <= 0, %d", tokenlen);
            result = -EINVAL;
        } else if (memchr(token, '\n', tokenlen) != NULL) {
            cfs_debug("token contains newline");
            result = -EINVAL;
        } else if (token[tokenlen] != '\0') {
            cfs_debug("token not NULL-terminated");
            result = -EINVAL;
        } else if (strnlen(token, tokenlen) != tokenlen) {
            cfs_debug("token contains NULL-byte");
            result = -EINVAL;
        } else {
            cfs_debug("cfs_verify_token: basic validity checked, reading token.cfg");
            gpointer tmp = NULL;
            int bytes_read = memdb_read(memdb, "priv/token.cfg", &tmp);
            size_t remaining = bytes_read > 0 ? bytes_read : 0;
            if (tmp != NULL && remaining >= tokenlen) {
                const char *line = (char *)tmp;
                const char *next_line;
                const char *const end = line + remaining;
                size_t linelen;

                while (line != NULL) {
                    next_line = memchr(line, '\n', remaining);
                    linelen = next_line == NULL ? remaining : next_line - line;
                    if (linelen == tokenlen && token_equal(line, token, linelen)) {
                        result = 0;
                        break;
                    }
                    line = next_line;
                    if (line != NULL) {
                        line += 1;
                        remaining = end - line;
                    }
                }
                if (line == NULL) {
                    result = -ENOENT;
                }
                g_free(tmp);
            } else {
                cfs_debug("token: token.cfg does not exist - ENOENT");
                result = -ENOENT;
            }
        }
    }

    return result;
}

/* Sends as much of buf from offset on as fits into a single message, returns the number of body
 * bytes sent or a negative errno value. */
static ssize_t s1_msg_send_chunk(
    qb_ipcs_connection_t *c,
    gboolean chunked,
    int32_t request_id,
    int32_t result,
    GString *buf,
    size_t offset,
    uint32_t index
) {
    struct cfs_ipc_response_header res_header;
    struct iovec iov[2];

    /* Only send the extended response header if the client supports it */
    iov[0].iov_base = &res_header;
    iov[0].iov_len = chunked ? sizeof(res_header) : sizeof(res_header.qb_header);

    size_t max_chunk_size = qb_ipcs_connection_get_buffer_size(c) - iov[0].iov_len;
    size_t size = buf->len - offset;

    res_header.flags = CFS_IPC_RES_FLAG_CHUNK_LAST;
    if (size > max_chunk_size) {
        size = max_chunk_size;
        res_header.flags = CFS_IPC_RES_FLAG_CHUNK;
    }
    res_header.index = index;

    iov[1].iov_base = buf->str + offset;
    iov[1].iov_len = size;

    res_header.qb_header.id = request_id;
    res_header.qb_header.error = result;
    res_header.qb_header.size = iov[0].iov_len + iov[1].iov_len;

    ssize_t res = qb_ipcs_response_sendv(c, iov, 2);
    if (res < 0) {
        return res;
    }

    cfs_debug("msg %d chunk %u with %zu bytes sent", request_id, index, size);

    return size;
}

/* A failed send only drops the response. Disconnecting the client here would free the connection,
 * which libqb keeps using after the message callback returns. A client that reads each response
 * before sending its next request never gets here, so log only once per connection. */
static void s1_msg_send_failed(struct s1_context *ctx, int32_t request_id, ssize_t err) {
    if (!ctx->logged_send_error) {
        ctx->logged_send_error = TRUE;
        cfs_critical("sending response for id %d failed: %s", request_id, strerror(-err));
    }
}

static void s1_msg_send_response(
    qb_ipcs_connection_t *c,
    struct s1_context *ctx,
    int32_t request_id,
    gboolean chunked,
    int32_t result
) {
    int32_t max_msg_size = qb_ipcs_connection_get_buffer_size(c);

    /* Clients without chunk support only get the libqb response header and a single message, so
     * the response has to fit into their buffer. */
    size_t response_size = sizeof(struct qb_ipc_response_header) + outbuf->len;
    if (!chunked && response_size > max_msg_size) {
        cfs_critical(
            "response for id %d is too large: %zu > %d", request_id, response_size, max_msg_size
        );
        result = -EMSGSIZE;
    }

    /* Do not send the response body in case of an error */
    if (result < 0) {
        g_string_truncate(outbuf, 0);
    }

    ssize_t sent = s1_msg_send_chunk(c, chunked, request_id, result, outbuf, 0, 0);
    if (sent < 0) {
        s1_msg_send_failed(ctx, request_id, sent);
        return;
    }

    if ((size_t)sent < outbuf->len) {
        /* Keep the rest for the client to fetch one chunk per CFS_IPC_GET_RESPONSE_CHUNK request.
         * The client reads each chunk before asking for the next, so the response ring buffer
         * always has room for it and the server never waits on a client, which would hold up all
         * other connections. */
        ctx->pending = outbuf;
        ctx->pending_offset = sent;
        ctx->pending_index = 1;
        outbuf = g_string_sized_new(OUTBUF_SIZE);
    }
}

/* Sends the next chunk of the pending response. Returns 0 if a chunk was sent or sending it failed,
 * or a negative errno value for an unexpected request. */
static int32_t s1_msg_send_pending_chunk(
    qb_ipcs_connection_t *c, struct s1_context *ctx, void *data, int32_t request_size
) {
    uint32_t index;

    if (!ctx->pending || request_size != sizeof(index)) {
        s1_context_drop_pending(ctx);
        return -EINVAL;
    }

    memcpy(&index, data, sizeof(index));
    if (index != ctx->pending_index) {
        s1_context_drop_pending(ctx);
        return -EINVAL;
    }

    ssize_t sent = s1_msg_send_chunk(
        c, TRUE, CFS_IPC_GET_RESPONSE_CHUNK, 0, ctx->pending, ctx->pending_offset, index
    );
    if (sent < 0) {
        s1_context_drop_pending(ctx);
        s1_msg_send_failed(ctx, CFS_IPC_GET_RESPONSE_CHUNK, sent);
        return 0;
    }

    ctx->pending_offset += sent;
    ctx->pending_index++;

    if (ctx->pending_offset == ctx->pending->len) {
        s1_context_drop_pending(ctx);
    }

    return 0;
}

static int32_t s1_msg_process_fn(qb_ipcs_connection_t *c, void *data, size_t size) {
    struct qb_ipc_request_header *req_pt = (struct qb_ipc_request_header *)data;

    struct s1_context *ctx = (struct s1_context *)qb_ipcs_context_get(c);

    if (!ctx) {
        /* do not disconnect from within the message callback, see s1_msg_send_failed() */
        cfs_critical("qb_ipcs_context_get failed");
        return 0;
    }

    /* read the header just once, the client can change it at any time, see below */
    int32_t raw_id = req_pt->id;
    int32_t raw_size = req_pt->size;

    gboolean chunked = (raw_id & CFS_IPC_REQ_FLAG_CHUNKED_RESPONSE) != 0;
    int32_t request_id = raw_id & ~CFS_IPC_REQ_FLAG_CHUNKED_RESPONSE;
    cfs_debug("process msg:%d, size:%d, chunked:%d", request_id, raw_size, chunked);

    /* the size is taken from the request header, which the client fully controls and libqb passes
     * on unvalidated - bound it against the receive buffer before it is used to index into it */
    int32_t max_request_size = qb_ipcs_connection_get_buffer_size(c);
    gboolean size_valid = raw_size >= (int32_t)sizeof(struct qb_ipc_request_header) &&
                          max_request_size >= 0 && raw_size <= max_request_size;
    int32_t request_size =
        size_valid ? raw_size - (int32_t)sizeof(struct qb_ipc_request_header) : 0;

    /* for the shared memory transport 'data' points straight into the request ring, which the
     * client keeps mapped writable - it can change any field between the check and the use, so
     * parse the request body from a private copy. The extra trailing byte replaces the read one
     * past the request that the terminator checks used to do on the ring. */
    g_autofree char *request = size_valid ? g_malloc0((size_t)request_size + 1) : NULL;
    if (request) {
        memcpy(request, (char *)data + sizeof(struct qb_ipc_request_header), request_size);
    }

    int32_t result;
    if (!request) {
        /* any client that may open the socket can send these in a loop, so log one per
         * connection - enough to spot a broken client, too little to drown the log */
        if (!ctx->logged_bad_request) {
            ctx->logged_bad_request = TRUE;
            cfs_critical("received request with invalid size %d", raw_size);
        }
        result = -EINVAL;
    } else if (chunked && request_id == CFS_IPC_GET_RESPONSE_CHUNK) {
        result = s1_msg_send_pending_chunk(c, ctx, request, request_size);
        if (result == 0) {
            return 0;
        }
    } else {
        /* any other request means the client gave up on the rest of a previous response */
        s1_context_drop_pending(ctx);
        result = s1_msg_handle_request(ctx, request, request_id, request_size);
    }
    cfs_debug("process result %d", result);

    s1_msg_send_response(c, ctx, request_id, chunked, result);

    return 0;
}

static int32_t my_job_add(enum qb_loop_priority p, void *data, qb_loop_job_dispatch_fn fn) {
    return qb_loop_job_add(loop, p, data, fn);
}

static int32_t my_dispatch_add(
    enum qb_loop_priority p, int32_t fd, int32_t evts, void *data, qb_ipcs_dispatch_fn_t fn
) {
    return qb_loop_poll_add(loop, p, fd, evts, data, fn);
}

static int32_t my_dispatch_mod(
    enum qb_loop_priority p, int32_t fd, int32_t evts, void *data, qb_ipcs_dispatch_fn_t fn
) {
    return qb_loop_poll_mod(loop, p, fd, evts, data, fn);
}

static int32_t my_dispatch_del(int32_t fd) { return qb_loop_poll_del(loop, fd); }

static struct qb_ipcs_service_handlers service_handlers = {
    .connection_accept = s1_connection_accept_fn,
    .connection_created = s1_connection_created_fn,
    .msg_process = s1_msg_process_fn,
    .connection_destroyed = s1_connection_destroyed_fn,
    .connection_closed = s1_connection_closed_fn,
};

static struct qb_ipcs_poll_handlers poll_handlers = {
    .job_add = my_job_add,
    .dispatch_add = my_dispatch_add,
    .dispatch_mod = my_dispatch_mod,
    .dispatch_del = my_dispatch_del,
};

static void timer_job(void *data) {
    gboolean terminate = FALSE;

    g_mutex_lock(&server_started_mutex);

    if (terminate_server) {
        cfs_debug("got terminate request");

        if (loop) {
            qb_loop_stop(loop);
        }

        if (s1) {
            qb_ipcs_destroy(s1);
            s1 = 0;
        }
        server_started = 0;

        g_cond_signal(&server_stopped_cond);

        terminate = TRUE;
    } else if (!server_started) {
        server_started = 1;
        g_cond_signal(&server_started_cond);
    }

    g_mutex_unlock(&server_started_mutex);

    if (terminate) {
        return;
    }

    qb_loop_timer_handle th;
    qb_loop_timer_add(loop, QB_LOOP_LOW, 1000000000, NULL, timer_job, &th);
}

static gpointer worker_thread(gpointer data) {
    g_return_val_if_fail(loop != NULL, NULL);

    cfs_debug("start event loop");

    qb_ipcs_run(s1);

    qb_loop_timer_handle th;
    qb_loop_timer_add(loop, QB_LOOP_LOW, 1000, NULL, timer_job, &th);

    qb_loop_run(loop);

    cfs_debug("event loop finished - exit worker thread");

    return NULL;
}

gboolean server_start(memdb_t *db) {
    g_return_val_if_fail(loop == NULL, FALSE);
    g_return_val_if_fail(worker == NULL, FALSE);
    g_return_val_if_fail(db != NULL, FALSE);

    terminate_server = 0;
    server_started = 0;

    memdb = db;

    outbuf = g_string_sized_new(OUTBUF_SIZE);

    if (!(loop = qb_loop_create())) {
        cfs_critical("cant create event loop");
        return FALSE;
    }

    s1 = qb_ipcs_create("pve2", 1, QB_IPC_SHM, &service_handlers);
    if (s1 == 0) {
        cfs_critical("qb_ipcs_create failed: %s", strerror(errno));
        return FALSE;
    }
    qb_ipcs_poll_handlers_set(s1, &poll_handlers);

    worker = g_thread_new("server", worker_thread, NULL);

    g_mutex_lock(&server_started_mutex);
    while (!server_started) {
        g_cond_wait(&server_started_cond, &server_started_mutex);
    }
    g_mutex_unlock(&server_started_mutex);

    cfs_debug("server started");

    return TRUE;
}

void server_stop(void) {
    cfs_debug("server stop");

    g_mutex_lock(&server_started_mutex);
    terminate_server = 1;
    while (server_started) {
        g_cond_wait(&server_stopped_cond, &server_started_mutex);
    }
    g_mutex_unlock(&server_started_mutex);

    if (worker) {
        g_thread_join(worker);
        worker = NULL;
    }

    cfs_debug("worker thread finished");

    if (loop) {
        qb_loop_destroy(loop);

        loop = NULL;
    }

    if (outbuf) {
        g_string_free(outbuf, TRUE);
        outbuf = NULL;
    }
}
