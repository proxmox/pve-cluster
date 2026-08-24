#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

/* sendfd: BSD style file descriptor passing over unix domain sockets
 *  Richard Stevens: Unix Network Programming, Prentice Hall, 1990;
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#ifndef SCM_RIGHTS
#error "SCM_RIGHTS undefined"
#endif 

/* interface to pmxcfs (libqb) */
#include <sys/syslog.h>
#include <qb/qbdefs.h>
#include <qb/qbutil.h>
#include <qb/qblog.h>
#include <qb/qbipcc.h>

#include "cfs-ipc-common.h"

#define RESTART_FLAG_FILE "/run/pve-cluster/cfs-restart-flag"
#define RESTART_GRACE_PERIOD 10

#define PCS_SOCKET_NAME "pve2"

#define PCS_SERVICE1 1
#define MAX_MSG_SIZE (8192*128)

/* how long to wait for a response before checking if pmxcfs is still connected */
#define RECV_WAIT_SLICE_MS 2000

static qb_ipcc_connection_t *conn;
static pid_t conn_pid;
/* pmxcfs on the cached connection does not support chunked responses
 * FIXME: remove with PVE 10 together with all its uses, upgrades to it start from the latest
 * PVE 9, whose pmxcfs already supports chunked responses */
static int conn_legacy;

static char ipcbuffer[MAX_MSG_SIZE];

static qb_ipcc_connection_t *init_connection() {

	static qb_ipcc_connection_t *connection = NULL;
	struct timespec retry_timeout, now;
	int cfs_restart_flag_fd = -1;

	// check if pmxcfs is currently restarting
	if ((cfs_restart_flag_fd = open(RESTART_FLAG_FILE, 0)) > 0) {
		clock_gettime(CLOCK_MONOTONIC, &retry_timeout);
		retry_timeout.tv_sec += RESTART_GRACE_PERIOD;
	}

	qb_log_init("IPCC.xs", LOG_USER, LOG_EMERG);
	qb_log_ctl(QB_LOG_SYSLOG, QB_LOG_CONF_ENABLED, QB_TRUE);

retry_connection:
	connection = qb_ipcc_connect(PCS_SOCKET_NAME, MAX_MSG_SIZE);

	if (!connection) {
		if (cfs_restart_flag_fd >= 0) {
			// cfs restarting and hopefully back soon, poll
			clock_gettime(CLOCK_MONOTONIC, &now);

			if (now.tv_sec < retry_timeout.tv_sec ||
			   (now.tv_sec == retry_timeout.tv_sec &&
			    now.tv_nsec < retry_timeout.tv_nsec)) {

				usleep(100 * 1000);
				goto retry_connection;

			} else {
				// timeout: cleanup flag file if still the same
				struct stat s;
				fstat(cfs_restart_flag_fd, &s);
				if (s.st_nlink > 0)
					unlink(RESTART_FLAG_FILE);
			}
		}
	}

	if (cfs_restart_flag_fd >= 0) close(cfs_restart_flag_fd);

	return connection;
}

/* Wait for the next response message like qb_ipcc_sendv_recv() with an infinite timeout does, as
 * long as pmxcfs is connected. Handling a request can take a while, e.g. if the memdb is busy. */
static ssize_t ipcc_recv(void) {
	ssize_t res;

	do {
		res = qb_ipcc_recv(conn, ipcbuffer, sizeof(ipcbuffer), RECV_WAIT_SLICE_MS);
	} while ((res == -ETIMEDOUT || res == -EAGAIN) && qb_ipcc_is_connected(conn));

	return res;
}

/* Sends a request over the cached connection and appends the response body to result. Returns 0 and
 * sets *error to the error field of the response, or returns a negative errno value if the request or
 * the response could not be transferred, in which case the connection must not be reused. */
static int ipcc_request(I32 msgid, char *dataptr, size_t len, SV *result, int32_t *error) {
	struct qb_ipc_response_header *qb_header = (struct qb_ipc_response_header *)ipcbuffer;
	struct cfs_ipc_response_header *res_header = (struct cfs_ipc_response_header *)ipcbuffer;
	struct qb_ipc_request_header req_header;
	struct iovec iov[2];
	int32_t response_id;
	uint32_t index;
	ssize_t res;

resend:
	response_id = msgid;
	req_header.id = conn_legacy ? msgid : msgid | CFS_IPC_REQ_FLAG_CHUNKED_RESPONSE;
	req_header.size = sizeof(req_header) + len;

	iov[0].iov_base = (char *)&req_header;
	iov[0].iov_len = sizeof(req_header);
	iov[1].iov_base = dataptr;
	iov[1].iov_len = len;

	res = qb_ipcc_sendv(conn, iov, 2);
	if (res < 0)
		return res;

	index = 0;
	while (1) {
		res = ipcc_recv();
		if (res < 0)
			return res;

		if (res < (ssize_t)sizeof(*qb_header) || qb_header->size != res)
			return -EBADMSG;

		/* A pmxcfs without chunked responses does not know the flagged request id and did
		 * not handle the request, send plain requests on this connection from now on. */
		if (!conn_legacy && index == 0 && qb_header->id == req_header.id &&
		    qb_header->error == -ECHRNG && res == sizeof(*qb_header)) {
			conn_legacy = 1;
			goto resend;
		}

		if (qb_header->id != response_id)
			return -EBADMSG;

		if (conn_legacy) {
			sv_catpvn(result, ipcbuffer + sizeof(*qb_header), res - sizeof(*qb_header));
			*error = qb_header->error;
			return 0;
		}

		if (res < (ssize_t)sizeof(*res_header))
			return -EBADMSG;

		/* errors come without body as standalone message, also for a chunk request */
		if (qb_header->error < 0) {
			*error = qb_header->error;
			return 0;
		}

		if (res_header->index != index)
			return -EBADMSG;

		sv_catpvn(result, ipcbuffer + sizeof(*res_header), res - sizeof(*res_header));

		if (res_header->flags & CFS_IPC_RES_FLAG_CHUNK_LAST) {
			/* Either the last part of a multi-message response or
			 * a standalone message response. There are no more
			 * incoming message chunks to expect. */
			*error = qb_header->error;
			return 0;
		} else if (!(res_header->flags & CFS_IPC_RES_FLAG_CHUNK)) {
			return -EPROTO;
		}

		/* An intermediate part of a multi-message response,
		 * fetch the next one. */
		index++;

		response_id = CFS_IPC_GET_RESPONSE_CHUNK;
		req_header.id = CFS_IPC_GET_RESPONSE_CHUNK | CFS_IPC_REQ_FLAG_CHUNKED_RESPONSE;
		req_header.size = sizeof(req_header) + sizeof(index);
		iov[1].iov_base = &index;
		iov[1].iov_len = sizeof(index);

		res = qb_ipcc_sendv(conn, iov, 2);
		if (res < 0)
			return res;
	}
}


MODULE = PVE::IPCC		PACKAGE = PVE::IPCC		

SV *
ipcc_send_rec(msgid, data=NULL)
I32 msgid;
SV * data;
PROTOTYPE: $;$
CODE:
{
	size_t len = 0;
	char *dataptr = NULL;
	if (data && SvPOK(data))
		dataptr = SvPV(data, len);

	uint8_t retried_cache_connection = 0;
	pid_t cpid = getpid();

	/* Each process needs its own ipcc connection,
	 * else the shared memory buffer gets corrupted.
	 */ 
	if (conn && conn_pid != cpid) {
		conn = NULL;
	}

	if (conn == NULL) {
recache_connection:
		conn = init_connection();

		if (!conn)
			XSRETURN_UNDEF;

		conn_pid = cpid;
		conn_legacy = 0;
	}

	SV *result = newSVpvs("");
	int32_t error = 0;

	int res = ipcc_request(msgid, dataptr, len, result, &error);
	if (res < 0) {
		SvREFCNT_dec(result);
		qb_ipcc_disconnect(conn);
		conn = NULL;
		// requests during cfs restart and the first thereafter will fail, retry
		if (!retried_cache_connection) {
			retried_cache_connection = 1;
			goto recache_connection;
		}
		errno = -res;
		XSRETURN_UNDEF;
	}

	if (error < 0 || SvCUR(result) == 0) {
		SvREFCNT_dec(result);
		errno = error < 0 ? -error : 0;
		XSRETURN_UNDEF;
	}

	errno = 0;
	RETVAL = result;
}
OUTPUT: RETVAL

# helper to pass SCM ACCESS RIGHTS

int
sendfd(sock_fd, send_me_fd, data=NULL)
int sock_fd
int send_me_fd
SV * data;
CODE:
{
	int ret = 0;
	struct iovec  iov[1];
	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));

	size_t len = 0;
	char *dataptr = NULL;
	if (data && SvPOK(data))
		dataptr = SvPV(data, len);
	
	iov[0].iov_base = dataptr;
	iov[0].iov_len = len;	
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_name = 0;
	msg.msg_namelen = 0;

	char control[CMSG_SPACE(sizeof(int))];
	memset(control, 0, sizeof(control));

	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	msg.msg_flags = 0;
		
	struct cmsghdr* h = CMSG_FIRSTHDR(&msg);
	h->cmsg_len = CMSG_LEN(sizeof(int));
	h->cmsg_level= SOL_SOCKET;
	h->cmsg_type = SCM_RIGHTS;
	*((int*)CMSG_DATA(h)) = send_me_fd;

	int repeat;
	do {
		repeat = 0;
		ret = sendmsg(sock_fd, &msg, 0);
		if (ret < 0) {
			if (errno == EINTR) {
				repeat = 1;
			} else if (errno == EAGAIN || errno == EWOULDBLOCK) {
				repeat = 1;
				usleep(1000);
			}
		}
	} while (repeat);
	
	RETVAL = ret;
}
OUTPUT: RETVAL
