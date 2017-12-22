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

#define RESTART_FLAG_FILE "/run/pve-cluster/cfs-restart-flag"
#define RESTART_GRACE_PERIOD 5

#define PCS_SOCKET_NAME "pve2"

#define PCS_SERVICE1 1
#define MAX_MSG_SIZE (8192*128)

static qb_ipcc_connection_t *conn;
static pid_t conn_pid;

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


MODULE = PVE::IPCC		PACKAGE = PVE::IPCC		

SV *
ipcc_send_rec(msgid, data=NULL)
I32 msgid;
SV * data;
PROTOTYPE: $;$
CODE:
{
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
	}

	size_t len = 0;
	char *dataptr = NULL;
	if (data && SvPOK(data))
		dataptr = SvPV(data, len);

	int iov_len = 2;
	struct iovec iov[iov_len];

	struct qb_ipc_request_header req_header;

	req_header.id = msgid;
	req_header.size = sizeof(req_header) + len;

	iov[0].iov_base = (char *)&req_header;
	iov[0].iov_len = sizeof(req_header);
	iov[1].iov_base = dataptr;
	iov[1].iov_len = len;

	int32_t ms_timeout = -1; // fixme:     
	int res = qb_ipcc_sendv_recv(conn, iov, iov_len, ipcbuffer, sizeof(ipcbuffer), ms_timeout);
	if (res < 0) {
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

	struct qb_ipc_response_header *res_header;

	res_header = (struct qb_ipc_response_header *)ipcbuffer;
	int dsize = res_header->size - sizeof(struct qb_ipc_response_header);

	if (res_header->error < 0) {
		errno = -res_header->error;
		XSRETURN_UNDEF;
	} else {
		errno = 0;
		if (dsize > 0) {
			RETVAL = newSVpv(ipcbuffer + sizeof(struct qb_ipc_response_header), dsize);
		} else {
			XSRETURN_UNDEF;
		}
	}
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
