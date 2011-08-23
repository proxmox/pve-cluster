#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <sys/syslog.h>
#include <qb/qbdefs.h>
#include <qb/qbutil.h>
#include <qb/qbipcc.h>

#define PCS_SOCKET_NAME "pve2"

#define PCS_SERVICE1 1
#define MAX_MSG_SIZE (8192*128)

static qb_ipcc_connection_t *conn;
static char ipcbuffer[MAX_MSG_SIZE];

static void libqb_log_writer(const char *file_name,
			     int32_t file_line,
			     int32_t severity, const char *msg)
{
	if (severity == LOG_DEBUG)
		return;

	warn("libqb: %s:%d [%d] %s\n", file_name, file_line, severity, msg);
}

MODULE = PVE::IPCC		PACKAGE = PVE::IPCC		

SV *
ipcc_send_rec(msgid, data=NULL)
I32 msgid;
SV * data;
PROTOTYPE: $;$
CODE:
{
	if (conn == NULL) {
		qb_util_set_log_function(libqb_log_writer);
		conn = qb_ipcc_connect(PCS_SOCKET_NAME, MAX_MSG_SIZE);

		if (!conn)
			XSRETURN_UNDEF;
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
		if (dsize > 0) {
			RETVAL = newSVpv(ipcbuffer + sizeof(struct qb_ipc_response_header), dsize);
		} else {
			errno = 0;
			XSRETURN_UNDEF;
		}
	}
}
OUTPUT: RETVAL

