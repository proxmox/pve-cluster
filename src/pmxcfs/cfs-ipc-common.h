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

  Author: Daniel Kral <d.kral@proxmox.com>

*/

#ifndef _PVE_CFS_IPC_COMMON_H_
#define _PVE_CFS_IPC_COMMON_H_

#include <qb/qbipc_common.h>

/* Set in the request id by clients that can handle the extended response header and responses
 * split into multiple chunks. A pmxcfs without chunked responses does not know such a request id
 * and answers with only the libqb response header and -ECHRNG, without handling the request, which
 * lets the client fall back to plain requests. Clients without chunk support never set it, so no
 * request body can be mistaken for a capability announcement. */
#define CFS_IPC_REQ_FLAG_CHUNKED_RESPONSE (1 << 30)

/* Request id with which a client fetches the next chunk of a response, with the uint32_t index of
 * that chunk as request body. Only valid with CFS_IPC_REQ_FLAG_CHUNKED_RESPONSE set, and only while
 * the rest of the previous response is pending. Defined here and not in cfs-ipc-ops.h, as it is
 * part of the transfer protocol and no operation of its own, and numbered apart from those
 * operations so that their ids can continue without a gap. */
#define CFS_IPC_GET_RESPONSE_CHUNK (1 << 16)

enum cfs_ipc_response_flags {
    /* An intermediate response message chunk. Receivers fetch the next
     * chunk with a CFS_IPC_GET_RESPONSE_CHUNK request. */
    CFS_IPC_RES_FLAG_CHUNK = 1 << 1,
    /* A standalone response message or the last response message chunk.
     * Receivers can expect to not receive any message afterwards. */
    CFS_IPC_RES_FLAG_CHUNK_LAST = 1 << 2,
};

struct cfs_ipc_response_header {
    struct qb_ipc_response_header qb_header;
    uint32_t flags __attribute__((aligned(8)));
    uint32_t index __attribute__((aligned(8)));
} __attribute__((aligned(8)));

#endif /* _PVE_CFS_IPC_COMMON_H_ */
