/*
  Copyright (C) 2010 Proxmox Server Solutions GmbH

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

#ifndef _PVE_DCDB_H_
#define _PVE_DCDB_H_

#include <glib.h>

#include "dfsm.h"
#include "memdb.h"

#define DCDB_CPG_GROUP_NAME "pve_dcdb_v1"
/* please increase protocol version if you want to stop older nodes */
#define DCDB_PROTOCOL_VERSION 1
#define DCDB_VERIFY_TIME (60*60)

typedef enum {
	DCDB_MESSAGE_CFS_WRITE = 1,
	DCDB_MESSAGE_CFS_MKDIR = 2,
	DCDB_MESSAGE_CFS_DELETE = 3,
	DCDB_MESSAGE_CFS_RENAME = 4,
	DCDB_MESSAGE_CFS_CREATE = 5,
	DCDB_MESSAGE_CFS_MTIME = 6,
	DCDB_MESSAGE_CFS_UNLOCK_REQUEST = 7,
	DCDB_MESSAGE_CFS_UNLOCK = 8,
} dcdb_message_t;

#define DCDB_VALID_MESSAGE_TYPE(mt) (mt >= DCDB_MESSAGE_CFS_WRITE && mt <= DCDB_MESSAGE_CFS_UNLOCK)

dfsm_t *dcdb_new(memdb_t *memdb);

void dcdb_sync_cluster_conf(
	memdb_t *memdb, 
	gboolean notify_cman);

int dcdb_send_fuse_message(
	dfsm_t *dfsm, 
	dcdb_message_t msg_type,
	const char *path, 
	const char *to, 
	const char *buf,
	guint32 size, 
	guint32 offset, 
	guint32 flags);

void
dcdb_send_unlock(
	dfsm_t *dfsm,
	const char *path,
	const guchar csum[32],
	gboolean request);

#endif /* _PVE_DCDB_H_ */
