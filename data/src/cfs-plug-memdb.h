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

#ifndef _PVE_CFS_PLUG_MEMDB_H_
#define _PVE_CFS_PLUG_MEMDB_H_

#include <unistd.h>
#include <fcntl.h>
#include "cfs-plug.h"

#include "dfsm.h"
#include "memdb.h"


typedef struct {
	cfs_plug_t plug;
	memdb_t *memdb;
	dfsm_t *dfsm;
} cfs_plug_memdb_t;

cfs_plug_memdb_t *cfs_plug_memdb_new(
	const char *name, 
	memdb_t *memdb, 
	dfsm_t *dfsm);

#endif /* _PVE_CFS_PLUG_MEMDB_H_ */
