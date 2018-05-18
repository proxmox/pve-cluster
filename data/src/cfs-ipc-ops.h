/*
  Copyright (C) 2018 Proxmox Server Solutions GmbH

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

#ifndef _PVE_CFS_IPC_OPS_H_
#define _PVE_CFS_IPC_OPS_H_

#define CFS_IPC_GET_FS_VERSION 1

#define CFS_IPC_GET_CLUSTER_INFO 2

#define CFS_IPC_GET_GUEST_LIST 3

#define CFS_IPC_SET_STATUS 4

#define CFS_IPC_GET_STATUS 5

#define CFS_IPC_GET_CONFIG 6

#define CFS_IPC_LOG_CLUSTER_MSG 7

#define CFS_IPC_GET_CLUSTER_LOG 8

#define CFS_IPC_GET_RRD_DUMP 10

#endif
