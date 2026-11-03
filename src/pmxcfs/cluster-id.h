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

#ifndef _PVE_CLUSTER_ID_H_
#define _PVE_CLUSTER_ID_H_

#include <glib.h>

#include "memdb.h"

/* the ID is 20 random characters of the lowercase RFC 4648 base32 alphabet, so 100 random bits,
 * pmxcfs writes it plus a newline */
#define CLUSTER_ID_LEN 20
#define CLUSTER_ID_FILE_SIZE (CLUSTER_ID_LEN + 1)

gboolean cluster_id_generate(char id[CLUSTER_ID_FILE_SIZE]);

gboolean cluster_id_is_valid(gconstpointer data, size_t len);

typedef enum {
    CLUSTER_ID_VALID,
    CLUSTER_ID_MISSING,
    CLUSTER_ID_INVALID,
    /* a directory, which only rmdir can remove */
    CLUSTER_ID_NOT_A_FILE,
} cluster_id_state_t;

cluster_id_state_t cluster_id_state(memdb_t *memdb);

/* generates and stores an ID unless a valid one exists, failures only get logged */
void cluster_id_ensure_standalone(memdb_t *memdb);

#endif /* _PVE_CLUSTER_ID_H_ */
