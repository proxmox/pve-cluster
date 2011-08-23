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

#ifndef _PVE_LOGGER_H_
#define _PVE_LOGGER_H_

#define CLOG_MAX_ENTRY_SIZE 4096
#define CLOG_DEFAULT_SIZE (8192*16)

typedef struct clog_base clog_base_t;

typedef struct clusterlog clusterlog_t;

typedef struct {
	uint32_t prev;
	uint32_t next;
	uint32_t uid; /* unique id */
	uint32_t time;
	uint64_t node_digest;
	uint64_t ident_digest;
	uint32_t pid;
	uint8_t priority; 
	uint8_t node_len;
	uint8_t ident_len;
	uint8_t tag_len;
	uint32_t msg_len;
	char data[];
} clog_entry_t;

clusterlog_t *
clusterlog_new(void);

void
clusterlog_destroy(clusterlog_t *cl);

gpointer
clusterlog_get_state(	
	clusterlog_t *cl,
	unsigned int *res_len);

void
clusterlog_add(
	clusterlog_t *cl,
	const char *ident, 
	const char *tag, 
	uint32_t pid,
	uint8_t priority, 
	const gchar *format,
	...) G_GNUC_PRINTF (6, 7);

void
clusterlog_insert(
	clusterlog_t *cl,
	const clog_entry_t *entry);

void 
clusterlog_dump(
	clusterlog_t *cl,
	GString *str, 
	const char *user, 
	guint max_entries);

clog_base_t *
clusterlog_merge(
	clusterlog_t *cl,
	clog_base_t **clog, 
	int count,
	int local_index);

clog_base_t *
clog_new(uint32_t size);

uint32_t
clog_size(clog_base_t *clog);

void
clog_dump(clog_base_t *clog);

void
clog_dump_json(
	clog_base_t *clog, 
	GString *str, 
	const char *ident, 
	guint max_entries);

clog_base_t *
clog_sort(clog_base_t *clog);

uint32_t
clog_pack(
	clog_entry_t *buffer,
	const char *node, 
	const char *ident, 
	const char *tag, 
	uint32_t pid,
	time_t logtime,
	uint8_t priority, 
	const char *msg);

uint32_t
clog_entry_size(const clog_entry_t *entry);

void
clog_copy(
	clog_base_t *clog,
	const clog_entry_t *entry);

#endif /* _PVE_LOGGER_H_ */
