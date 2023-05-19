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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#define _XOPEN_SOURCE /* glibc2 needs this */
#include <time.h> /* for strptime */

#include <unistd.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdint.h>
#include <glib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#define SYSLOG_MAX_LINE_LENGTH 8192

#include "cfs-utils.h"
#include "logger.h"

/*
 * 64 bit FNV-1a non-zero initial basis
 */
#define FNV1A_64_INIT ((uint64_t) 0xcbf29ce484222325ULL)
/*
 * 64 bit Fowler/Noll/Vo FNV-1a hash code
 * (copied from sheepdog sources)
 */
static inline uint64_t fnv_64a_buf(const void *buf, size_t len, uint64_t hval)
{
	unsigned char *bp = (unsigned char *) buf;
	unsigned char *be = bp + len;
	while (bp < be) {
		hval ^= (uint64_t) *bp++;
		hval += (hval << 1) + (hval << 4) + (hval << 5) +
			(hval << 7) + (hval << 8) + (hval << 40);
	}
	return hval;
}

static uint32_t uid_counter = 0;

struct clog_base {
	uint32_t size;
	uint32_t cpos;
	char data[];
};

typedef struct {
	uint64_t node_digest;
	uint32_t uid;
	uint32_t time;
} dedup_entry_t;

static clog_entry_t *
clog_alloc_entry(
	clog_base_t *clog,
	uint32_t size)
{
	g_return_val_if_fail(clog != NULL, NULL);
	g_return_val_if_fail(size > sizeof(clog_entry_t), NULL);
	g_return_val_if_fail(size <= CLOG_MAX_ENTRY_SIZE, NULL);

	uint32_t realsize = ((size + 7) & 0xfffffff8);

	uint32_t newpos;

	if (!clog->cpos) {
		newpos = sizeof(clog_base_t);
	} else {
		clog_entry_t *cur = (clog_entry_t *)((char *)clog + clog->cpos);
		newpos = cur->next;
		if ((newpos + realsize) >= clog->size) {
			newpos = sizeof(clog_base_t);
		}
	}

	clog_entry_t *entry = (clog_entry_t *)((char *)clog + newpos);

	entry->prev = clog->cpos;
	clog->cpos = newpos;
	entry->next = newpos + realsize; 

	return entry;
}

static void
clog_dump_entry(clog_entry_t *cur, uint32_t cpos)
{
	g_return_if_fail(cur != NULL);

	char *node = cur->data;
	char *ident = node + cur->node_len;
	char *tag = ident + cur->ident_len;
	char *msg = tag + cur->tag_len;

	time_t lt = cur->time;
	char tbuf[256];
	strftime(tbuf, sizeof(tbuf), "%F %T", localtime(&lt));
	printf("cpos %05d %08x %s", cpos, cur->uid, tbuf);
	printf(" %s{%016" PRIX64 "} %s[%s{%016" PRIX64 "}]: %s\n", node, cur->node_digest, tag, ident, cur->ident_digest, msg);
	
}

void
clog_dump(clog_base_t *clog)
{
	g_return_if_fail(clog != NULL);
	
	uint32_t cpos = clog->cpos;

	while (cpos && (cpos <= clog->cpos || cpos > (clog->cpos + CLOG_MAX_ENTRY_SIZE))) {
		clog_entry_t *cur = (clog_entry_t *)((char *)clog + cpos);
		clog_dump_entry(cur, cpos);

		// wrap-around has to land after initial position
		if (cpos < cur->prev && cur->prev <= clog->cpos) {
			break;
		}
		cpos = cur->prev;
	}
}

void
clog_dump_json(
	clog_base_t *clog, 
	GString *str, 
	const char *ident, 
	guint max_entries)
{
	g_return_if_fail(clog != NULL);
	g_return_if_fail(str != NULL);
	
	guint64 ident_digest = 0;

	if (ident && ident[0]) {
		ident_digest = fnv_64a_buf(ident, strlen(ident) + 1, FNV1A_64_INIT);
	}

	uint32_t cpos = clog->cpos;

	g_string_append_printf(str, "{\n");

	g_string_append_printf(str, "\"data\": [\n");

	guint count = 0;
	while (cpos && (cpos <= clog->cpos || cpos > (clog->cpos + CLOG_MAX_ENTRY_SIZE))) {
		clog_entry_t *cur = (clog_entry_t *)((char *)clog + cpos);

		// wrap-around has to land after initial position
		if (cpos < cur->prev && cur->prev <= clog->cpos) {
			break;
		}
		cpos = cur->prev;

		if (count >= max_entries)
			break;

		if (ident_digest && ident_digest != cur->ident_digest)
			continue;

		char *node = cur->data;
		char *ident = node + cur->node_len;
		char *tag = ident + cur->ident_len;
		char *msg = tag + cur->tag_len;

		if (count)
			g_string_append_printf(str, ",\n");

		g_string_append_printf(str, "{\"uid\": %u, \"time\": %u, \"pri\": %d, \"tag\": \"%s\", "
				       "\"pid\": %u, \"node\": \"%s\", \"user\": \"%s\", "
				       "\"msg\": \"%s\"}", cur->uid, cur->time, cur->priority, tag, 
				       cur->pid, node, ident, msg);
		
		count++;

	}

	if (count)
		g_string_append_printf(str, "\n");

	g_string_append_printf(str, "]\n");
	g_string_append_printf(str, "}\n");

}

uint32_t
clog_entry_size(const clog_entry_t *entry)
{
	g_return_val_if_fail(entry != NULL, 0);

	return sizeof(clog_entry_t) + entry->node_len + 
		entry->ident_len + entry->tag_len + entry->msg_len;
}

void
clog_copy(
	clog_base_t *clog,
	const clog_entry_t *entry)
{
	g_return_if_fail(clog != NULL);
	g_return_if_fail(entry != NULL);

	uint32_t size = clog_entry_size(entry);
	
	clog_entry_t *new;
	if ((new = clog_alloc_entry(clog, size)))
		memcpy((char *)new + 8, (char *)entry + 8, size - 8);
}

uint32_t
clog_pack(
	clog_entry_t *entry,
	const char *node, 
	const char *ident, 
	const char *tag,
	uint32_t pid,
	time_t logtime,
	uint8_t priority,
	const char *msg)
{
	g_return_val_if_fail(entry != NULL, 0);
	g_return_val_if_fail(ident != NULL, 0);
	g_return_val_if_fail(tag != NULL, 0);
	g_return_val_if_fail(msg != NULL, 0);
	g_return_val_if_fail(priority >= 0, 0);
	g_return_val_if_fail(priority < 8, 0);

	uint8_t node_len = CFS_MIN(strlen(node) + 1, 255);
	uint8_t ident_len = CFS_MIN(strlen(ident) + 1, 255);
	uint8_t tag_len = CFS_MIN(strlen(tag) + 1, 255);

	char *msg_start = entry->data + node_len + ident_len + tag_len;
	*msg_start = 0;

	int buf_len = CLOG_MAX_ENTRY_SIZE - (msg_start - (char *)entry);
	utf8_to_ascii(msg_start, buf_len, msg, TRUE);

	uint32_t msg_len = strlen(msg_start) + 1;

	uint32_t size = sizeof(clog_entry_t) + node_len + ident_len + 
		tag_len + msg_len;

	if (size > CLOG_MAX_ENTRY_SIZE) {
		int diff = size - CLOG_MAX_ENTRY_SIZE;
		msg_len -= diff;
		size = CLOG_MAX_ENTRY_SIZE;
	}

	entry->prev = 0;
	entry->next = 0;
	entry->uid = ++uid_counter;
	entry->time = logtime;
	entry->node_digest = fnv_64a_buf(node, node_len, FNV1A_64_INIT);
	entry->ident_digest = fnv_64a_buf(ident, ident_len, FNV1A_64_INIT);
	entry->pid = pid;
	entry->priority = priority;
	entry->node_len = node_len;
	entry->ident_len = ident_len;
	entry->tag_len = tag_len;
	entry->msg_len = msg_len;

	char *p = entry->data;
	g_strlcpy(p, node, node_len);
	p = p + node_len;
	g_strlcpy(p, ident, ident_len);
	p = p + ident_len;
	g_strlcpy(p, tag, tag_len);

	return size;
}

clog_base_t *
clog_new(uint32_t size)
{
	g_return_val_if_fail(sizeof(clog_base_t) == 8, NULL);

	if (!size)
		size = CLOG_DEFAULT_SIZE;

	g_return_val_if_fail(size >= (CLOG_MAX_ENTRY_SIZE*10), NULL);


	clog_base_t *clog = (clog_base_t *)g_malloc0(size);
	if (clog) {
		clog->size = size;
	}

	return clog;
}

static gint
clog_entry_sort_fn(
	gconstpointer v1, 
	gconstpointer v2,
	gpointer user_data)
{
	clog_entry_t *entry1 = (clog_entry_t *)v1;
	clog_entry_t *entry2 = (clog_entry_t *)v2;

	if (entry1->time != entry2->time)
		return entry1->time - entry2->time;

	if (entry1->node_digest != entry2->node_digest)
		return entry1->node_digest - entry2->node_digest;

	return entry1->uid - entry2->uid;
}

static gboolean
clog_tree_foreach_fn(
	gpointer key,
	gpointer value,
	gpointer data)
{
	clog_entry_t *entry = (clog_entry_t *)value;
	clog_base_t *clog = (clog_base_t *)data;

	clog_copy(clog, entry);

	return FALSE;
}

clog_base_t *
clog_sort(clog_base_t *clog)
{
	g_return_val_if_fail(clog != NULL, NULL);
	g_return_val_if_fail(clog->cpos != 0, NULL);
	
	clog_base_t *res = clog_new(clog->size);
	if (!res)
		return NULL;

	GTree *tree = g_tree_new_with_data(clog_entry_sort_fn, NULL);
	if (!tree) {
		g_free(res);
		return NULL;
	}

	uint32_t cpos = clog->cpos;

	while (cpos && (cpos <= clog->cpos || cpos > (clog->cpos + CLOG_MAX_ENTRY_SIZE))) {
		clog_entry_t *cur = (clog_entry_t *)((char *)clog + cpos);

		g_tree_insert(tree, cur, cur);

		// wrap-around has to land after initial position
		if (cpos < cur->prev && cur->prev <= clog->cpos) {
			break;
		}

		cpos = cur->prev;
	}

	g_tree_foreach(tree, clog_tree_foreach_fn, res);
	g_tree_destroy(tree);

	return res;
}

uint32_t
clog_size(clog_base_t *clog)
{
	g_return_val_if_fail(clog != NULL, 0);
	return clog->size;
}

static gboolean
dedup_lookup(
	GHashTable *dedup,
	const clog_entry_t *entry)
{
	g_return_val_if_fail(dedup != NULL, FALSE);
	g_return_val_if_fail(entry != NULL, FALSE);

	dedup_entry_t *dd = g_hash_table_lookup(dedup, &entry->node_digest);
	if (!dd) {
		if (!(dd = g_new0(dedup_entry_t, 1)))
			return FALSE;

		dd->node_digest = entry->node_digest;
		dd->time = entry->time;
		dd->uid = entry->uid;

		g_hash_table_insert(dedup, dd, dd); 

		return TRUE;
	}

	if (entry->time > dd->time ||
	    (entry->time == dd->time && entry->uid > dd->uid)) {
		dd->time = entry->time; 
		dd->uid = entry->uid; 
		return TRUE;
	}

	return FALSE;
}

struct clusterlog {
	GHashTable *dedup;
	GMutex mutex;
	clog_base_t *base;
};

void 
clusterlog_dump(
	clusterlog_t *cl,
	GString *str, 
	const char *user, 
	guint max_entries)
{
	g_return_if_fail(cl != NULL);
	g_return_if_fail(str != NULL);

	g_mutex_lock(&cl->mutex);
	clog_dump_json(cl->base, str, user, max_entries);
	g_mutex_unlock(&cl->mutex);
}

clog_base_t *
clusterlog_merge(
	clusterlog_t *cl,
	clog_base_t **clog, 
	int count,
	int local_index)
{
	g_return_val_if_fail(cl != NULL, NULL);
	g_return_val_if_fail(clog != NULL, NULL);
	g_return_val_if_fail(count >= 2, NULL);
	g_return_val_if_fail(local_index >= 0, NULL);
	g_return_val_if_fail(local_index < count, NULL);

	uint32_t cpos[count];
	uint32_t maxsize = 0;

	GHashTable *dedup;
	if (!(dedup = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, g_free)))
		return NULL;

	GTree *tree = g_tree_new_with_data(clog_entry_sort_fn, NULL);
	if (!tree) {
		g_hash_table_destroy(dedup);
		return NULL;
	}

	clog_base_t *res = clog_new(maxsize);
	if (!res) {
		g_hash_table_destroy(dedup);
		g_tree_destroy(tree);
		return NULL;
	}

	g_mutex_lock(&cl->mutex);

	for (int i = 0; i < count; i++) {
		if (i == local_index)
			clog[i] = cl->base;

		if (!clog[i]) {
			cfs_critical("log pointer is NULL!");
			cpos[i] = 0;
			continue;
		}
		cpos[i] = clog[i]->cpos;
		if (clog[i]->size > maxsize)
			maxsize = clog[i]->size;
	}

	size_t logsize = 0;
	maxsize = res->size - sizeof(clog_base_t) - CLOG_MAX_ENTRY_SIZE;

	int found = 0;
	while (found >= 0) {

		found = -1;
		uint32_t last = 0;

		/* select entry wit latest time */
		for (int i = 0; i < count; i++) {
			if (!cpos[i])
				continue;
			clog_entry_t *cur = (clog_entry_t *)((char *)clog[i] + cpos[i]);
			if (cur->time > last) {
				last = cur->time;
				found = i;
			}
		}

		if (found < 0)
			break;

		clog_entry_t *cur = (clog_entry_t *)((char *)clog[found] + cpos[found]);

		if (!g_tree_lookup(tree, cur)) {
			g_tree_insert(tree, cur, cur);
			dedup_lookup(dedup, cur); /* just to record versions */
			logsize += cur->next - cpos[found];
			if (logsize >= maxsize)
				break;
		}

		// no previous entry or wrap-around into already overwritten entry
		if (!cur->prev || (cpos[found] < cur->prev && cur->prev <= clog[found]->cpos)) {
			cpos[found] = 0;
		} else {
			cpos[found] = cur->prev;
			// wrap-around into current entry
			if (!(cpos[found] <= clog[found]->cpos || 
			      cpos[found] > (clog[found]->cpos + CLOG_MAX_ENTRY_SIZE))) {
				cpos[found] = 0;
			}
		}
	}

	g_tree_foreach(tree, clog_tree_foreach_fn, res);
	g_tree_destroy(tree);

	g_hash_table_destroy(cl->dedup);
	cl->dedup = dedup;

	g_free(cl->base);
	cl->base = res;

	g_mutex_unlock(&cl->mutex);

	return res;
}

void
clusterlog_destroy(clusterlog_t *cl)
{
	g_return_if_fail(cl != NULL);

	g_mutex_clear(&cl->mutex);

	if (cl->base)
		g_free(cl->base);

	if (cl->dedup)
		g_hash_table_destroy(cl->dedup);

	g_free(cl);
}

clusterlog_t *
clusterlog_new(void)
{
	clusterlog_t *cl = g_new0(clusterlog_t, 1);
	if (!cl)
		return NULL;

	g_mutex_init(&cl->mutex);

	if (!(cl->base = clog_new(0)))
		goto fail;

	if (!(cl->dedup = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, g_free)))
		goto fail;

	return cl;

fail:
	clusterlog_destroy(cl);
	return NULL;
}

gpointer
clusterlog_get_state(	
	clusterlog_t *cl,
	unsigned int *res_len)
{
	g_return_val_if_fail(cl != NULL, NULL);
	g_return_val_if_fail(res_len != NULL, NULL);
	
	g_mutex_lock(&cl->mutex);

	clog_base_t *new;
	if ((new = clog_sort(cl->base))) {
		g_free(cl->base);
		cl->base = new;
	}

	*res_len = clog_size(cl->base);
	gpointer msg = g_memdup2(cl->base, *res_len);

	g_mutex_unlock(&cl->mutex);

	return msg;
}

void
clusterlog_insert(
	clusterlog_t *cl,
	const clog_entry_t *entry)
{
	g_return_if_fail(cl != NULL);
	g_return_if_fail(entry != NULL);

	g_mutex_lock(&cl->mutex);

	if (dedup_lookup(cl->dedup, entry)) {
		clog_copy(cl->base, entry);
	} else {
		cfs_message("ignore insert of duplicate cluster log");
	}

	g_mutex_unlock(&cl->mutex);
}

void
clusterlog_add(
	clusterlog_t *cl,
	const char *ident, 
	const char *tag, 
	uint32_t pid,
	uint8_t priority, 
	const gchar *format,
	...)
{
	g_return_if_fail(cl != NULL);
	g_return_if_fail(format != NULL);

	va_list args;
	va_start (args, format);
	char *msg = g_strdup_vprintf (format, args);
	va_end (args);

	time_t ctime = time(NULL);
	clog_entry_t *entry = (clog_entry_t *)alloca(CLOG_MAX_ENTRY_SIZE);
	uint32_t size = clog_pack(entry, cfs.nodename, ident, tag, pid, ctime, priority, msg);
	g_free(msg);

	if (!size)
		return;

	clusterlog_insert(cl, entry);
}

