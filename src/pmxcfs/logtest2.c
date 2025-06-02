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

#define _XOPEN_SOURCE /* glibc2 needs this */
#include <time.h>     /* for strptime */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <sys/types.h>
#include <unistd.h>

#include "cfs-utils.h"
#include "logger.h"

struct clog_base {
    uint32_t size;
    uint32_t cpos;
    char data[];
};

struct clusterlog {
    GHashTable *dedup;
    GMutex mutex;
    clog_base_t *base;
};

cfs_t cfs = {
    .debug = 0,
    .nodename = "testnode",
};

void get_state(clusterlog_t *cl) {
    unsigned int res_len;
    clusterlog_get_state(cl, &res_len);
}

void insert(clusterlog_t *cl) {
    uint32_t pid = getpid();
    clog_entry_t *entry = (clog_entry_t *)alloca(CLOG_MAX_ENTRY_SIZE);
    clog_pack(entry, cfs.nodename, "root", "cluster", pid, time(NULL), LOG_INFO, "short");
    clusterlog_insert(cl, entry);
}

void insert2(clusterlog_t *cl) {
    uint32_t pid = getpid();
    clog_entry_t *entry = (clog_entry_t *)alloca(CLOG_MAX_ENTRY_SIZE);
    clog_pack(
        entry, cfs.nodename, "root", "cluster", pid, time(NULL), LOG_INFO,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaa"
    );
    clusterlog_insert(cl, entry);
}

int main(void) {
    uint32_t pid = getpid();

    clusterlog_t *cl3 = clusterlog_new();

    clog_entry_t *entry = (clog_entry_t *)alloca(CLOG_MAX_ENTRY_SIZE);
    clog_pack(
        entry, cfs.nodename, "root", "cluster", pid, time(NULL), LOG_INFO, "starting cluster log"
    );
    clusterlog_insert(cl3, entry);

    for (int i = 0; i < 184; i++) {
        insert2(cl3);
    }

    for (int i = 0; i < 1629; i++) {
        insert(cl3);
    }

    GString *outbuf = g_string_new(NULL);

    // all of these segfault if they don't handle wrap-arounds pointing to already overwritten
    // entries
    clusterlog_dump(cl3, outbuf, NULL, 8192);
    clog_dump(cl3->base);
    get_state(cl3);

    clusterlog_destroy(cl3);
}
