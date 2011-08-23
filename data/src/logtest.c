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

#define _XOPEN_SOURCE /* glibc2 needs this */
#include <time.h> /* for strptime */

#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <sys/types.h>
#include <sys/syslog.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include "cfs-utils.h"
#include "logger.h"

cfs_t cfs = {
        .debug = 0,
	.nodename = "testnode",
        .print_to_console = 1,
};


int
main(void)
{

	uint32_t pid = getpid();

#if 1
	clusterlog_t *cl3 = clusterlog_new();

	clog_entry_t *entry = (clog_entry_t *)alloca(CLOG_MAX_ENTRY_SIZE);
	clog_pack(entry, cfs.nodename, "root", "cluster", pid, time(NULL), LOG_INFO, "starting cluster log");
	clusterlog_insert(cl3, entry);

	for (int i = 0; i < 5000; i++) {
		clusterlog_add(cl3, "user1", "TESTDOMAIN1", pid, LOG_INFO, 
			       "test user1 ä message asdasd d dsgfdfgdgdg dgg dgdg %d", i);
	}

#if 0
	for (int i = 0; i < 5000; i++) {
		clog_base_t *clog[2] = { cl3->base, cl3->base };

		clusterlog_merge(cl3, clog, 2);
		//clusterlog_sort(cl3);
	}
#endif

	//clog_dump(cl3->base);

	clusterlog_destroy(cl3);

	exit(0);

#endif


	clusterlog_t *cl1 = clusterlog_new();

	for (int i = 0; i < 5; i++) {
		clusterlog_add(cl1, "user1", "TESTDOMAIN1", pid, LOG_INFO, 
			       "test user1 message asdasd %d", i);		
	}
	

#if 0
	for (int i = 0; i < 5; i++) {
		clusterlog_add(cl1, "user2", "TESTDOMAIN1", pid, LOG_INFO, 
			       "test user2 message asdasd %d", i);		
	}
#endif

	clusterlog_t *cl2 = clusterlog_new();

#if 1
	for (int i = 0; i < 5; i++) {
		clusterlog_add(cl2, "user3", "TESTDOMAIN2", pid, LOG_INFO, 
			       "test user3 message asdasd %d", i);	
	}
#endif

#if 0
	clog_base_t *clog[2] = { cl1->base, cl2->base };

	clusterlog_merge(cl1, clog, 2);
	clog_dump(cl1->base);

	clusterlog_destroy(cl1);
	clusterlog_destroy(cl2);
#endif
}
