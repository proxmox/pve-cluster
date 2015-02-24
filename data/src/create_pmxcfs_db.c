/*
  Copyright (C) 2010-2012 Proxmox Server Solutions GmbH

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

  Note: we use this with the installer to create the initial db
  without starting pmxcfs/fuse
*/

#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <errno.h>
#include <string.h>
#include <check.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>

#include "cfs-utils.h"
#include "status.h"
#include "memdb.h"

cfs_t cfs = {
	.debug = 0,
	.nodename = "dummy",
};

static memdb_t *memdb;

static void
usage_error(void) 
{
	fprintf(stderr, "Usage: create_pmxcfs_db /a/dir /a/filename.db\n");
	exit(-1);
}

int 
main(int argc, char *argv[]) 
{
	cfs_status_init();

	if (argc != 3) {
		usage_error();
	}

	const char *dir_name = argv[1];
	const char *dbfile = argv[2];

	DIR *dh = opendir(dir_name);
	if (!dh) {
		perror("unable to open dir");
		exit(-1);
	}
	memdb = memdb_open(dbfile);	

	struct dirent *de;
	time_t ctime = time(NULL);

	while((de = readdir(dh))) {
		if (de->d_type != DT_REG) {
			continue;
		}

		char *cdata = NULL;
		gsize clen = 0;
		char *fn = g_strdup_printf("%s/%s", dir_name, de->d_name);
		if (g_file_get_contents(fn, &cdata, &clen, NULL)) {
			//printf("FOUND %ld %s\n", clen, fn);
			if (memdb_create(memdb, de->d_name, 0, ctime) != 0) {
				fprintf(stderr, "memdb_create '%s' failed\n", de->d_name);
				exit(-1);
			}
			if (memdb_write(memdb, de->d_name, 0, ctime, cdata, clen, 0, 1) != clen) {
				fprintf(stderr, "memdb_write '%s' failed\n", de->d_name);
				exit(-1);
			}

		}
		g_free(fn);
	}

	memdb_close(memdb);

	closedir(dh);
}
