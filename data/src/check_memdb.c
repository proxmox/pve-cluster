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

*/

#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <errno.h>
#include <string.h>
#include <check.h>
#include <errno.h>
#include <unistd.h>

#include "cfs-utils.h"
#include "status.h"
#include "memdb.h"

cfs_t cfs = {
	.debug = 0,
	.nodename = "testnode",
	.print_to_console = 1,
};

#define TESTDB "/tmp/test.db"

static memdb_t *memdb;

static void
setup(void)
{
	unlink(TESTDB);
	memdb = memdb_open(TESTDB);	
	fail_unless (memdb != NULL);

	struct statvfs stbuf;
	fail_unless(memdb_statfs(memdb, &stbuf) == 0);

	int count = stbuf.f_files - stbuf.f_ffree;
	fail_unless(count == 1);
}
 	
void
teardown(void)
{
	fail_unless (memdb != NULL);	

	memdb_close(memdb);
}

START_TEST(test_indextest1)
{
	char namebuf[100];

	time_t ctime = 1234;
	int testsize = 1024*32;
	gchar *testdata = g_malloc0(testsize);

	for (int i = 0; i < 100; i++) {
		sprintf(namebuf, "testfile%d", i);

		fail_unless(memdb_create(memdb, namebuf, 0, ctime) == 0);
		fail_unless(memdb_write(memdb, namebuf, 0, ctime, testdata, testsize, 0, 0) == testsize);
	}

	struct statvfs stbuf;
	fail_unless(memdb_statfs(memdb, &stbuf) == 0);

	int count = stbuf.f_files - stbuf.f_ffree;
	fail_unless(count == 101);

	memdb_index_t *idx = memdb_encode_index(memdb->index, memdb->root);
	fail_unless(idx != NULL);
	
	fail_unless(idx->version == 201);
	fail_unless(idx->last_inode == 200);
	fail_unless(idx->writer == 0);
	fail_unless(idx->size == 101);
	fail_unless(idx->bytes == (101*40 + sizeof( memdb_index_t)));

	GChecksum *sha256 = g_checksum_new(G_CHECKSUM_SHA256); 
	fail_unless(sha256 != NULL);
	g_checksum_update(sha256, (unsigned char *)idx, idx->bytes);
	const char *csum = g_checksum_get_string(sha256);
	fail_unless(strcmp(csum, "913fd95015af9d93f10dd51ba2a7bb11351bcfe040be21e95fcba834adc3ec10") == 0, "wrong idx checksum %s", csum);

}
END_TEST

START_TEST (test_dirtest1)
{
	const char *dn = "/dir1";
	const char *sdn = "/dir1/sdir1";
	time_t ctime = 1234;

	fail_unless(memdb_mkdir(memdb, sdn, 0, ctime) == -ENOENT);
	fail_unless(memdb_delete(memdb, dn, 0, ctime) == -ENOENT);

	fail_unless(memdb_mkdir(memdb, dn, 0, ctime) == 0);
	fail_unless(memdb_mkdir(memdb, dn, 0, ctime) == -EEXIST);
	fail_unless(memdb_mkdir(memdb, sdn, 0, ctime) == 0);
	fail_unless(memdb_mkdir(memdb, sdn, 0, ctime) == -EEXIST);
	fail_unless(memdb_delete(memdb, dn, 0, ctime) == -ENOTEMPTY);
	fail_unless(memdb_delete(memdb, sdn, 0, ctime) == 0);
	fail_unless(memdb_delete(memdb, dn, 0, ctime) == 0);
}
END_TEST

START_TEST (test_filetest1)
{
	const char *dn = "/dir1";
	const char *fn = "/dir1/f1";
	time_t ctime = 1234;
	gpointer data;

	char buf[1024];
	memset(buf, 0, sizeof(buf));

	fail_unless(memdb_read(memdb, fn, &data) == -ENOENT);

	fail_unless(memdb_mkdir(memdb, dn, 0, ctime) == 0);

	fail_unless(memdb_read(memdb, fn, &data) == -ENOENT);

	fail_unless(memdb_write(memdb, fn, 0, ctime, buf, sizeof(buf), 0, 0) == -ENOENT);

	fail_unless(memdb_create(memdb, fn, 0, ctime) == 0);

	fail_unless(memdb_write(memdb, fn, 0, ctime, buf, sizeof(buf), 0, 0) == sizeof(buf));

	fail_unless(memdb_read(memdb, fn, &data) == sizeof(buf));

	fail_unless(memcmp(buf, data, sizeof(buf)) == 0);

	g_free(data);

	fail_unless(memdb_write(memdb, fn, 0, ctime, "0123456789", 10, 0, 1) == 10);
	
	fail_unless(memdb_read(memdb, fn, &data) == 10);
	g_free(data);

	fail_unless(memdb_write(memdb, fn, 0, ctime, "X", 1, 3, 0) == 1);

	fail_unless(memdb_write(memdb, fn, 0, ctime, "X", 1, 6, 0) == 1);

	fail_unless(memdb_read(memdb, fn, &data) == 10);

	fail_unless(strncmp(data, "012X45X789", 10) == 0);

	fail_unless(memdb_delete(memdb, fn, 0, ctime) == 0);

	fail_unless(memdb_delete(memdb, fn, 0, ctime) == -ENOENT);

	fail_unless(memdb_delete(memdb, dn, 0, ctime) == 0);
}
END_TEST

/* Nornmaly, parent inode number is always less than contained inode,
 * but this is not allways the case. A simple move can destroy that 
 * ordering. This code test the placeholder algorithm in 
 * bdb_backend_load_index()
 */
START_TEST (test_loaddb1)
{
	time_t ctime = 1234;

	fail_unless(memdb_mkdir(memdb, "dir1", 0, ctime) == 0);

	fail_unless(memdb_create(memdb, "dir1/file1", 0, ctime) == 0);

	fail_unless(memdb_create(memdb, "dir1/file2", 0, ctime) == 0);

	fail_unless(memdb_mkdir(memdb, "dir2", 0, ctime) == 0);

	fail_unless(memdb_rename(memdb, "dir1/file1", "dir2/file1", 0, ctime) == 0);

	fail_unless(memdb_rename(memdb, "dir1/file2", "dir2/file2", 0, ctime) == 0);

	fail_unless(memdb_create(memdb, "dir2/file1", 0, ctime) == -EEXIST);

	fail_unless(memdb_create(memdb, "dir2/file2", 0, ctime) == -EEXIST);

	//memdb_dump(memdb);

	memdb_close(memdb);

	memdb = memdb_open(TESTDB);	
	fail_unless (memdb != NULL);

	fail_unless(memdb_create(memdb, "dir2/file1", 0, ctime) == -EEXIST);

	fail_unless(memdb_create(memdb, "dir2/file2", 0, ctime) == -EEXIST);

	//memdb_dump(memdb);

}
END_TEST

START_TEST (test_loaddb2)
{
	time_t ctime = 1234;

	fail_unless(memdb_mkdir(memdb, "dir1", 0, ctime) == 0);

	fail_unless(memdb_mkdir(memdb, "dir1/sd1", 0, ctime) == 0);

	fail_unless(memdb_create(memdb, "dir1/file1", 0, ctime) == 0);

	fail_unless(memdb_create(memdb, "dir1/file2", 0, ctime) == 0);

	fail_unless(memdb_mkdir(memdb, "dir2", 0, ctime) == 0);

	fail_unless(memdb_rename(memdb, "dir1/sd1", "dir2/sd1", 0, ctime) == 0);

	fail_unless(memdb_rename(memdb, "dir1/file1", "dir2/sd1/file1", 0, ctime) == 0);

	fail_unless(memdb_rename(memdb, "dir1/file2", "dir2/sd1/file2", 0, ctime) == 0);

	fail_unless(memdb_create(memdb, "dir2/file3", 0, ctime) == 0);

	fail_unless(memdb_mkdir(memdb, "dir2/sd1", 0, ctime) == -EEXIST);

	//memdb_dump(memdb);

	memdb_close(memdb);

	memdb = memdb_open(TESTDB);	
	fail_unless (memdb != NULL);

	fail_unless(memdb_mkdir(memdb, "dir2/sd1", 0, ctime) == -EEXIST);

	//memdb_dump(memdb);

}
END_TEST

static void
add_test(
	Suite *s,
	TFun tf,
	const char *name)
{
	TCase *tc = tcase_create (name);
	tcase_add_checked_fixture (tc, setup, teardown);
	tcase_add_test (tc, tf);
	suite_add_tcase (s, tc);
}

static Suite *
memdb_suite(void)
{
	Suite *s = suite_create ("memdb");

	add_test(s, test_dirtest1, "dirtest1");

	add_test(s, test_filetest1, "filetest1");
 
	add_test(s, test_indextest1, "indextest1");
 
	add_test(s, test_loaddb1, "loaddb1");
 
	add_test(s, test_loaddb2, "loaddb2");
 
	return s;
}

int
main(void)
{
	int number_failed;

	g_thread_init(NULL);
	
	cfs_status_init();

	Suite *s = memdb_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

