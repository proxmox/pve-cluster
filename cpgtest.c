/*
  Copyright (C) 2009 Proxmox Server Solutions GmbH

  Copyright: This program is under GNU GPL, the GNU General Public License.

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 dated June, 1991.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
  02111-1307, USA.

  Author: Dietmar Maurer <dietmar@proxmox.com>

*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <corosync/corotypes.h>
#include <corosync/cpg.h>

static int cpg_mode_leave;

static void my_cpg_deliver_callback (
        cpg_handle_t handle,
        const struct cpg_name *groupName,
        uint32_t nodeid,
        uint32_t pid,
        void *msg,
        size_t msg_len)
{
	printf("got message form %d/%d\n", nodeid, pid);

	cpg_mode_leave = 1;

	return;
}

static void my_cpg_confchg_callback (
        cpg_handle_t handle,
        const struct cpg_name *groupName,
        const struct cpg_address *member_list, size_t member_list_entries,
        const struct cpg_address *left_list, size_t left_list_entries,
        const struct cpg_address *joined_list, size_t joined_list_entries)
{
        int i;

	printf("cpg_confchg_callback %ld joined, %ld left, %ld members\n",
	       joined_list_entries, left_list_entries, member_list_entries);

	for (i = 0; i < member_list_entries; i++) {
		printf("cpg member %d/%d\n", member_list[i].nodeid, member_list[i].pid);
	}

	/* send update message */
	char *inbuf = "This is jus a test message\n";
	struct iovec iov;
	iov.iov_base = inbuf;
	iov.iov_len = strlen(inbuf)+1;

	cpg_error_t result;
loop:
	result = cpg_mcast_joined(handle, CPG_TYPE_AGREED, &iov, 1);
	if (result == CPG_ERR_TRY_AGAIN) {
		usleep(1000);
		printf("cpg_send_message retry");
		goto loop;
	}

	if (result != CS_OK) 
		printf("cpg_send_message failed: %d\n", result);

}

static cpg_callbacks_t callbacks = {
        .cpg_deliver_fn =            my_cpg_deliver_callback,
        .cpg_confchg_fn =            my_cpg_confchg_callback,
};


int main(int argc, char *argv[])
{
	struct cpg_name group_name;
	char *gn = "TESTGROUP";
	strcpy(group_name.value, gn);
	group_name.length = strlen(gn) + 1;

	cs_error_t result;
	cpg_handle_t handle;

start:
	printf("starting cpgtest\n");

	cpg_mode_leave = 0;
 
	handle = 0;

	printf("calling cpg_initialize\n");
	result = cpg_initialize(&handle, &callbacks);
	if (result != CS_OK) {
		printf("cpg_initialize failed: %d\n", result);
		goto retry;
	}

	printf("calling cpg_join\n");
	while ((result = cpg_join(handle, &group_name)) == CS_ERR_TRY_AGAIN) { 
		printf("cpg_join returned %d\n", result);
		sleep (1);
	}

	if (result != CS_OK) {
		printf("cpg_join failed: %d\n", result);
		exit(-1);		
	}

	fd_set read_fds;
	FD_ZERO(&read_fds);
	int cpg_fd;

	cpg_fd_get(handle, &cpg_fd);

	printf("starting main loop\n");

	do {
		FD_SET(cpg_fd, &read_fds);
		struct timeval timeout = { 1, 0};
		result = select(cpg_fd + 1, &read_fds, 0, 0, &timeout);

		if (result == -1) {
			printf("select error: %d\n", result);
			break;
		} 
		if (result > 0) {

			if (FD_ISSET(cpg_fd, &read_fds)) {			
				cs_error_t res = cpg_dispatch(handle, CPG_DISPATCH_ALL);
				if (res != CS_OK) {
					printf("cpg_dispatch failed: %d\n", res);
					break;
				}
			}
		}

		if (cpg_mode_leave)
			break;

	} while(1);

retry:

	printf("end loop - trying to restart\n");

	usleep (1000);

	if (handle) {

		result = cpg_finalize(handle);
		if (result != CS_OK) {
			printf("cpg_finalize failed: %d\n", result);
			exit(-1);
		}
	}

	goto start;

	exit(0);
}
