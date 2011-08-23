noinst_PROGRAMS = logtest
logtest_SOURCES = logtest.c

bin_PROGRAMS = pmxcfs
pmxcfs_SOURCES = pmxcfs.c

TESTS = check_memdb
check_PROGRAMS = ${TESTS}
check_memdb_SOURCES = check_memdb.c
check_memdb_CFLAGS = $(CFLAGS) @CHECK_CFLAGS@
check_memdb_LDADD = $(LDADD) @CHECK_LIBS@ 

noinst_LIBRARIES = libpmxcfs.a
libpmxcfs_a_SOURCES = 		\
	logger.h		\
	logger.c		\
	loop.h			\
	loop.c			\
	server.h		\
	server.c		\
	status.h		\
	status.c		\
	confdb.h		\
	confdb.c		\
	quorum.h		\
	quorum.c		\
	dcdb.h			\
	dcdb.c			\
	dfsm.c			\
	dfsm.h			\
	cfs-plug.h 		\
	cfs-plug.c 		\
	cfs-plug-link.c		\
	cfs-plug-func.c		\
	cfs-plug-memdb.h 	\
	cfs-plug-memdb.c 	\
	cfs-utils.h		\
	cfs-utils.c		\
	database.c		\
	memdb.h			\
	memdb.c

# add -lprofiler for google perftools
CFLAGS =  -g -O -std=gnu99 -Wall $(COROSYNC_CFLAGS) $(SQLITE3_CFLAGS) $(FUSE_CFLAGS) $(QB_CFLAGS) $(GLIB_CFLAGS) $(LIBRRD_CFLAGS) 
LDADD = libpmxcfs.a $(COROSYNC_LIBS) $(SQLITE3_LIBS) $(FUSE_LIBS) $(QB_LIBS) $(GLIB_LIBS) $(LIBRRD_LIBS)

CLEANFILES = *~