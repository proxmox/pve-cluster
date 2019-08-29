
DEPENDENCIES=libcpg libcmap libquorum libqb glib-2.0 fuse sqlite3 librrd

CC = gcc
CFLAGS += -std=gnu99
CFLAGS += -Wall -Werror -Wno-unknown-pragmas -Wno-strict-aliasing
CFLAGS += -Wpedantic
CFLAGS += -g -O2 -Wl,-z,relro
CFLAGS += -I.
CFLAGS += $(shell pkg-config --cflags ${DEPENDENCIES})

LDFLAGS += $(shell pkg-config --libs ${DEPENDENCIES})

AR = ar
ARFLAGS = crs

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $< -MMD -MT $@ -MF $@.d

all: pmxcfs create_pmxcfs_db logtest check_memdb

libpmxcfs.a: logger.o loop.o server.o status.o confdb.o quorum.o dcdb.o dfsm.o
libpmxcfs.a: cfs-plug.o cfs-plug-memdb.o cfs-plug-link.o cfs-plug-func.o
libpmxcfs.a: cfs-utils.o memdb.o database.o
libpmxcfs.a:
	$(AR) $(ARFLAGS) $@ $^

pmxcfs: pmxcfs.o libpmxcfs.a
	$(CC) $(LDFLAGS) -o $@ $^


create_pmxcfs_db: create_pmxcfs_db.o libpmxcfs.a
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

logtest: logtest.o libpmxcfs.a
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

check_memdb: check_memdb.o libpmxcfs.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(shell pkg-config --libs check)

pmxcfs.8:

export NOVIEW=1
-include /usr/share/pve-doc-generator/pve-doc-generator.mk

.PHONY: install
install: pmxcfs create_pmxcfs_db pmxcfs.8
	install -D -m 0755 pmxcfs ${DESTDIR}/usr/bin/pmxcfs
	install -D -m 0755 create_pmxcfs_db ${DESTDIR}/usr/bin/create_pmxcfs_db
	install -D pmxcfs.8 ${DESTDIR}/usr/share/man/man8/pmxcfs.8

.PHONY: check
check: check_memdb
	./check_memdb

.PHONY: clean
clean:
	rm -f *.o *.o.d *.a pmxcfs create_pmxcfs_db check_memdb logtest pmxcfs.8

-include *.o.d
