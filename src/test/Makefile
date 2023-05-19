all:

cpgtest: cpgtest.c
	gcc -Wall cpgtest.c $(shell pkg-config --cflags --libs libcpg libqb) -o cpgtest

.PHONY: check install clean distclean
check:
	./corosync_parser_test.pl

distclean: clean
clean:
