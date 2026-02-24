all:

cpgtest: cpgtest.c
	gcc -Wall cpgtest.c $(shell pkg-config --cflags --libs libcpg libqb) -o cpgtest

.PHONY: check install clean distclean
check: corosync-parser-test test-mac-prefix

.PHONY: corosync-parser-test
corosync-parser-test:
	./corosync_parser_test.pl

.PHONY: test-mac-prefix
test-mac-prefix:
	perl test_mac_prefix.pl

distclean: clean
clean:
