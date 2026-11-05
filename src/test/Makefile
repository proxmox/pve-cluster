all:

cpgtest: cpgtest.c
	gcc -Wall cpgtest.c $(shell pkg-config --cflags --libs libcpg libqb) -o cpgtest

.PHONY: check install clean distclean
check: corosync-parser-test test-mac-prefix test-token-policy test-cluster-id

.PHONY: corosync-parser-test
corosync-parser-test:
	./corosync_parser_test.pl

.PHONY: test-mac-prefix
test-mac-prefix:
	perl test_mac_prefix.pl

.PHONY: test-token-policy
test-token-policy:
	perl test_token_policy.pl

.PHONY: test-cluster-id
test-cluster-id:
	perl test_cluster_id.pl

distclean: clean
clean:
