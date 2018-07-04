DESTDIR=
PERL5DIR=${DESTDIR}/usr/share/perl5
PVEDIR=${PERL5DIR}/PVE
MAN=${DESTDIR}/usr/share/man
BASHCOMPLETION=${DESTDIR}/usr/share/bash-completion/completions

PERL_VENDORARCH=$(shell perl -MConfig -e 'print $$Config{vendorarch};')
PVE_VENDORARCH=${DESTDIR}/${PERL_VENDORARCH}/auto/PVE/IPCC

SUBDIRS=Cluster CLI API2
SOURCES=IPCC.pm Cluster.pm Corosync.pm

all:

.PHONY: install
install: pvecm ${SOURCES} IPCC.so pvecm.1 pvecm.bash-completion datacenter.cfg.5
	install -D -m 0755 pvecm ${DESTDIR}/usr/bin/pvecm
	install -d ${PVEDIR}
	for f in ${SOURCES}; do install -m 0664 $$f ${PVEDIR}/$$f; done
	install -D IPCC.so ${PVE_VENDORARCH}/IPCC.so
	install -D pvecm.1 ${MAN}/man1/pvecm.1
	install -D datacenter.cfg.5 ${MAN}/man5/datacenter.cfg.5
	install -m 0644 -D pvecm.bash-completion ${BASHCOMPLETION}/pvecm
	for d in ${SUBDIRS}; do $(MAKE) -C $$d install; done

%.bash-completion:
	LD_LIBRARY_PATH=. perl -I.. -T -e "use PVE::CLI::$*; PVE::CLI::$*->generate_bash_completions();" >$@.tmp
	mv $@.tmp $@

check:
	LD_LIBRARY_PATH=. perl -I.. -T -e "use PVE::CLI::pvecm; PVE::CLI::pvecm->verify_api();"

CC=gcc
CFLAGS += -fPIC -Wl,-z,relro -Wall -Werror -Wno-strict-aliasing -g -O2 -shared
CFLAGS += $(shell perl -MExtUtils::Embed -e perl_inc)
LDFLAGS = $(shell pkg-config --libs libqb)

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

IPCC.c: IPCC.xs ppport.h
	xsubpp -noversioncheck IPCC.xs > IPCC.xsc
	mv IPCC.xsc IPCC.c

IPCC.so: IPCC.o
	$(CC) ${CFLAGS} ${LDFLAGS} -shared -o $@ $<

export PERLLIB=..
export NOVIEW=1
-include /usr/share/pve-doc-generator/pve-doc-generator.mk

.PHONY: clean
clean:
	$(MAKE) cleanup-docgen
	rm -f IPCC.so IPCC.o IPCC.c pvecm.bash-completion
	for d in ${SUBDIRS}; do $(MAKE) -C $$d clean; done
