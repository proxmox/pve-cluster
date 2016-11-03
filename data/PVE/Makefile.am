bin_SCRIPTS = pvecm

IPCC.c: IPCC.xs
	xsubpp IPCC.xs > IPCC.xsc
	mv IPCC.xsc IPCC.c

AM_CFLAGS = -shared -fPIC -Wl,-z,relro -Wall -Werror -Wno-strict-aliasing $(PERL_INC) -DXS_VERSION=VERSION
LDADD = $(QB_LIBS)

perlbin_PROGRAMS = IPCC.so
perlbindir = $(PERL_INSTALLARCHLIB)/auto/PVE/IPCC

# this require package pve-doc-generator
export NOVIEW=1
include /usr/share/pve-doc-generator/pve-doc-generator.mk

export PERLLIB=..

%.bash-completion:
	perl -I.. -T -e "use PVE::CLI::$*; PVE::CLI::$*->generate_bash_completions();" >$@.tmp
	mv $@.tmp $@

man1_MANS = pvecm.1
man5_MANS = datacenter.cfg.5

IPCC_so_SOURCES = IPCC.c ppport.h

pvelib_DATA = IPCC.pm Cluster.pm
pvelibdir = $(PERL_VENDORLIB)/PVE

noinst_DATA = pvecm.bash-completion

cliclass_DATA = CLI/pvecm.pm
cliclassdir = $(PERL_VENDORLIB)/PVE/CLI

install-exec-hook: pvecm.bash-completion
	perl -I.. -T -e "use PVE::CLI::pvecm; PVE::CLI::pvecm->verify_api();"
	install -m 0644 -D pvecm.bash-completion ${DESTDIR}/usr/share/bash-completion/completions/pvecm

clean-local:
	make cleanup-docgen
	rm -f IPCC.c *~ *.1 *.5
