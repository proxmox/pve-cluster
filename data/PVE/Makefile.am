bin_SCRIPTS = pvecm

IPCC.c: IPCC.xs
	xsubpp IPCC.xs > IPCC.xsc
	mv IPCC.xsc IPCC.c

AM_CFLAGS = -shared -fPIC -Wl,-z,relro -Wall -Werror -Wno-strict-aliasing $(PERL_INC) -DXS_VERSION=VERSION
LDADD = $(QB_LIBS)

perlbin_PROGRAMS = IPCC.so
perlbindir = $(PERL_INSTALLARCHLIB)/auto/PVE/IPCC

%.1.gz: %.1.pod
	cat $<|pod2man -n $* -s 1 -r ${VERSION} -c "Proxmox Documentation"|gzip -c9 >$@

%.5.gz: %.5.pod
	cat $<|pod2man -n $* -s 5 -r ${VERSION} -c "Proxmox Documentation"|gzip -c9 >$@

%.1.pod: %
	perl -I.. ./$* printmanpod > $@

datacenter.cfg.5.pod: Cluster.pm gen-datacenter-pod.pl
	perl -I.. ./gen-datacenter-pod.pl > $@

#datacenter.cfg.5.gz: Cluster.pm gen-datacenter-pod.pl
#	./gen-datacenter-pod.pl|pod2man -n datacenter.cfg -s 5 -r ${VERSION} -c #"Proxmox Documentation"|gzip -c9 >$@


pod_DATA = pvecm.1.pod datacenter.cfg.5.pod
poddir = /usr/share/doc/pve-cluster/pod

man1_MANS = pvecm.1.gz
man5_MANS = datacenter.cfg.5.gz

IPCC_so_SOURCES = IPCC.c ppport.h

pvelib_DATA = IPCC.pm Cluster.pm
pvelibdir = $(PERL_VENDORLIB)/PVE

install-exec-hook:
	perl -I.. ./pvecm verifyapi

CLEANFILES = IPCC.c *~ *.1.gz *.5.gz *.pod
