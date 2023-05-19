include /usr/share/dpkg/default.mk

PACKAGE=pve-cluster
BUILDDIR ?= $(PACKAGE)-$(DEB_VERSION)
DSC=$(PACKAGE)_$(DEB_VERSION).dsc

GITVERSION:=$(shell git rev-parse HEAD)

DEB=$(PACKAGE)_$(DEB_VERSION)_$(DEB_BUILD_ARCH).deb
LIB_DEB  = libpve-cluster-perl_$(DEB_VERSION)_all.deb
LIB_DEB += libpve-cluster-api-perl_$(DEB_VERSION)_all.deb
DBG_DEB=$(PACKAGE)-dbgsym_$(DEB_VERSION)_$(DEB_BUILD_ARCH).deb

DEBS = $(DEB) $(DBG_DEB) $(LIB_DEB)

PERL_APIVER := `perl -MConfig -e 'print $$Config(debian_abi)//$$Config(version);'`

all: $(DEB) $(DBG_DEB)

cpgtest: cpgtest.c
	gcc -Wall cpgtest.c $(shell pkg-config --cflags --libs libcpg libqb) -o cpgtest

$(BUILDDIR):
	rm -rf $@ $@.tmp
	cp -a data $@.tmp
	cp -a debian $@.tmp/
	echo "git clone git://git.proxmox.com/git/pve-cluster.git\\ngit checkout $(GITVERSION)" > $@.tmp/debian/SOURCE
	mv $@.tmp $@

.PHONY: deb
deb $(DBG_DEB) $(LIB_DEB): $(DEB)
$(DEB): $(BUILDDIR)
	cd $(BUILDDIR); dpkg-buildpackage -b -us -uc
	lintian $(DEB)

.PHONY: dinstall
dinstall: $(DEB) $(LIB_DEB)
	dpkg -i $^

.PHONY: upload
upload: $(DEBS)
	tar cf - $(DEBS) | ssh -X repoman@repo.proxmox.com -- upload --product pve --dist bullseye --arch $(DEB_BUILD_ARCH)

.PHONY: clean
clean:
	rm -rf $(PACKAGE)-[0-9]*/ *.deb *.changes *.dsc *.buildinfo
