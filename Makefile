include /usr/share/dpkg/default.mk

PACKAGE=pve-cluster

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

.PHONY: dinstall
dinstall: $(DEB) $(LIB_DEB)
	dpkg -i $^

.PHONY: deb
deb $(DBG_DEB) $(LIB_DEB): $(DEB)
$(DEB):
	rm -f *.deb
	rm -rf build
	cp -a data build
	cp -a debian build/debian
	echo "git clone git://git.proxmox.com/git/pve-cluster.git\\ngit checkout $(GITVERSION)" > build/debian/SOURCE
	cd build; dpkg-buildpackage -rfakeroot -b -us -uc
	lintian $(DEB)


.PHONY: upload
upload: $(DEBS)
	tar cf - $(DEBS) | ssh -X repoman@repo.proxmox.com -- upload --product pve --dist bullseye --arch $(DEB_BUILD_ARCH)

.PHONY: clean
clean:
	rm -rf *~ build *.deb *.changes *.dsc *.buildinfo
