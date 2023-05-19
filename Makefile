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

all: $(DEB) $(DBG_DEB)

$(BUILDDIR):
	rm -rf $@ $@.tmp
	cp -a src $@.tmp
	cp -a debian $@.tmp/
	echo "git clone git://git.proxmox.com/git/pve-cluster.git\\ngit checkout $(GITVERSION)" > $@.tmp/debian/SOURCE
	mv $@.tmp $@

dsc: $(DSC)
$(DSC): $(BUILDDIR)
	cd $(BUILDDIR); dpkg-buildpackage -S -us -uc -d
	lintian $(DSC)

.PHONY: deb
deb $(DBG_DEB) $(LIB_DEB): $(DEB)
$(DEB): $(BUILDDIR)
	cd $(BUILDDIR); dpkg-buildpackage -b -us -uc
	lintian $(DEB)

sbuild: $(DSC)
	sbuild $(DSC)

.PHONY: dinstall
dinstall: $(DEB) $(LIB_DEB)
	dpkg -i $^

.PHONY: upload
upload: UPLOAD_DIST ?= $(DEB_DISTRIBUTION)
upload: $(DEBS)
	tar cf - $(DEBS) | ssh -X repoman@repo.proxmox.com -- upload --product pve --dist $(UPLOAD_DIST) --arch $(DEB_BUILD_ARCH)

.PHONY: clean
clean:
	rm -rf $(PACKAGE)-[0-9]*/ *.deb *.dsc *.changes *.buildinfo *.build  *.tar.*
