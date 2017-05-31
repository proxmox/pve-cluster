PACKAGE=pve-cluster
PKGVER=5.0
PKGREL=8

ARCH:=$(shell dpkg-architecture -qDEB_BUILD_ARCH)
GITVERSION:=$(shell cat .git/refs/heads/master)

DEB=${PACKAGE}_${PKGVER}-${PKGREL}_${ARCH}.deb
DBG_DEB=${PACKAGE}-dbg_${PKGVER}-${PKGREL}_${ARCH}.deb

PERL_APIVER := `perl -MConfig -e 'print $$Config{debian_abi}//$$Config{version};'`

all: ${DEB} ${DBG_DEB}

cpgtest: cpgtest.c
	gcc -Wall cpgtest.c $(shell pkg-config --cflags --libs libcpg libqb) -o cpgtest

.PHONY: dinstall
dinstall: ${DEB}
	dpkg -i ${DEB} 

.PHONY: deb
deb ${DBG_DEB}: ${DEB}
${DEB}:
	rm -f *.deb
	rm -rf build
	cp -a data build
	cp -a debian build/debian
	sed -e "s|@PERLAPI@|perlapi-$(PERL_APIVER)|g" debian/control.in > build/debian/control
	echo "git clone git://git.proxmox.com/git/pve-cluster.git\\ngit checkout ${GITVERSION}" > build/debian/SOURCE
	cd build; ./autogen.sh
	cd build; dpkg-buildpackage -rfakeroot -b -us -uc
	lintian ${DEB}


.PHONY: upload
upload: ${DEB} ${DBG_DEB}
	tar cf - ${DEB} ${DBG_DEB}| ssh repoman@repo.proxmox.com -- upload --product pve --dist stretch --arch ${ARCH}

.PHONY: clean
clean:
	rm -rf *~ build *_${ARCH}.deb *.changes *.dsc ${CSDIR} *.buildinfo
