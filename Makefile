RELEASE=2.2

PACKAGE=pve-cluster
PKGVER=1.0
PKGREL=30

ARCH:=$(shell dpkg-architecture -qDEB_BUILD_ARCH)

DEB=${PACKAGE}_${PKGVER}-${PKGREL}_${ARCH}.deb


all: ${DEB}

cpgtest: cpgtest.c
	gcc -Wall cpgtest.c $(shell pkg-config --cflags --libs libcpg libcoroipcc) -o cpgtest

.PHONY: dinstall
dinstall: ${DEB}
	dpkg -i ${DEB}

.PHONY: ${DEB}
${DEB}:
	rm -rf build
	rsync -a --exclude .svn data/ build
	cp -a debian build/debian
	cd build; ./autogen.sh
	cd build; dpkg-buildpackage -rfakeroot -b -us -uc
	lintian ${DEB}


.PHONY: upload
upload: ${DEB}
	umount /pve/${RELEASE}; mount /pve/${RELEASE} -o rw 
	mkdir -p /pve/${RELEASE}/extra
	rm -f /pve/${RELEASE}/extra/${PACKAGE}*.deb
	rm -f /pve/${RELEASE}/extra/Packages*
	cp ${DEB} /pve/${RELEASE}/extra
	cd /pve/${RELEASE}/extra; dpkg-scanpackages . /dev/null > Packages; gzip -9c Packages > Packages.gz
	umount /pve/${RELEASE}; mount /pve/${RELEASE} -o ro

.PHONY: clean
clean:
	rm -rf *~ build *_${ARCH}.deb *.changes *.dsc ${CSDIR}
