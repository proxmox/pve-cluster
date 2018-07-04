PVEDIR=${DESTDIR}/usr/share/perl5/PVE

SOURCES=ClusterConfig.pm

.PHONY: install
install: ${SOURCES}
	install -d ${PVEDIR}/API2/
	for f in ${SOURCES}; do install -m 0664 $$f ${PVEDIR}/API2/$$f; done

.PHONY: clean
clean:
