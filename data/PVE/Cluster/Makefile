PVEDIR=${DESTDIR}/usr/share/perl5/PVE

SOURCES=IPCConst.pm

.PHONY: install
install: ${SOURCES}
	install -d ${PVEDIR}/Cluster
	for f in ${SOURCES}; do install -m 0664 $$f ${PVEDIR}/Cluster/$$f; done

IPCConst.pm: ../../src/cfs-ipc-ops.h
	awk -f IPCConst.pm.awk $< > $@.tmp
	mv $@.tmp $@
IPCConst.pm: IPCConst.pm.awk

.PHONY: clean
clean:
	rm -f IPCConst.pm IPCConst.pm.tmp
