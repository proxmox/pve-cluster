PVEDIR=$(DESTDIR)/usr/share/perl5/PVE

SOURCES=pvecm.pm

.PHONY: install
install: $(SOURCES)
	install -d -m 0755 $(PVEDIR)/CLI
	for f in $(SOURCES); do install -D -m 0644 $$f $(PVEDIR)/CLI/$$f; done

.PHONY: clean
clean:
