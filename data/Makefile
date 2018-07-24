SUBDIRS := PVE src test

all:
	for i in $(SUBDIRS); do $(MAKE) -C $$i $@; done

.PHONY: install
install:
	for i in $(SUBDIRS); do $(MAKE) -C $$i $@; done


.PHONY: check
check:
	for i in $(SUBDIRS); do $(MAKE) -C $$i $@; done

.PHONY: clean
clean:
	for i in $(SUBDIRS); do $(MAKE) -C $$i $@; done
