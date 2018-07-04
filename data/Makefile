all:

.PHONY: install
install:
	$(MAKE) -C src install
	$(MAKE) -C PVE install


.PHONY: check
check:
	$(MAKE) -C test check
	$(MAKE) -C src check
	$(MAKE) -C PVE check

.PHONY: clean
clean:
	$(MAKE) -C src clean
	$(MAKE) -C PVE clean
