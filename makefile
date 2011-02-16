all:
	echo Building in the "'build'" subdirectory
	make -C build

install:
	make -C build DESTDIR=${DESTDIR} install

# make a tarball that is friendly to  rpm build infra
VERSION =$(shell git describe | sed 's/^v//' | sed 's/-/./g')
tarball:
	git archive --prefix="bios-crypto-$(VERSION)/"  HEAD | bzip2 > bios-crypto-$(VERSION).tar.bz2 ; echo bios-crypto-$(VERSION).tar.bz2

.PHONY: install tarball
