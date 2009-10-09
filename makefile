# install root
DESTDIR=/

$(DESTDIR):
	test -e ${DESTDIR} || mkdir -p $(DESTDIR)

# symbols
PKGNAME = olpc-bios-crypto
VERSION =$(shell git describe | sed 's/^v//' | sed 's/-/./g')
RELEASE = 1
COMMITID = $(shell git rev-parse HEAD)
ARCH = i586

# NOTE: Release is hardcoded in the spec file to 1
NV = $(PKGNAME)-$(VERSION)
NVR = $(NV)-$(RELEASE)
DISTVER=xs11

# rpm target directory
BUILDDIR = $(PWD)/build-rpm
TARBALL    = $(BUILDDIR)/SOURCES/$(NV).tar.bz2
SRPM       = $(BUILDDIR)/SRPMS/$(NVR).$(DISTVER).src.rpm
RPM        = $(BUILDDIR)/RPMS/$(ARCH)/$(NVR).$(DISTVER).$(ARCH).rpm

all:
	echo Building in the "'build'" subdirectory
	make -C build

install:
	make -C build DESTDIR=${DESTDIR} install

# like install, but with symlink mangling for the rpm
install-rpm:
	make -C build DESTDIR=${DESTDIR} install-rpm
# for scp `make rpm-name` ...
rpm-name:
	@echo $(RPM)


RPMBUILD = rpmbuild \
	--define "_topdir $(BUILDDIR)" \
         --define "dist .$(DISTVER)"

SOURCES: $(TARBALL)
$(TARBALL):
	mkdir -p $(BUILDDIR)/BUILD $(BUILDDIR)/RPMS \
	$(BUILDDIR)/SOURCES $(BUILDDIR)/SPECS $(BUILDDIR)/SRPMS
	mkdir -p $(NV)
	git archive --format=tar --prefix="$(NV)/" HEAD > $(NV).tar
	mkdir -p $(NV)
	echo $(VERSION) > $(NV)/build-version
	tar -rf $(NV).tar $(NV)/build-version
	rm -fr $(NV)
	bzip2 $(NV).tar
	mv $(NV).tar.bz2 $(BUILDDIR)/SOURCES/

SRPM: $(SRPM)
$(SRPM): olpc-bios-crypto.spec SOURCES
	$(RPMBUILD) -bs --nodeps $(PKGNAME).spec

olpc-bios-crypto.spec: olpc-bios-crypto.spec.in
	sed -e 's:@PKGNAME@:$(PKGNAME):g' \
	    -e 's:@VERSION@:$(VERSION):g' \
	    -e 's:@RELEASE@:$(RELEASE):g' \
	    -e 's:@COMMITID@:$(COMMITID):g' \
		< $< > $@

rpm: $(RPM)
RPM: $(RPM)
$(RPM): SRPM
	$(RPMBUILD) --rebuild $(SRPM)
	rm -fr $(BUILDDIR)/BUILD/$(NV)
	# Tolerate rpmlint errors
	rpmlint $(RPM) || echo "rpmlint errored out but we love you anyway"

publish: SOURCES SRPM
	rsync -e ssh --progress  $(RPM) \
	    xs-dev.laptop.org:/xsrepos/testing/olpc/11/i586/
	rsync -e ssh --progress $(SRPM) \
	    xs-dev.laptop.org:/xsrepos/testing/olpc/11/source/SRPMS/
	rsync -e ssh --progress $(TARBALL) \
	    xs-dev.laptop.org:/xsrepos/testing/olpc/11/source/SOURCES/
	ssh xs-dev.laptop.org sudo createrepo /xsrepos/testing/olpc/11/i586

.PHONY: olpc-bios-crypto.spec.in install
