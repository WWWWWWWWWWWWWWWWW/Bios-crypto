LIBGCC=`$(CC) -print-libgcc-file-name`

CFLAGS += -Os -I../depends/libtomcrypt/src/headers -I../depends/tomsfastmath/src/headers -fno-stack-protector

# Libraries are built deeper in the tree, so we need ../.. instead of ..
LIBCFLAGS += -Os -I../../depends/libtomcrypt/src/headers -I../../depends/tomsfastmath/src/headers -fno-stack-protector

VPATH = ..

CLI = makekey sign verify sig01 key01 hashfs zhashfs zdextract

default: bios_verify.img $(CLI)

cli: $(CLI)
cli_shared: $(patsubst %,shared/%,$(CLI))

%.img: %.elf
	objcopy -O binary $< $@


# bios_verify is the crypto module that is linked into the boot firmware.

bios_verify.elf: bios_verify.o stack_alloc.o bios_string.o ../depends/libtomcrypt.a ../depends/libtfm.a
	$(LD) -Ttext 0xc0000 -Tbss 0xd0000 --defsym _start=verify_data bios_verify.o stack_alloc.o bios_string.o ../depends/libtomcrypt.a ../depends/libtfm.a $(LIBGCC) -o $@


# A BIOS module that does only hashing.  It was used as a test.

bios_hash.elf: bios_hash.o stack_alloc.o bios_string.o ../depends/libtomcrypt.a ../depends/libtfm.a
	$(LD) -Ttext 0xa0000 -Tbss 0xa8000 --defsym _start=bios_hash bios_hash.o stack_alloc.o bios_string.o ../depends/libtomcrypt.a ../depends/libtfm.a $(LIBGCC) -o $@


# Command line tool used for testing the bios code.
bios_side: bios_side.o stack_alloc.o ../depends/libtomcrypt.a ../depends/libtfm.a
	$(CC) $(CFLAGS) bios_side.o stack_alloc.o ../depends/libtomcrypt.a ../depends/libtfm.a -o $@

bios_verify.o: bios_verify.c
	$(CC) -c $(CFLAGS) -m32 -DARGTYPE=1 $< -o $@

bios_hash.o: bios_hash.c
	$(CC) -c $(CFLAGS) -m32 -DARGTYPE=1 $< -o $@

bios_side.o: bios_side.c
	$(CC) -c $(CFLAGS) -m32 -DARGTYPE=1 $< -o $@

# We build these individual command lines tool to have smaller binaries
# by linking to the non-_cli versions of the libraries, thus reducing their
# size by a factor of nearly 10.

makekey: makekey.o ../depends/libtomcrypt.a ../depends/libtfm.a
	$(CC) $(CFLAGS) makekey.o ../depends/libtomcrypt.a ../depends/libtfm.a -o $@ 

sign: sign.o ../depends/libtomcrypt.a ../depends/libtfm.a
	$(CC) $(CFLAGS) sign.o ../depends/libtomcrypt.a ../depends/libtfm.a -o $@ 

verify: verify.o ../depends/libtomcrypt.a ../depends/libtfm.a
	$(CC) $(CFLAGS) verify.o ../depends/libtomcrypt.a ../depends/libtfm.a -o $@ 

sig01: sig01.o ../depends/libtomcrypt.a ../depends/libtfm.a
	$(CC) $(CFLAGS) sig01.o ../depends/libtomcrypt.a ../depends/libtfm.a -o $@ 

key01: key01.o ../depends/libtomcrypt.a ../depends/libtfm.a
	$(CC) $(CFLAGS) key01.o ../depends/libtomcrypt.a ../depends/libtfm.a -o $@ 

hashfs: hashfs.o ../depends/libtomcrypt.a ../depends/libtfm.a
	$(CC) $(CFLAGS) hashfs.o ../depends/libtomcrypt.a ../depends/libtfm.a -o $@ 

zhashfs: zhashfs.o ../depends/libtomcrypt.a ../depends/libtfm.a
	$(CC) $(CFLAGS) zhashfs.o ../depends/libtomcrypt.a ../depends/libtfm.a -lz -o $@ 

zdextract: zdextract.o
	$(CC) $(CFLAGS) zdextract.o -lz -o $@ 

shared:
	mkdir -p shared

shared/%: %.o shared shlib/libtomcrypt_olpc.so shlib/libtfm_olpc.so
	$(CC) $(CFLAGS) -shared $< -Lshlib -o $@ -ltomcrypt_olpc -ltfm_olpc

# python binding for verify functionality.
%.o: %.pyx
	pyrexc -o $*.c $<
	gcc -c -fPIC -I/usr/include/python2.5/ -I../depends/libtomcrypt/src/headers -I.. $*.c
pyverify.so: pyverify.o ../depends/libtomcrypt.a ../depends/libtfm.a
	gcc -shared $^ -o $@
pysign.so: pysign.o ../depends/libtomcrypt.a ../depends/libtfm.a
	gcc -shared $^ -o $@
pyverify.o: pyverify.h
pysign.o: pysign.h

# With ARGTYPE=1, LTC_ARGCHK() is equivalent to assert(), which is a reasonable
# behavior for this program.  The default value - ARGTYPE=0 - results in LTC_ARGTYPE()
# calling crypt_argchk(), which is not defined in the smaller (non-_cli) libraries.

zhashfs.o: zhashfs.c
	$(CC) -c $(CFLAGS) -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 -DARGTYPE=1 $< -o $@

%.o: %.c
	$(CC) -c $(CFLAGS) -DARGTYPE=1 $< -o $@

# The non-_cli versions of the libraries are used by the firmware crypto code and
# by command line tools that need to be small.

../depends/libtomcrypt.a:
	cd ../depends/libtomcrypt ; IGNORE_SPEED=1 CFLAGS="${LIBCFLAGS} -DLTC_NO_TEST -I../tomsfastmath/ -DLTC_SMALL_CODE -DARGTYPE=3 -DTFM_DESC" make ; \
	cp libtomcrypt.a .. ; make clean

../depends/libtfm.a:
	cd ../depends/tomsfastmath ; IGNORE_SPEED=1 CFLAGS="${LIBCFLAGS} -DTFM_ALREADY_SET -DTFM_NO_ASM" make ; cp libtfm.a .. ; make clean

shlib:
	mkdir -p shlib

shlib/libtomcrypt_olpc.so: shlib
	LIBNAME=libtomcrypt_olpc.la IGNORE_SPEED=1 CFLAGS="${LIBCFLAGS} -DLTC_NO_TEST -I../tomsfastmath/ -DLTC_SMALL_CODE -DARGTYPE=3 -DTFM_DESC" make -C ../depends/libtomcrypt -f makefile.shared
	cp -a ../depends/libtomcrypt/.libs/libtomcrypt_olpc.so.0.0.117 shlib
	make -C ../depends/libtomcrypt clean
	ln -snf libtomcrypt_olpc.so.0.0.117 $@.0
	ln -snf libtomcrypt_olpc.so.0.0.117 $@

shlib/libtfm_olpc.so: shlib
	LIBNAME=libtfm_olpc.la IGNORE_SPEED=1 CFLAGS="${LIBCFLAGS} -DTFM_ALREADY_SET -DTFM_NO_ASM" make -C ../depends/tomsfastmath -f makefile.shared
	cp -a ../depends/tomsfastmath/.libs/libtfm_olpc.so.0.0.12 shlib
	make -C ../depends/tomsfastmath clean
	ln -snf libtfm_olpc.so.0.0.12 $@.0
	ln -snf libtfm_olpc.so.0.0.12 $@

cli_tool: cli_tool.o ../depends/libtomcrypt_cli.a ../depends/libtfm_cli.a
	$(CC) $(CFLAGS) cli_tool.o ../depends/libtomcrypt_cli.a ../depends/libtfm_cli.a -o $@ 

# The _cli versions of the libraries are used by cli_tool.  They have more
# extensive argument checking, and are much larger than the non-_cli versions.

../depends/libtomcrypt_cli.a:
	cd ../depends/libtomcrypt ; CFLAGS="-DTFM_DESC ${LIBCFLAGS} -I../tomsfastmath/ " make ; cp libtomcrypt.a ../libtomcrypt_cli.a ; make clean

../depends/libtfm_cli.a:
	cd ../depends/tomsfastmath ; CFLAGS="${LIBCFLAGS}" make ; cp libtfm.a ../libtfm_cli.a ; make clean

clean:
	rm -f *.o *.a *.img ../depends/*.a cli_tool bios_side sign verify makekey bios_hash bios_verify
	cd ../depends/libtomcrypt ; make clean
	cd ../depends/tomsfastmath ; make clean
	rm -rf shared shlib

DESTDIR=/
LIBEXEC=/usr/libexec/olpc-bios-crypto
LIBDIR=/usr/lib
BINDIR=/usr/bin
INCDIR=/usr/include
install:
	install -d "${DESTDIR}${LIBEXEC}"
	install -d "${DESTDIR}${BINDIR}"
	install -d "${DESTDIR}${LIBDIR}"

	# using an explicit `ls *` avoids ending up with
	# a symlink called "*" if the glob doesn't match
	# anything
	for p in `ls *.py`; do \
           barename=$${p%.py}; \
	   install "$$p" "${DESTDIR}${LIBEXEC}/$$p" ; \
           ln -fs "../libexec/olpc-bios-crypto/$$p" "${DESTDIR}${BINDIR}/obc-$$barename"; \
	done

	for p in `ls *.sh`; do \
	   barename=$${p%.sh}; \
	   install "$$p" "${DESTDIR}${LIBEXEC}/$$p" ; \
	   ln -fs "../libexec/olpc-bios-crypto/$$p" "${DESTDIR}${BINDIR}/obc-$$barename"; \
	done

	#install shlib/* "${DESTDIR}${LIBDIR}"
	#for p in `ls shared/*` ; do \
	#   bname=$$(basename "$$p") ; \
	#   install "$$p" "${DESTDIR}${LIBEXEC}" ; \
	#   ln -fs "../libexec/olpc-bios-crypto/$$bname" "${DESTDIR}${BINDIR}/obc-$$bname"; \
	#done

	# Static binaries
	for p in $(CLI) ; do \
	   install "$$p" "${DESTDIR}${LIBEXEC}/$$p" ; \
	   ln -fs "../libexec/olpc-bios-crypto/$$p" "${DESTDIR}${BINDIR}/obc-$$p"; \
	done
	
	install -d "${DESTDIR}${INCDIR}"/tommath_olpc
	install ../depends/tomsfastmath/src/headers/* "${DESTDIR}${INCDIR}"/tommath_olpc

	install -d "${DESTDIR}${INCDIR}"/tomcrypt_olpc
	install ../depends/libtomcrypt/src/headers/* "${DESTDIR}${INCDIR}"/tomcrypt_olpc

