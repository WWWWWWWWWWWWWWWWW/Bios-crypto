LIBGCC=`$(CC) -print-libgcc-file-name`

CFLAGS += -Os -I../depends/libtomcrypt/src/headers -I../depends/tomsfastmath/src/headers  -I/usr/include/tomcrypt -I/usr/include/tomsfastmath -fno-stack-protector

# Libraries are built deeper in the tree, so we need ../.. instead of ..
LIBCFLAGS += -Os -I../../depends/libtomcrypt/src/headers -I../../depends/tomsfastmath/src/headers -I/usr/include/tomcrypt -I/usr/include/tomsfastmath -fno-stack-protector

VPATH = ..

CLI = makekey sign verify sig01 key01 hashfs zhashfs zdextract

default: bios_verify.img $(CLI)

cli: $(CLI)

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

# shell conditionals - watch out for tabs, spaces and backslashes
../depends/libtomcrypt.a:
	if [ -e /usr/lib/libtomcrypt.a ]; then \
	    mkdir -p ../depends ; \
	    ln -s /usr/lib/libtomcrypt.a ../depends/libtomcrypt.a; \
	else \
	    cd ../depends/libtomcrypt ;\
	    IGNORE_SPEED=1 CFLAGS="${LIBCFLAGS} -DLTC_NO_EST -I../tomsfastmath/ -DLTC_SMALL_CODE -DARGTYPE=3 -DTFM_DESC" make ; \
	    cp libtomcrypt.a .. ; make clean;\
	fi

# shell conditionals - watch out for tabs, spaces and backslashes
../depends/libtfm.a:
	if [ -e /usr/lib/libtfm.a ]; then \
           mkdir -p ../depends ; \
           ln -s /usr/lib/libtfm.a ../depends/libtfm.a; \
        else \
           cd ../depends/tomsfastmath ; \
           IGNORE_SPEED=1 CFLAGS="${LIBCFLAGS} -DTFM_ALREADY_SET -DTFM_NO_ASM" make ;\
           cp libtfm.a .. ; make clean ; \
       fi

clean:
	rm -f *.o *.a *.img bios_side sign verify makekey bios_hash bios_verify key01 zdextract zhashfs

DESTDIR=/
LIBEXEC=/usr/libexec/bios-crypto
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
           ln -fs "../libexec/bios-crypto/$$p" "${DESTDIR}${BINDIR}/bc-$$barename"; \
	done

	for p in `ls *.sh`; do \
	   barename=$${p%.sh}; \
	   install "$$p" "${DESTDIR}${LIBEXEC}/$$p" ; \
	   ln -fs "../libexec/bios-crypto/$$p" "${DESTDIR}${BINDIR}/bc-$$barename"; \
	done

	#install shlib/* "${DESTDIR}${LIBDIR}"
	#for p in `ls shared/*` ; do \
	#   bname=$$(basename "$$p") ; \
	#   install "$$p" "${DESTDIR}${LIBEXEC}" ; \
	#   ln -fs "../libexec/bios-crypto/$$bname" "${DESTDIR}${BINDIR}/bc-$$bname"; \
	#done

	# Static binaries
	for p in $(CLI) ; do \
	   install "$$p" "${DESTDIR}${LIBEXEC}/$$p" ; \
	   ln -fs "../libexec/bios-crypto/$$p" "${DESTDIR}${BINDIR}/bc-$$p"; \
	done




