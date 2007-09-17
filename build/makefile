LIBDIRS=-L/usr/lib/gcc/i486-linux-gnu/4.1/

CFLAGS += -Os -I../depends/libtomcrypt/src/headers -I../depends/tomsfastmath

VPATH = ..

CLI = makekey sign verify sig01

default: bios_verify.img $(CLI)

cli: $(CLI)

%.img: %.elf
	objcopy -O binary $< $@


# bios_verify is the crypto module that is linked into the boot firmware.

bios_verify.elf: bios_verify.o stack_alloc.o bios_string.o ../depends/libtomcrypt.a ../depends/libtfm.a
	$(LD) -Ttext 0xc0000 -Tbss 0xd0000 --defsym _start=verify_data bios_verify.o stack_alloc.o bios_string.o ../depends/libtomcrypt.a ../depends/libtfm.a $(LIBDIRS) -lgcc -o $@


# A BIOS module that does only hashing.  It was used as a test.

bios_hash.elf: bios_hash.o stack_alloc.o bios_string.o ../depends/libtomcrypt.a ../depends/libtfm.a
	$(LD) -Ttext 0xc0000 -Tbss 0xd0000 --defsym _start=bios_hash bios_hash.o stack_alloc.o bios_string.o ../depends/libtomcrypt.a ../depends/libtfm.a $(LIBDIRS) -lgcc -o $@


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

# python binding for verify functionality.
pyverify.c: pyverify.pyx pyverify.h
	pyrexc -o $@ $<
pyverify.o: pyverify.c
	gcc -c -fPIC -I/usr/include/python2.5/ -I../depends/libtomcrypt/src/headers -I.. $<
pyverify.so: pyverify.o ../depends/libtomcrypt.a ../depends/libtfm.a
	gcc -shared $^ -o $@

# With ARGTYPE=1, LTC_ARGCHK() is equivalent to assert(), which is a reasonable
# behavior for this program.  The default value - ARGTYPE=0 - results in LTC_ARGTYPE()
# calling crypt_argchk(), which is not defined in the smaller (non-_cli) libraries.

makekey.o: makekey.c
	$(CC) -c $(CFLAGS) -DARGTYPE=1 $< -o $@

sign.o: sign.c
	$(CC) -c $(CFLAGS) -DARGTYPE=1 $< -o $@

verify.o: verify.c
	$(CC) -c $(CFLAGS) -DARGTYPE=1 $< -o $@

sig01.o: sig01.c
	$(CC) -c $(CFLAGS) -DARGTYPE=1 $< -o $@

# The non-_cli versions of the libraries are used by the firmware crypto code and
# by command line tools that need to be small.

../depends/libtomcrypt.a:
	cd ../depends/libtomcrypt ; IGNORE_SPEED=1 CFLAGS="${CFLAGS} -DLTC_NO_TEST -I../tomsfastmath/ -DLTC_SMALL_CODE -DARGTYPE=3 -DTFM_DESC" make ; \
	cp libtomcrypt.a .. ; make clean

../depends/libtfm.a:
	cd ../depends/tomsfastmath ; IGNORE_SPEED=1 CFLAGS="${CFLAGS} -DTFM_ALREADY_SET -DTFM_NO_ASM" make ; cp libtfm.a .. ; make clean



cli_tool: cli_tool.o ../depends/libtomcrypt_cli.a ../depends/libtfm_cli.a
	$(CC) $(CFLAGS) cli_tool.o ../depends/libtomcrypt_cli.a ../depends/libtfm_cli.a -o $@ 

# The _cli versions of the libraries are used by cli_tool.  They have more
# extensive argument checking, and are much larger than the non-_cli versions.

../depends/libtomcrypt_cli.a:
	cd ../depends/libtomcrypt ; CFLAGS="-DTFM_DESC ${CFLAGS} -I../tomsfastmath/ " make ; cp libtomcrypt.a ../libtomcrypt_cli.a ; make clean

../depends/libtfm_cli.a:
	cd ../depends/tomsfastmath ; CFLAGS="${CFLAGS}" make ; cp libtfm.a ../libtfm_cli.a ; make clean

clean:
	rm -f *.o *.a *.img ../depends/*.a cli_tool bios_side sign verify makekey bios_hash bios_verify
	cd ../depends/libtomcrypt ; make clean
	cd ../depends/tomsfastmath ; make clean