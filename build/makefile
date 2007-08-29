LIBDIRS=-L/usr/lib/gcc/i486-linux-gnu/4.1/

CFLAGS += -Os -m32 -I../depends/libtomcrypt/src/headers -I../depends/tomsfastmath

VPATH = ..

CLI = makekey sign verify

default: bios_crypto.img $(CLI)

cli: $(CLI)

bios_crypto.img: bios_crypto
	objcopy -O binary $< $@

bios_hash.img: bios_hash
	objcopy -O binary $< $@

bios_crypto: bios_verify.o stack_alloc.o bios_string.o ../depends/libtomcrypt.a ../depends/libtfm.a
	$(LD) -Ttext 0xc0000 -Tbss 0xd0000 --defsym _start=verify_data bios_verify.o stack_alloc.o bios_string.o ../depends/libtomcrypt.a ../depends/libtfm.a $(LIBDIRS) -lgcc -o $@

bios_hash: bios_hash.o stack_alloc.o bios_string.o ../depends/libtomcrypt.a ../depends/libtfm.a
	$(LD) -Ttext 0xc0000 -Tbss 0xd0000 --defsym _start=bios_hash bios_hash.o stack_alloc.o bios_string.o ../depends/libtomcrypt.a ../depends/libtfm.a $(LIBDIRS) -lgcc -o $@

bios_side: bios_side.o stack_alloc.o ../depends/libtomcrypt.a ../depends/libtfm.a
	$(CC) $(CFLAGS) bios_side.o stack_alloc.o ../depends/libtomcrypt.a ../depends/libtfm.a -o $@

cli_tool: cli_tool.o ../depends/libtomcrypt_cli.a ../depends/libtfm_cli.a
	$(CC) $(CFLAGS) cli_tool.o ../depends/libtomcrypt_cli.a ../depends/libtfm_cli.a -o $@ 

test: test.o ../depends/libtomcrypt_cli.a ../depends/libtfm_cli.a
	$(CC) $(CFLAGS) test.o ../depends/libtomcrypt_cli.a ../depends/libtfm_cli.a -o $@ 


makekey: makekey.o ../depends/libtomcrypt_cli.a ../depends/libtfm_cli.a
	$(CC) $(CFLAGS) makekey.o ../depends/libtomcrypt_cli.a ../depends/libtfm_cli.a -o $@ 

sign: sign.o ../depends/libtomcrypt_cli.a ../depends/libtfm_cli.a
	$(CC) $(CFLAGS) sign.o ../depends/libtomcrypt_cli.a ../depends/libtfm_cli.a -o $@ 

sig01: sig01.o ../depends/libtomcrypt_cli.a ../depends/libtfm_cli.a
	$(CC) $(CFLAGS) sig01.o ../depends/libtomcrypt_cli.a ../depends/libtfm_cli.a -o $@ 

verify: verify.o ../depends/libtomcrypt_cli.a ../depends/libtfm_cli.a
	$(CC) $(CFLAGS) verify.o ../depends/libtomcrypt_cli.a ../depends/libtfm_cli.a -o $@ 

cli_tool_ecc256: cli_tool_ecc256.o ../depends/libtomcrypt_cli.a ../depends/libtfm_cli.a
	$(CC) $(CFLAGS) cli_tool_ecc256.o ../depends/libtomcrypt_cli.a ../depends/libtfm_cli.a -o $@ 

../depends/libtomcrypt_cli.a:
	cd ../depends/libtomcrypt ; CFLAGS="-DTFM_DESC ${CFLAGS} -I../tomsfastmath/ " make ; cp libtomcrypt.a ../libtomcrypt_cli.a ; make clean

../depends/libtfm_cli.a:
	cd ../depends/tomsfastmath ; CFLAGS="${CFLAGS}" make ; cp libtfm.a ../libtfm_cli.a ; make clean

../depends/libtomcrypt.a:
	cd ../depends/libtomcrypt ; IGNORE_SPEED=1 CFLAGS="${CFLAGS} -DLTC_NO_TEST -I../tomsfastmath/ -DLTC_SMALL_CODE -DARGTYPE=3 -DTFM_DESC" make ; \
	cp libtomcrypt.a .. ; make clean

../depends/libtfm.a:
	cd ../depends/tomsfastmath ; IGNORE_SPEED=1 CFLAGS="${CFLAGS} -DTFM_ALREADY_SET -DTFM_NO_ASM" make ; cp libtfm.a .. ; make clean

clean:
	rm -f *.o *.a *.img ../depends/*.a cli_tool bios_side sign verify makekey bios_hash bios_crypto bios_interface
	cd ../depends/libtomcrypt ; make clean
	cd ../depends/tomsfastmath ; make clean
