CFLAGS += -Os -m32 -Idepends/libtomcrypt/src/headers -Idepends/tomsfastmath -DDEBUG

default: cli_tool

bios_side: bios_side.o depends/libtomcrypt.a depends/libtfm.a
	$(CC) $(CFLAGS) bios_side.o depends/libtomcrypt.a depends/libtfm.a -o $@

cli_tool: cli_tool.o depends/libtomcrypt_cli.a depends/libtfm_cli.a
	$(CC) $(CFLAGS) cli_tool.o depends/libtomcrypt_cli.a depends/libtfm_cli.a -o $@ 

depends/libtomcrypt_cli.a:
	cd depends/libtomcrypt ; CFLAGS="-DTFM_DESC ${CFLAGS}" make ; cp libtomcrypt.a ../libtomcrypt_cli.a ; make clean

depends/libtfm_cli.a:
	cd depends/tomsfastmath ; CFLAGS="${CFLAGS}" make ; cp libtfm.a ../libtfm_cli.a ; make clean

depends/libtomcrypt.a:
	cd depends/libtomcrypt ; IGNORE_SPEED=1 CFLAGS="${CFLAGS} -DLTC_NO_TEST -I../tomsfastmath/ -DLTC_SMALL_CODE -DTFM_DESC -DXMALLOC=bios_malloc -DXCALLOC=bios_calloc -DXFREE=bios_free -DREALLOC=bios_realloc -DXMEMCMP=bios_memcmp -DXMEMCPY=bios_memcpy -DXMEMSET=bios_memset -DXQSORT=bios_qsort -DXSTRCMP=bios_strcmp" make ; \
	cp libtomcrypt.a .. ; make clean

depends/libtfm.a:
	cd depends/tomsfastmath ; IGNORE_SPEED=1 CFLAGS="${CFLAGS} -DTFM_ALREADY_SET -DTFM_NO_ASM -Dmemcpy=bios_memcpy -Dmemset=bios_memset" make ; cp libtfm.a .. ; make clean

clean:
	rm -f *.o *.a depends/*.a cli_tool bios_side
	cd depends/libtomcrypt ; make clean
	cd depends/tomsfastmath ; make clean
