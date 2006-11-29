CFLAGS += -Os -fomit-frame-pointer -m32 -Iheader/

default: cli_tool

bios_code: bios_side.o depends/libtomcrypt.a depends/libtfm.a
	$(CC) $(CFLAGS) bios_code.o depends/libtomcrypt.a depends/libtfm.a -o $@

cli_tool: cli_tool.o
	$(CC) $(CFLAGS) cli_tool.o lib/libtomcrypt.a lib/libtfm.a -o $@ 

depends/libtomcrypt.a:
	cd depends/libtomcrypt ; CFLAGS="${CFLAGS} -DTFM_DESC -DXMALLOC=bios_malloc -DXCALLOC=bios_calloc -DXFREE=bios_free -DREALLOC=bios_realloc -DXMEMCMP=bios_memcmp -DXMEMCPY=bios_memcpy -DXMEMSET=bios_memset -DXQSORT=bios_qsort" make ; \
	cp libtomcrypt.a ..

depends/libtfm.a:
	cd depends/tomsfastmath ; CFLAGS="${CFLAGS} -DTFM_ALREADY_SET -DTFM_NO_ASM" make ; cp libtfm.a ..

clean:
	rm -f *.o *.a depends/*.a
	cd depends/libtomcrypt ; make clean
	cd depends/tomsfastmath ; make clean
