CFLAGS += -Os -fomit-frame-pointer -m32 -Iheader/

default: cli_tool

cli_tool: cli_tool.o
	$(CC) $(CFLAGS) cli_tool.o lib/libtomcrypt.a lib/libtfm.a -o $@ 

clean:
	rm -f *.o *.a

