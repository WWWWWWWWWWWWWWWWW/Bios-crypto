DEST = /usr/libexec/olpc-crypto

all:
	echo Building in the "'build'" subdirectory
	make -C build

install:
	make -C build install
