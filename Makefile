CC=gcc
CFLAGS=-march=native -O3 -pipe -static -DNDEBUG

TARGET_EXEC:=init



all: init

init:
	cc ${CFLAGS} -Iinclude -L. -lcryptsetup -luuid main.c libcryptsetup.a libdevmapper.a libjson-c.a libblkid.a libuuid.a libargon2.a -o init

clean:
	rm -v init

.PHONY: all clean
