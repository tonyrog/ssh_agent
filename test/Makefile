CC = gcc
CFLAGS = -DBIGNUM_DEBUG -O2
all: bignum_test sha1_test

bignum_test:	bignum_test.c ../c_src/bignum.h ../c_src/sha1.h
	$(CC) $(CFLAGS) -o$@ bignum_test.c

sha1_test:	sha1_test.c ../c_src/sha1.h
	$(CC) -o$@ sha1_test.c
