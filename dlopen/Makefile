CC = gcc
LD = ld
CFLAGS = -c -Wall -O2

all:
	$(CC) $(CFLAGS) -fPIC my_lib.c
	$(LD) -shared -o my_lib.so my_lib.o

	$(CC) $(CFLAGS) test.c
	$(CC) -o test test.o -ldl

clean:
	rm -rf ./*.o
	rm -rf ./*.so
	rm -rf ./test
