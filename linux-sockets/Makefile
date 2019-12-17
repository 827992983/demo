CC = gcc

all: server client0 client1

server: server.c
	gcc -o server server.c

client0: client0.c
	gcc -o client0 client0.c

client1: client1.c
	gcc -o client1 client1.c

clean:
	rm -rf ./*.o
	rm -rf ./server
	rm -rf ./client0
	rm -rf ./client1
