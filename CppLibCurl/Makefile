OBJ := http_client.o
CC := g++
CFLAGS := -g

EXECUTABLE := http_client

all: $(EXECUTABLE)

http_client.o:http_client.cpp
	$(CC) $(CFLAGS) -c http_client.cpp

$(EXECUTABLE): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(EXECUTABLE) -lcurl
clean:
	rm -rf ./http_client
	rm -rf ./*.o
