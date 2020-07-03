OBJ := mongoose.o http_client.o main.o
CC := x86_64-w64-mingw32-c++
CFLAGS := -g

EXECUTABLE := http_client.exe

all: $(EXECUTABLE)

mongoose.o:mongoose.c
	$(CC) $(CFLAGS) -c -fpermissive mongoose.c
http_client.o:http_client.cpp
	$(CC) $(CFLAGS) -c http_client.cpp
main.o:main.cpp
	$(CC) $(CFLAGS) -c main.cpp

$(EXECUTABLE): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(EXECUTABLE) -lws2_32
clean:
	rm -rf ./http_client.exe
	rm -rf ./*.o
