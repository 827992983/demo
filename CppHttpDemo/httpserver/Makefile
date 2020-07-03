OBJ := mongoose.o http_server.o main.o
CC := x86_64-w64-mingw32-c++
CFLAGS := -g

EXECUTABLE := http_server.exe

all: $(EXECUTABLE)

mongoose.o:mongoose.c
	$(CC) $(CFLAGS) -c -fpermissive mongoose.c
http_server.o:http_server.cpp
	$(CC) $(CFLAGS) -c http_server.cpp
main.o:main.cpp
	$(CC) $(CFLAGS) -c main.cpp

$(EXECUTABLE): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(EXECUTABLE) -lws2_32
clean:
	rm -rf ./http_server.exe
	rm -rf ./*.o
