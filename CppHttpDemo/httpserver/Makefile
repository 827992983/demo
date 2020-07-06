OBJ := mongoose.o http_server.o main.o
CC := g++
CFLAGS := -g

EXECUTABLE := http_server.exe

all: $(EXECUTABLE)

mongoose.o:../common/mongoose.cpp
	$(CC) $(CFLAGS) -c -fpermissive ../common/mongoose.cpp
http_server.o:http_server.cpp
	$(CC) $(CFLAGS) -c http_server.cpp
main.o:main.cpp
	$(CC) $(CFLAGS) -c main.cpp

$(EXECUTABLE): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(EXECUTABLE) -lpthread
clean:
	rm -rf ./http_server.exe
	rm -rf ./*.o
