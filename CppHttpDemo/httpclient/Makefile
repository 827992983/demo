OBJ := mongoose.o http_client.o main.o
CC := g++
CFLAGS := -g

EXECUTABLE := http_client.exe

all: $(EXECUTABLE)

mongoose.o:../common/mongoose.cpp
	$(CC) $(CFLAGS) -c -fpermissive ../common/mongoose.cpp
http_client.o:http_client.cpp
	$(CC) $(CFLAGS) -c http_client.cpp
main.o:main.cpp
	$(CC) $(CFLAGS) -c main.cpp

$(EXECUTABLE): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(EXECUTABLE) -lpthread
clean:
	rm -rf ./http_client.exe
	rm -rf ./*.o
