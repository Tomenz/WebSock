
# ACHTUNG unbedingt TABS benutzen beim einrücken

CC = g++
#CFLAGS = -ggdb -w -std=c++14 -pthread
CFLAGS = -Wall -O3 -std=c++14 -pthread -ffunction-sections -fdata-sections -shared -fPIC
LDFLAGS = -Wl,--gc-sections -lpthread -static-libgcc -static-libstdc++ -latomic
TARGET = ../WebSocket.so
INC_PATH = -I ..
LIB_PATH = -L ../socketlib -L ../CommonLib
#VPATH = ../
LIB = -l socketlib -l crypto -l ssl -l commonlib

OBJ = $(patsubst %.cpp,%.o,$(wildcard *.cpp))	#OBJ = SslSocket.o StdSocket.o OpenSSLWraper.o

$(TARGET): $(OBJ) TempFile.o ConfFile.o
	$(CC) -o $(TARGET) $(OBJ) TempFile.o ConfFile.o $(LIB_PATH) $(LIB) $(LDFLAGS)

%.o: %.cpp
	$(CC) $(CFLAGS) $(INC_PATH) -c $<
	
TempFile.o: ../TempFile.cpp
	$(CC) $(CFLAGS) $(INC_PATH) -c $<

ConfFile.o: ../ConfFile.cpp
	$(CC) $(CFLAGS) $(INC_PATH) -c $<

clean:
	rm -f $(TARGET) $(OBJ) TempFile.o ConfFile.o *~
