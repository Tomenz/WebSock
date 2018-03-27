
# ACHTUNG unbedingt TABS benutzen beim einrücken

CC = g++
#CFLAGS = -ggdb -w -m32 -D _DEBUG -D ZLIB_CONST -pthread
CFLAGS = -Wall -O3 -std=c++14 -pthread -ffunction-sections -fdata-sections -shared -fPIC
LDFLAGS = -Wl,--gc-sections -lpthread -shared
TARGET = ../WebSocket.so
INC_PATH = -I ..
VPATH=..

OBJ = $(patsubst %.cpp,%.o,$(wildcard *.cpp))	#OBJ = SslSocket.o StdSocket.o OpenSSLWraper.o

$(TARGET): $(OBJ) TempFile.o
	 $(CC) -o $(TARGET) $(OBJ) TempFile.o $(LDFLAGS)

%.o: %.cpp TempFile.cpp
	$(CC) $(CFLAGS) $(INC_PATH) -c $<

clean:
	rm -f $(TARGET) $(OBJ) TempFile.o *~

