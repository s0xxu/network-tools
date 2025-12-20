CC = gcc
CFLAGS = -Iinclude -g
TARGET = netscan
SRC = $(wildcard src/*.c)
MAIN = $(wildcard *.c)
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(MAIN) $(SRC)

clean:
	rm -f $(TARGET)



.PHONY: all clean
