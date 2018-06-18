CC = gcc
CFLAGS = -std=gnu11 -Wall -I include
TARGET = \
	src/main.c \
	src/utils.c \
	src/network.c \

raw-ping: $(TARGET)
	$(CC) $^ -o $@ $(CFLAGS) -O3 -static

clean:
	rm -rf raw-ping
