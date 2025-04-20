CC := $(CROSS_COMPILE)gcc
all: writer

writer: writer.o
	$(CC) -Wall -Werror -g -o writer writer.o

writer.o: writer.c
	$(CC) -Wall -Werror -g -c writer.c -o writer.o

clean:
	rm -f writer $(wildcard *.o)