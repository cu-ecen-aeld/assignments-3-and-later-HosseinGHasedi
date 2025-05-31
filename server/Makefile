CC := $(CROSS_COMPILE)gcc

all: aesdsocket 

aesdsocket: aesdsocket.o
	$(CC) -Wall -Werror -g -o aesdsocket aesdsocket.o

aesdsocket.o: aesdsocket.c
	$(CC) -Wall -Werror -g -c aesdsocket.c -o aesdsocket.o

clean:
	rm -f aesdsocket $(wildcard *.o)
