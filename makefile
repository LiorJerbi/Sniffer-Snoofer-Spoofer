CC = gcc
FLAGS = -Wall -g -fPIC

all: Sniffer

Sniffer: Sniffer.o
	$(CC) $(FLAGS) -o Sniffer Sniffer.o -lpcap

Sniffer.o: Sniffer.c
	$(CC) $(FLAGS) -c Sniffer.c -lpcap

.PHONY: clean all

clean:
	rm -f *.o Sniffer