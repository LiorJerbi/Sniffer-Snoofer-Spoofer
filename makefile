CC = gcc
FLAGS = -Wall -g -fPIC

all: Sniffer Spoofer

Spoofer:Spoofer.o
	$(CC) $(FLAGS) -o Spoofer Spoofer.o -lpcap

Sniffer: Sniffer.o
	$(CC) $(FLAGS) -o Sniffer Sniffer.o
	
Spoofer.o: Spoofer.c
	$(CC) $(FLAGS) -c Spoofer.c
Sniffer.o: Sniffer.c
	$(CC) $(FLAGS) -c Sniffer.c -lpcap


.PHONY: clean all

clean:
	rm -f *.o Sniffer