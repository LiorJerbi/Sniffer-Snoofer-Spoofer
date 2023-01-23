CC = gcc
FLAGS = -Wall -g -fPIC

all: Sniffer Spoofer Snoofer Gateway



Gateway: Gateway.o
	$(CC) $(FLAGS) -o Gateway Gateway.o

Snoofer: Snoofer.o
	$(CC) $(FLAGS) -o Snoofer Snoofer.o -lpcap
	

Spoofer:Spoofer.o
	$(CC) $(FLAGS) -o Spoofer Spoofer.o -lpcap

Sniffer: Sniffer.o
	$(CC) $(FLAGS) -o Sniffer Sniffer.o -lpcap
	


Gateway.o: Gateway.c	
	$(CC) $(FLAGS) -c Gateway.c

Snoofer.o: Snoofer.c
	$(CC) $(FLAGS) -c Snoofer.c 

Spoofer.o: Spoofer.c
	$(CC) $(FLAGS) -c Spoofer.c 

Sniffer.o: Sniffer.c
	$(CC) $(FLAGS) -c Sniffer.c 


.PHONY: clean all

clean:
	rm -f *.o Sniffer Spoofer Snoofer Gateway