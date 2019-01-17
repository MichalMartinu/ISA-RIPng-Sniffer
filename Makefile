#********************************************************           
# * ISA Project                                          *    
# * Author:   Michal Martinu                             *   
#********************************************************/#

CC=gcc
CFLAGS= -std=gnu99 -W -Wall -Wextra -pedantic
LDFLAGS=-lpcap
PROG_SNIFFER=myripsniffer
PROG_RESPONSE=myripresponse

.PHONY: all tar clean

all: $(PROG_SNIFFER) $(PROG_RESPONSE)

$(PROG_SNIFFER): myripsniffer.o parse_packet.o
	$(CC) -o $@ myripsniffer.o parse_packet.o $(LDFLAGS)

$(PROG_RESPONSE): myripresponse.c
	$(CC) -o $@ myripresponse.c $(LDFLAGS)


myripsniffer.o: myripsniffer.c packet_headers.h 
	$(CC) $(CFLAGS) -c -o $@ myripsniffer.c

parse_packet.o: parse_packet.c packet_headers.h
	$(CC) $(CFLAGS) -c -o $@ parse_packet.c 

clean:
	rm -f *.o