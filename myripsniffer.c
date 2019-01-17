/********************************************************           
 * ISA Project                                          *    
 * Author:   Michal Martinu                             *   
 ********************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#include "parse_packet.h"

void start_sniffing(char *interface);
int checkIfFile(char *str);

int main(int argc, char *argv[])
{
    //Interface from arguments
    char *interface;

    if (argc == 3 && strcmp(argv[1], "-i") == 0)
    {
        interface = argv[2];
    }
    else
    {
        fprintf(stderr, "Error: Wrong arguments\n./myripsniffer -i <port>\n");
        exit(EXIT_FAILURE);
    }

    start_sniffing(interface);

    return 0;
}

/**
 * Copyright (c) 2002 Tim Carstens (http://www.tcpdump.org/pcap.html)
 * Licensed under BSD license
 * 
 * 1. Redistribution must retain the above copyright notice and this list of conditions.
 * 2. The name of Tim Carstens may not be used to endorse or promote products derived from this document
 *    without specific prior written permission.
 */

void start_sniffing(char *interface)
{
    pcap_t *handle;                                  /* Session handle */
    char *dev = interface;                           /* Device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];                   /* Error string */
    struct bpf_program fp;                           /* The compiled filter expression */
    char filter_exp[] = "udp and portrange 520-521"; /* The filter expression */
    bpf_u_int32 mask;                                /* The netmask of our sniffing device */
    bpf_u_int32 net;                                 /* The IP of our sniffing device */

    if (checkIfFile(dev) == 1)
    {
        //For testing from pcap file
        handle = pcap_open_offline(dev, errbuf);
    }
    else
    {
        //Search for netmask
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
        {
            fprintf(stderr, "Can't get netmask for device %s\n", dev);
            net = 0;
            mask = 0;
        }

        //Open needed port for sniffing
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    }

    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(2);
    }

    //Compile
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(2);
    }

    //Applicate filter
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(2);
    }

    //Callback function packet_process
    pcap_loop(handle, 0, packet_parse, NULL);

    /* And close the session */
    pcap_close(handle);

    printf("\n");
}

/**
 * Check if string has suffix .pcap or .pcapng
 */
int checkIfFile(char *str)
{
    str = strrchr(str, '.');

    if (str != NULL)
    {
        if (strcmp(str, ".pcapng") == 0 || strcmp(str, ".pcap") == 0)
        {
            return 1;
        }
        else
        {
            return 0;
        }
    }
    return 0;
}
