/********************************************************           
 * ISA Project                                          *    
 * Author:   Michal Martinu                             *   
 ********************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <sys/socket.h>
#include <net/if.h>

#include "packet_headers.h"

#define PACKET_SIZE 44
#define RIP_HEADER_LENGTH 4
#define RIP_RECORD_LENGTH 20

#define HELP "./myripresponse -i <rozhraní> -r <IPv6>/[16-128] {-n <IPv6>} {-m [0-16]} {-t [0-65535]}"

char *arg_interface;         //arg i
struct in6_addr arg_addr;    //arg r
uint8_t arg_metric = 1;      //arg m
struct in6_addr arg_nexthop; //arg n
uint16_t arg_tag = 0;        //arg t
uint8_t arg_prefix = 0;

void response();
u_char *packet_set();
void print_help();

int main(int argc, char *argv[])
{
    inet_pton(AF_INET6, "::", &arg_nexthop); //Default next hop address

    int c;                      //Used for getopt
    int flag = 0;               //Count of arguments
    int invalid_address;        //Used for checking address
    char *err = "";             //Used for checking stcmp()
    long int arg_tag_value = 0; //Used for convert to uint16_t


    while ((c = getopt(argc, argv, "i:r:n:m:t:")) != -1)
    {

        switch (c)
        {
        case 'i':
            flag++;
            arg_interface = optarg;
            break;
        case 'r':
            flag++;
            char *string;
            string = strtok(optarg, "/");
            if ((invalid_address = inet_pton(AF_INET6, string, &arg_addr)) == 0)
            {
                fprintf(stderr, "Invalid source IPv6 address: %s\n", optarg);
                print_help();
                exit(EXIT_FAILURE);
            }

            string = strtok(NULL, "/");
            if (string != NULL)
            {
                arg_prefix = strtol(string, &err, 10);
                if (strcmp(err, ""))
                {
                    fprintf(stderr, "Prefix length cannot be char!\n");
                    print_help();
                    exit(EXIT_FAILURE);
                }
            }
            else
            {
                fprintf(stderr, "Missing prefix length!\n");
                print_help();
                exit(EXIT_FAILURE);
            }

            if (arg_prefix < 16 || arg_prefix > 128)
            {
                fprintf(stderr, "Wrong prefix length!\n");
                print_help();
                exit(EXIT_FAILURE);
            }
            break;
        case 'm':
            arg_metric = strtol(optarg, &err, 10);
            if (strcmp(err, ""))
            {
                fprintf(stderr, "Metric cannot be char!\n");
                print_help();
                exit(EXIT_FAILURE);
            }
            if (arg_metric < 0 || arg_metric > 16)
            {
                fprintf(stderr, "Wrong metric!\n");
                print_help();
                exit(EXIT_FAILURE);
            }
            break;
        case 'n':
            strtok(optarg, "/");
            if ((invalid_address = inet_pton(AF_INET6, optarg, &arg_nexthop)) == 0)
            {
                fprintf(stderr, "Invalid next hop address: %s\n", optarg);
                exit(EXIT_FAILURE);
            }
            break;
        case 't':
            arg_tag_value = strtol(optarg, &err, 0);
            if (strcmp(err, ""))
            {
                fprintf(stderr, "Tag cannot be char!\n");
                print_help();
                exit(EXIT_FAILURE);
            }
            if (arg_tag_value < 0 || arg_tag_value > 65535)
            {
                fprintf(stderr, "Wrong router tag!\n");
                print_help();
                exit(EXIT_FAILURE);
            }
            arg_tag = (uint16_t)arg_tag_value;
            break;

        default:
            print_help();
            exit(EXIT_FAILURE);
        }
    }

    if (flag != 2)
    {
        fprintf(stderr, "Invalid number of agruments\n");
        print_help();
        exit(EXIT_FAILURE);
    }

    response(); //Send response

    return 0;
}

/**
 * Function sends packet to UDP socket.
 */
void response()
{
    u_char *packet;
    size_t packet_size = PACKET_SIZE;

    packet = packet_set();

    int sockfd;
    struct sockaddr_in6 my_addr, dest_addr;

    sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    int flag = 1;

    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, arg_interface, strlen(arg_interface)) < 0)
    {
        fprintf(stderr, "Fail of setsockopt\n");
        exit(EXIT_FAILURE);
    }

    int index_of_interface = if_nametoindex(arg_interface);
    if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &index_of_interface, sizeof(index_of_interface)) != 0)
    {
        fprintf(stderr, "Fail of setsockopt\n");
        exit(EXIT_FAILURE);
    }

    int hop = 255;
    if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hop, sizeof(hop)) != 0)
    {
        fprintf(stderr, "Fail of setsockopt\n");
        exit(EXIT_FAILURE);
    }

    bzero(&my_addr, sizeof(my_addr));

    my_addr.sin6_family = AF_INET6;
    my_addr.sin6_addr = in6addr_any;
    my_addr.sin6_port = htons(521);

    if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(my_addr)))
    {
        fprintf(stderr, "Cannot bind socket\n");
    }

    bzero(&dest_addr, sizeof(dest_addr));
    dest_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "FF02::9", &dest_addr.sin6_addr);
    dest_addr.sin6_port = htons(521);

    sendto(sockfd, packet, packet_size, 0, (struct sockaddr *)&dest_addr,
           sizeof(dest_addr));

    close(sockfd);
}

/**
 * Function set and returns packet.
 */
u_char *packet_set()
{
    u_char *packet;

    packet = (u_char *)malloc(PACKET_SIZE);

    struct rip_hdr hdr;
    hdr.rip_info = 2;
    hdr.rip_ver = 1;
    hdr.zeroes = 0;

    memcpy(packet, &hdr, 4);

    struct ripng_entry next_hop;
    struct ripng_entry record;

    next_hop.pref = arg_nexthop;
    next_hop.pref_len = 0;
    next_hop.tag = 0;
    next_hop.metric = 0xFF;

    memcpy(packet + 4, &next_hop, 20);

    record.pref = arg_addr;
    record.tag = htons(arg_tag);
    record.pref_len = arg_prefix;
    record.metric = arg_metric;

    memcpy(packet + 24, &record, 20);

    return packet;
}

/**
 * Function prints help.
 */
void print_help()
{
    fprintf(stderr, "%s\n", HELP);
}
