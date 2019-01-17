/********************************************************           
 * ISA Project                                          *    
 * Author:   Michal Martinu                             *   
 ********************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <time.h>
#include <string.h>
#include "parse_packet.h"
#include "packet_headers.h"

#define UNUSED(x) (void)(x) //Used when any variable is unused

//Definitions
#define ETHERNET_HEADER_LENGTH 14
#define UDP_HEADER_LENGTH 8
#define IPv6_HEADER_LENGTH 40
#define RIP_HEADER_LENGTH 4
#define RIP_RECORD_LENGTH 20

//Function declarations
void print_rip_info(struct rip_hdr *header_rip,  struct in_addr *src, int len_of_packet);
char *rip_version(struct rip_hdr *header_rip);
void print_rip_header(char *src, char *ver, struct rip_hdr *header_rip);
void print_authentication(char *pswd);
void print_authentication_MD5(u_char pswd[16]);
void print_entry(struct rip_entry *record);
char *get_info(struct rip_hdr *header_rip);
void print_ripng_info(struct rip_hdr *header_rip,  struct ip6_hdr *ip6_hdr, int len_of_packet);
void print_ripng_entry(struct ripng_entry *record, char *next_hop);
void print_tab_header(int ip_version);
void concatenate(char p[], char q[]);
u_char *get_md5_data(struct rip_entry *record, int len_of_packet);


int couter = 0;     //Global variable counter of packets

/**
 * Function parse packet and check if it has ip version 4 or 5.
 * Then function select which method would apply.
 */
void packet_parse(u_char *args, const struct pcap_pkthdr *header,
                  const u_char *packet)
{
    UNUSED(args);
    UNUSED(header);

    struct ip *m_ip;            //Pointer to the beginning of IP header
    const struct udphdr *m_udp; //Pointer to the beginning of UDP header
    struct rip_hdr *m_rip;      //Pointer to the beginning of RIP header

    u_int rip_len;   //Length of rip packet
    u_int m_ip_size; //Length of IP header

    couter++;

    m_ip = (struct ip *)(packet + ETHERNET_HEADER_LENGTH);
    m_ip_size = m_ip->ip_hl * 4;

    if (m_ip->ip_v == 4)
    {
        //When IP address is of version 4 parse RIPv1 and RIPv2 packet

        m_udp = (struct udphdr *)(packet + m_ip_size + ETHERNET_HEADER_LENGTH);

        rip_len = ntohs(m_udp->uh_ulen) - UDP_HEADER_LENGTH; //Lenght of RIP packet
        struct in_addr src = m_ip->ip_src;        //Source IPv4 address

        m_rip = (struct rip_hdr *)(packet + m_ip_size + ETHERNET_HEADER_LENGTH + UDP_HEADER_LENGTH);

        print_rip_info(m_rip, &src, rip_len);
    }
    else if (m_ip->ip_v == 6)
    {
        //When IP address is of version 6 parse RIPv1 and RIPv2 packet

        struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)(m_ip); //Type conversion of IPv4 header to version 6
        //struct in6_addr source_address = ip6_hdr->ip6_src;  //Source IPv4 address

        m_udp = (struct udphdr *)(packet + ETHERNET_HEADER_LENGTH + IPv6_HEADER_LENGTH);

        rip_len = ntohs(m_udp->uh_ulen) - UDP_HEADER_LENGTH; //Lenght of RIP packet

        m_rip = (struct rip_hdr *)(packet + IPv6_HEADER_LENGTH + ETHERNET_HEADER_LENGTH + UDP_HEADER_LENGTH);

        print_ripng_info(m_rip, ip6_hdr, rip_len);
    }
}

/**
 * Function print info from RIP header
 */
void print_rip_info(struct rip_hdr *header_rip, struct in_addr *src, int len_of_packet)
{
    char *version = rip_version(header_rip); //Version of RIP
    char *pswd;                              //Password
    int flag_first = 0;

    print_rip_header(inet_ntoa(*src), version, header_rip);

    struct rip_entry *record = (struct rip_entry *)((u_char *)header_rip + 4);
    len_of_packet = len_of_packet - RIP_HEADER_LENGTH;

    //Parse all records
    while (len_of_packet >= RIP_RECORD_LENGTH)
    {
        if (record->rip_afi == 0xFFFF) //Authentization
        {
            pswd = (char *) record->data.auth.pswd;

            if (record->rip_tag == 0x300) //RIPv2 MD5
            {
                print_authentication_MD5(get_md5_data(record, len_of_packet));

            }
            else if (record->rip_tag == 0x100) //RIPv2 MD5
            {
                //For debug purpose
                //printf("MD5 type\n");

            }
            else if (record) //RIPv2
            {
                print_authentication(pswd);
            }
        }
        else //Metric
        {
            if (flag_first == 0)
            {
                print_tab_header(4);
            }
            flag_first = 1;
            print_entry(record);
        }

        len_of_packet = len_of_packet - RIP_RECORD_LENGTH;
        record = (struct rip_entry *)((u_char *)record + RIP_RECORD_LENGTH);
    }
}

/**
 * Function print info from RIPng header
 */
void print_ripng_info(struct rip_hdr *header_rip,  struct ip6_hdr *ip6_hdr, int len_of_packet)
{
    char source[INET6_ADDRSTRLEN]; //Source IPv6 address
    char *ver = "RIPng";           //Version of RIPng
    int flag_first = 0;

    inet_ntop(AF_INET6, &ip6_hdr->ip6_src, source, sizeof(source));

    print_rip_header(source, ver, header_rip);

    struct ripng_entry *record = (struct ripng_entry *)((u_char *)header_rip + RIP_HEADER_LENGTH);

    char next_hop[INET6_ADDRSTRLEN] = "";

    //Parse all records
    while (len_of_packet >= RIP_RECORD_LENGTH)
    {
        if (flag_first == 0)
        {
            print_tab_header(6);
        }
        flag_first = 1;

        if(record->metric == 0xFF)
        {
            
            inet_ntop(AF_INET6, &record->pref, next_hop, sizeof(next_hop)); 
        }
        else
        {
            print_ripng_entry(record, next_hop);
        }

        len_of_packet -= RIP_RECORD_LENGTH;

        record = (struct ripng_entry *)((u_char *)record + RIP_RECORD_LENGTH);
    }
}

/**
 * Function return RIP version in string format
 */
char *rip_version(struct rip_hdr *header_rip)
{
    if (header_rip->rip_ver == 1)
    {
        return "RIPv1";
    }
    else if (header_rip->rip_ver == 2)
    {
        return "RIPv2";
    }

    return "Error";
}

/**
 * Function print RIP header
 */
void print_rip_header(char *src, char *ver, struct rip_hdr *header_rip)
{
    time_t t = time(NULL);
    struct tm m_time = *localtime(&t);

    char *info = get_info(header_rip);
    printf("\n================================================================================\n");
    printf("No. %d ", couter);
    printf("[%d:%d:%d]\n", m_time.tm_hour, m_time.tm_min, m_time.tm_sec);
    printf("Protocol: %s\n", ver);
    printf("Recieved %s ", info);
    printf("from [%s]\n\n", src);
}

/**
 * Initialize table
 * 4 for RIP and RIPv2
 * 6 for RIPng
 */
void print_tab_header(int ip_version)
{
    if (ip_version == 4)
    {
        printf("\n   --------------------------------------------------------------------------\n");
        printf("   IP                  Mask                Next hop            Tag     Metric\n\n");
    }
    else
    {
        printf("\n   --------------------------------------------------------------------------\n");
        printf("   IP/Prefix-length                                            Tag     Metric\n\n");
    }
}

/**
 * Print simple autentization
 */
void print_authentication(char *pswd)
{
    printf("   Authentication\n");
    printf("     Authentication type: Simple Password (2)\n");
    printf("     Password: %s\n", pswd);
}

/**
 * Get password data of RIPmd5
 */
 u_char *get_md5_data(struct rip_entry *record, int len_of_packet)
 {
     while (len_of_packet >= RIP_RECORD_LENGTH)
    {
        if(record->rip_tag == 0x100) //RIPv2 MD5
        {
            
            return record->data.auth.pswd;
        }

        len_of_packet -= RIP_RECORD_LENGTH;

        record = (struct rip_entry *)((u_char *)record + RIP_RECORD_LENGTH);
    }

    return record->data.auth.pswd;
 }

/**
 * Print autentization with MD5
 */
void print_authentication_MD5(u_char pswd[16])
{
    printf("  Authentication\n");
    printf("    Authentication type: Keyed Message Digest (3)\n");
    
        printf("    Data: ");
        for (int i = 0; i < 16; i++)
        {
            printf("%02x", pswd[i]);
        }
        printf("\n");
    
}

/**
 * Print line of tabble of RIP or RIPv2
 */
void print_entry(struct rip_entry *record)
{

    char ip_address[INET_ADDRSTRLEN];
    char netmask[INET_ADDRSTRLEN];
    int route_tag = ntohs(record->rip_tag);
    char next_hop[INET_ADDRSTRLEN] = "";
    int metric = ntohl(record->data.rip_ip.metric);

    strcpy(ip_address, inet_ntoa(record->data.rip_ip.addr));
    strcpy(netmask, inet_ntoa(record->data.rip_ip.mask));
    strcpy(next_hop, inet_ntoa(record->data.rip_ip.hop));

    printf("   %-20s", ip_address);
    printf("%-20s", netmask);
    printf("%-20s", next_hop);
    printf("%-8d", route_tag);
    printf("%d\n", metric);
}

/**
 * Print line of tabble of RIPng
 */
void print_ripng_entry(struct ripng_entry *record, char *next_hop)
{
    char ip_address[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &record->pref, ip_address, sizeof(ip_address));
    int tag = ntohs(record->tag);
    int prefix_len = record->pref_len;
    int metric = record->metric;
    
    char prefix_len_string[4];
    sprintf(prefix_len_string, "%d", prefix_len);
    char *ip_pref;
    ip_pref = strcat(ip_address, "/");
    ip_pref = strcat(ip_pref, prefix_len_string);

    printf("   %-60s", ip_address);
    printf("%-8d", tag);
    printf("%d\n", metric);

    if(strcmp(next_hop, ""))
    {
            printf("    |___ Next hop: %s \n\n", next_hop);
    }
    
}

/**
 * Return string of command
 */
char *get_info(struct rip_hdr *header_rip)
{
    if (header_rip->rip_info == 1)
    {
        return "Request";
    }
    else if (header_rip->rip_info == 2)
    {
        return "Response";
    }

    return "Error";
}
