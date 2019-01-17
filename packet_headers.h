/********************************************************           
 * ISA Project                                          *    
 * Author:   Michal Martinu                             *   
 ********************************************************/

#include <stdint.h>
#include <netinet/ip.h>

#define RIP_AUTH_LENGTH 16

struct rip_hdr
{
  uint8_t rip_info; //RIP command
  uint8_t rip_ver;  //RIP version
  uint16_t zeroes;
};

struct auth_type
{
  u_char pswd[RIP_AUTH_LENGTH]; //Password
};

struct rip_ip_type
{
  struct in_addr addr; //IP address
  struct in_addr mask; //Subnet mask
  struct in_addr hop;  //Next hop
  uint32_t metric;
};

struct rip_entry
{
  uint16_t rip_afi; //Address family indetificator
  uint16_t rip_tag; //Route tag
  union Data {
    struct auth_type auth;
    struct rip_ip_type rip_ip;
  } data;
};

struct ripng_entry
{
  struct in6_addr pref; //Prefix
  uint16_t tag;         //Route tag
  uint8_t pref_len;     //Length of prefix
  uint8_t metric;
};
