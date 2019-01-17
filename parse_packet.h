/********************************************************           
 * ISA Project                                          *    
 * Author:   Michal Martinu                             *   
 ********************************************************/

/**
 * Function parse packet and check if it has ip version 4 or 5.
 * Then function select which method would apply.
 */
void packet_parse(u_char *args, const struct pcap_pkthdr *header,
                    const u_char *packet);
