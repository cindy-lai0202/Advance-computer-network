#include "arp.h"

#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <linux/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define IP_ADDR_LEN 4

//struct ether_arp *arp_packet;
//You can fill the following functions or add other functions if needed. If not, you needn't write anything in them.  
void set_hard_type(struct ether_arp *packet, unsigned short int type)
{
	packet->arp_hrd=htons(type);
}
void set_prot_type(struct ether_arp *packet, unsigned short int type)
{
	packet->arp_pro=htons(type);
}
void set_hard_size(struct ether_arp *packet, unsigned char size)
{
	packet->arp_hln=size;
}
void set_prot_size(struct ether_arp *packet, unsigned char size)
{
	packet->arp_pln=size;
}
void set_op_code(struct ether_arp *packet, short int code)
{
	packet->arp_op=htons(code);
}

void set_sender_hardware_addr(struct ether_arp *packet, char *address)
{	
	memcpy(packet->arp_sha,address,ETH_ALEN);
}
void set_sender_protocol_addr(struct ether_arp *packet, char *address)
{
	struct in_addr saddr;
	inet_pton(AF_INET, address, &saddr);
	memcpy(packet->arp_spa,&saddr,IP_ADDR_LEN);
}
void set_target_hardware_addr(struct ether_arp *packet, char *address)
{
	memcpy(packet->arp_tha,address,ETH_ALEN);
}
void set_target_protocol_addr(struct ether_arp *packet, char *address)
{
	struct in_addr taddr;
	inet_pton(AF_INET,address, &taddr);
	memcpy(packet->arp_tpa,&taddr,IP_ADDR_LEN);
}



char* get_target_protocol_addr(struct ether_arp *packet)
{
	// if you use malloc, remember to free it.
        struct in_addr taddr;
        memcpy(&taddr,packet->arp_tpa,4);
        return inet_ntoa(taddr);
        
}
char* get_sender_protocol_addr(struct ether_arp *packet)
{
	// if you use malloc, remember to free it.
        struct in_addr saddr;
        memcpy(&saddr,packet->arp_spa,4);
        return inet_ntoa(saddr);
}
char* get_sender_hardware_addr(struct ether_arp *packet)
{
	// if you use malloc, remember to free it.
       struct ether_addr send_mac;
	char Sendmac[32];
	memcpy(&send_mac,packet->arp_sha,6);
	return ether_ntoa_r(&send_mac,Sendmac);

}
char* get_target_hardware_addr(struct ether_arp *packet)
{
	// if you use malloc, remember to free it.
	struct ether_addr target_mac;
	char targetmac[32];
	memcpy(&target_mac,packet->arp_tha,6);
	return ether_ntoa_r(&target_mac,targetmac);
}
