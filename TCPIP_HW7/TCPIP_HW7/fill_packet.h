#ifndef __FILLPACKET__H_
#define __FILLPACKET__H_

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

typedef char u8;
typedef unsigned short u16;

#define DEFAULT_TIMEOUT 1500
#define ETHERNET_HDR_SIZE 14

typedef struct
{
	struct ip ip_hdr;
	struct icmphdr icmp_hdr;
	u8 data[10];
} myicmp ;

typedef struct
{
	struct icmphdr icmp_hdr;
	u8 data[10];
} icmp_all ;


void fill_iphdr (struct ip *ip_hdr, uint32_t src_ip, uint32_t dst_ip);
void fill_icmphdr(struct icmphdr *icmp_hdr, pid_t pid, int seq, icmp_all *icmp_all);
 
#endif
