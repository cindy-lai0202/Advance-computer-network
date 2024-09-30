#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<signal.h>
#include<errno.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netdb.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include <netinet/in.h>
#include <sys/time.h>
#define BUFSIZE 1500
#define ICMP_HLEN 8
#define ICMP_DLEN 56
#define TRACE_RESULT_TIMEOUT -3
#define TRACE_RESULT_TIMEEXCEED -2
#define TRACE_RESULT_UNREACH -1
#define TRUE 1
#define FALSE 0

char *hostip;
struct sockaddr_in dst_sa;

char *sock_ntop_host(const struct sockaddr *addr,socklen_t addrlen);
int sock_addr_cmp(const struct sockaddr *sa1,const struct sockaddr *sa2, socklen_t salen);
void sig_alrm(int signo);
uint16_t in_cksum(uint16_t *addr,int len);
int recive_icmp(int sockfd,int seq,struct timeval *tv,struct sockaddr *addr,socklen_t *addrlen);
void send_icmp(int input_ttl);

char sendbuf[BUFSIZE],recvbuf[BUFSIZE];
int alarm_flag;

int main(int argc,char *argv[]){
	uid_t uid=getuid();
	if(uid!=0){
		fprintf(stdout,"%s\n","Error : You must be root to use this tool!");
		exit(1);
	}
	else{	
	
	in_addr_t saddr;
	bzero(&dst_sa,sizeof(dst_sa));
	hostip=argv[2];
	inet_aton(hostip,&dst_sa.sin_addr);
	dst_sa.sin_family=AF_INET;
	send_icmp(atoi(argv[1]));
	}
	return 0;
}

int recive_icmp(int sockfd,int seq,struct timeval *tv,struct sockaddr *addr,socklen_t *addrlen){

	struct ip *ip1,*ip2;
	struct icmp *icmp1,*icmp2;
	int iphlen1,iphlen2,icmplen,ret,n;
	struct sigaction act;
	
	sigemptyset(&act.sa_mask);
	act.sa_handler=sig_alrm;
	act.sa_flags=0;
	sigaction(SIGALRM,&act,NULL);
	
	alarm(3);
	alarm_flag=FALSE;
	for(;;){
		if(alarm_flag){
			ret=TRACE_RESULT_TIMEOUT;
			break;
		}
		n=recvfrom(sockfd,recvbuf,sizeof(recvbuf),0,addr,addrlen);
		if(n<0){
			if(errno==EINTR)	//when recive singal it be interrupt
				continue;
			else{
				perror("recv error");
				exit(1);
			}
		}
		ip1=(struct ip *)recvbuf;
		iphlen1=ip1->ip_hl<<2;	//left shift 2bit
		icmp1=(struct icmp *) (recvbuf+iphlen1);
		if((icmplen=n-iphlen1)<ICMP_HLEN)
			continue;
		if(icmp1->icmp_type==ICMP_TIMXCEED&&icmp1->icmp_code==ICMP_TIMXCEED_INTRANS){
			if(icmplen<ICMP_HLEN+sizeof(struct ip))
				continue;
			ip2=(struct ip *) (recvbuf+iphlen1+ICMP_HLEN);
			iphlen2=ip2->ip_hl << 2;
			if(icmplen<ICMP_HLEN+iphlen2+ICMP_HLEN)
				continue;
			
			icmp2=(struct icmp *) (recvbuf+iphlen1+ICMP_HLEN+iphlen2);
			if(icmp2->icmp_type==ICMP_ECHO && icmp2->icmp_code==0 && 
			   icmp2->icmp_id==htons(getpid()) && icmp2->icmp_seq==htons(seq)){
			   	ret=TRACE_RESULT_TIMEEXCEED;
			   	break;
			   }		
		}else if(icmp1->icmp_type==ICMP_ECHOREPLY){
			if(icmp1->icmp_id==htons(getpid()) && icmp1->icmp_seq==htons(seq)){
				ret=TRACE_RESULT_UNREACH;
				break;
			}
		}
		
	}
	alarm(0);
	gettimeofday(tv,NULL);
	return ret;

}

void send_icmp(int input_ttl){
	
	int sockfd;
	struct sockaddr addr,lastaddr;
	int ttl,done,seq,recive_code;
	struct timeval tvsend,tvrecv;
	struct icmp *icmp;
	size_t len;
	socklen_t addrlen;
	double rtt;
	
	if((sockfd=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP))<0){
		perror("socket error");
		exit(1);
	}
	setuid(getuid());
	printf("traceroute %s\n",hostip);
	seq=0;
	done=0;
	
	for(ttl=1;ttl<input_ttl+1&&done==0;ttl++){
		setsockopt(sockfd,IPPROTO_IP,IP_TTL,&ttl,sizeof(int));
		printf("%d",ttl);
		fflush(stdout);
		
		bzero(&lastaddr,sizeof(lastaddr));
		for(int query=0;query<3;query++){
			++seq;
			gettimeofday(&tvsend,NULL);
			
			icmp=(struct icmp *)sendbuf;
			icmp->icmp_type=ICMP_ECHO;
			icmp->icmp_code=0;
			icmp->icmp_id=htons(getpid());
			icmp->icmp_seq=htons(seq);
			memset(icmp->icmp_data,0xa5,ICMP_DLEN); 	//memset(void *s,int ch,size_t n)
			memcpy(icmp->icmp_data,&tvsend,sizeof(struct timeval));		//memcy(void *dst,const void *src,size_t n)
			
			len=ICMP_HLEN+ICMP_DLEN;
			icmp->icmp_cksum=0;
			icmp->icmp_cksum=in_cksum((u_short *) icmp,len);	//in_cksun() return 0:right
			if(sendto(sockfd,sendbuf,len,0,(struct sockaddr *) &dst_sa,sizeof(dst_sa))<0){
				perror("sento error");
				exit(1);
			}
			
			recive_code=recive_icmp(sockfd,seq,&tvrecv,&addr,&addrlen);
			if(recive_code==TRACE_RESULT_TIMEOUT){
				printf("\t*");
			}else{
				char str[NI_MAXHOST];
				if(sock_addr_cmp(&lastaddr,&addr,addrlen)!=0){
					/*memcmp(&((struct sockaddr_in *) lastaddr)->sin_addr,
					&((struct sockaddr_in *) addr)->sin_addr,
					sizeof(struct in_addr));*/
					if(getnameinfo(&addr,addrlen,str,sizeof(str),NULL,0,0)==0)
						printf("\t%s (%s)",str,sock_ntop_host(&addr,addrlen));
					else
						printf("\t%s",sock_ntop_host(&addr,addrlen));
						
					memcpy(&lastaddr,&addr,addrlen);
				}
				if((tvrecv.tv_usec -= tvsend.tv_usec)<0){
					--tvrecv.tv_sec;
					tvrecv.tv_usec +=100000000;
				}
				tvrecv.tv_sec -=tvrecv.tv_sec;
				rtt=tvrecv.tv_sec*1000.0+tvrecv.tv_usec /1000.0;
				printf("\t%.3f ms",rtt);
				if(recive_code==TRACE_RESULT_UNREACH)
					++done;
			}
		
		}
		printf("\n");
	}
}


uint16_t in_cksum(uint16_t *addr,int len){
	int nleft=len;
	uint32_t sum=0;
	uint16_t *w=addr;
	uint16_t answer=0;
	
	while(nleft>1){
		sum+=*w++;
		nleft-=2;
	}
	if(nleft==1){
		*(unsigned char *)(&answer)=*(unsigned char *)w;
		sum+=answer;
	}
	sum=(sum>>16)+(sum & 0xffff);
	sum+=(sum>>16);
	answer=~sum;
	return answer;
	
}

void sig_alrm(int signo){
	alarm_flag =TRUE;
	return;
}

int sock_addr_cmp(const struct sockaddr *sa1,const struct sockaddr *sa2, socklen_t salen){
	if(sa1->sa_family!=sa2->sa_family)
		return -1;
	switch(sa1->sa_family){
		case AF_INET:
			return memcmp(&((struct sockaddr_in *) sa1)->sin_addr,
					&((struct sockaddr_in *) sa2)->sin_addr,
					sizeof(struct in_addr));
		case AF_INET6:
			return memcmp(&((struct sockaddr_in6 *) sa1)->sin6_addr,
					&((struct sockaddr_in6 *) sa2)->sin6_addr,
					sizeof(struct in6_addr));
	}		
	return -1;
}

char *sock_ntop_host(const struct sockaddr *addr,socklen_t addrlen){
	static char str[64];
	
	switch(addr->sa_family){
		case AF_INET:
			struct sockaddr_in *sin=(struct sockaddr_in *) addr;
			if(inet_ntop(AF_INET,&sin->sin_addr,str,sizeof(str))==NULL)
				return NULL;
			break;
			
		case AF_INET6:
			struct sockaddr_in6 *sin6=(struct sockaddr_in6 *) addr;
			if(inet_ntop(AF_INET6,&sin6->sin6_addr,str,sizeof(str))==NULL)
				return NULL;
			break;
	}
	return str;
}
