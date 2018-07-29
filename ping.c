#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <string.h>

char sendbuf[1024];
char recvbuf[1024];
int sendnum = 0;
int recvnum = 0;
#define DATA_LEN 56
struct sockaddr_in from;

float diftime(struct timeval *end, struct timeval *sta)
{
	return (float)((end->tv_sec - sta->tv_sec)*1000 +
						(end->tv_usec - sta->tv_usec) / 1000);
}

unsigned short chksum(unsigned short *addr, int len)
{
	unsigned int ret = 0;

	while ( len > 1 ) {
		ret += *addr++;
		len -= 2;
	}
	if ( len == 1 ) {
		ret += *(unsigned char *)(addr);
	}

	ret = (ret>>16) + (ret&0xffff);
	ret = (ret>>16) + ret;

	return (unsigned short)(~ret);
}

int pack(int no, pid_t pid)
{
	struct icmp *p = (struct icmp*)sendbuf;
	p->icmp_type   = ICMP_ECHO;
	p->icmp_code   = 0;
	p->icmp_cksum  = 0;
	p->icmp_id     = pid;
	p->icmp_seq    = htons(no);
	gettimeofday((struct timeval *)p->icmp_data, NULL);

	p->icmp_cksum = chksum((unsigned short*)sendbuf, DATA_LEN+8);

	return DATA_LEN+8;
}

void send_packet(int sfd, pid_t pid, struct sockaddr_in addr)
{
	sendnum++;
	int r = pack(sendnum, pid);
	sendto(sfd, sendbuf, r, 0, (struct sockaddr*)&addr, sizeof addr);
}

void unpack(int num, pid_t pid)
{
	struct timeval end;
	gettimeofday(&end, NULL);

	struct ip *pip = (struct ip*)(recvbuf);
	struct icmp *picmp = (struct icmp*)(recvbuf+(pip->ip_hl<<2));
	printf("64 bytes from %s: icmp_seq=%d ttl=%d time=%.1f ms\n",
				inet_ntoa(from.sin_addr), 
				ntohs(picmp->icmp_seq),
				pip->ip_ttl, 
				diftime(&end, (struct timeval*)picmp->icmp_data));
}

void recv_packet(int sfd, pid_t pid)
{
	socklen_t len = sizeof from;
	recvfrom(sfd, recvbuf, 1024, 0, (struct sockaddr*)&from, &len);
	recvnum++;
	unpack(recvnum, pid);
}

// a.out ip/域名
int main( int argc, char *argv[])
{
	if ( argc != 2 ) {
		fprintf(stderr, "usage:a.out ip/域名\n");
		exit(1);
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	int sfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	
	if ( (addr.sin_addr.s_addr=inet_addr(argv[1])) 
										== INADDR_NONE) {
		struct hostent *p = gethostbyname(argv[1]);
		if ( p == NULL ) {
			perror("gethostbyname");
			exit(1);
		}
		memcpy((void*)&addr.sin_addr, (void*)p->h_addr, p->h_length);
	}
	
	pid_t pid = getpid();
	printf("ping %s(%s) %d bytes of data.\n", argv[1],
			inet_ntoa(addr.sin_addr), DATA_LEN);

	while ( 1 ) {
		send_packet(sfd, pid, addr);
		recv_packet(sfd, pid);
		sleep(1);
	}
}

