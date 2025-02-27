#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <ifaddrs.h>
#include <errno.h>
#include <pcap.h>

#define ETH_MIN_LEN	60	/*ETHER_MIN_LEN*/

#define ARPHDR_SRCMAC(X)	((u8_t *)X+sizeof(arphdr_t))
#define ARPHDR_DSTMAC(X)	((u8_t *)X+sizeof(arphdr_t) + X->ar_hln + X->ar_pln)

#define ARPHDR_SRCIP(X)		(in_addr_t *)((u8_t *)X+sizeof(arphdr_t) + X->ar_hln)
#define ARPHDR_DSTIP(X)		(in_addr_t *)((u8_t *)X+sizeof(arphdr_t) + (X->ar_hln * 2) + X->ar_pln)

typedef unsigned char u8_t;
typedef unsigned short u16_t;
typedef unsigned long u32_t;
typedef struct ip	ip_t;
typedef struct arphdr	arphdr_t;
typedef	struct ether_addr mac_t;
typedef char ipstr_t[18];

// struct for an ethernet frame.
#pragma pack(8)
typedef struct {
	ether_header_t header;
	u8_t	payload[ETHER_MAX_LEN - ETHER_HDR_LEN];
} frame_t;

/*** prototype of the packet handler ***/
void 	pkt_handler(u8_t *param, const struct pcap_pkthdr *header, const u8_t *pkt_data);

/*** Vars ***/
pcap_t 	*fd;
int	pktno=0;

in_addr_t spoof_ip;
mac_t 	  spoof_mac = {0x00, 0x0c, 0x87, 0x47, 0x50, 0x27};

typedef char macstr_t[18];

char *
ARPProto(arphdr_t *arphdr)
{
static	char	str[80];
static	ipstr_t src_ip, dst_ip;
static  macstr_t src_mac, dst_mac;
	
	str[0]=0;
	strcpy(src_mac,ether_ntoa((mac_t *)ARPHDR_SRCMAC(arphdr)));
	strcpy(dst_mac,ether_ntoa((mac_t *)ARPHDR_DSTMAC(arphdr)));

	sprintf(src_ip,"%s",inet_ntoa(*(struct in_addr *)ARPHDR_SRCIP(arphdr))); 
	sprintf(dst_ip,"%s",inet_ntoa(*(struct in_addr *)ARPHDR_DSTIP(arphdr))); 

	switch(ntohs(arphdr->ar_op)) {
	case ARPOP_REQUEST: 	
		sprintf(str,"ARP REQUEST Who has %s Tell %s",dst_ip,src_ip); break;
	case ARPOP_REPLY: 	
		sprintf(str,"ARP REPLY   %s  is at %s",src_ip,src_mac); break;
	}
	return str;
}

char *
EthProto(frame_t *frame) 
{
	u16_t	type = ntohs(frame->header.ether_type);

	if (ntohs(frame->header.ether_type >= 1536)) {
		// Ethernet II
		switch(type) {
		case 0x0806: return ARPProto((arphdr_t *)&frame->payload[0]);
		}
	}
	return "";
}

void 
pkt_handler(u8_t *param, const struct pcap_pkthdr *header, const u8_t *pkt_data)
{
static  macstr_t src_mac, dst_mac;
	u16_t	type;
	frame_t *frame,*nframe;
	arphdr_t *arp, *narp;
	ether_header_t *eth;
	int	sz, n, ok=1; 

	(void)(param);/*** Quiet Compiler ***/
	pktno++;

	frame = (frame_t *)pkt_data;
	type = ntohs(frame->header.ether_type);

	if (type != ETHERTYPE_ARP) return;

	arp = ((arphdr_t *)&frame->payload[0]);

	if ( (ntohs(arp->ar_op) == ARPOP_REQUEST) &&
	     ((in_addr_t)(*ARPHDR_DSTIP(arp)) != spoof_ip) || 
	     (ntohs(arp->ar_op) == ARPOP_REPLY) && 
	     (memcmp((mac_t *)ARPHDR_SRCMAC(arp),(void *)&spoof_mac,sizeof(mac_t)) != 0) ) {
		ok=0;
	}

	/*** ether_ntoa not reentrant ***/
	strcpy(src_mac,ether_ntoa((mac_t *)&frame->header.ether_shost));
	strcpy(dst_mac,ether_ntoa((mac_t *)&frame->header.ether_dhost));

	/*** Print the packet ***/
	printf("%s %4d %5d - %-18s %-18s %s\n", 
		ok ? "*" : " ",
		pktno,
		header->len,
		src_mac,
		dst_mac,
		EthProto(frame));

	if (ok == 1 && ntohs(arp->ar_op) == ARPOP_REQUEST) {
		sz = MAX(header->len,ETH_MIN_LEN);

		nframe=malloc(sz);
		memset(nframe,0,sz);

		memcpy((mac_t *)&nframe->header.ether_shost,(void *)&spoof_mac,sizeof(mac_t));
		memcpy((mac_t *)&nframe->header.ether_dhost,(mac_t *)&frame->header.ether_shost,sizeof(mac_t));

		nframe->header.ether_type = htons(ETHERTYPE_ARP);
		narp = ((arphdr_t *)&nframe->payload[0]);

		narp->ar_hrd = htons(ARPHRD_ETHER);
		narp->ar_pro = htons(ETHERTYPE_IP);
		narp->ar_hln = 6;
		narp->ar_pln = 4;
		narp->ar_op  = htons(ARPOP_REPLY);

		memcpy((mac_t *)ARPHDR_SRCMAC(narp),(void *)&spoof_mac,sizeof(mac_t));
		*ARPHDR_SRCIP(narp) = spoof_ip;

		memcpy((mac_t *)ARPHDR_DSTMAC(narp),(mac_t *)ARPHDR_SRCMAC(arp), sizeof(mac_t));
		*ARPHDR_DSTIP(narp) = *ARPHDR_SRCIP(arp);

		/*** pcap send ***/
		if ((n=pcap_sendpacket(fd, (void *)nframe, sz)) == -1) {
			perror("Failed to pcap_sendpacket()\n");
		}
		free(nframe);
	}
}

int 
main(int argc,char **argv)
{
	char 	errbuf[PCAP_ERRBUF_SIZE], filter[255];
	char	*edev;
	struct bpf_program fp;
	bpf_u_int32 netp;

	if (argc != 3) {
		printf("Usage: %s iface guestip\n",argv[0]);
		exit(1);
	}
	edev=argv[1];
	spoof_ip = inet_addr(argv[2]);

 	printf("Will respond to ARP's for %s\n", inet_ntoa(*(struct in_addr *)&spoof_ip));
	printf("Listening on %s for ARP requests to %s\n", edev,argv[2]);

	/*** Open the adapter ***/
	if ((fd = pcap_open_live(edev, BUFSIZ, 1, 1000, errbuf)) == NULL)
	{
		fprintf(stderr,"Unable to open the adapter. %s\n", edev);
		exit(-1);
	}

	/*** We set a filter to reduce the load ***/
	sprintf(filter,"arp");

        //    "( (ether broadcast) or (ether multicast) or (ether dst %02x:%02x:%02x:%02x:%02x:%02x) or (arp) )",
        //    	spoof_mac.octet[0], spoof_mac.octet[1], spoof_mac.octet[2], 
	//	spoof_mac.octet[3], spoof_mac.octet[4], spoof_mac.octet[5]);

	if (pcap_compile(fd,&fp,filter,0,0xffffffff) == -1) {
		fprintf(stderr,"Failed to compile filter\n");
		exit(1);
	}

	if (pcap_setfilter(fd, &fp) == -1) {
		fprintf(stderr,"Error setting filter\n");
		exit(1);
	}

	/*** start the capture ***/
	pcap_loop(fd, -1, pkt_handler, NULL);
	pcap_close(fd);
	exit(0);
}
