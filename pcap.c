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

#define MIN(A,B)	((A)<(B)?(A):(B))

#define SRCMAC(X)		(memcmp(&frame->header.ether_shost,&X,sizeof(mac_t))==0)
#define DSTMAC(X)		(memcmp(&frame->header.ether_dhost,&X,sizeof(mac_t))==0)

#define ARPHDR_SRCMAC(X)	((u8_t *)X+sizeof(arphdr_t))
#define ARPHDR_DSTMAC(X)	((u8_t *)X+sizeof(arphdr_t) + X->ar_hln + X->ar_pln)

#define ARPHDR_SRCIP(X)		(struct in_addr *)((u8_t *)X+sizeof(arphdr_t) + X->ar_hln)
#define ARPHDR_DSTIP(X)		(struct in_addr *)((u8_t *)X+sizeof(arphdr_t) + (X->ar_hln * 2) + X->ar_pln)

typedef unsigned char u8_t;
typedef unsigned short u16_t;
typedef unsigned long u32_t;
typedef struct ip	ip_t;
typedef struct arphdr	arphdr_t;
typedef	struct ether_addr mac_t;
typedef char ipstr_t[18];

// struct for an ethernet frame.
typedef struct {
	ether_header_t header;
	u8_t	payload[ETHER_MAX_LEN - ETHER_HDR_LEN];
} frame_t;

/*** prototype of the packet handler ***/
void 	packet_handler(u8_t *param, const struct pcap_pkthdr *header, const u8_t *pkt_data);

/*** Vars ***/
int	pktno=0;
pcap_t 	*fd;

u32_t	  hostipv4; 
mac_t	  hostmac;
in_addr_t guestipv4;
mac_t 	  guestmac = {0x00, 0x0c, 0x87, 0x47, 0x50, 0x27};

mac_t 	  broadcastmac = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

char *
ether_ntoa_r(const mac_t *p_a, char *x) 
{
	char 	*y=x;

	for (int ii = 0; ii < 6; ii++) {
		x += sprintf (x, ii == 0 ? "%.2x" : ":%.2x", p_a->ether_addr_octet[ii]);
	}
	return y;
}

char *
ether_ntoa(const mac_t *p_a) 
{
typedef char macstr_t[18];
static 	macstr_t xx[4];
static 	int 	idx= -1;
	
	if (++idx > (sizeof(xx)/sizeof(macstr_t))-1) idx=0;
	return ether_ntoa_r (p_a, (char *)&xx[idx]);
}

char *
ARPProto(arphdr_t *arphdr)
{
static	char	str[80];
static	ipstr_t src_ip, dst_ip;
static	mac_t 	src_mac, dst_mac;
	u8_t *ptr;
	struct in_addr sip, dip;
	
	str[0]=0;
	switch(ntohs(arphdr->ar_hrd)) {
	case ARPHRD_ETHER:		break;
	case ARPHRD_IEEE802:		break;
	case ARPHRD_FRELAY:		break;
	case ARPHRD_IEEE1394:		break;
	case ARPHRD_IEEE1394_EUI64:	break;
	default:			break;
	}

	memcpy((void *)&src_mac,(mac_t *)ARPHDR_SRCMAC(arphdr),arphdr->ar_hln);
	memcpy((void *)&dst_mac,(mac_t *)ARPHDR_DSTMAC(arphdr),arphdr->ar_hln);
	sip = *(struct in_addr *)ARPHDR_SRCIP(arphdr); 
	dip = *(struct in_addr *)ARPHDR_DSTIP(arphdr); 

	sprintf(src_ip,"%s",inet_ntoa(sip));
	sprintf(dst_ip,"%s",inet_ntoa(dip));

	switch(ntohs(arphdr->ar_op)) {
	case ARPOP_REQUEST: 	
		sprintf(str,"ARP REQUEST Who has %s Tell %s",dst_ip,src_ip); break;
	case ARPOP_REPLY: 	
		sprintf(str,"ARP REPLY   %s  is at %s [%s]",src_ip,ether_ntoa(&src_mac),dst_ip); break;

	case ARPOP_REVREQUEST: 	break;
	case ARPOP_REVREPLY: 	break;
	case ARPOP_INVREQUEST: 	break;
	case ARPOP_INVREPLY: 	break;
	default: 		break;
	}
	return str;
}

char *
IPProto(ip_t *ipheader)
{
static 	char 	str[80];
	ipstr_t	src_ip, dst_ip;

	sprintf(src_ip,"%s",inet_ntoa(ipheader->ip_src));
	sprintf(dst_ip,"%s",inet_ntoa(ipheader->ip_dst));

	switch(ipheader->ip_p) {
	case IPPROTO_IP: {
			sprintf(str,"IP src=%s dst=%s",src_ip,dst_ip);
			return str; // "IP IP";
		}
	case IPPROTO_ICMP:	return "IP ICMP";
	case IPPROTO_IGMP:	return "IP IGMP";
	case IPPROTO_GGP:	return "IP GGP";
	case IPPROTO_IPV4:	return "IP IPV4";
	case IPPROTO_TCP: {
			sprintf(str,"TCP src=%s dst=%s",src_ip,dst_ip);
			return str; // "IP TCP";
		}
	case IPPROTO_ST:	return "IP ST";
	case IPPROTO_EGP:	return "IP EGP";
	case IPPROTO_PIGP:	return "IP PIGP";
	case IPPROTO_RCCMON:	return "IP RCCMON";
	case IPPROTO_NVPII:	return "IP NVPII";
	case IPPROTO_PUP:	return "IP PUP";
	case IPPROTO_ARGUS:	return "IP ARGUS";
	case IPPROTO_EMCON:	return "IP EMCON";
	case IPPROTO_XNET:	return "IP XNET";
	case IPPROTO_CHAOS:	return "IP CHAOS";
	case IPPROTO_UDP: {
			sprintf(str,"UDP src=%s dst=%s",src_ip,dst_ip);
			return str; // "IP UDP";
		}
	case IPPROTO_MUX:	return "IP MUX";
	case IPPROTO_MEAS:	return "IP MEAS";
	case IPPROTO_HMP:	return "IP HMP";
	case IPPROTO_PRM:	return "IP PRM";
	case IPPROTO_IDP:	return "IP IDP";
	case IPPROTO_TRUNK1:	return "IP TRUNK1";
	case IPPROTO_TRUNK2:	return "IP TRUNK2";
	case IPPROTO_LEAF1:	return "IP LEAF1";
	case IPPROTO_LEAF2:	return "IP LEAF2";
	case IPPROTO_RDP:	return "IP RDP";
	case IPPROTO_IRTP:	return "IP IRTP";
	case IPPROTO_TP:	return "IP TP";
	case IPPROTO_BLT:	return "IP BLT";
	case IPPROTO_NSP:	return "IP NSP";
	case IPPROTO_INP:	return "IP INP";
	case IPPROTO_SEP:	return "IP SEP";
	case IPPROTO_3PC:	return "IP 3PC";
	case IPPROTO_IDPR:	return "IP IDPR";
	case IPPROTO_XTP:	return "IP XTP";
	case IPPROTO_DDP:	return "IP DDP";
	case IPPROTO_CMTP:	return "IP CMTP";
	case IPPROTO_TPXX:	return "IP TPXX";
	case IPPROTO_IL:	return "IP IL";
	case IPPROTO_IPV6:	return "IP IPV6";
	case IPPROTO_ROUTING:	return "IP ROUTING";
	case IPPROTO_FRAGMENT:	return "IP FRAGMENT";
	case IPPROTO_IDRP:	return "IP IDRP";
	case IPPROTO_RSVP:	return "IP RSVP";
	case IPPROTO_GRE:	return "IP GRE";
	case IPPROTO_MHRP:	return "IP MHRP";
	case IPPROTO_BHA:	return "IP BHA";
	case IPPROTO_ESP:	return "IP ESP";
	case IPPROTO_AH:	return "IP AH";
	case IPPROTO_INLSP:	return "IP INLSP";
	case IPPROTO_SWIPE:	return "IP SWIPE";
	case IPPROTO_NHRP:	return "IP NHRP";
	case IPPROTO_ICMPV6:	return "IP ICMPV6";
	case IPPROTO_NONE:	return "IP NONE";
	case IPPROTO_DSTOPTS:	return "IP DSTOPTS";
	case IPPROTO_AHIP:	return "IP AHIP";
	case IPPROTO_CFTP:	return "IP CFTP";
	case IPPROTO_HELLO:	return "IP HELLO";
	case IPPROTO_SATEXPAK:	return "IP SATEXPAK";
	case IPPROTO_KRYPTOLAN:	return "IP KRYPTOLAN";
	case IPPROTO_RVD:	return "IP RVD";
	case IPPROTO_IPPC:	return "IP IPPC";
	case IPPROTO_ADFS:	return "IP ADFS";
	case IPPROTO_SATMON:	return "IP SATMON";
	case IPPROTO_VISA:	return "IP VISA";
	case IPPROTO_IPCV:	return "IP IPCV";
	case IPPROTO_CPNX:	return "IP CPNX";
	case IPPROTO_CPHB:	return "IP CPHB";
	case IPPROTO_WSN:	return "IP WSN";
	case IPPROTO_PVP:	return "IP PVP";
	case IPPROTO_BRSATMON:	return "IP BRSATMON";
	case IPPROTO_ND:	return "IP ND";
	case IPPROTO_WBMON:	return "IP WBMON";
	case IPPROTO_WBEXPAK:	return "IP WBEXPAK";
	case IPPROTO_EON:	return "IP EON";
	case IPPROTO_VMTP:	return "IP VMTP";
	case IPPROTO_SVMTP:	return "IP SVMTP";
	case IPPROTO_VINES:	return "IP VINES";
	case IPPROTO_TTP:	return "IP TTP";
	case IPPROTO_IGP:	return "IP IGP";
	case IPPROTO_DGP:	return "IP DGP";
	case IPPROTO_TCF:	return "IP TCF";
	case IPPROTO_IGRP:	return "IP IGRP";
	case IPPROTO_OSPFIGP:	return "IP OSPFIGP";
	case IPPROTO_SRPC:	return "IP SRPC";
	case IPPROTO_LARP:	return "IP LARP";
	case IPPROTO_MTP:	return "IP MTP";
	case IPPROTO_AX25:	return "IP AX25";
	case IPPROTO_IPEIP:	return "IP IPEIP";
	case IPPROTO_MICP:	return "IP MICP";
	case IPPROTO_SCCSP:	return "IP SCCSP";
	case IPPROTO_ETHERIP:	return "IP ETHERIP";
	case IPPROTO_ENCAP:	return "IP ENCAP";
	case IPPROTO_APES:	return "IP APES";
	case IPPROTO_GMTP:	return "IP GMTP";
	case IPPROTO_PIM:	return "IP PIM";
	case IPPROTO_IPCOMP:	return "IP IPCOMP";
	case IPPROTO_PGM:	return "IP PGM";
	case IPPROTO_SCTP:	return "IP SCTP";
	default:		return "IP ??";
	}
	/*NOTREACHED*/
}

char *
EthProto(frame_t *frame) 
{
static 	char 	str[20];
	u16_t	type = ntohs(frame->header.ether_type);

	if (type >= 1536) {
		// Ethernet II
		switch(type) {
		case 0x0800: return IPProto((ip_t *)&frame->payload[0]);
		case 0x0806: return ARPProto((arphdr_t *)&frame->payload[0]);
		case 0x0842: return "WOL";
		case 0x22EA: return "SRP";
		case 0x22F0: return "AVTP";
		case 0x22F3: return "TRILL";
		case 0x6002: return "DECMOP";
		case 0x6003: return "DECNet";
		case 0x6004: return "DECLAT";
		case 0x8035: return "RARP";
		case 0x809B: return "EtherTalk";
		case 0x80F3: return "AARP";
		case 0x8100: return "VLAN Tagged";
		case 0x8102: return "SLPP";
		case 0x8103: return "VLACP";
		case 0x8137: return "IPX";
		case 0x8204: return "Qnet";
		case 0x86DD: return "IPv6";
		case 0x8808: return "Ether Flow Control";
		case 0x8809: return "LACP";
		case 0x8819: return "CobraNet";
		case 0x8847: return "MPLS Unicast";
		case 0x8848: return "MPLS Multicast";
		case 0x8863: return "PPPoE Discovery";
		case 0x8864: return "PPPoE Session";
		case 0x887B: return "HomePlug";
		case 0x888E: return "802.1X";
		case 0x8892: return "PROFINET";
		case 0x88A4: return "EtherCAT";
		case 0x88A8: return "SVLAN";
		case 0x88AB: return "Powerlink";
		case 0x88B8: return "GOOSE";
		case 0x88B9: return "GSE";
		case 0x88BA: return "SV";
		case 0x88BF: return "RoMON";
		case 0x88CC: return "LLDP";
		case 0x88CD: return "SERCOS III";
		case 0x88E1: return "HomePlug Green";
		case 0x88E3: return "MRP";
		case 0x88E5: return "802.1AE";
		case 0x88E7: return "802.1ah";
		case 0x88F7: return "PTP";
		case 0x88F8: return "NC-SI";
		case 0x88FB: return "PRP";
		case 0x8902: return "802.1ag";
		case 0x8906: return "FCoE";
		case 0x8914: return "FCoE";
		case 0x8915: return "RoCE";
		case 0x891D: return "TTE";
		case 0x893A: return "1905.1";
		case 0x892F: return "HSR";
		case 0x9000: return "ECTP";
		case 0xF1C1: return "802.1CB";
		default:
			sprintf(str,"?? %x",type);
			return str;
		}
	} else { 	/* <= 1500 */
		u16_t *iptr=(u16_t *)&frame->payload;

		// If Payload starts 0xAAAA = 802.2 SNAP
		if (*iptr == 0xAAAA)
			return "802.2 SNAP";

		// If Payload starts 0xFFFF = 802.3
		if (*iptr == 0xFFFF)
			return "802.3";

		// Else 802.2 LLC
		return "802.2 LLC";
	}
	/*NOTREACHED*/
}

int 
getnetif(char *iface,int family,void *ipaddr,void *netmask,u8_t *ether) 
{
	struct  ifaddrs *if_addrs, *ifa;
	char 	buf[INET6_ADDRSTRLEN];
	u8_t	mac[6];
	void 	*tmp;
	int	found=0;
	int	flags;
	char	fstr[80];
	u32_t	_netmask=0;

	if (netmask == 0) netmask=(void *)&_netmask;

	if (getifaddrs(&if_addrs) == -1) {    
		perror("getifaddrs");
		exit(1);
	}

	for (ifa = if_addrs; ifa != NULL; ifa = ifa->ifa_next) {
		if ((iface != (char *)0) && strncmp(ifa->ifa_name,iface,strlen(iface)) != 0) continue;

		family=ifa->ifa_addr->sa_family;
		switch(family) {
			case AF_INET:
				tmp = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
				*(u32_t *)ipaddr = *(u32_t *)tmp;

				if (ifa->ifa_netmask != NULL) {
					u32_t *p = (u32_t *)&((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr;
					*(u32_t *)netmask = *(u32_t *)p;
				}
				break;
			case AF_INET6:
				tmp = &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
				break;

			case AF_LINK: 
				if (ifa->ifa_addr == NULL) break;
				struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;


				if (6 == sdl->sdl_alen) {
					memcpy(ether,LLADDR(sdl),sdl->sdl_alen);
				}
			    	break;
		}
    	}
	freeifaddrs(if_addrs);
	return 0;
}

void 
packet_handler(u8_t *param, const struct pcap_pkthdr *header, const u8_t *pkt_data)
{
	u16_t	type;
	frame_t *frame,*nframe;
	arphdr_t *arp, *narp;
	ether_header_t *eth;
	int	sz, n; 

	/*
	 * unused parameters
	 */
	(void)(param);
	frame = (frame_t *)pkt_data;
	pktno++;

	type = ntohs(frame->header.ether_type);

	if (type != ETHERTYPE_ARP) return;

	printf("%5d %4d - %s %s %s\n", 
		header->len,
		pktno,
		ether_ntoa((mac_t *)&frame->header.ether_shost),
		ether_ntoa((mac_t *)&frame->header.ether_dhost),
		EthProto(frame));

	arp = ((arphdr_t *)&frame->payload[0]);
	sz = MIN(header->len,ETHER_MIN_LEN);

	if (ntohs(arp->ar_op) != ARPOP_REQUEST) return;
	if (!SRCMAC(hostmac)) return;
	if (!DSTMAC(broadcastmac)) return;

	nframe=malloc(sz);
	memcpy((mac_t *)&nframe->header.ether_shost,(void *)&guestmac,sizeof(mac_t));
	memcpy((mac_t *)&nframe->header.ether_dhost,(void *)&hostmac,sizeof(mac_t));
	nframe->header.ether_type = htons(ETHERTYPE_ARP);
	narp = ((arphdr_t *)&nframe->payload[0]);

	narp->ar_hrd = htons(ARPHRD_ETHER);
	narp->ar_pro = arp->ar_pro;
	narp->ar_hln = arp->ar_hln;
	narp->ar_pln = arp->ar_pln;
	narp->ar_op  = htons(ARPOP_REPLY);

	memcpy((mac_t *)ARPHDR_SRCMAC(narp),(void *)&guestmac,sizeof(mac_t));
	memcpy((mac_t *)ARPHDR_DSTMAC(narp),(void *)&hostmac, sizeof(mac_t));

	*ARPHDR_SRCIP(narp) = *(struct in_addr *)&guestipv4;
	*ARPHDR_DSTIP(narp) = *(struct in_addr *)&hostipv4;

	/*** pcap send ***/
	n=pcap_sendpacket(fd, (void *)nframe, sz);

	free(nframe);
}

int 
main(int argc,char **argv)
{
	pcap_if_t *alldevs=0;
	pcap_if_t *d;
	int	inum, i=0;
	char 	errbuf[PCAP_ERRBUF_SIZE];
	char	*edev = "en0";
	u32_t	x;

	if (argc != 3) {
		printf("Usage: %s iface guestip\n",argv[0]);
		exit(1);
	}
	edev=argv[1];
	guestipv4 = inet_addr(argv[2]);

	getnetif(edev, AF_INET, (void *)&hostipv4, (void *)0, (u8_t *)&hostmac);

 	printf("Will respond to ARP's for %s\n", inet_ntoa(*(struct in_addr *)&guestipv4));
	printf("Listening on %s(%s) %s\n", edev,
					   inet_ntoa(*(struct in_addr *)&hostipv4),
					   ether_ntoa((struct ether_addr *)&hostmac));

	/*** Open the adapter ***/
	if ((fd = pcap_open_live(edev, 65536, 1, 1000, errbuf)) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		return -1;
	}

	/*** start the capture ***/
	pcap_loop(fd, -1, packet_handler, NULL);

	pcap_close(fd);
	return 0;
}
