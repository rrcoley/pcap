% cc pcap.c -o pcap -lpcap


I'm using 192.168.1.7 which is a free IP address on my network...

start 2 terminal windows on your machine

In one run ;-
% ./pcap en0 192.168.1.7
This will monitor en0 for ARP_REQUESTS to IP 192.168.1.7 and will issue an ARP_REPLY providing a example MAC address.


on the terminal other run
% ping 192.168.1.7
This will issue an ARP_REQUEST to find the MAC address for 192.168.1.7, which should cause above to issue a response.  The kernel should then cache the reply in its arp cache..

Check arp table and see if it caches a MAC for 192.168.1.7
% arp -a |grep 192.168.1.7

