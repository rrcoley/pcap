% cc pcap.c -o pcap -lpcap



start 2 terminal windows
on one run (Im using 192.168.1.7 which isnt in use on my network)
% ./pcap en0 192.168.1.7
This will monitor en0 for ARP_REQUESTS to IP 192.168.1.7 and it will then issue an ARP_REPLY providing a example MAC address.


on the termina other run
% ping 192.168.1.7
This will issue an ARP_REQUEST to find the MAC address of 192.168.1.7, which should cause the above pcap to issue a response.  The kernel should then cache the reply in its arp cache..

Check arp table and see if it caches a MAC for 192.168.1.7
% arp -a |grep 192.168.1.7

