cc pcap.c -o pcap -lpcap



start 2 terminal windows
on one run
% ./pcap en0 192.168.1.7

on the other run
% ping 192.168.1.7


192.168.1.7 shouldn't exist
Check arp table and see if it caches a MAC for 192.168.1.7

