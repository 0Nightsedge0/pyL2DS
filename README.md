## My HD team FYP project
### Layer 2 Prevention System

This program is a python program using cisco's SPAN (port mirroring) function to detect/defend some local network attacks such as ARP spoofing, ICMP redirection...

Used python library:
- scapy for packet analysis.
- pyQt4 for GUI

## Core
1. Get Packets From Interface
2. Packet Filtering
3. Connect to DataBase
	+ DataBase Structure
	+ Recording (Logs)
4. Multiprocessing
	+ Process 1: Sniffer and packet filtering
		+ SubProcess 1: Detector
		+ SubProcess 2: Log
	+ Process 2: Display function
	+ Process 3: Stop Signal creater
5. Connect to Router and Switch
	+ ssh
6. Prevention
7. Report & Log HTML

## Detection Functions
###  MITM
1. ARP Frame Checking
2. ARP frequency
3. ICMP Frame Checking
4. ICMP Frame frequency
5. DHCP Checking
6. DHCP frequency
7. DNS checking
8. DNS frequency

### Network Scan
1. TCP SYN scan
2. TCP connect scan
3. UDP scan
4. Ping scan [arp frequency + icmp frequency above]
5. Version detection scan
6. TCP ACK scan
7. TCP Xmas Tree scan
8. TCP Maimon scan
9. TCP FIN scan

## GUI
1. Design
2. Mergo with core
3. Graph
