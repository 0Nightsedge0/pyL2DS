							Final Year Project
						Layer 2 Defense System v1
	
	This program is a python program using cisco's SPAN function to
	defend some local network attacks such as ARP spoofing, ICMP redirection...
	
	Also, it use scapy module for packet analysis.
	GUI use pyQt4 to build.
	Graph module to draw graph such as line graph, bar graph.
	
	------------------------------------------------------------------------
	Stage:
		
		Core:
			1. Get Packets From Interface 					[Yes]
			2. Packet Filtering								[Yes]
			3. Connect to DataBase
				a. DataBase Structure			[Yes]
				b. Recording (Logs)				[Yes]
			4. Multiprocessing
				a.	Process 1: Sniffer and packet filtering [Yes]
					 I. SubProcess 1: Detector  [Yes]
					II. SubProcess 2: Log	    [Yes]
				b.	Process 2: Display function				[Yes]
				c.  Process 3: Stop Signal creater			[Yes]
		
		Detection Functions:
			a. MITM
				1. ARP Frame Checking 						[Yes]
				2. ARP frequency 							[NO]
				3. ICMP Frame Checking						[NO]
				4. ICMP Frame frequency						[NO]
				5. DHCP Checking							[NO]
				6. DHCP frequency							[NO]
				7. DNS checking								[NO]
				8. DNS frequency							[NO]
			b. Network Scan
				1. TCP SYN scan
				2. TCP connect scan
				3. UDP scan
				4. Ping scan
				5. Version detection scan
				6. OS detection scan
				7. Aggrestive scan
		
		GUI											
			1. Design										[Yes]
			2. Mergo with core								[NO]
			Track:
				a. Draw graph								[NO]
					a1. line graph						[No]
					a2. bar graph						[NO]
				b. Mergo with GUI							[NO]
			...Still need to add...
			
	------------------------------------------------------------------------
	Newest Version:
			Files:
				L2PS_v1a4.py