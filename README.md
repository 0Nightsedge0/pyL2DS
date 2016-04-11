							Final Year Project
						Layer 2 Prevention System v1
	
	This program is a python program using cisco's SPAN function to
	defend some local network attacks such as ARP spoofing, ICMP redirection...
	
	Also, it use scapy module for packet analysis.
	GUI use pyQt4 to build.
	Graph module to draw graph such as line graph, bar graph.
	
	------------------------------------------------------------------------
	Stage:
		#########################################################
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
			5. Connect to Router and Switch
				a. ssh										[Yes]
			6. Prevention									[Test]
			7. Report & Log HTML							[Test]
			
		#########################################################	
		Detection Functions:
			a. MITM
				1. ARP Frame Checking 						[Yes]
				2. ARP frequency 							[Yes]
				3. ICMP Frame Checking						[Yes]
				4. ICMP Frame frequency						[Yes]
				5. DHCP Checking							[Test]
				6. DHCP frequency							[Yes]
				7. DNS checking								[Test]
				8. DNS frequency							[Yes]
			b. Network Scan
				1. TCP SYN scan								[YES]
				2. TCP connect scan							[YES]
				3. UDP scan									[YES]
				4. Ping scan								[arp frequency + icmp frequency above]
				5. Version detection scan					[YES]
				6. TCP ACK scan
				7. TCP Xmas Tree scan
				8. -sM 
		#########################################################
		GUI											
			1. Design										[Yes]
			2. Mergo with core								[YES]
			Track:
				a. Draw graph								[Yes]
					a1. line graph						[YES]
					a2. bar graph						[YES]
				b. Mergo with GUI							[YES]
			...Still need to add...
			
	------------------------------------------------------------------------
	Newest Version:
			Files:
				L2PS_v1a5.py