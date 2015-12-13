							Final Year Project
						Layer 2 Defense System v1
	
	This program is a python program using cisco's SPAN function to
	defend some local network attacks such as ARP spoofing, ICMP redirection
	
	Also, it use scapy module for packet analysis.
	GUI use pyQt4 to build.
	Graph module to draw graph such as line graph, bar graph.
	
	------------------------------------------------------------------------
	Stage:

		Core:
			1. Get Packet From Interface 				[Yes]
			2. Packet Filtering							[Yes]
			3. Connect to DataBase						[Yes]
			4. Mutithread Control 						[NO]
		
		Detection Functions:
			1. ARP Frame Checking 						[Yes]
			2. ARP frequency 							[NO]
			3. ICMP Fram Checking						[NO]
			...Still need to add...
		
		GUI											
			1. Design									[NO]
			2. Mergo with core							[NO]
			Track:
				Draw graph								[NO]
			...Still need to add...
			
	------------------------------------------------------------------------
	Newest Version:
			Files:
				l2dsv1.py