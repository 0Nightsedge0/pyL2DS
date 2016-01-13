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
			1. Get Packets From Network Interface 			[Yes]
			2. Packet Filtering								[Yes]
			3. DataBase									
				a. Connect to DataBase						[Yes]
				b. DataBase Sturcture						[Yes]
				c. Recording								[NO]
			4. Mutithread Control 						
				a. Thread 1 : Packet Filtering & sniffing	[Yes]
				b. Thread 2 : Logging						[NO]
				c. Thread 3 : Detection						[Yes]
				d. Thread 4 : Thread Controller				[NO]
		
		Detection Functions:
			1. ARP Frame Checking 							[Yes]
			2. ARP frequency 								[NO]
			3. ICMP Frame Checking							[NO]
			4. ICMP frequency                				[NO]
			5. DHCP Checking								[NO]
			6. DHCP frequency								[NO]
			7. NDP Checking									[NO]
			8. NDP frequency								[NO]
			...Still need to add...
		
		GUI											
			1. Design										[Yes]
			2. Mergo with core								[NO]
			Track:
				a. Draw graph								[NO]
					a1. line graph							[YES]
					a2. bar graph							[NO]
				b. Mergo with GUI							[NO]
			...Still need to add...
			
	------------------------------------------------------------------------
	Newest Version:
			Files:
				l2ds_v1.2.py