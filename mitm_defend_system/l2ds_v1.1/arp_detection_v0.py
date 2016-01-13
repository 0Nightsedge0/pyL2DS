__author__ = 'TKS'
'''
compare ip and mac address only
'''


from scapy.all import *

###default gateway ip,mac address
defgateway = ["",""]


def ARP_detection(pkt):
    if(pkt[0][1].op == 2):
        if(pkt[0].psrc == defgateway[0] and pkt[0].hwsrc != defgateway[1]):
            print "ALERT! ARP packet is wrong!"


def get_packet_type(pkt):
    if(ARP in pkt[0]):
        print "ARP Packet"
        if(pkt[0][1].op == 1):
            print("who-has (request)")

        if(pkt[0][1].op == 2):
            print("is-at (response)")

        print "DST IP: ",pkt[0][1].pdst
        print "SRC IP: ",pkt[0][1].psrc
        ARP_detection(pkt)

    if(IP in pkt[0]):
        print "IP Packet"

        if(UDP in pkt[0]):
            print "UDP Packet"

        if(ICMP in pkt[0]):
            print "ICMP Packet"

        print "DST IP: ",pkt[0][1].dst
        print "SRC IP: ",pkt[0][1].src,"\n"


def sniffing():
    count = 1
    pktlist = []
    while count <= 5:
        print ("###################################")
        print ("%5d" %count),
        a = sniff(iface = "eth0", count = 1,filter="")
        pktlist.append(a)
        pktlist[count-1].nsummary()
        print str(pktlist[count-1])+"\n"

        print "-----Ethernet-----"
        print "DST MAC: ",pktlist[count-1][0].dst
        print "SRC MAC: ",pktlist[count-1][0].src
        print "------------------"
        get_packet_type(pktlist[count-1])
        count += 1


def main():
    #defgateway[0] = input("set the gateway IP address: ")
    #defgateway[1] = input("set the gateway MAC address: ")
    sniffing()


main()
