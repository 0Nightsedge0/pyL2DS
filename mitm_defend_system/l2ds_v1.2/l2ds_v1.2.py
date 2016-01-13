__author__ = 'TKS'

'''external modules''' '''by build-in or download'''
from scapy.all import *
import numpy as np
from threading import Thread
import platform
'''internal modules'''
import databasefyp
import detection

packets = [] #store pkts
gateway = [] #store gateway
arpcountperip = np.empty((24, 2), dtype=object) #store all port of host

'''store count per s for arp, icmp, dhcp '''
arpcount = 0
icmpcount = 0
dhcpcount = 0

'''store total count of arp, icmp, dhcp and store the count of network traffic  '''
totalarp = 0
totalicmp = 0
totaldhcp = 0
count = 0


def get_packet_type(pkt):
    global count, gateway
    global arpcount, dhcpcount, icmpcount
    # tcheck use for new thread -> detection

    dmac = pkt[0].dst
    smac = pkt[0].src

    print ("###################################")
    print "No.", count,
    print "-----Ethernet-----"
    print "DST MAC: ", dmac
    print "SRC MAC: ", smac
    print "------------------"

    if(ARP in pkt[0]):
        dstip = pkt[0][1].pdst
        srcip = pkt[0][1].psrc
        hwsrc = pkt[0][1].hwsrc
        hwdst = pkt[0][1].hwdst

        print "-> ARP Packet"
        if(pkt[0][1].op == 1):
            print("->-> who-has (request)")

        if(pkt[0][1].op == 2):
            print("->-> is-at (response)")

        print "DST IP : %16s" %dstip,
        print "| DST HW MAC : %20s" %hwdst
        print "SRC IP : %16s" %srcip,
        print "| SRC HW MAC : %20s" %hwsrc


        tcheck = Thread(target=detection.arp_detection,
                        args=(pkt, dmac, smac, dstip, hwsrc, srcip, hwdst, gateway))
        tcheck.start()
        arpcount += 1

    if(IP in pkt[0]):
        print "-> IP Packet"

        if(TCP in pkt[0]):
            print "->-> TCP Packet"

        if(UDP in pkt[0]):
            print "->-> UDP Packet"
            if(DHCP in pkt[0]):
                print "->->-> DHCP Packet"
                dhcpcount += 1

        if(ICMP in pkt[0]):
            print "->-> ICMP Packet"
            icmpcount += 1

        print "DST IP : %16s" %pkt[0][1].dst
        print "SRC IP : %16s" %pkt[0][1].src

    #print pkt.summary(),
    #print pkt.show(),
    print "\n"
    count += 1
    packets.append(pkt[0])


def displaycounting(pname, countpers, total):
    print "Number of %6s packets per second: %5d  | " % (pname, countpers),
    print "Total %6s packets: %5d" % (pname, total)


def sniffing():
    time = 0
    while True:
        # reset arpcount,icmpcount per second
        global totalarp, totalicmp, totaldhcp

        global arpcount, icmpcount, dhcpcount
        arpcount = icmpcount = 0

        sniff(iface="eth0", prn=get_packet_type, count=0, timeout=1)
        #sniff(iface="wlan0", prn = get_packet_type,count= 0,timeout = 1)

        totalarp += arpcount
        totalicmp += icmpcount
        totaldhcp += dhcpcount

        print "------------------------------time : %d seconds--------------------------------" %(time)
        displaycounting('ARP', arpcount, totalarp)
        displaycounting('ICMP', icmpcount, totalicmp)
        displaycounting('DHCP', dhcpcount, totaldhcp)
        #print "number of dhcp packets per second: | ",
        #print "total dhcp packets: "
        #print "number of ndp packets per second: | ",
        #print "total ndp packets: "

        print "->>Total Network Traffic : %6d" %count
        thdreturn = Thread(target=getresult, args=(arpcount, totalarp, icmpcount, totalicmp, dhcpcount, totaldhcp, count))
        thdreturn.start()
        time += 1


def getresult(arpcount, totalarp, icmpcount, totalicmp, dhcpcount, totaldhcp, count):
    print arpcount, totalarp, icmpcount, totalicmp, dhcpcount, totaldhcp, count
    result = (arpcount, totalarp, icmpcount, totalicmp, dhcpcount, totaldhcp, count)
    #result = buffer(result)
    print result
    return result


def main():
    # thd0 -> thread of sniffing
    # thd1 -> check input of stopping sniffing
    # get information from database and collect system info
    global gateway
    gateway = databasefyp.getgateway()
    print 'Current OS: ', platform.platform()

    lock = thread.allocate_lock()
    thd0 = Thread(target=sniffing)
    thd0.start()


if( '__main__' == __name__):
    main()
