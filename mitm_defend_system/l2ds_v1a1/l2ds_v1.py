__author__ = 'TKS'

from scapy.all import *
import MySQLdb
import numpy as np
from threading import Thread
import livegraph

packets = []
gateway = []
arpcountperip = np.empty((24, 2), dtype=object)
arpcount = 0
totalarp = 0
icmpcount = 0
totalicmp = 0
dhcpcount = 0
totaldhcp = 0
count = 0


def arp_detection(pkt, dmac, smac, dstip, hwsrc, srcip, hwdst):
    global gateway

    for i in gateway:
        #print i[0], i[1]
        if(srcip == i[0] and hwsrc != i[1]):
            print "alert ip: %s" %srcip
        elif(srcip == i[0] and hwsrc == i[1]):
            print "ok"
        else:
            print "bye"


def get_packet_type(pkt):
    global count, y
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


        tcheck = Thread(target=arp_detection, args=(pkt, dmac, smac, dstip, hwsrc, srcip, hwdst))
        tcheck.start()
        #arp_detection(pkt, dmac, smac, dstip, hwsrc, srcip, hwdst)
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
        # reset arpcount
        global totalarp, totalicmp, totaldhcp

        global arpcount, icmpcount, dhcpcount
        arpcount = icmpcount = 0

        #sniff(iface="eth0", prn=get_packet_type, count=0, timeout=1)
        sniff(iface="wlan0", prn = get_packet_type,count= 0,timeout = 1)

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
        time += 1


def getgateway():
    global gateway

    try:
        db = MySQLdb.connect(host="localhost", user="root", passwd="", db="fyp")
        cursor = db.cursor()

        cursor.execute("select * from defaultgatewaytable")
        result = cursor.fetchall()

        for i in result:
            gateway.append([i[0], i[1]])

        db.close()
        return gateway

    except MySQLdb.Error as e:
        print("Error %d: %s" % (e.args[0], e.args[1]))


def spsniffing(): # stop or pause sniffing
    while True:
        spinput = raw_input("Stop(Press S) or Pause(Press) \n")
        if(spinput.upper() == 'S'):
            print "STOP!!"
        elif(spinput.upper() == 'P'):
            print "PAUSE!!"


def main():
    # thd0 -> thread of sniffing
    # thd1 -> check input of stopping sniffing
    getgateway()

    thd0 = Thread(target=sniffing)
    thd1 = Thread(target=spsniffing)
    thd1.daemon = True

    thd0.start()
    thd1.start()

main()