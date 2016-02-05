__author__ = 'TKS'

'''external modules''' '''build-in or download'''
from scapy.all import *
import numpy as np
from threading import Thread
import platform
import time
'''internal modules'''
import Database_get2insert
import Detection

packets = [] #store pkts (cache) *clear every ten seconds and insert to database
gateway = [] #store gateway
arpcountperip = np.empty((24, 2), dtype=object) #store all port of host
operation_time = 0

'''store count per s for arp, icmp, dhcp, dns '''
arpcount = 0
icmpcount = 0
dhcpcount = 0
dnscount = 0

'''store total count of arp, icmp, dhcp, dns and store the count of network traffic  '''
totalarp = 0
totalicmp = 0
totaldhcp = 0
totaldns = 0
count = 0
countpers = 0

'''store now data and time '''
datetime = ""
printdatetime = ""


def get_packet_type(pkt):
    global gateway, countpers, count, printdatetime
    global arpcount, dhcpcount, icmpcount, dnscount
    # thd_check use for new thread -> detection

    dmac = pkt[0].dst
    smac = pkt[0].src
    dstip = 0
    srcip = 0
    proto_type = ""
    pktdata = ""

    print "###############################################################################"
    print "No. %05d" % count
    print "----------------------Ethernet----------------------"
    print "DST MAC: ", dmac
    print "SRC MAC: ", smac
    print "----------------------------------------------------"

    if(ARP in pkt[0]):
        proto_type = "ARP"
        dstip = pkt[0][1].pdst
        srcip = pkt[0][1].psrc
        hwsrc = pkt[0][1].hwsrc
        hwdst = pkt[0][1].hwdst

        pktdata = "dstip=%s srcip=%s hwsrc=%s hwdst=%s" % (dstip, srcip, hwsrc, hwdst)

        print "-> ARP Packet"
        if(pkt[0][1].op == 1):
            print("->-> who-has (request)")
            pktdata += " (Who-has (request) %s? Tell %s)" % (dstip, srcip)

        if(pkt[0][1].op == 2):
            print("->-> is-at (response)")
            pktdata += " (%s is-at (response) %s Tell %s)" % (dstip, hwdst, srcip)

        print "DST IP : %16s" % dstip,
        print "| DST HW MAC : %20s" % hwdst
        print "SRC IP : %16s" %srcip,
        print "| SRC HW MAC : %20s" % hwsrc

        thd_check = Thread(target=Detection.arp_detection, args=(pkt, dmac, smac,
                                                                    dstip, hwsrc, srcip,
                                                                    hwdst, gateway))
        thd_check.start()
        arpcount += 1

    if(IP in pkt[0]):
        print "-> IP Packet"
        proto_type = "IP"

        if(TCP in pkt[0]):
            print "->-> TCP Packet"
            proto_type = "TCP"

        if(UDP in pkt[0]):
            print "->-> UDP Packet"
            proto_type = "UDP"
            if(DHCP in pkt[0]):
                print "->->-> DHCP Packet"
                proto_type = "DHCP"
                dhcpcount += 1
            if(DNS in pkt[0]):
                print "->->-> DNS Packet"
                proto_type = "DNS"
                dnscount += 1

        if(ICMP in pkt[0]):
            print "->-> ICMP Packet"
            proto_type = "ICMP"
            icmpcount += 1

        print "DST IP : %16s" %pkt[0][1].dst
        print "SRC IP : %16s" %pkt[0][1].src
    temp = [datetime+"%04d" % countpers, printdatetime, srcip,
                dstip, smac, dmac, proto_type, pktdata]

    packets.append(temp)

    #print pkt.summary(),
    #print pkt.show(),
    countpers += 1

    #print datetime+"%04d" % (countpers)
    print "###############################################################################\n"


def displaycounting(pname, countpers, total):
    print "Number of %6s packets per second: %5d  | " % (pname, countpers),
    print "     Total %6s packets: %5d" % (pname, total)


def sniffing(q, l):
    global operation_time
    operation_times = 0

    signal = False #control signal

    while True:
        global packets, datetime, printdatetime, count, countpers
        # reset each protocol counts per second
        global totalarp, totalicmp, totaldhcp, totaldns
        global arpcount, icmpcount, dhcpcount, dnscount

        arpcount = icmpcount = dhcpcount = dnscount = countpers = 0

        thd_gettime = Thread(target=getnowdatetime)
        thd_gettime.start()

        sniff(iface="eth0", prn=get_packet_type, count=0, timeout=1)
        #sniff(iface="wlan0", prn=get_packet_type, count=0, timeout=1)

        totalarp += arpcount
        totalicmp += icmpcount
        totaldhcp += dhcpcount
        totaldns += dnscount
        count += countpers

        print "-------------------Now data and time : %s --------------------" % (printdatetime)
        print "-------------------------Operation times : %d seconds---------------------------" % (operation_times)
        displaycounting('ARP', arpcount, totalarp)
        displaycounting('ICMP', icmpcount, totalicmp)
        displaycounting('DHCP', dhcpcount, totaldhcp)
        displaycounting('DNS', dnscount, totaldns)

        print "---->> Network Traffic : %6d \n" %count

        if(operation_times % 5 == 0 and packets):
            Database_get2insert.insert_Log(packets)
            packets = []


        signal = getresult(arpcount, totalarp, icmpcount, totalicmp, dhcpcount,
                            totaldhcp, count, operation_times, printdatetime, q, l)

        if(signal is True):
            break

        #print datetime+"%04d" % (countpers)
        #print "count = ", count
        operation_times += 1


def getresult(arpcount, totalarp, icmpcount, totalicmp, dhcpcount, totaldhcp, count, times, printdatetime, q, lock):
    #print arpcount, totalarp, icmpcount, totalicmp, dhcpcount, totaldhcp, count
    result = [arpcount, totalarp, icmpcount, totalicmp, dhcpcount, totaldhcp, count, times, printdatetime]
    #print "queue size: ", q.qsize()
    lock.acquire()
    if(q.qsize() == 2):
        #print q.get(block=False)
        #print "Putter OUT!"
        return True
    #print "Putter put ", result
    q.put(result)

    lock.release()
    return False


def getnowdatetime():
    global datetime, printdatetime
    datetime = time.strftime("%Y%m%d%H%M%S")
    printdatetime = time.strftime("%Y-%m-%d %H:%M:%S")


def main(q, l):
    # get information from database and collect system info
    print "Collecting information ..."
    time.sleep(1)
    global gateway
    gateway = Database_get2insert.get_Gateway()
    print 'Current OS: ', platform.platform()
    print "Starting L2PS ..."
    time.sleep(0.5)
    sniffing(q, l)


#if( '__main__' == __name__):
#    main()
