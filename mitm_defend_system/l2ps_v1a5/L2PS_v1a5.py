__author__ = 'TKS'

'''external modules''' '''build-in or download'''
from scapy.all import *
import numpy as np
import time
from multiprocessing import Process
from threading import Thread
'''internal modules'''
import Database_get2insert
import Detection

packets = [] #store pkts (cache) *clear every ten seconds and insert to database
oripackets = [] #store original packet
gateway = [] #store gateway

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

        dmac = pkt[0].dst
        smac = pkt[0].src
        dstip = 0
        srcip = 0
        proto_type = ""
        pktdata = ""
        '''
        #Layer 2
        print "###############################################################################"
        print "No. %05d" % count
        print "----------------------Ethernet----------------------"
        print "DST MAC: ", dmac
        print "SRC MAC: ", smac
        print "----------------------------------------------------"
        '''
        if(ARP in pkt[0]):
            proto_type = "ARP"
            dstip = pkt[0][1].pdst
            srcip = pkt[0][1].psrc
            hwsrc = pkt[0][1].hwsrc
            hwdst = pkt[0][1].hwdst

            pktdata = "dstip=%s srcip=%s hwsrc=%s hwdst=%s" % (dstip, srcip, hwsrc, hwdst)

            #print "-> ARP Packet"
            if(pkt[0][1].op == 1):
                #print("->-> who-has (request)")
                pktdata += " (Who-has (request) %s? Tell %s)" % (dstip, srcip)

            if(pkt[0][1].op == 2):
                #print("->-> is-at (response)")
                pktdata += " (%s is-at (response) %s Tell %s)" % (dstip, hwdst, srcip)
            '''
            print "DST IP : %16s" % dstip,
            print "| DST HW MAC : %20s" % hwdst
            print "SRC IP : %16s" % srcip,
            print "| SRC HW MAC : %20s" % hwsrc
            '''
            arpcount += 1

        #Layer 3
        if(IP in pkt[0]):
            #print "-> IP Packet"
            proto_type = "IP"

            if(TCP in pkt[0]):
                #print "->-> TCP Packet"
                proto_type = "TCP"

            if(UDP in pkt[0]):
                #print "->-> UDP Packet"
                proto_type = "UDP"
                if(DHCP in pkt[0]):
                    #print "->->-> DHCP Packet"
                    proto_type = "DHCP"
                    dhcpcount += 1
                if(DNS in pkt[0]):
                    #print "->->-> DNS Packet"
                    proto_type = "DNS"
                    dnscount += 1

            if(ICMP in pkt[0]):
                #print "->-> ICMP Packet"
                proto_type = "ICMP"
                icmpcount += 1
            #print "DST IP : %16s" % pkt[0][1].dst
            #print "SRC IP : %16s" % pkt[0][1].src

        if proto_type == "":
            proto_type = 'Unknown'

        temp = [datetime+"%04d" % countpers, printdatetime, srcip,
                    dstip, smac, dmac, proto_type, pktdata]

        packets.append(temp)
        oripackets.append(pkt)

        #print pkt.summary(),
        #print pkt.show(),
        countpers += 1

        #print datetime+"%04d" % (countpers)
        #print "###############################################################################\n"


def sniffing(q, lock, iface, q2, lock2, q3):
    operation_times = 0

    signal = False      #control signal

    while True:
        global packets, datetime, printdatetime, count, countpers, oripackets
        # reset each protocol counts per second
        global totalarp, totalicmp, totaldhcp, totaldns
        global arpcount, icmpcount, dhcpcount, dnscount

        arpcount = icmpcount = dhcpcount = dnscount = countpers = 0

        getnowdatetime()

        sniff(iface=iface, prn=get_packet_type, count=0, timeout=1, store=0)
        totalarp += arpcount
        totalicmp += icmpcount
        totaldhcp += dhcpcount
        totaldns += dnscount
        count += countpers

        signal = getresult(arpcount, totalarp, icmpcount, totalicmp, dhcpcount,
                            totaldhcp, dnscount, totaldns, count, operation_times, printdatetime, q, lock, q3)

        if signal is True:
            break

        if packets:
            thd_log = Thread(target=Database_get2insert.insert_Log, args=(packets, ))
            thd_detector = Thread(target=Detection.detector, args=(oripackets, q2, lock2, gateway, datetime, printdatetime))
            thd_log.start()
            thd_detector.start()
            '''
            ps_log = Process(target=Database_get2insert.insert_Log, args=(packets, ))
            ps_detector = Process(target=Detection.detector, args=(oripackets, q2, lock2, gateway, datetime, printdatetime))
            ps_log.start()
            ps_detector.start()
            '''
            packets = []
            oripackets = []

        #print datetime+"%04d" % (countpers)
        #print "count = ", count
        operation_times += 1


def getresult(arpcount, totalarp, icmpcount, totalicmp, dhcpcount, totaldhcp, dnscount, totaldns, count, times, printdatetime, q, lock, q3):
    #print arpcount, totalarp, icmpcount, totalicmp, dhcpcount, totaldhcp, count
    result = [arpcount, totalarp, icmpcount, totalicmp, dhcpcount, totaldhcp, dnscount, totaldns, count, times, printdatetime]
    #print "queue size: ", q.qsize()
    lock.acquire()
    #print "Putter put ", result
    q.put(result)
    lock.release()
    try:
        signal = q3.get(block=False)
        if signal == 's':
            return True
    except:
        return False


def getnowdatetime():
    global datetime, printdatetime
    datetime = time.strftime("%Y%m%d%H%M%S")
    printdatetime = time.strftime("%Y-%m-%d %H:%M:%S")


def main(q, l, iface, q2, l2, q3):
    # get information from database and collect system info
    print "Collecting information ..."
    time.sleep(0.5)
    global gateway
    gateway = Database_get2insert.get_Gateway()
    time.sleep(0.5)
    sniffing(q, l, iface, q2, l2, q3)

