__author__ = 'TKS'

'''external modules''' '''build-in or download'''
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import time
from multiprocessing import Process
from threading import Thread
'''internal modules'''
import Database_get2insert
import Detection
import Config

packets = [] #store pkts (cache) *clear every ten seconds and insert to database
oripackets = [] #store original packet
gateway = [] #store gateway
device = [] #store device info

''' remark the tcp and udp knock port '''
remark_scan_host_tcp = []# [IP, MAC, port ...]
remark_scan_host_tcp_alerted = [] # alerted ip
remark_scan_host_udp = []# [IP, MAC, port ...]
remark_scan_host_udp_alerted = [] # alerted ip


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

'''store setting or baseline'''
optime = 1
freq_baseline = 10
tcp_port_knock_limit = 300
udp_port_knock_limit = 300


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
            srcip = pkt[0][1].src
            dstip = pkt[0][1].dst

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

        temp = [datetime+"%05d" % countpers, printdatetime, srcip,
                    dstip, smac, dmac, proto_type, pktdata]

        packets.append(temp)
        oripackets.append(pkt)

        #print pkt.summary(),
        #print pkt.show(),
        countpers += 1

        #print datetime+"%04d" % (countpers)
        #print "###############################################################################\n"


def sniffing(q, lock, iface, q2, lock2, q3, optime, freq_basline, tcp_port_knock_limit, udp_port_knock_limit):
    operation_times = remark_clean_time_tcp = remark_clean_time_udp = 0

    signal = False      #control signal

    while True:
        global packets, datetime, printdatetime, count, countpers, oripackets
        # reset each protocol counts per second
        global totalarp, totalicmp, totaldhcp, totaldns
        global arpcount, icmpcount, dhcpcount, dnscount

        arpcount = icmpcount = dhcpcount = dnscount = countpers = 0

        getnowdatetime()

        sniff(iface=iface, prn=get_packet_type, count=0, timeout=optime, store=0)
        totalarp += arpcount
        totalicmp += icmpcount
        totaldhcp += dhcpcount
        totaldns += dnscount
        count += countpers

        signal = getresult(arpcount, totalarp, icmpcount, totalicmp, dhcpcount,
                           totaldhcp, dnscount, totaldns, count, countpers, operation_times, printdatetime, q, lock, q3)

        if signal is True:
            break
        if packets:
            thd_log = Thread(target=Database_get2insert.insert_Log, args=(packets, ))
            thd_detector = Thread(target=Detection.detector, args=(oripackets, q2, lock2, gateway, datetime,
                                                                   printdatetime, freq_baseline, operation_times,
                                                                   tcp_port_knock_limit, udp_port_knock_limit,
                                                                   remark_scan_host_tcp, remark_scan_host_tcp_alerted,
                                                                   remark_scan_host_udp, remark_scan_host_udp_alerted,
                                                                   device))
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
        operation_times += optime
        remark_clean_time_tcp += optime
        remark_clean_time_udp += optime
        # every x second clean remark once
        if remark_clean_time_tcp > 300:
            remark_scan_host_tcp_alerted[:] = remark_scan_host_tcp[:] = []
            remark_clean_time_tcp = 0
        if remark_clean_time_udp > 600:
            remark_scan_host_udp[:] = remark_scan_host_udp_alerted[:] = []
            remark_clean_time_udp = 0


def getresult(arpcount, totalarp, icmpcount, totalicmp, dhcpcount, totaldhcp, dnscount, totaldns, count, countpers, times, printdatetime, q, lock, q3):
    #print arpcount, totalarp, icmpcount, totalicmp, dhcpcount, totaldhcp, count
    result = [arpcount, totalarp, icmpcount, totalicmp, dhcpcount, totaldhcp, dnscount, totaldns, count, countpers, times, printdatetime]
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


def core_setting():
    setting = Config.read_core_setting()
    global optime, freq_baseline
    for s in setting:
        if s[0] == 'optime':
            optime = int(s[1])
        if s[0] == 'frequency_baseline':
            freq_baseline = int(s[1])
        if s[0] == 'tcp_port_knock_limit':
            tcp_port_knock_limit = int(s[1])
        if s[0] == 'tcp_port_knock_limit':
            tcp_port_knock_limit = int(s[1])


def main(q, l, iface, q2, l2, q3):
    # get information from database and collect system info
    print "Collecting information ..."
    time.sleep(0.5)
    global gateway
    gateway = Database_get2insert.get_Gateway()
    global device
    device = Database_get2insert.get_Device2address_list()
    core_setting()
    sniffing(q, l, iface, q2, l2, q3, optime, freq_baseline, tcp_port_knock_limit, udp_port_knock_limit)
