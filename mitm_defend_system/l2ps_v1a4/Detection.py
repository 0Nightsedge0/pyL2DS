__author__ = 'TKS'
'''external modules''' '''build-in or download'''
from scapy.all import *

import Database_get2insert


def arp_detection(pkt, l2_dst_mac, l2_src_mac, dstip, srcip, hwsrc, hwdst, gateway,
                  q2, lock, op, datetime, printdatetime, num):
    alert = None
    #print "gateway: ", gateway
    for g in gateway:
        if(srcip == g[1] and hwsrc != g[2]):
            alert = "Alert IP: %s" % srcip
            alert += " Source MAC: %s" % hwsrc
            alert += " Real MAC address: %s" % g[2]
            alert += " Summary: "
            if(op == 1):
                alert += "Who-has (request) %s? Tell %s" % (dstip, srcip)
            else:
                alert += "%s is-at (response) %s Tell %s" % (srcip, hwsrc, dstip)
        elif(srcip != g[1] and hwsrc == g[2]):
            alert = "Is IP of Device (MAC address: %s ) changed?" % hwsrc
            alert += "Past IP: %s  Now IP: %s" % (g[1], srcip)
        elif(srcip != g[1] and hwsrc != g[2]):
            alert = "Found New Device! IP: %s  MAC address: %s" % (srcip, hwsrc)
        lock.acquire()
        q2.put(alert)
        lock.release()
        temp = [datetime+"%04d" % num, printdatetime, srcip,
                        dstip, l2_src_mac, l2_dst_mac, 'ARP', alert]
        #print temp
        Database_get2insert.insert_Report(temp)


def dhcp_detection():
    return 0


def dns_detection():
    return 0


def icmp_detection():
    return 0


def get_proto_type(num, pkt, gateway, q2, lock, datetime, printdatetime):
    l2_dst_mac = pkt[0].dst
    l2_src_mac = pkt[0].src
    print "-------------------------------------------------------------------------------"
    print "No: %05d" % num
    print "Layer 2 Destination MAC address : %s | Layer 2 Source MAC address : %s" % (l2_dst_mac, l2_src_mac)

    # Layer 2 : ARP
    if(ARP in pkt[0]):
        proto_type = "ARP"
        dstip = pkt[0][1].pdst
        srcip = pkt[0][1].psrc
        hwsrc = pkt[0][1].hwsrc
        hwdst = pkt[0][1].hwdst

        print "Type   : %s" % proto_type
        if(pkt[0][1].op == 1):
            print "Data   : Who-has (request) %s? Tell %s" % (dstip, srcip)
        if(pkt[0][1].op == 2):
            print "Data   : %s is-at (response) %s Tell %s" % (srcip, hwsrc, dstip)

        print "DST IP : %16s" % dstip,
        print "| DST HW MAC : %20s" % hwdst
        print "SRC IP : %16s" % srcip,
        print "| SRC HW MAC : %20s" % hwsrc
        arp_detection(pkt, l2_dst_mac, l2_src_mac, dstip, srcip, hwsrc, hwdst, gateway,
                      q2, lock, pkt[0][1].op, datetime, printdatetime, num)

    #Layer 3
    if(IP in pkt[0]):
        proto_type = "IP"
        print "Type : %s" % proto_type,

        if(TCP in pkt[0]):
            proto_type = "TCP"
            print "/ %s" % proto_type,

            if(DHCP in pkt[0]):
                proto_type = "DHCP"
                print "/ %s" % proto_type
                return 0

            print "\n"

        if(UDP in pkt[0]):
            proto_type = "UDP"
            print "/ %s" % proto_type,

            if(DHCP in pkt[0]):
                proto_type = "DHCP"
                print "/ %s" % proto_type
                return 0

            if(DNS in pkt[0]):
                proto_type = "DNS"
                print "/ %s" % proto_type
                return 0

            print "\n"

        if(ICMP in pkt[0]):
            proto_type = "ICMP"
            print "/ %s" % proto_type

    print "-------------------------------------------------------------------------------"


def detector(pkts, q2, lock, gateway, datetime, printdatetime):
    for i in range(len(pkts)):
        #print pkts[i].show()
        #print pkts[i].summary()
        get_proto_type(i, pkts[i], gateway, q2, lock, datetime, printdatetime)