__author__ = 'TKS'
'''
compare ip and mac address only with db
'''


from scapy.all import *
import MySQLdb

packetcount = 0

def getgateway():
    gateway = []

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


def arp_detection(pkt, pktdstip, srcip, macdst, macsrc):
    gateway = getgateway()

    for i in gateway:
        print i[0], i[1]
        if(srcip == i[0] and macsrc != i[1]):
            print "alert"
        if(srcip == i[0] and macsrc == i[1]):
            print "ok"


def get_packet_type(pkt, macdst, macsrc):
    if(ARP in pkt[0]):
        print "ARP Packet"
        if(pkt[0][1].op == 1):
            print("who-has (request)")

        if(pkt[0][1].op == 2):
            print("is-at (response)")

        dstip = pkt[0][1].pdst
        srcip = pkt[0][1].psrc
        print "DST IP: ", dstip
        print "SRC IP: ", srcip
        print "DST MAC: ", macdst
        print "SRC MAC: ", macsrc

        arp_detection(pkt, dstip, srcip, macdst, macsrc)

    if(IP in pkt[0]):
        print "IP Packet"

        if(UDP in pkt[0]):
            print "UDP Packet"

        if(ICMP in pkt[0]):
            print "ICMP Packet"

        print "DST IP: ", pkt[0][1].dst
        print "SRC IP: ", pkt[0][1].src, "\n"


def sniffing():
    count = 1
    pktlist = []
    while count <= 5:
        print ("###################################")
        print ("%5d" % count),
        #a = sniff(iface="eth0", count=1, filter="")
        a = sniff(iface="wlan1", count=1, filter="")
        pktlist.append(a)
        pktlist[count-1].nsummary()
        print str(pktlist[count-1])+"\n"

        print "-----Ethernet-----"
        print "DST MAC: ", pktlist[count-1][0].dst
        print "SRC MAC: ", pktlist[count-1][0].src
        pktmacdst = pktlist[count-1][0].dst
        pktmacsrc = pktlist[count-1][0].src
        print "------------------"
        get_packet_type(pktlist[count-1], pktmacdst, pktmacsrc)
        count += 1


def main():
    sniffing()


main()
