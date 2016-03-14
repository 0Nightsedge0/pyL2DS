__author__ = 'TKS'
'''external modules''' '''build-in or download'''
from scapy.all import *
'''internal modules'''
import Database_get2insert

arpcountpers = [] #store all port of host(destination) with arp freq per s
dhcpcountpers = [] #dhcp
icmpcountpers = [] #icmp
dnscountpers = [] #dns

# scanning detection
def tcpsyn_scan():
    return 0


def tcpcon_scan():
    return 0


def udp_scan():
    return 0


def version_detect_scan():
    return 0


def os_detect_scan():
    return 0


def aggrestive_scan():
    return 0

# packet detection
def arp_detection(pkt, l2_dst_mac, l2_src_mac, dstip, srcip, hwsrc, hwdst, gateway,
                  q2, lock, op, datetime, printdatetime, num):
    alert = None
    #print "gateway: ", gateway
    for g in gateway:
        if srcip == g[1] and hwsrc == g[2]:
            return 0
        elif srcip == g[1] and hwsrc != g[2]:
            alert = "Alert IP: %s" % srcip
            alert += " Source MAC: %s" % hwsrc
            alert += " Real MAC address: %s" % g[2]
            alert += " Summary: "
            if(op == 1):
                alert += "Who-has (request) %s? Tell %s" % (dstip, srcip)
            else:
                alert += "%s is-at (response) %s Tell %s" % (srcip, hwsrc, dstip)
            break
        elif(srcip != g[1] and hwsrc == g[2]):
            alert = "Is IP of Device (MAC address: %s ) changed?" % hwsrc
            alert += "Past IP: %s  Now IP: %s" % (g[1], srcip)
            break
        elif(srcip != g[1] and hwsrc != g[2]):
            alert = "Found New Device! IP: %s  MAC address: %s" % (srcip, hwsrc)
    if alert is not None:
        lock.acquire()
        q2.put(alert)
        print alert
        lock.release()
        temp = [datetime+"%05d" % num, printdatetime, srcip,
                dstip, l2_src_mac, l2_dst_mac, 'ARP', alert]
        #print temp
        Database_get2insert.insert_Report(temp)


def dhcp_detection(pkt, l2_dst_mac, l2_src_mac, dstip, srcip, hwsrc, hwdst, gateway,
                   q2, lock, datetime, printdatetime, num):
    #print pkt[0][3][0].show()
    if pkt[0][3][0].op == 2:
        print 'source IP : ', srcip
        print 'source MAC: ', hwsrc
        #print pkt[0][3][1].show()
        print pkt[0][3][1].options
        dhcplay = pkt[0][3][1].options
        for l in dhcplay:
            print l
    return 0


def dns_detection(pkt, l2_dst_mac, l2_src_mac, dstip, srcip, hwsrc, hwdst, gateway,
                  q2, lock, datetime, printdatetime, num):
    #print pkt[0].show()
    print "DNS packet"
    return 0


def icmp_detection(pkt, l2_dst_mac, l2_src_mac, dstip, srcip, hwsrc, hwdst, gateway,
                   q2, lock, datetime, printdatetime, num):
    if pkt[0][2].type == 5 and pkt[0][2].code == 1:
        check = False
        for g in gateway:
            #print g[1]
            if pkt[0][2].gw == g[1]:
                check = True
                return 0
        alert = 'Alert ICMP redirect'
        alert += 'from Source IP: %s Source MAC: %s' % (srcip, hwsrc)
        alert += 'say gateway is %s' % pkt[0][2].gw
        lock.acquire()
        q2.put(alert)
        #print alert
        lock.release()
        temp = [datetime+"%05d" % num, printdatetime, srcip,
                dstip, l2_src_mac, l2_dst_mac, 'ICMP', alert]
        #print temp
        Database_get2insert.insert_Report(temp)
    else:
        return 0


def freq_check(count, proto, q2, lock, freq_basline, optime):
    for item in count:
        #print item
        if item[2] > (optime * freq_basline):
            alert = "alert Frequency Protocol: %4s |frequency: %5d times \n" % (proto, item[2])
            alert += "source IP   : %16s | MAC address: %18s" % (item[0], item[1])
            lock.acquire()
            q2.put(alert)
            lock.release()


def freq_add(srcip, dstip, hwsrc, hwdst, list):
    remark = False

    if not list:
        list.append([srcip, hwsrc, 1])
        remark = True
    else:
        for item in list:
            if item[0] == srcip and item[1] == hwsrc:
                item[2] += 1
                remark = True
                break
    if remark == False:
        list.append([srcip, hwsrc, 1])


def freq_handler(srcip, dstip, hwsrc, hwdst, list):
    global arpcountpers, dhcpcountpers, dnscountpers, icmpcountpers

    if list == 'ARP':
        freq_add(srcip, dstip, hwsrc, hwdst, arpcountpers)
    elif list == 'DNS':
        freq_add(srcip, dstip, hwsrc, hwdst, dnscountpers)
    elif list == 'DHCP':
        freq_add(srcip, dstip, hwsrc, hwdst, dhcpcountpers)
    elif list == 'ICMP':
        freq_add(srcip, dstip, hwsrc, hwdst, icmpcountpers)


def get_proto_type(num, pkt, gateway, q2, lock, datetime, printdatetime):
    hwdst = l2_dst_mac = pkt[0].dst
    hwsrc = l2_src_mac = pkt[0].src
    proto_type = ""

    # Layer 2 : ARP
    if(ARP in pkt[0]):
        proto_type = "ARP"
        dstip = pkt[0][1].pdst
        srcip = pkt[0][1].psrc
        hwsrc = pkt[0][1].hwsrc
        hwdst = pkt[0][1].hwdst

        arp_detection(pkt, l2_dst_mac, l2_src_mac, dstip, srcip, hwsrc, hwdst, gateway,
                      q2, lock, pkt[0][1].op, datetime, printdatetime, num)

    #Layer 3
    if(IP in pkt[0]):
        proto_type = "IP"
        #print pkt[0][1].show()
        srcip = pkt[0][1].src
        dstip = pkt[0][1].dst

        if(TCP in pkt[0]):
            proto_type = "TCP"

            if(DHCP in pkt[0]):
                proto_type = "DHCP"
                dhcp_detection(pkt, l2_dst_mac, l2_src_mac, dstip, srcip, hwsrc, hwdst, gateway,
                               q2, lock, datetime, printdatetime, num)

        if(UDP in pkt[0]):
            proto_type = "UDP"

            if(DHCP in pkt[0]):
                proto_type = "DHCP"
                dhcp_detection(pkt, l2_dst_mac, l2_src_mac, dstip, srcip, hwsrc, hwdst, gateway,
                               q2, lock, datetime, printdatetime, num)

            if(DNS in pkt[0]):
                proto_type = "DNS"
                dns_detection(pkt, l2_dst_mac, l2_src_mac, dstip, srcip, hwsrc, hwdst, gateway,
                              q2, lock, datetime, printdatetime, num)

        if(ICMP in pkt[0]):
            proto_type = "ICMP"
            icmp_detection(pkt, l2_dst_mac, l2_src_mac, dstip, srcip, hwsrc, hwdst, gateway,
                            q2, lock, datetime, printdatetime, num)

    if proto_type == "":
        proto_type = 'Unknown'
    else:
        freq_handler(srcip, dstip, hwsrc, hwdst, proto_type)

    #print "-------------------------------------------------------------------------------"


def detector(pkts, q2, lock, gateway, datetime, printdatetime, freq_baseline, optime):

    global arpcountpers, dhcpcountpers, icmpcountpers, dnscountpers

    for i in range(len(pkts)):
        #print i,
        #print pkts[i].show()
        #print pkts[i].summary()
        get_proto_type(i, pkts[i], gateway, q2, lock, datetime, printdatetime)

    #checking
    freq_check(arpcountpers, "ARP", q2, lock, freq_baseline, optime)
    freq_check(dhcpcountpers, "DHCP", q2, lock, freq_baseline, optime)
    freq_check(dnscountpers, "DNS", q2, lock, freq_baseline, optime)
    freq_check(icmpcountpers, "ICMP", q2, lock, freq_baseline, optime)
    #print "ARP: ", arpcountpers
    #print "DNS: ", dnscountpers
    #print "DHCP: ", dhcpcountpers
    #print "ICMP: ", icmpcountpers

    #reset list
    arpcountpers[:] = dhcpcountpers[:] = icmpcountpers[:] = dnscountpers[:] = []
