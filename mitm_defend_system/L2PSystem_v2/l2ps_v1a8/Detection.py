__author__ = 'TKS'
'''external modules''' '''build-in or download'''
from scapy.all import *
'''internal modules'''
import Database_get2insert
import Detection_tcpudp_scan
import RS_connector

''' scanning detection '''
tcp_stack = []# [[IP src, IP dst, dst port, flag],...]
tcp_scan_method_alerted = [] # [[IP src, scanning method],...]

''' packet detection '''
arpcountpers = [] #store all port of host(destination) with arp freq per s
dhcpcountpers = [] #dhcp
icmpcountpers = [] #icmp
dnscountpers = [] #dns

''' freq use counter '''
fnum = 0


# packet detection
def arp_detection(pkt, l2_dst_mac, l2_src_mac, dstip, srcip, hwsrc, hwdst, gateway,
                  q2, lock, op, datetime, printdatetime, num):
    alert = None
    #print "gateway: ", gateway

    if not gateway:
        return 0

    if len(gateway) == 0:
        return 0

    for g in gateway:
        #print gateway, srcip, hwsrc
        if srcip == g[0] and hwsrc == g[1]:
            return 0
        elif srcip == g[0] and hwsrc != g[1]:
            alert = "Alert IP: %s" % srcip
            alert += " Source MAC: %s" % hwsrc
            alert += " Real MAC address: %s" % g[1]
            alert += " Summary: "
            if(op == 1):
                alert += "Who-has (request) %s? Tell %s" % (dstip, srcip)
            else:
                alert += "%s is-at (response) %s Tell %s" % (srcip, hwsrc, dstip)
            break
        elif(srcip != g[0] and hwsrc == g[1]):
            break
            alert = "Is IP of Device (MAC address: %s ) changed?" % hwsrc
            alert += "Past IP: %s  Now IP: %s" % (g[0], srcip)
            break
        #elif(srcip != g[0] and hwsrc != g[1]):
        #    alert = "Found New Device! IP: %s  MAC address: %s" % (srcip, hwsrc)
    if alert is not None:
        lock.acquire()
        q2.put([srcip, dstip, hwsrc, hwdst, 'ARP', alert])
        #print alert
        lock.release()
        temp = [datetime+"%05d" % num, printdatetime, srcip,
                dstip, l2_src_mac, l2_dst_mac, 'ARP', alert]
        #print temp
        Database_get2insert.insert_Report(temp)
        RS_connector.remote_shell(4, l2_src_mac, '')


def dhcp_detection(pkt, l2_dst_mac, l2_src_mac, dstip, srcip, hwsrc, hwdst, gateway,
                   q2, lock, datetime, printdatetime, num, device):
    #print pkt.show()
    if not gateway:
        return 0

    if len(gateway) == 0:
        return 0

    # DHCP SERVER info
    DHCP = []
    for d in device:
        if d[3] == 'DHCP':
            DHCP.append([d[4], d[5]])

    # DHCP offer
    if pkt[0][3][0].op == 2:
        #print 'source IP : ', srcip
        #print 'source MAC: ', hwsrc
        #print pkt[0][3][1].show()
        #print pkt[0][3][1].options
        #dhcplay = pkt[0][3][1].options
        if [srcip, hwsrc] in DHCP:
            return 0
        alert = 'Wrong DHCP source! IP: %s MAC: %s' % (srcip, hwsrc)
        lock.acquire()
        q2.put([srcip, dstip, hwsrc, hwdst, 'DHCP', alert])
        # print alert
        lock.release()
        temp = [datetime + "%05d" % num, printdatetime, srcip,
                dstip, l2_src_mac, l2_dst_mac, 'DNS', alert]
        # print temp
        Database_get2insert.insert_Report(temp)
        #RS_connector.remote_shell(4, l2_src_mac, '')


def dns_detection(pkt, l2_dst_mac, l2_src_mac, dstip, srcip, hwsrc, hwdst, gateway,
                  q2, lock, datetime, printdatetime, num, device):
    #print pkt[0].show()
    if not gateway:
        return 0

    if len(gateway) == 0:
        return 0

    DNS = []
    for d in device:
        if d[3] == 'DNS':
            DNS.append([d[4], d[5]])

    if [srcip, hwsrc] in DNS:
        return 0
    alert = 'Wrong DNS source! IP: %s MAC: %s' % (srcip, hwsrc)
    lock.acquire()
    q2.put([srcip, dstip, hwsrc, hwdst, 'DNS', alert])
    # print alert
    lock.release()
    temp = [datetime + "%05d" % num, printdatetime, srcip,
                dstip, l2_src_mac, l2_dst_mac, 'DNS', alert]
    # print temp
    Database_get2insert.insert_Report(temp)
    #RS_connector.remote_shell(4, l2_src_mac, '')


def icmp_detection(pkt, l2_dst_mac, l2_src_mac, dstip, srcip, hwsrc, hwdst, gateway,
                   q2, lock, datetime, printdatetime, num, device):
    if not gateway:
        return 0

    if len(gateway) == 0:
        return 0

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
        q2.put([srcip, dstip, hwsrc, hwdst, 'ICMP redirect', alert])
        #print alert
        lock.release()
        temp = [datetime+"%05d" % num, printdatetime, srcip,
                dstip, l2_src_mac, l2_dst_mac, 'ICMP', alert]
        #print temp
        Database_get2insert.insert_Report(temp)
        #RS_connector.remote_shell(4, l2_src_mac, '')
    else:
        return 0


def freq_check(count, proto, q2, lock, freq_basline, optime, fnum, datetime, printdatetime):
    for item in count:
        #print item

        if item[2] > freq_basline:
            fnum += 1
            alert = "alert Frequency Protocol: %4s |frequency: %5d times " % (proto, item[2])
            alert += "source IP   : %16s | MAC address: %18s" % (item[0], item[1])
            lock.acquire()
            q2.put([item[0], '', item[1], '', 'frequency problem', alert])
            lock.release()
            temp = [datetime+"F%04d" % fnum, printdatetime, item[0],
                    '', item[1], '', proto, alert]
            Database_get2insert.insert_Report(temp)


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


def get_proto_type(num, pkt, gateway, q2, lock, datetime, printdatetime,
                   remark_scan_host_tcp, remark_scan_host_tcp_alerted,
                   remark_scan_host_udp, remark_scan_host_udp_alerted,
                   tcp_port_knock_limit, udp_port_knock_limit, device):

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
                #dhcp_detection(pkt, l2_dst_mac, l2_src_mac, dstip, srcip, hwsrc, hwdst, gateway,
                #               q2, lock, datetime, printdatetime, num, device)

        if(UDP in pkt[0]):
            proto_type = "UDP"

            if(DHCP in pkt[0]):
                proto_type = "DHCP"
                dhcp_detection(pkt, l2_dst_mac, l2_src_mac, dstip, srcip, hwsrc, hwdst, gateway,
                               q2, lock, datetime, printdatetime, num, device)

            if(DNS in pkt[0]):
                proto_type = "DNS"
                #dns_detection(pkt, l2_dst_mac, l2_src_mac, dstip, srcip, hwsrc, hwdst, gateway,
                #              q2, lock, datetime, printdatetime, num, device)

        if(ICMP in pkt[0]):
            proto_type = "ICMP"
            icmp_detection(pkt, l2_dst_mac, l2_src_mac, dstip, srcip, hwsrc, hwdst, gateway,
                           q2, lock, datetime, printdatetime, num, device)

    if proto_type == "":
        proto_type = 'Unknown'
    elif proto_type == 'TCP':
        Detection_tcpudp_scan.tcp_scan_detection(pkt, l2_dst_mac, l2_src_mac, dstip, srcip, hwsrc, hwdst,
                                                 q2, lock, datetime, printdatetime, num,
                                                 tcp_stack, tcp_scan_method_alerted)
        if pkt[TCP].flags == 2:
            Detection_tcpudp_scan.tcp_syn_checker(pkt, l2_dst_mac, l2_src_mac, dstip, srcip, hwsrc, hwdst,
                                                  q2, lock, datetime, printdatetime, num,
                                                  remark_scan_host_tcp, remark_scan_host_tcp_alerted,
                                                  tcp_port_knock_limit)

        return 0
    elif proto_type == 'UDP':
        Detection_tcpudp_scan.udp_scan(pkt, l2_dst_mac, l2_src_mac, dstip, srcip, hwsrc, hwdst,
                                       q2, lock, datetime, printdatetime, num,
                                       remark_scan_host_udp, remark_scan_host_udp_alerted, udp_port_knock_limit)
    else:
        freq_handler(srcip, dstip, hwsrc, hwdst, proto_type)


def detector(pkts, q2, lock, gateway, datetime, printdatetime, freq_baseline, optime,
             tcp_port_knock_limit, udp_port_knock_limit,
             remark_scan_host_tcp, remark_scan_host_tcp_alerted,
             remark_scan_host_udp, remark_scan_host_udp_alerted,
             device):
    global arpcountpers, dhcpcountpers, icmpcountpers, dnscountpers

    for i in range(len(pkts)):
        #print i,
        #print pkts[i].show()
        #print pkts[i].summary()
        get_proto_type(i, pkts[i], gateway, q2, lock, datetime, printdatetime,
                       remark_scan_host_tcp, remark_scan_host_tcp_alerted,
                       remark_scan_host_udp, remark_scan_host_udp_alerted,
                       tcp_port_knock_limit, udp_port_knock_limit,
                       device)

    #checking F+4 numbers -> db index for freq
    global fnum
    freq_check(arpcountpers, "ARP", q2, lock, freq_baseline, optime, fnum, datetime, printdatetime)
    freq_check(dhcpcountpers, "DHCP", q2, lock, freq_baseline, optime, fnum, datetime, printdatetime)
    freq_check(dnscountpers, "DNS", q2, lock, freq_baseline, optime, fnum, datetime, printdatetime)
    freq_check(icmpcountpers, "ICMP", q2, lock, freq_baseline, optime, fnum, datetime, printdatetime)
    #print "ARP: ", arpcountpers
    #print "DNS: ", dnscountpers
    #print "DHCP: ", dhcpcountpers
    #print "ICMP: ", icmpcountpers
    fnum = 0

    Detection_tcpudp_scan.tcp_scan_checker(q2, lock, datetime, printdatetime, fnum,
                                           remark_scan_host_tcp, remark_scan_host_tcp_alerted,
                                           tcp_stack, tcp_scan_method_alerted)

    #reset list
    #print optime

    arpcountpers[:] = dhcpcountpers[:] = icmpcountpers[:] = dnscountpers[:] = []
    #print tcp_scan_method_alerted
    if optime % 3 == 0:
        tcp_scan_method_alerted[:] = []
        tcp_stack[:] = []
    #print 'tcp stack outside:', tcp_stack
    #print tcp_scan_method_alerteds
