__author__ = 'TKS'
import IPy
from scapy.all import *

def scan_host():
    global iplist
    print "-------- Host Scanner --------"
    while True:
        try:
            networkid = raw_input("Network Address: ")
            netmask = raw_input("Netmask(/?): ")
            network = '{}/{}'.format(networkid, netmask)
            print "Network ID  : %15s/%2s" % (IPy.IP(networkid), netmask)
            break
        except:
            print "Input error!"
            continue
    print "Scanning..."
    alivelist = []
    alive, dead = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst='%s' % network),
                      timeout=10, verbose=0)
    for i in range(0, len(alive)):
        alivelist.append([alive[i][1].psrc, alive[i][1].hwsrc])
    alivelist.sort()
    for ipmac in alivelist:
        print "IP: %15s  MAC: %17s" % (ipmac[0], ipmac[1])