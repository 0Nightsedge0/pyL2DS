__author__ = 'TKS'

def arp_detection(pkt, dmac, smac, dstip, hwsrc, srcip, hwdst, gateway):

    for i in gateway:
        #print i[0], i[1]
        if(srcip == i[1] and hwsrc != i[2]):
            print "Alert IP: %s" %srcip,
            print " Source MAC: %s" %hwdst,
            print "Real MAC address: %s" %i[2]
        elif(srcip == i[1] and hwsrc == i[2]):
            print "Ok,This is safe!"
        else:
            print "Not my business!"
